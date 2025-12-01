import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import bodyParser from 'body-parser';
import multer from 'multer';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import sanitizeHtml from 'sanitize-html';
import session from 'express-session';
import Database from 'better-sqlite3';
import expressLayouts from 'express-ejs-layouts';

dotenv.config();
const app = express();
app.locals.isProd = process.env.NODE_ENV === 'production';
// Si se despliega detrás de proxy (Render/Heroku/nginx)
app.set('trust proxy', 1);
const db = new Database(path.join(process.cwd(), 'content.db'));

// Ensure tables
db.exec(`
CREATE TABLE IF NOT EXISTS offers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  summary TEXT,
  content TEXT,
  image TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  excerpt TEXT,
  content TEXT,
  cover TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT
);
CREATE TABLE IF NOT EXISTS media (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL,
  url TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT,
  message TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  phone TEXT,
  whatsapp TEXT,
  instagram TEXT,
  facebook TEXT,
  twitter TEXT,
  email TEXT,
  updated_at TEXT
);
`);

// Ensure column 'image' exists in offers (for older DBs)
try {
  const cols = db.prepare("PRAGMA table_info(offers)").all();
  const hasImage = cols.some(c => c.name === 'image');
  if (!hasImage) {
    db.prepare('ALTER TABLE offers ADD COLUMN image TEXT').run();
  }
} catch {}

// Seed offers if empty
const countOffers = db.prepare('SELECT COUNT(*) as c FROM offers').get().c;
if (countOffers === 0) {
  const seed = db.prepare('INSERT INTO offers (title, slug, summary, content, image) VALUES (?, ?, ?, ?, ?)');
  seed.run('Diseño de Páginas Web', 'diseno-web', 'Sitios modernos, rápidos y SEO-friendly.', 'Construimos sitios responsive, optimizados y de alto impacto visual.', '/static/img/diseño web_bajada.png');
  seed.run('Sistemas para Pymes', 'sistemas-pymes', 'Automatización y gestión eficiente.', 'Diseñamos sistemas a medida para optimizar tus operaciones.', '/static/img/diseñoapp.png');
  seed.run('Soluciones para Comercios', 'soluciones-comercios', 'Herramientas en Sistemas/Excel.', 'Desarrollos ligeros en software o Excel para pequeños comercios.', '/static/img/diseñografico_2.png');
}

// Seed settings row if missing
const settingsRow = db.prepare('SELECT COUNT(*) as c FROM settings').get().c;
if (settingsRow === 0) {
  db.prepare('INSERT INTO settings (id, phone, whatsapp, instagram, facebook, twitter, email, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?)')
    .run('+54 11 0000-0000', 'https://wa.me/541100000000', 'https://instagram.com/', 'https://facebook.com/', 'https://twitter.com/', 'info@goodduck.test', new Date().toISOString());
}

// View engine
app.set('views', path.join(process.cwd(), 'views'));
app.set('view engine', 'ejs');
app.use(expressLayouts);
app.set('layout', path.join('layouts', 'main'));

// Static
app.use('/static', express.static(path.join(process.cwd(), 'public')));
// Seguridad básica
app.use(helmet({ contentSecurityPolicy: false }));
// Cargar settings en locals (con fallback que crea fila si falta)
app.use((req, res, next) => {
  let s = db.prepare('SELECT * FROM settings WHERE id = 1').get();
  if (!s) {
    db.prepare('INSERT INTO settings (id, phone, whatsapp, instagram, facebook, twitter, email, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?)')
      .run('+54 11 0000-0000', 'https://wa.me/541100000000', 'https://instagram.com/', 'https://facebook.com/', 'https://twitter.com/', 'info@goodduck.test', new Date().toISOString());
    s = db.prepare('SELECT * FROM settings WHERE id = 1').get();
  }
  res.locals.settings = s;
  next();
});
// Sesiones para autenticación básica
app.use(
  session({
    name: 'gd.sid',
    secret: process.env.ADMIN_SESSION_SECRET || 'change_me_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax' },
  })
);

// Parsers
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Uploads
// Subidas guardadas en public/uploads para servir estáticamente
const upload = multer({
  dest: path.join(process.cwd(), 'public', 'uploads'),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'].includes(file.mimetype);
    cb(ok ? null : new Error('Tipo de archivo no permitido'), ok);
  },
});

// Helpers
function getOffers() {
  return db.prepare('SELECT * FROM offers ORDER BY id').all();
}
function getRecentPosts(limit = 6) {
  return db.prepare('SELECT * FROM posts ORDER BY created_at DESC LIMIT ?').all(limit);
}

// Utilidades de validación/sanitización
function clamp(str, max) { return (str || '').toString().trim().slice(0, max); }
function cleanHTML(html) {
  return sanitizeHtml(html || '', {
    allowedTags: ['b','i','em','strong','a','p','ul','ol','li','br'],
    allowedAttributes: { a: ['href','target','rel'] },
    transformTags: { a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer', target: '_blank' }) },
  });
}
function cleanSlug(s) {
  const base = clamp(s, 60).toLowerCase();
  return base.replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || 'item';
}

// Rate limiting
const adminLimiter = rateLimit({ windowMs: 15*60*1000, max: 200, standardHeaders: true, legacyHeaders: false });
const formLimiter = rateLimit({ windowMs: 10*60*1000, max: 100 });

// Routes: Public
app.get('/', (req, res) => {
  const offers = getOffers();
  const posts = getRecentPosts();
  res.render('home', { offers, posts });
});
app.get('/oferta/:slug', (req, res) => {
  const offer = db.prepare('SELECT * FROM offers WHERE slug = ?').get(req.params.slug);
  if (!offer) return res.status(404).render('404');
  res.render('offer', { offer });
});
app.get('/blog/:slug', (req, res) => {
  const post = db.prepare('SELECT * FROM posts WHERE slug = ?').get(req.params.slug);
  if (!post) return res.status(404).render('404');
  res.render('post', { post });
});
app.post('/contacto', formLimiter, (req, res) => {
  const name = clamp(req.body.name, 80);
  const email = clamp(req.body.email, 120);
  const message = clamp(req.body.message, 1000);
  db.prepare('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)').run(name, email, message);
  res.redirect('/?sent=1');
});

// Routes: Admin (simple)
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.redirect('/admin/login');
}

app.get('/admin/login', (req, res) => {
  res.render('admin/login', { title: 'Acceso Admin', error: null });
});

app.post('/admin/login', (req, res) => {
  const user = (process.env.ADMIN_USER || 'admin').trim();
  const pass = (process.env.ADMIN_PASS || 'admin123').trim();
  const { username, password } = req.body;
  if (username === user && password === pass) {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  }
  return res.render('admin/login', { title: 'Acceso Admin', error: 'Credenciales inválidas' });
});

app.post('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.use('/admin', adminLimiter);
app.get('/admin', requireAdmin, (req, res) => {
  const offers = getOffers();
  const posts = db.prepare('SELECT * FROM posts ORDER BY created_at DESC').all();
  res.render('admin/index', { offers, posts });
});
// Settings admin
app.get('/admin/settings', requireAdmin, (req, res) => {
  const settings = db.prepare('SELECT * FROM settings WHERE id = 1').get();
  res.render('admin/settings', { title: 'Configuración', settings });
});
app.post('/admin/settings', requireAdmin, (req, res) => {
  const { phone, whatsapp, instagram, facebook, twitter, email } = req.body;
  db.prepare('UPDATE settings SET phone=?, whatsapp=?, instagram=?, facebook=?, twitter=?, email=?, updated_at=? WHERE id=1')
    .run(phone, whatsapp, instagram, facebook, twitter, email, new Date().toISOString());
  res.redirect('/admin/settings');
});
// Offers CRUD
app.post('/admin/offers', requireAdmin, (req, res) => {
  const title = clamp(req.body.title, 100);
  const slug = cleanSlug(req.body.slug);
  const summary = clamp(req.body.summary, 240);
  const content = cleanHTML(req.body.content);
  db.prepare('INSERT INTO offers (title, slug, summary, content) VALUES (?, ?, ?, ?)').run(title, slug, summary, content);
  res.redirect('/admin');
});
app.post('/admin/offers/:id/delete', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM offers WHERE id = ?').run(req.params.id);
  res.redirect('/admin');
});
// Posts CRUD
app.post('/admin/posts', requireAdmin, upload.single('cover'), (req, res) => {
  const title = clamp(req.body.title, 120);
  const slug = cleanSlug(req.body.slug);
  const excerpt = clamp(req.body.excerpt, 280);
  const content = cleanHTML(req.body.content);
  const cover = req.file ? `/static/uploads/${req.file.filename}` : null;
  db.prepare('INSERT INTO posts (title, slug, excerpt, content, cover) VALUES (?, ?, ?, ?, ?)').run(title, slug, excerpt, content, cover);
  res.redirect('/admin');
});
app.post('/admin/posts/:id/delete', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM posts WHERE id = ?').run(req.params.id);
  res.redirect('/admin');
});

// Update offer image
app.post('/admin/offers/:id/image', requireAdmin, upload.single('image'), (req, res) => {
  if (req.file) {
    const url = `/static/uploads/${req.file.filename}`;
    db.prepare('UPDATE offers SET image=?, updated_at=? WHERE id=?').run(url, new Date().toISOString(), req.params.id);
  }
  res.redirect('/admin');
});

// Media manager
app.get('/admin/media', requireAdmin, (req, res) => {
  const media = db.prepare('SELECT * FROM media ORDER BY created_at DESC').all();
  res.render('admin/media', { title: 'Media', media });
});
app.post('/admin/media', requireAdmin, upload.single('file'), (req, res) => {
  const f = req.file;
  if (f) {
    const url = `/static/uploads/${f.filename}`;
    db.prepare('INSERT INTO media (filename, url, created_at) VALUES (?, ?, ?)').run(f.originalname, url, new Date().toISOString());
  }
  res.redirect('/admin/media');
});

// 404
app.use((req, res) => res.status(404).render('404'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`GOOD DUCK web running on http://localhost:${port}`));
