import express from 'express';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import bcrypt from 'bcryptjs';
import bodyParser from 'body-parser';
import multer from 'multer';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import sanitizeHtml from 'sanitize-html';
import session from 'express-session';
import { createDbAdapter, ensureSchema } from './db.js';
import expressLayouts from 'express-ejs-layouts';

dotenv.config();
const app = express();
app.locals.isProd = process.env.NODE_ENV === 'production';
// Si se despliega detrás de proxy (Render/Heroku/nginx)
app.set('trust proxy', 1);

// Directorio de datos (persistencia si Disk disponible). Fallback si EACCES.
const requestedDataDir = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(process.cwd(), 'data');
let dataDir = requestedDataDir;
try {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
} catch (e) {
  console.warn(`No se pudo usar DATA_DIR '${requestedDataDir}' (${e.code || e.message}), usando fallback local.`);
  dataDir = path.join(process.cwd(), 'data_fallback');
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
}
const dbPath = path.join(dataDir, 'content.db');
const uploadsDir = path.join(dataDir, 'uploads');
try {
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
  }
} catch (e) {
  console.warn('No se pudo crear uploads en dataDir, usando ./public/uploads como último recurso');
  // Último fallback: carpeta pública (no persistente si no hay Disk)
}

let db; // se inicializa en init()

// View engine
app.set('views', path.join(process.cwd(), 'views'));
app.set('view engine', 'ejs');
app.use(expressLayouts);
app.set('layout', path.join('layouts', 'main'));

// Static
// Servir primero /static/uploads desde el directorio de datos (persistente si se monta Disk)
app.use('/static/uploads', express.static(uploadsDir));
// Luego el resto de /static desde la carpeta pública del proyecto
app.use('/static', express.static(path.join(process.cwd(), 'public')));
// Seguridad básica
app.use(helmet({ contentSecurityPolicy: false }));
// Cargar settings en locals (con fallback que crea fila si falta)
app.use(async (req, res, next) => {
  try {
    let s = await db.get('SELECT * FROM settings WHERE id = 1');
    if (!s) {
      await db.run('INSERT INTO settings (id, phone, whatsapp, instagram, facebook, twitter, email, hero_image, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)',
        ['+54 11 0000-0000', 'https://wa.me/541100000000', 'https://instagram.com/', 'https://facebook.com/', 'https://twitter.com/', 'info@goodduck.test', '/static/img/diseñoapp.png', new Date().toISOString()]);
      s = await db.get('SELECT * FROM settings WHERE id = 1');
    }
    res.locals.settings = s;
    next();
  } catch (e) { next(e); }
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

// Email (SMTP)
let transporter = null;
try {
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = parseInt(process.env.SMTP_PORT || '0', 10);
  const smtpSecure = (process.env.SMTP_SECURE === 'true') || smtpPort === 465;
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;
  if (smtpHost && smtpPort && smtpUser && smtpPass) {
    transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpSecure,
      auth: { user: smtpUser, pass: smtpPass },
    });
  }
} catch (e) {
  console.warn('SMTP no configurado o inválido:', e?.message);
}

// Parsers
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Uploads
// Subidas guardadas en uploadsDir para servir por /static/uploads
const upload = multer({
  dest: uploadsDir,
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp'].includes(file.mimetype);
    cb(ok ? null : new Error('Tipo de archivo no permitido'), ok);
  },
});

// Helpers
async function getOffers() {
  return db.all('SELECT * FROM offers ORDER BY id');
}
async function getRecentPosts(limit = 6) {
  return db.all('SELECT * FROM posts ORDER BY created_at DESC LIMIT ?', [limit]);
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
app.get('/', async (req, res) => {
  const offers = await getOffers();
  const posts = await getRecentPosts();
  res.render('home', { offers, posts });
});
app.get('/oferta/:slug', async (req, res) => {
  const offer = await db.get('SELECT * FROM offers WHERE slug = ?', [req.params.slug]);
  if (!offer) return res.status(404).render('404');
  res.render('offer', { offer });
});
app.get('/blog/:slug', async (req, res) => {
  const post = await db.get('SELECT * FROM posts WHERE slug = ?', [req.params.slug]);
  if (!post) return res.status(404).render('404');
  res.render('post', { post });
});
app.post('/contacto', formLimiter, async (req, res) => {
  const name = clamp(req.body.name, 80);
  const emailAddr = clamp(req.body.email, 120);
  const message = clamp(req.body.message, 1000);
  await db.run('INSERT INTO contacts (name, email, message) VALUES (?, ?, ?)', [name, emailAddr, message]);
  if (transporter) {
    try {
      const to = process.env.MAIL_TO || (res.locals.settings && res.locals.settings.email) || process.env.SMTP_USER;
      const from = process.env.MAIL_FROM || 'GOOD DUCK <no-reply@goodduck.local>';
      const subject = `Nuevo contacto desde GOOD DUCK: ${name}`;
      const html = `<h2>Nuevo mensaje</h2><p><strong>Nombre:</strong> ${name}</p><p><strong>Email:</strong> ${emailAddr}</p><p><strong>Mensaje:</strong><br>${message}</p>`;
      const text = `Nuevo mensaje\nNombre: ${name}\nEmail: ${emailAddr}\nMensaje:\n${message}`;
      await transporter.sendMail({ from, to, subject, text, html });
    } catch (err) {
      console.error('Error enviando email:', err?.message);
    }
  }
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

app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const row = await db.get('SELECT * FROM admin_users WHERE username = ?', [username]);
  if (row && bcrypt.compareSync(password, row.password_hash)) {
    req.session.isAdmin = true;
    req.session.adminUser = row.username;
    return res.redirect('/admin');
  }
  return res.render('admin/login', { title: 'Acceso Admin', error: 'Credenciales inválidas' });
});

app.post('/admin/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.use('/admin', adminLimiter);
app.get('/admin', requireAdmin, async (req, res) => {
  const offers = await getOffers();
  const posts = await db.all('SELECT * FROM posts ORDER BY created_at DESC');
  res.render('admin/index', { offers, posts });
});
app.get('/admin/account', requireAdmin, (req, res) => {
  const user = req.session.adminUser;
  res.render('admin/account', { title: 'Cuenta', user, error: null, success: null });
});
app.post('/admin/account/password', requireAdmin, async (req, res) => {
  const { current_password, new_password, confirm_password } = req.body;
  const user = req.session.adminUser;
  const row = await db.get('SELECT * FROM admin_users WHERE username=?', [user]);
  if (!row) return res.render('admin/account', { title: 'Cuenta', user, error: 'Usuario no encontrado', success: null });
  if (!bcrypt.compareSync(current_password, row.password_hash)) {
    return res.render('admin/account', { title: 'Cuenta', user, error: 'Contraseña actual incorrecta', success: null });
  }
  if (new_password !== confirm_password) {
    return res.render('admin/account', { title: 'Cuenta', user, error: 'Las contraseñas nuevas no coinciden', success: null });
  }
  if (new_password.length < 6) {
    return res.render('admin/account', { title: 'Cuenta', user, error: 'La nueva contraseña debe tener al menos 6 caracteres', success: null });
  }
  const hash = bcrypt.hashSync(new_password, 10);
  await db.run('UPDATE admin_users SET password_hash=?, updated_at=? WHERE id=?', [hash, new Date().toISOString(), row.id]);
  return res.render('admin/account', { title: 'Cuenta', user, error: null, success: 'Contraseña actualizada correctamente' });
});
// Settings admin
app.get('/admin/settings', requireAdmin, async (req, res) => {
  const settings = await db.get('SELECT * FROM settings WHERE id = 1');
  res.render('admin/settings', { title: 'Configuración', settings });
});
app.post('/admin/settings', requireAdmin, async (req, res) => {
  const { phone, whatsapp, instagram, facebook, twitter, email, hero_image } = req.body;
  await db.run('UPDATE settings SET phone=?, whatsapp=?, instagram=?, facebook=?, twitter=?, email=?, hero_image=?, updated_at=? WHERE id=1',
    [phone, whatsapp, instagram, facebook, twitter, email, hero_image, new Date().toISOString()]);
  res.redirect('/admin/settings');
});
// Offers CRUD
app.post('/admin/offers', requireAdmin, async (req, res) => {
  const title = clamp(req.body.title, 100);
  const slug = cleanSlug(req.body.slug);
  const summary = clamp(req.body.summary, 240);
  const content = cleanHTML(req.body.content);
  await db.run('INSERT INTO offers (title, slug, summary, content) VALUES (?, ?, ?, ?)', [title, slug, summary, content]);
  res.redirect('/admin');
});
app.post('/admin/offers/:id/edit', requireAdmin, async (req, res) => {
  const title = clamp(req.body.title, 100);
  const slug = cleanSlug(req.body.slug);
  const summary = clamp(req.body.summary, 240);
  const content = cleanHTML(req.body.content);
  await db.run('UPDATE offers SET title=?, slug=?, summary=?, content=?, updated_at=? WHERE id=?',
    [title, slug, summary, content, new Date().toISOString(), req.params.id]);
  res.redirect('/admin');
});
app.post('/admin/offers/:id/delete', requireAdmin, async (req, res) => {
  await db.run('DELETE FROM offers WHERE id = ?', [req.params.id]);
  res.redirect('/admin');
});
// Posts CRUD
app.post('/admin/posts', requireAdmin, upload.single('cover'), async (req, res) => {
  const title = clamp(req.body.title, 120);
  const slug = cleanSlug(req.body.slug);
  const excerpt = clamp(req.body.excerpt, 280);
  const content = cleanHTML(req.body.content);
  const cover = req.file ? `/static/uploads/${req.file.filename}` : null;
  await db.run('INSERT INTO posts (title, slug, excerpt, content, cover) VALUES (?, ?, ?, ?, ?)', [title, slug, excerpt, content, cover]);
  res.redirect('/admin');
});
app.post('/admin/posts/:id/edit', requireAdmin, async (req, res) => {
  const title = clamp(req.body.title, 120);
  const slug = cleanSlug(req.body.slug);
  const excerpt = clamp(req.body.excerpt, 280);
  const content = cleanHTML(req.body.content);
  await db.run('UPDATE posts SET title=?, slug=?, excerpt=?, content=?, updated_at=? WHERE id=?',
    [title, slug, excerpt, content, new Date().toISOString(), req.params.id]);
  res.redirect('/admin');
});
app.post('/admin/posts/:id/delete', requireAdmin, async (req, res) => {
  await db.run('DELETE FROM posts WHERE id = ?', [req.params.id]);
  res.redirect('/admin');
});

// Update offer image
app.post('/admin/offers/:id/image', requireAdmin, upload.single('image'), async (req, res) => {
  if (req.file) {
    const url = `/static/uploads/${req.file.filename}`;
    await db.run('UPDATE offers SET image=?, updated_at=? WHERE id=?', [url, new Date().toISOString(), req.params.id]);
  }
  res.redirect('/admin');
});

// Media manager
app.get('/admin/media', requireAdmin, async (req, res) => {
  const media = await db.all('SELECT * FROM media ORDER BY created_at DESC');
  res.render('admin/media', { title: 'Media', media });
});
app.post('/admin/media', requireAdmin, upload.single('file'), async (req, res) => {
  const f = req.file;
  if (f) {
    const url = `/static/uploads/${f.filename}`;
    await db.run('INSERT INTO media (filename, url, created_at) VALUES (?, ?, ?)', [f.originalname, url, new Date().toISOString()]);
  }
  res.redirect('/admin/media');
});

// 404
app.use((req, res) => res.status(404).render('404'));

async function init() {
  // Inicializar adaptador DB
  db = createDbAdapter({ provider: process.env.DB_PROVIDER || 'sqlite', sqlitePath: dbPath });
  await ensureSchema(db);

  // Migraciones puntuales solo para SQLite
  if (db.provider === 'sqlite' && db._raw) {
    try {
      const settingsCols = db._raw.prepare("PRAGMA table_info(settings)").all();
      const hasHero = settingsCols.some(c => c.name === 'hero_image');
      if (!hasHero) {
        db._raw.prepare('ALTER TABLE settings ADD COLUMN hero_image TEXT').run();
        db._raw.prepare('UPDATE settings SET hero_image=? WHERE id=1').run('/static/img/diseñoapp.png');
      }
    } catch {}
    try {
      const cols = db._raw.prepare("PRAGMA table_info(offers)").all();
      const hasImage = cols.some(c => c.name === 'image');
      if (!hasImage) {
        db._raw.prepare('ALTER TABLE offers ADD COLUMN image TEXT').run();
      }
    } catch {}
  }

  // Seed admin user y settings/ofertas
  try {
    const adminRow = await db.get('SELECT COUNT(*) as c FROM admin_users');
    const adminCount = parseInt(adminRow?.c || adminRow?.count || 0, 10);
    if (!adminCount) {
      const seedUser = process.env.ADMIN_USER || 'admin';
      const seedPass = process.env.ADMIN_PASS || 'admin123';
      const hash = bcrypt.hashSync(seedPass, 10);
      await db.run('INSERT INTO admin_users (username, password_hash, updated_at) VALUES (?, ?, ?)', [seedUser, hash, new Date().toISOString()]);
      console.log('Admin user seeded');
    }
  } catch (e) {
    console.warn('No se pudo crear usuario admin:', e.message);
  }

  const countOffersRow = await db.get('SELECT COUNT(*) as c FROM offers');
  const countOffers = parseInt(countOffersRow?.c || countOffersRow?.count || 0, 10);
  if (!countOffers) {
    await db.run('INSERT INTO offers (title, slug, summary, content, image) VALUES (?, ?, ?, ?, ?)', ['Diseño de Páginas Web', 'diseno-web', 'Sitios modernos, rápidos y SEO-friendly.', 'Construimos sitios responsive, optimizados y de alto impacto visual.', '/static/img/diseño web_bajada.png']);
    await db.run('INSERT INTO offers (title, slug, summary, content, image) VALUES (?, ?, ?, ?, ?)', ['Sistemas para Pymes', 'sistemas-pymes', 'Automatización y gestión eficiente.', 'Diseñamos sistemas a medida para optimizar tus operaciones.', '/static/img/diseñoapp.png']);
    await db.run('INSERT INTO offers (title, slug, summary, content, image) VALUES (?, ?, ?, ?, ?)', ['Soluciones para Comercios', 'soluciones-comercios', 'Herramientas en Sistemas/Excel.', 'Desarrollos ligeros en software o Excel para pequeños comercios.', '/static/img/diseñografico_2.png']);
  }

  const settingsRow = await db.get('SELECT COUNT(*) as c FROM settings');
  const settingsCount = parseInt(settingsRow?.c || settingsRow?.count || 0, 10);
  if (!settingsCount) {
    await db.run('INSERT INTO settings (id, phone, whatsapp, instagram, facebook, twitter, email, hero_image, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)',
      ['+54 11 0000-0000', 'https://wa.me/541100000000', 'https://instagram.com/', 'https://facebook.com/', 'https://twitter.com/', 'info@goodduck.test', '/static/img/diseñoapp.png', new Date().toISOString()]);
  }

  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`GOOD DUCK web running on http://localhost:${port}`));
}

init().catch(err => {
  console.error('Fallo inicializando la app:', err);
  process.exit(1);
});
