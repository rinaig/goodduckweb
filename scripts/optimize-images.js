// Optimiza imágenes en public/img a WebP
import fs from 'fs';
import path from 'path';
import sharp from 'sharp';

const IMG_DIR = path.join(process.cwd(), 'public', 'img');

async function toWebp(file) {
  const ext = path.extname(file).toLowerCase();
  if (!['.png', '.jpg', '.jpeg'].includes(ext)) return;
  const base = path.basename(file, ext);
  const out = path.join(IMG_DIR, `${base}.webp`);
  if (fs.existsSync(out)) return; // skip if already exists
  const input = path.join(IMG_DIR, file);
  console.log('→ webp', file);
  await sharp(input)
    .resize({ width: 1600, withoutEnlargement: true })
    .webp({ quality: 80 })
    .toFile(out);
}

async function run() {
  if (!fs.existsSync(IMG_DIR)) return;
  const files = fs.readdirSync(IMG_DIR);
  for (const f of files) {
    try { await toWebp(f); } catch (e) { console.warn('skip', f, e.message); }
  }
  console.log('Optimización completada.');
}

run();
