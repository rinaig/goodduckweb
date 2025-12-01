# GOOD DUCK Web

Sitio web profesional con backend ligero (Express + EJS + SQLite) y panel de administración protegido.

## Stack
- Node.js LTS (recomendado 20.x con nvm-windows)
- Express 4
- EJS + express-ejs-layouts
- better-sqlite3 (rendimiento sin ORM)
- multer (uploads)
- express-session (auth admin)

## Estructura
```
web_pro/
  server.js          # App principal y rutas
  content.db         # Base de datos SQLite
  views/             # EJS templates (layout + páginas)
  public/            # Assets estáticos (/static/...)
  public/img         # Imágenes migradas
  public/css         # custom.css estilos complementarios
  uploads/           # Archivos subidos (covers posts) en producción mover a persistent storage
```

## Variables de entorno
Crear `.env` (opcional) para sobreescribir credenciales y secretos:
```
PORT=3000
ADMIN_USER=admin
ADMIN_PASS=admin123
ADMIN_SESSION_SECRET=algún_secreto_largo
```

## Inicio rápido
```powershell
cd "C:\PROYECTOS_DE_DESARROLLOS\GOOD DUCK\web_pro"
npm install
npm run dev
```
Abrir: `http://localhost:3000`
Panel admin: `http://localhost:3000/admin/login`

## Gestión de contenido
- Ofertas: título, slug, resumen, contenido.
- Posts: título, slug, excerpt, contenido + cover opcional.
- Settings: teléfono, whatsapp (URL), instagram, facebook, twitter, email.

## Imágenes
Mapeos por slug en `home.ejs` y `offer.ejs`. Para nuevas ofertas, añadir imagen al directorio y actualizar el mapeo.

## Seguridad
- Sesiones no persistentes (cookie httpOnly).
- Cambiar `ADMIN_SESSION_SECRET` en producción.
- Agregar cabeceras (ej. helmet) y rate limiting en despliegue.

## Despliegue
1. Copiar proyecto al servidor.
2. Instalar Node LTS.
3. Configurar `.env` seguro.
4. Usar PM2 o servicio systemd:
```bash
pm2 start server.js --name good-duck
pm2 save
```
5. Servir estáticos detrás de Nginx/Traefik con reverse proxy SSL.

## Próximos pasos recomendados
- Autenticación con usuario persistente y hash de contraseña.
- Validaciones servidor (longitud campos, sanitización HTML si se permite).
- Mini API JSON para frontend alternativo.
- Optimización de imágenes (generar versiones webp).

## Scripts
- `npm run dev` desarrollo (sin hot reload).
- `npm start` producción simple.

## Backup DB
`content.db` contiene todo el contenido. Realizar respaldo periódico.

## Licencia
Privado / Uso interno.
