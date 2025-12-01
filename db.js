import Database from 'better-sqlite3';
import { Pool } from 'pg';

function replacePlaceholders(sql, valuesLength) {
  let out = '';
  let idx = 0;
  let inSingle = false;
  let inDouble = false;
  let param = 1;
  while (idx < sql.length) {
    const ch = sql[idx];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      out += ch;
      idx++;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      out += ch;
      idx++;
      continue;
    }
    if (ch === '?' && !inSingle && !inDouble) {
      out += `$${param}`;
      param++;
      idx++;
      continue;
    }
    out += ch;
    idx++;
  }
  return out;
}

export function createDbAdapter(options = {}) {
  const provider = (process.env.DB_PROVIDER || options.provider || 'sqlite').toLowerCase();
  if (provider === 'postgres' || provider === 'pg' || provider === 'postgresql') {
    const conn = process.env.DATABASE_INTERNAL_URL || process.env.DATABASE_URL;
    if (!conn) {
      throw new Error('DATABASE_URL/INTERNAL_URL no está configurada para PostgreSQL');
    }
    const ssl = conn.startsWith('postgres://') || conn.startsWith('postgresql://') ? { rejectUnauthorized: false } : undefined;
    const pool = new Pool({ connectionString: conn, ssl });

    return {
      provider: 'postgres',
      async get(sql, params = []) {
        const text = replacePlaceholders(sql, params.length);
        const res = await pool.query(text, params);
        return res.rows[0] || null;
      },
      async all(sql, params = []) {
        const text = replacePlaceholders(sql, params.length);
        const res = await pool.query(text, params);
        return res.rows;
      },
      async run(sql, params = []) {
        const text = replacePlaceholders(sql, params.length);
        const res = await pool.query(text, params);
        return { changes: res.rowCount };
      },
      async exec(sql) {
        const parts = sql
          .split(';')
          .map(s => s.trim())
          .filter(Boolean);
        for (const stmt of parts) {
          await pool.query(stmt);
        }
      },
      async end() { await pool.end(); },
    };
  }

  // SQLite por defecto
  const dbPath = options.sqlitePath;
  const sqlite = new Database(dbPath);
  return {
    provider: 'sqlite',
    async get(sql, params = []) { return sqlite.prepare(sql).get(...params) || null; },
    async all(sql, params = []) { return sqlite.prepare(sql).all(...params); },
    async run(sql, params = []) { return sqlite.prepare(sql).run(...params); },
    async exec(sql) { sqlite.exec(sql); },
    async end() { sqlite.close(); },
    _raw: sqlite,
  };
}

export async function ensureSchema(adapter) {
  if (adapter.provider === 'postgres') {
    await adapter.exec(`
      CREATE TABLE IF NOT EXISTS offers (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        summary TEXT,
        content TEXT,
        image TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS posts (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        excerpt TEXT,
        content TEXT,
        cover TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS media (
        id SERIAL PRIMARY KEY,
        filename TEXT NOT NULL,
        url TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS contacts (
        id SERIAL PRIMARY KEY,
        name TEXT,
        email TEXT,
        message TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS settings (
        id SMALLINT PRIMARY KEY CHECK (id = 1),
        phone TEXT,
        whatsapp TEXT,
        instagram TEXT,
        facebook TEXT,
        twitter TEXT,
        email TEXT,
        hero_image TEXT,
        updated_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        updated_at TIMESTAMPTZ
      );
      CREATE TABLE IF NOT EXISTS reset_tokens (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        used_at TIMESTAMPTZ
      );
    `);
    return;
  }

  // SQLite DDL
  await adapter.exec(`
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
      hero_image TEXT,
      updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      expires_at TEXT NOT NULL,
      used_at TEXT
    );
  `);
}
