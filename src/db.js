'use strict';

// Database layer.
//  - If DATABASE_URL is set (production), we use PostgreSQL.
//  - Otherwise we use a local SQLite file, so you can run it with zero setup.
// Every query uses parameters ($1, $2 ...) and never glues user input into
// SQL text, which is what makes SQL injection impossible here.

const path = require('node:path');
const fs = require('node:fs');

const isPg = Boolean(process.env.DATABASE_URL);
let pool = null;
let sqlite = null;

if (isPg) {
  const pg = require('pg');
  pg.types.setTypeParser(20, (v) => Number(v)); // BIGINT columns -> JS numbers
  // Neon's connection strings say "sslmode=require". The pg driver already
  // treats that as "verify-full" (encrypted, and the server's certificate is
  // checked) but prints a scary-looking warning about it. Spelling it out
  // keeps exactly the same security and keeps the logs clean.
  const connectionString = process.env.DATABASE_URL
    .trim()
    .replace(/([?&])sslmode=(require|prefer|verify-ca)(?=&|$)/, '$1sslmode=verify-full');
  pool = new pg.Pool({ connectionString, max: 5 });
} else {
  const { DatabaseSync } = require('node:sqlite');
  const file = process.env.SQLITE_PATH || path.join(__dirname, '..', 'data', 'app.db');
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  sqlite = new DatabaseSync(file);
  sqlite.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
}

// SQLite understands "?1, ?2" instead of Postgres' "$1, $2".
const toSqlite = (sql) => sql.replace(/\$(\d+)/g, '?$1');

async function all(sql, params = []) {
  if (isPg) return (await pool.query(sql, params)).rows;
  return sqlite.prepare(toSqlite(sql)).all(...params);
}

async function get(sql, params = []) {
  return (await all(sql, params))[0];
}

async function run(sql, params = []) {
  if (isPg) {
    const r = await pool.query(sql, params);
    return { changes: r.rowCount };
  }
  const r = sqlite.prepare(toSqlite(sql)).run(...params);
  return { changes: Number(r.changes) };
}

function isUniqueViolation(err) {
  if (!err) return false;
  if (err.code === '23505') return true; // Postgres
  return /UNIQUE constraint failed/i.test(err.message || ''); // SQLite
}

async function init() {
  const idCol = isPg ? 'SERIAL PRIMARY KEY' : 'INTEGER PRIMARY KEY AUTOINCREMENT';
  // username_lower / email_lower carry UNIQUE constraints. That means the
  // database itself refuses a duplicate, even if two people click "Create
  // account" at the exact same millisecond. "Shyamal" and "shyamal" count as
  // the same name, so nobody can register a look-alike.
  const schema = `
    CREATE TABLE IF NOT EXISTS users (
      id ${idCol},
      username TEXT NOT NULL,
      username_lower TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL,
      email_lower TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      email_verified INTEGER NOT NULL DEFAULT 0,
      failed_logins INTEGER NOT NULL DEFAULT 0,
      locked_until BIGINT NOT NULL DEFAULT 0,
      created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at BIGINT NOT NULL,
      last_seen BIGINT NOT NULL,
      expires_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
    CREATE TABLE IF NOT EXISTS tokens (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      purpose TEXT NOT NULL,
      expires_at BIGINT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS tokens_user_idx ON tokens(user_id, purpose);
  `;
  if (isPg) await pool.query(schema);
  else sqlite.exec(schema);
}

async function close() {
  if (pool) await pool.end();
  if (sqlite) sqlite.close();
}

module.exports = { all, get, run, init, close, isUniqueViolation, kind: isPg ? 'postgres' : 'sqlite' };
