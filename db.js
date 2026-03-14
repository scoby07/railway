// db.js — SQLite menggunakan node:sqlite (built-in Node.js v22+, ZERO dependency)
// Tidak perlu install apapun, tidak ada kompilasi native.

const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs   = require('fs');

const DB_PATH = process.env.DB_PATH || '/tmp/pixelup.db';
const dbDir   = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

console.log('[DB] Path:', DB_PATH);

const db = new DatabaseSync(DB_PATH);

// Pragmas
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');
db.exec('PRAGMA secure_delete = ON');

// ── Schema ────────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    email           TEXT UNIQUE NOT NULL,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    password        TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'user',
    plan            TEXT NOT NULL DEFAULT 'free',
    credits         INTEGER NOT NULL DEFAULT 10,
    status          TEXT NOT NULL DEFAULT 'active',
    login_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    last_ip         TEXT,
    last_user_agent TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT PRIMARY KEY,
    family_id   TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    user_agent  TEXT,
    ip          TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS ip_blocks (
    ip          TEXT PRIMARY KEY,
    reason      TEXT NOT NULL,
    blocked_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT,
    permanent   INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS auth_attempts (
    id          TEXT PRIMARY KEY,
    ip          TEXT NOT NULL,
    email       TEXT NOT NULL,
    success     INTEGER NOT NULL DEFAULT 0,
    user_agent  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS security_events (
    id          TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info',
    user_id     TEXT,
    ip          TEXT,
    user_agent  TEXT,
    details     TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS jobs (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    filename      TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_type     TEXT NOT NULL,
    file_size     INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'queued',
    scale_mode    TEXT NOT NULL DEFAULT '2x',
    content_type  TEXT NOT NULL DEFAULT 'photo',
    noise_level   INTEGER NOT NULL DEFAULT 50,
    sharpness     INTEGER NOT NULL DEFAULT 70,
    output_path   TEXT,
    orig_width    INTEGER,
    orig_height   INTEGER,
    out_width     INTEGER,
    out_height    INTEGER,
    process_ms    INTEGER,
    error_msg     TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS subscriptions (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL UNIQUE,
    plan           TEXT NOT NULL DEFAULT 'free',
    status         TEXT NOT NULL DEFAULT 'active',
    price_idr      INTEGER NOT NULL DEFAULT 0,
    started_at     TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at     TEXT,
    payment_method TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL,
    amount_idr     INTEGER NOT NULL,
    plan           TEXT NOT NULL,
    payment_method TEXT,
    status         TEXT NOT NULL DEFAULT 'pending',
    external_id    TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    name          TEXT NOT NULL,
    key_prefix    TEXT NOT NULL,
    key_hash      TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL DEFAULT 'active',
    request_count INTEGER NOT NULL DEFAULT 0,
    monthly_limit INTEGER NOT NULL DEFAULT 1000,
    last_used     TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id          TEXT PRIMARY KEY,
    admin_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    old_values  TEXT,
    new_values  TEXT,
    ip          TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_users_email   ON users(email);
  CREATE INDEX IF NOT EXISTS idx_rt_hash       ON refresh_tokens(token_hash);
  CREATE INDEX IF NOT EXISTS idx_rt_user       ON refresh_tokens(user_id);
  CREATE INDEX IF NOT EXISTS idx_ip_blocks     ON ip_blocks(ip);
  CREATE INDEX IF NOT EXISTS idx_auth_ip       ON auth_attempts(ip, created_at);
  CREATE INDEX IF NOT EXISTS idx_jobs_user     ON jobs(user_id);
  CREATE INDEX IF NOT EXISTS idx_api_user      ON api_keys(user_id);
  CREATE INDEX IF NOT EXISTS idx_sec_events    ON security_events(created_at);
`);

// ── Wrapper agar API tetap sama seperti better-sqlite3 ───────────────────────
// node:sqlite pakai .prepare(sql).get/all/run tapi parameter pakai named binding
// Kita buat thin wrapper agar kode lain tidak perlu diubah.

const _prepare = db.prepare.bind(db);

// Override prepare untuk support positional params (?) sama seperti better-sqlite3
const origPrepare = (sql) => {
  // node:sqlite sudah support .prepare() langsung
  const stmt = _prepare(sql);
  return {
    run:  (...args) => stmt.run(positional(sql, args)),
    get:  (...args) => stmt.get(positional(sql, args)),
    all:  (...args) => stmt.all(positional(sql, args))
  };
};

// Konversi positional params (?) ke named params {p0, p1, ...}
function positional(sql, args) {
  const flat = args.flat();
  if (!flat.length) return {};
  const obj = {};
  flat.forEach((v, i) => { obj[`p${i}`] = v; });
  return obj;
}

// Patch SQL: ganti ? dengan $p0, $p1, ...
function patchSQL(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$p${i++}`);
}

// Final wrapper
const dbWrapper = {
  prepare: (sql) => {
    const patched = patchSQL(sql);
    const stmt = _prepare(patched);
    return {
      run:  (...args) => stmt.run(positional(sql, args)),
      get:  (...args) => stmt.get(positional(sql, args)),
      all:  (...args) => stmt.all(positional(sql, args))
    };
  },
  exec: (sql) => db.exec(sql),
  pragma: (p) => db.exec(`PRAGMA ${p}`)
};

console.log('[DB] node:sqlite siap (Node.js built-in, zero dependency).');
module.exports = dbWrapper;
