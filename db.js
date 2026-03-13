// database/db.js — SQLite schema dengan tabel keamanan

require('dotenv').config();
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const logger = require('../utils/logger');

const DB_PATH = process.env.DB_PATH || './database/pixelup.db';
const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(DB_PATH, {
  verbose: process.env.NODE_ENV === 'development' ? null : null
});

// Hardening SQLite
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('secure_delete = ON');    // Overwrite deleted data
db.pragma('auto_vacuum = INCREMENTAL');

// ── Schema ────────────────────────────────────────────────────────────────────
db.exec(`
  -- Users
  CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    email           TEXT UNIQUE NOT NULL,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    password        TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin','superadmin')),
    plan            TEXT NOT NULL DEFAULT 'free' CHECK(plan IN ('free','pro','ultra')),
    credits         INTEGER NOT NULL DEFAULT 10,
    status          TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','banned')),
    login_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    last_ip         TEXT,
    last_user_agent TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login      TEXT
  );

  -- Refresh Tokens (dengan rotation & family tracking untuk deteksi theft)
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          TEXT PRIMARY KEY,
    family_id   TEXT NOT NULL,     -- Semua token dalam satu sesi share family_id
    user_id     TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,  -- Hash dari token (bukan plaintext)
    expires_at  TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,  -- Jika used=1 tapi dipakai lagi = token theft!
    user_agent  TEXT,
    ip          TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- Brute-force / IP Tracking
  CREATE TABLE IF NOT EXISTS ip_blocks (
    ip          TEXT PRIMARY KEY,
    reason      TEXT NOT NULL,
    blocked_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT,
    permanent   INTEGER NOT NULL DEFAULT 0
  );

  -- Failed login attempts per IP+email
  CREATE TABLE IF NOT EXISTS auth_attempts (
    id          TEXT PRIMARY KEY,
    ip          TEXT NOT NULL,
    email       TEXT NOT NULL,
    success     INTEGER NOT NULL DEFAULT 0,
    user_agent  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Security events log (immutable append-only)
  CREATE TABLE IF NOT EXISTS security_events (
    id          TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info' CHECK(severity IN ('info','warn','critical')),
    user_id     TEXT,
    ip          TEXT,
    user_agent  TEXT,
    details     TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Jobs
  CREATE TABLE IF NOT EXISTS jobs (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL,
    filename      TEXT NOT NULL,
    original_name TEXT NOT NULL,
    file_type     TEXT NOT NULL CHECK(file_type IN ('image','video')),
    file_size     INTEGER NOT NULL,
    mime_type     TEXT,
    file_hash     TEXT,        -- SHA-256 untuk duplicate detection
    status        TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','processing','done','failed')),
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

  -- Subscriptions
  CREATE TABLE IF NOT EXISTS subscriptions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL UNIQUE,
    plan            TEXT NOT NULL DEFAULT 'free',
    status          TEXT NOT NULL DEFAULT 'active',
    price_idr       INTEGER NOT NULL DEFAULT 0,
    started_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT,
    cancelled_at    TEXT,
    payment_method  TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- Transactions
  CREATE TABLE IF NOT EXISTS transactions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    amount_idr      INTEGER NOT NULL,
    plan            TEXT NOT NULL,
    payment_method  TEXT,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','failed','refunded')),
    external_id     TEXT,
    invoice_number  TEXT UNIQUE,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  -- API Keys
  CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    name            TEXT NOT NULL,
    key_prefix      TEXT NOT NULL,
    key_hash        TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL DEFAULT 'active',
    request_count   INTEGER NOT NULL DEFAULT 0,
    monthly_limit   INTEGER NOT NULL DEFAULT 1000,
    last_used       TEXT,
    last_used_ip    TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- Admin Audit Logs
  CREATE TABLE IF NOT EXISTS audit_logs (
    id          TEXT PRIMARY KEY,
    admin_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_type TEXT,
    target_id   TEXT,
    old_values  TEXT,
    new_values  TEXT,
    ip          TEXT,
    user_agent  TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- CSRF Tokens
  CREATE TABLE IF NOT EXISTS csrf_tokens (
    token       TEXT PRIMARY KEY,
    user_id     TEXT,
    ip          TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
  );

  -- Indexes
  CREATE INDEX IF NOT EXISTS idx_users_email         ON users(email);
  CREATE INDEX IF NOT EXISTS idx_users_status        ON users(status);
  CREATE INDEX IF NOT EXISTS idx_rt_user_id          ON refresh_tokens(user_id);
  CREATE INDEX IF NOT EXISTS idx_rt_family           ON refresh_tokens(family_id);
  CREATE INDEX IF NOT EXISTS idx_rt_hash             ON refresh_tokens(token_hash);
  CREATE INDEX IF NOT EXISTS idx_ip_blocks           ON ip_blocks(ip);
  CREATE INDEX IF NOT EXISTS idx_auth_attempts_ip    ON auth_attempts(ip, created_at);
  CREATE INDEX IF NOT EXISTS idx_auth_attempts_email ON auth_attempts(email, created_at);
  CREATE INDEX IF NOT EXISTS idx_security_events     ON security_events(event_type, created_at);
  CREATE INDEX IF NOT EXISTS idx_jobs_user           ON jobs(user_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_jobs_status         ON jobs(status);
  CREATE INDEX IF NOT EXISTS idx_txn_user            ON transactions(user_id, created_at);
  CREATE INDEX IF NOT EXISTS idx_api_keys_user       ON api_keys(user_id);
  CREATE INDEX IF NOT EXISTS idx_api_keys_hash       ON api_keys(key_hash);
  CREATE INDEX IF NOT EXISTS idx_csrf_token          ON csrf_tokens(token, expires_at);
`);

logger.info('Database initialized', { path: DB_PATH });
module.exports = db;
