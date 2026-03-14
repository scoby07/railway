// server.js — PixelUp AI (Railway-ready, flat file structure)

require('dotenv').config();

// ── Cek env wajib ─────────────────────────────────────────────────────────────
const MUST = ['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET', 'ENCRYPTION_KEY'];
const missing = MUST.filter(k => !process.env[k] || process.env[k].startsWith('GANTI'));
if (missing.length) {
  console.error('\n❌ Set variabel berikut di Railway Dashboard → Variables:');
  missing.forEach(k => console.error(`   → ${k}`));
  console.error('\nLihat .env.example untuk panduan.\n');
  process.exit(1);
}

const express    = require('express');
const helmet     = require('helmet');
const cors       = require('cors');
const hpp        = require('hpp');
const morgan     = require('morgan');
const compress   = require('compression');
const rateLimit  = require('express-rate-limit');
const slowDown   = require('express-slow-down');
const cron       = require('node-cron');
const path       = require('path');
const fs         = require('fs');

// ── Semua import pakai path FLAT (tidak ada subfolder) ────────────────────────
const {
  checkIPBlock, validateUserAgent, validateRequestSize,
  detectSQLInjection, detectXSS, preventPathTraversal,
  addRequestId, sanitizeBody, runCleanup
} = require('./security');  // <── flat, bukan ./middleware/security

const app  = express();
const PORT = process.env.PORT || 3001;

// Upload dir (Railway ephemeral)
const UPLOAD_DIR = process.env.UPLOAD_DIR || '/tmp/pixelup_uploads';
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Trust Railway proxy
app.set('trust proxy', 1);

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      imgSrc:     ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      frameSrc:   ["'none'"],
      objectSrc:  ["'none'"]
    }
  },
  frameguard: { action: 'deny' },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
  noSniff: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));
app.disable('x-powered-by');

// ── CORS ──────────────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.CORS_ORIGIN || '*').split(',').map(s => s.trim());
app.use(cors({
  origin: (origin, cb) => {
    if (allowedOrigins.includes('*') || !origin || allowedOrigins.includes(origin))
      return cb(null, true);
    cb(new Error('CORS: origin tidak diizinkan'), false);
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization','X-Request-ID'],
  credentials: true,
  maxAge: 86400
}));

// ── Middleware umum ───────────────────────────────────────────────────────────
app.use(hpp());
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false, limit: '5mb', parameterLimit: 50 }));
app.use(compress());
app.use(addRequestId);
app.use(morgan(':method :url :status - :response-time ms'));

// ── Security chain ────────────────────────────────────────────────────────────
app.use(checkIPBlock);
app.use(validateUserAgent);
app.use(validateRequestSize);
app.use(preventPathTraversal);
app.use(sanitizeBody);
app.use('/api/', detectSQLInjection);
app.use('/api/', detectXSS);

// ── Rate limiting ─────────────────────────────────────────────────────────────
app.use('/api/', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 150,
  keyGenerator: req => req.ip,
  handler: (req, res) => res.status(429).json({ success: false, message: 'Terlalu banyak permintaan.' })
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX) || 10,
  keyGenerator: req => `${req.ip}:${req.body?.email || ''}`,
  handler: (req, res) => res.status(429).json({ success: false, message: 'Terlalu banyak percobaan. Tunggu 15 menit.' })
});

app.use('/api/auth/login',    slowDown({ windowMs: 15*60*1000, delayAfter: 3, delayMs: () => 1000 }), authLimiter);
app.use('/api/auth/register', authLimiter);

// ── Routes (import flat) ──────────────────────────────────────────────────────
app.use('/api/auth',  require('./routes-auth'));    // <── flat
app.use('/api/user',  require('./routes-user'));    // <── flat
app.use('/api/admin', require('./routes-admin'));   // <── flat

// ── Health check ──────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now(), env: process.env.NODE_ENV }));
app.get('/', (req, res) => res.json({ name: 'PixelUp AI API', version: '2.0.0', status: 'running' }));

// ── 404 & error handler ───────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ success: false, message: 'Endpoint tidak ditemukan.' }));
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(err.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production' ? 'Terjadi kesalahan server.' : err.message
  });
});

// ── Cron jobs ─────────────────────────────────────────────────────────────────
cron.schedule('0 * * * *', () => { console.log('[CRON] Cleanup...'); runCleanup(); });
cron.schedule('0 0 1 * *', () => {
  const db = require('./db');
  db.prepare("UPDATE users SET credits=10  WHERE plan='free'").run();
  db.prepare("UPDATE users SET credits=500 WHERE plan='pro'").run();
  console.log('[CRON] Credits reset.');
});

// ── Start ─────────────────────────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n✅ PixelUp API berjalan di port ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/api/health\n`);
});

process.on('SIGTERM', () => { console.log('SIGTERM — shutting down...'); process.exit(0); });
process.on('uncaughtException',  err => console.error('[UNCAUGHT]', err.message));
process.on('unhandledRejection', r   => console.error('[UNHANDLED]', String(r)));
