// server.js — PixelUp AI Production Server (Railway-compatible)

require('dotenv').config();
const express   = require('express');
const helmet    = require('helmet');
const cors      = require('cors');
const hpp       = require('hpp');
const morgan    = require('morgan');
const compress  = require('compression');
const rateLimit = require('express-rate-limit');
const slowDown  = require('express-slow-down');
const cron      = require('node-cron');
const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');
const logger    = require('./utils/logger');

// ── Validate env ──────────────────────────────────────────────────────────────
const REQUIRED_ENV = ['JWT_ACCESS_SECRET', 'JWT_REFRESH_SECRET', 'ENCRYPTION_KEY'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key] || process.env[key].includes('GANTI_')) {
    logger.error(`❌ ${key} belum dikonfigurasi di .env!`);
    process.exit(1);
  }
}

// Pastikan secret cukup panjang
if (process.env.JWT_ACCESS_SECRET.length < 32) {
  logger.error('JWT_ACCESS_SECRET terlalu pendek! Minimal 32 karakter.');
  process.exit(1);
}

const app  = express();
const PORT = process.env.PORT || 3001;
const { runCleanup, checkIPBlock, validateUserAgent, validateRequestSize, detectSQLInjection, detectXSS, preventPathTraversal, addRequestId, sanitizeBody } = require('./middleware/security');

// ── Upload dir ────────────────────────────────────────────────────────────────
const UPLOAD_DIR = process.env.UPLOAD_DIR || './uploads';
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ════════════════════════════════════════════════════════════════════════════
// LAYER 1: HELMET — HTTP Security Headers
// ════════════════════════════════════════════════════════════════════════════
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'"],
      styleSrc:       ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:        ["'self'", "https://fonts.gstatic.com"],
      imgSrc:         ["'self'", "data:", "blob:"],
      connectSrc:     ["'self'"],
      frameSrc:       ["'none'"],
      objectSrc:      ["'none'"],
      upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
    }
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  dnsPrefetchControl: { allow: false },
  expectCt: { maxAge: 86400, enforce: true },
  frameguard: { action: 'deny' },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true
}));

// ════════════════════════════════════════════════════════════════════════════
// LAYER 2: CORS
// ════════════════════════════════════════════════════════════════════════════
const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5500').split(',').map(s => s.trim());
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, false); // Blokir request tanpa origin
    if (allowedOrigins.includes(origin)) return cb(null, true);
    logger.security('CORS_VIOLATION', { origin });
    return cb(new Error('CORS: Origin tidak diizinkan'), false);
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
  exposedHeaders: ['X-Request-ID'],
  credentials: true,
  maxAge: 86400
}));

// ════════════════════════════════════════════════════════════════════════════
// LAYER 3: HTTP Parameter Pollution Protection
// ════════════════════════════════════════════════════════════════════════════
app.use(hpp());

// ════════════════════════════════════════════════════════════════════════════
// LAYER 4: Request Size Limit
// ════════════════════════════════════════════════════════════════════════════
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false, limit: '5mb', parameterLimit: 50 }));

// ════════════════════════════════════════════════════════════════════════════
// LAYER 5: Compression
// ════════════════════════════════════════════════════════════════════════════
app.use(compress());

// ════════════════════════════════════════════════════════════════════════════
// LAYER 6: Request ID (tracing)
// ════════════════════════════════════════════════════════════════════════════
app.use(addRequestId);

// ════════════════════════════════════════════════════════════════════════════
// LAYER 7: Logging (Morgan → Winston)
// ════════════════════════════════════════════════════════════════════════════
app.use(morgan(':method :url :status :res[content-length] - :response-time ms :remote-addr', {
  stream: { write: (msg) => logger.info(msg.trim()) },
  skip: (req) => req.path === '/api/health'
}));

// ════════════════════════════════════════════════════════════════════════════
// LAYER 8: Security Middleware Chain
// ════════════════════════════════════════════════════════════════════════════
app.use(checkIPBlock);
app.use(validateUserAgent);
app.use(validateRequestSize);
app.use(preventPathTraversal);
app.use(sanitizeBody);
app.use('/api/', detectSQLInjection);
app.use('/api/', detectXSS);

// ════════════════════════════════════════════════════════════════════════════
// LAYER 9: Rate Limiting
// ════════════════════════════════════════════════════════════════════════════

// Global limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.headers['x-forwarded-for']?.split(',')[0] || req.ip,
  handler: (req, res) => {
    logger.security('RATE_LIMIT_EXCEEDED', { ip: req.ip, path: req.path });
    res.status(429).json({ success: false, message: 'Terlalu banyak permintaan. Coba lagi nanti.' });
  }
});

// Auth-specific: sangat ketat
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX) || 5,
  keyGenerator: (req) => `${req.headers['x-forwarded-for']?.split(',')[0] || req.ip}:${req.body?.email || ''}`,
  handler: (req, res) => {
    logger.security('AUTH_RATE_LIMIT', { ip: req.ip, email: req.body?.email });
    res.status(429).json({ success: false, message: 'Terlalu banyak percobaan. Tunggu 15 menit.' });
  }
});

// Slow down sebelum hard limit
const authSlowDown = slowDown({
  windowMs: 15 * 60 * 1000,
  delayAfter: 2,
  delayMs: () => 1000
});

// API key limiter
const apiKeyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  keyGenerator: (req) => req.headers['x-api-key'] || req.ip
});

app.use('/api/', globalLimiter);
app.use('/api/auth/login', authSlowDown, authLimiter);
app.use('/api/auth/register', authLimiter);

// ════════════════════════════════════════════════════════════════════════════
// LAYER 10: Disable fingerprinting headers
// ════════════════════════════════════════════════════════════════════════════
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.removeHeader('Server');
  res.removeHeader('X-Powered-By');
  next();
});

// ════════════════════════════════════════════════════════════════════════════
// STATIC FILES (hanya untuk uploads — dengan validasi ekstensi)
// ════════════════════════════════════════════════════════════════════════════
app.use('/uploads', (req, res, next) => {
  // Hanya izinkan akses ke file gambar/video
  const allowed = /\.(jpg|jpeg|png|webp|mp4|mov)$/i;
  if (!allowed.test(req.path)) return res.status(403).json({ success: false, message: 'Akses ditolak.' });
  next();
}, express.static(path.resolve(UPLOAD_DIR), {
  dotfiles: 'deny',
  index: false,
  etag: true,
  maxAge: '7d'
}));

// ════════════════════════════════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════════════════════════════════
app.use('/api/auth',  require('./routes/auth'));
app.use('/api/user',  require('./routes/user'));
app.use('/api/admin', require('./routes/admin'));

// ── Health check (no auth required, minimal info) ────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// ════════════════════════════════════════════════════════════════════════════
// ERROR HANDLERS
// ════════════════════════════════════════════════════════════════════════════

// 404
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint tidak ditemukan.' });
});

// Global error handler — JANGAN kirim stack trace ke client di production
app.use((err, req, res, next) => {
  const status = err.status || 500;
  logger.error('Unhandled error', { error: err.message, stack: err.stack, path: req.path, requestId: req.id });

  if (err.message?.includes('CORS')) {
    return res.status(403).json({ success: false, message: 'Akses ditolak.' });
  }

  res.status(status).json({
    success: false,
    message: process.env.NODE_ENV === 'production' ? 'Terjadi kesalahan server.' : err.message
  });
});

// ════════════════════════════════════════════════════════════════════════════
// CRON JOBS
// ════════════════════════════════════════════════════════════════════════════

// Cleanup setiap jam
cron.schedule('0 * * * *', () => {
  logger.info('Running scheduled cleanup...');
  runCleanup();
});

// Reset kredit free user setiap tanggal 1
cron.schedule('0 0 1 * *', () => {
  logger.info('Resetting free tier credits...');
  try {
    const db = require('./database/db');
    db.prepare("UPDATE users SET credits = 10 WHERE plan = 'free'").run();
    db.prepare("UPDATE users SET credits = 500 WHERE plan = 'pro'").run();
    logger.info('Credits reset completed.');
  } catch (err) { logger.error('Credit reset error', { error: err.message }); }
});

// ════════════════════════════════════════════════════════════════════════════
// START
// ════════════════════════════════════════════════════════════════════════════
const server = app.listen(PORT, '0.0.0.0', () => {
  logger.info(`PixelUp API started`, {
    port: PORT,
    env: process.env.NODE_ENV,
    pid: process.pid
  });
  if (process.env.NODE_ENV !== 'production') {
    console.log(`\n🚀 Server: http://localhost:${PORT}\n`);
  }
});

// Graceful shutdown
const shutdown = (signal) => {
  logger.info(`${signal} received, shutting down gracefully...`);
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000);
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('uncaughtException', (err) => { logger.error('Uncaught exception', { error: err.message, stack: err.stack }); });
process.on('unhandledRejection', (reason) => { logger.error('Unhandled rejection', { reason: String(reason) }); });

module.exports = app;
