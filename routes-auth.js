// routes-auth.js — Auth routes

const express  = require('express');
const router   = express.Router();
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');
const db       = require('./db');
const { authenticate, issueTokens, exchangeRefreshToken, revokeAllUserTokens } = require('./auth');
const { detectBruteForce, logSecEvent, getIP } = require('./security');
const { body, validationResult } = require('express-validator');

const ROUNDS      = parseInt(process.env.BCRYPT_ROUNDS) || 12;
const MAX_ATTEMPT = parseInt(process.env.MAX_LOGIN_ATTEMPTS) || 5;
const LOCK_MINS   = parseInt(process.env.LOCKOUT_DURATION_MINUTES) || 30;

const validate = (rules) => [...rules, (req, res, next) => {
  const errs = validationResult(req);
  if (!errs.isEmpty()) return res.status(422).json({ success: false, message: errs.array()[0].msg });
  next();
}];

// POST /api/auth/register
router.post('/register', validate([
  body('name').trim().isLength({ min: 2, max: 80 }).withMessage('Nama harus 2–80 karakter.'),
  body('email').trim().isEmail().normalizeEmail().withMessage('Email tidak valid.'),
  body('password').isLength({ min: 8, max: 128 }).withMessage('Password minimal 8 karakter.')
    .matches(/[A-Z]/).withMessage('Password harus ada huruf kapital.')
    .matches(/[a-z]/).withMessage('Harus ada huruf kecil.')
    .matches(/\d/).withMessage('Harus ada angka.')
    .matches(/[!@#$%^&*]/).withMessage('Harus ada karakter khusus (!@#$%^&*).')
]), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (db.prepare('SELECT id FROM users WHERE email=?').get(email))
      return res.status(409).json({ success: false, message: 'Email sudah terdaftar.' });

    const hashed = await bcrypt.hash(password, ROUNDS);
    const uid    = crypto.randomUUID();
    db.prepare('INSERT INTO users (id,name,email,password) VALUES (?,?,?,?)').run(uid, name, email, hashed);
    db.prepare('INSERT INTO subscriptions (id,user_id,plan,price_idr) VALUES (?,?,?,?)').run(crypto.randomUUID(), uid, 'free', 0);

    const user = db.prepare('SELECT id,name,email,role,plan,credits FROM users WHERE id=?').get(uid);
    const { accessToken, refreshToken } = issueTokens(user, req);
    logSecEvent('USER_REGISTERED', 'info', req, { userId: uid });

    res.status(201).json({ success: true, message: 'Akun berhasil dibuat.', data: { user, accessToken, refreshToken } });
  } catch (err) {
    console.error('[REGISTER]', err.message);
    res.status(500).json({ success: false, message: 'Terjadi kesalahan.' });
  }
});

// POST /api/auth/login
router.post('/login', detectBruteForce, validate([
  body('email').trim().isEmail().normalizeEmail().withMessage('Email tidak valid.'),
  body('password').notEmpty().withMessage('Password wajib diisi.')
]), async (req, res) => {
  const ip = getIP(req);
  const { email, password } = req.body;

  const record = (ok) => {
    try { db.prepare('INSERT INTO auth_attempts (id,ip,email,success,user_agent) VALUES (?,?,?,?,?)').run(crypto.randomUUID(), ip, email, ok ? 1 : 0, req.headers['user-agent']?.slice(0, 200)); } catch {}
  };

  try {
    const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!user) { record(false); logSecEvent('LOGIN_FAILED', 'warn', req, { email }); return res.status(401).json({ success: false, message: 'Email atau password salah.' }); }
    if (user.status === 'banned')    return res.status(403).json({ success: false, message: 'Akun diblokir. Hubungi support.' });
    if (user.status === 'suspended') return res.status(403).json({ success: false, message: 'Akun ditangguhkan.' });

    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      const mins = Math.ceil((new Date(user.locked_until) - Date.now()) / 60000);
      return res.status(429).json({ success: false, message: `Akun dikunci. Coba lagi dalam ${mins} menit.`, code: 'ACCOUNT_LOCKED' });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      const attempts = user.login_attempts + 1;
      const locked   = attempts >= MAX_ATTEMPT ? new Date(Date.now() + LOCK_MINS * 60000).toISOString() : null;
      db.prepare("UPDATE users SET login_attempts=?, locked_until=? WHERE id=?").run(attempts, locked, user.id);
      record(false);
      logSecEvent('LOGIN_FAILED', 'warn', req, { email, attempts });
      const left = MAX_ATTEMPT - attempts;
      return res.status(401).json({ success: false, message: left > 0 ? `Email atau password salah. ${left} percobaan tersisa.` : `Akun dikunci ${LOCK_MINS} menit.`, code: left <= 0 ? 'ACCOUNT_LOCKED' : undefined });
    }

    db.prepare("UPDATE users SET login_attempts=0, locked_until=NULL, last_login=datetime('now'), last_ip=?, last_user_agent=? WHERE id=?").run(ip, req.headers['user-agent']?.slice(0, 200), user.id);
    record(true);
    logSecEvent('LOGIN_SUCCESS', 'info', req, { userId: user.id });

    const safe = { id: user.id, name: user.name, email: user.email, role: user.role, plan: user.plan, credits: user.credits };
    const { accessToken, refreshToken } = issueTokens(safe, req);
    res.json({ success: true, message: 'Login berhasil.', data: { user: safe, accessToken, refreshToken } });
  } catch (err) {
    console.error('[LOGIN]', err.message);
    res.status(500).json({ success: false, message: 'Terjadi kesalahan.' });
  }
});

// POST /api/auth/refresh
router.post('/refresh', (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ success: false, message: 'Refresh token diperlukan.' });
  const result = exchangeRefreshToken(refreshToken, req);
  if (!result) return res.status(401).json({ success: false, message: 'Sesi tidak valid. Login ulang.', code: 'INVALID_REFRESH' });
  res.json({ success: true, data: result.tokens });
});

// POST /api/auth/logout
router.post('/logout', authenticate, (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    const hash = require('crypto').createHash('sha256').update(refreshToken).digest('hex');
    db.prepare('DELETE FROM refresh_tokens WHERE token_hash=? AND user_id=?').run(hash, req.user.id);
  }
  res.json({ success: true, message: 'Logout berhasil.' });
});

// POST /api/auth/logout-all
router.post('/logout-all', authenticate, (req, res) => {
  revokeAllUserTokens(req.user.id);
  res.json({ success: true, message: 'Semua sesi dihapus.' });
});

// GET /api/auth/me
router.get('/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT id,name,email,role,plan,credits,status,created_at,last_login FROM users WHERE id=?').get(req.user.id);
  res.json({ success: true, data: { user } });
});

// POST /api/auth/change-password
router.post('/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword || newPassword.length < 8)
      return res.status(400).json({ success: false, message: 'Password lama dan baru (min 8 karakter) wajib diisi.' });
    const row   = db.prepare('SELECT password FROM users WHERE id=?').get(req.user.id);
    const match = await bcrypt.compare(currentPassword, row.password);
    if (!match) return res.status(401).json({ success: false, message: 'Password lama tidak sesuai.' });
    if (currentPassword === newPassword) return res.status(400).json({ success: false, message: 'Password baru tidak boleh sama.' });
    const hashed = await bcrypt.hash(newPassword, ROUNDS);
    db.prepare("UPDATE users SET password=?, updated_at=datetime('now') WHERE id=?").run(hashed, req.user.id);
    revokeAllUserTokens(req.user.id);
    res.json({ success: true, message: 'Password berhasil diubah. Silakan login ulang.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Gagal mengubah password.' });
  }
});

module.exports = router;
