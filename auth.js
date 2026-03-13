// middleware/auth.js — JWT dengan deteksi token theft & refresh rotation

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../database/db');
const logger = require('../utils/logger');
const { logSecurityEvent, blockIP, getIP } = require('./security');

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

if (!ACCESS_SECRET || !REFRESH_SECRET) {
  throw new Error('JWT secrets tidak dikonfigurasi! Set JWT_ACCESS_SECRET dan JWT_REFRESH_SECRET di .env');
}

// Hash token untuk disimpan di DB (tidak simpan plaintext)
const hashToken = (token) =>
  crypto.createHash('sha256').update(token).digest('hex');

// ── Access Token ──────────────────────────────────────────────────────────────
const authenticate = (req, res, next) => {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Autentikasi diperlukan.' });
  }

  const token = header.slice(7);

  try {
    const decoded = jwt.verify(token, ACCESS_SECRET, {
      algorithms: ['HS256'],
      issuer: 'pixelup-api',
      audience: 'pixelup-client'
    });

    // Ambil user terbaru dari DB (biar status ban/suspend langsung berlaku)
    const user = db.prepare(`
      SELECT id, name, email, role, plan, status, credits FROM users WHERE id = ?
    `).get(decoded.sub);

    if (!user) {
      logSecurityEvent('INVALID_TOKEN_USER', 'warn', req, { userId: decoded.sub });
      return res.status(401).json({ success: false, message: 'Akun tidak valid.' });
    }

    if (user.status === 'banned') {
      return res.status(403).json({ success: false, message: 'Akun Anda telah diblokir.' });
    }
    if (user.status === 'suspended') {
      return res.status(403).json({ success: false, message: 'Akun Anda sedang ditangguhkan.' });
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Sesi habis.', code: 'TOKEN_EXPIRED' });
    }
    if (err.name === 'JsonWebTokenError') {
      logSecurityEvent('INVALID_JWT', 'warn', req);
      return res.status(401).json({ success: false, message: 'Token tidak valid.' });
    }
    return res.status(401).json({ success: false, message: 'Autentikasi gagal.' });
  }
};

// ── Issue Token Pair ──────────────────────────────────────────────────────────
const issueTokens = (user, req, familyId = null) => {
  const jti = crypto.randomUUID(); // JWT ID unik

  const accessToken = jwt.sign(
    { sub: user.id, email: user.email, role: user.role, plan: user.plan },
    ACCESS_SECRET,
    {
      algorithm: 'HS256',
      expiresIn: process.env.JWT_ACCESS_EXPIRES || '15m',
      issuer: 'pixelup-api',
      audience: 'pixelup-client',
      jwtid: jti
    }
  );

  // Refresh token: random bytes (bukan JWT, lebih aman)
  const rawRefreshToken = crypto.randomBytes(64).toString('hex');
  const tokenHash = hashToken(rawRefreshToken);
  const fid = familyId || crypto.randomUUID(); // family ID untuk satu sesi
  const expiresAt = new Date(Date.now() + 7 * 24 * 3600000).toISOString(); // 7 hari

  db.prepare(`
    INSERT INTO refresh_tokens (id, family_id, user_id, token_hash, expires_at, user_agent, ip)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    crypto.randomUUID(), fid, user.id, tokenHash, expiresAt,
    req?.headers?.['user-agent']?.slice(0, 255),
    getIP(req)
  );

  return { accessToken, refreshToken: rawRefreshToken, familyId: fid };
};

// ── Refresh Token Exchange ────────────────────────────────────────────────────
const exchangeRefreshToken = (rawToken, req) => {
  const tokenHash = hashToken(rawToken);

  const stored = db.prepare(`
    SELECT * FROM refresh_tokens WHERE token_hash = ?
  `).get(tokenHash);

  if (!stored) {
    // Token tidak ditemukan — kemungkinan sudah dipakai atau tidak valid
    logSecurityEvent('INVALID_REFRESH_TOKEN', 'warn', req);
    return null;
  }

  // ⚠️ DETEKSI TOKEN THEFT: Token sudah pernah dipakai
  if (stored.used) {
    // Invalidasi SEMUA token dalam family ini → paksa logout semua device
    db.prepare('DELETE FROM refresh_tokens WHERE family_id = ?').run(stored.family_id);
    logSecurityEvent('REFRESH_TOKEN_REUSE', 'critical', req, {
      userId: stored.user_id,
      familyId: stored.family_id
    });
    logger.security('TOKEN_THEFT_DETECTED', { userId: stored.user_id });
    return null;
  }

  // Token expired
  if (new Date(stored.expires_at) < new Date()) {
    db.prepare('DELETE FROM refresh_tokens WHERE id = ?').run(stored.id);
    return null;
  }

  // Mark as used (rotation)
  db.prepare('UPDATE refresh_tokens SET used = 1 WHERE id = ?').run(stored.id);

  // Ambil user
  const user = db.prepare('SELECT id, name, email, role, plan, status FROM users WHERE id = ?').get(stored.user_id);
  if (!user || user.status !== 'active') {
    db.prepare('DELETE FROM refresh_tokens WHERE family_id = ?').run(stored.family_id);
    return null;
  }

  // Issue token baru dengan family ID yang sama
  return { tokens: issueTokens(user, req, stored.family_id), user };
};

// ── Role Guard ────────────────────────────────────────────────────────────────
const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ success: false, message: 'Login diperlukan.' });
  if (!roles.includes(req.user.role)) {
    logSecurityEvent('UNAUTHORIZED_ROLE_ACCESS', 'warn', req, { required: roles, actual: req.user.role });
    return res.status(403).json({ success: false, message: 'Akses ditolak.' });
  }
  next();
};

// ── Plan Guard ────────────────────────────────────────────────────────────────
const requirePlan = (...plans) => (req, res, next) => {
  if (!plans.includes(req.user.plan)) {
    return res.status(403).json({
      success: false,
      message: `Fitur ini memerlukan paket ${plans.join(' atau ')}.`,
      code: 'UPGRADE_REQUIRED'
    });
  }
  next();
};

// ── Revoke All User Tokens ────────────────────────────────────────────────────
const revokeAllUserTokens = (userId) => {
  db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(userId);
};

module.exports = { authenticate, issueTokens, exchangeRefreshToken, requireRole, requirePlan, revokeAllUserTokens };
