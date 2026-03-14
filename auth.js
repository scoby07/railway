// auth.js — JWT middleware (flat, root level)

const jwt    = require('jsonwebtoken');
const crypto = require('crypto');
const db     = require('./db');
const { getIP, logSecEvent } = require('./security');

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET;
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

const hashToken = (t) => crypto.createHash('sha256').update(t).digest('hex');

// Verifikasi access token
const authenticate = (req, res, next) => {
  const header = req.headers['authorization'];
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Login diperlukan.' });
  }
  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, ACCESS_SECRET, { algorithms: ['HS256'] });
    const user = db.prepare('SELECT id,name,email,role,plan,status,credits FROM users WHERE id=?').get(decoded.sub);
    if (!user) return res.status(401).json({ success: false, message: 'Akun tidak valid.' });
    if (user.status === 'banned')     return res.status(403).json({ success: false, message: 'Akun diblokir.' });
    if (user.status === 'suspended')  return res.status(403).json({ success: false, message: 'Akun ditangguhkan.' });
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({ success: false, message: 'Sesi habis.', code: 'TOKEN_EXPIRED' });
    logSecEvent('INVALID_JWT', 'warn', req);
    return res.status(401).json({ success: false, message: 'Token tidak valid.' });
  }
};

// Issue token pair
const issueTokens = (user, req, familyId = null) => {
  const accessToken = jwt.sign(
    { sub: user.id, email: user.email, role: user.role, plan: user.plan },
    ACCESS_SECRET,
    { algorithm: 'HS256', expiresIn: process.env.JWT_ACCESS_EXPIRES || '15m' }
  );
  const raw      = crypto.randomBytes(64).toString('hex');
  const hash     = hashToken(raw);
  const fid      = familyId || crypto.randomUUID();
  const expiresAt = new Date(Date.now() + 7 * 24 * 3600000).toISOString();

  db.prepare(`
    INSERT INTO refresh_tokens (id,family_id,user_id,token_hash,expires_at,user_agent,ip)
    VALUES (?,?,?,?,?,?,?)
  `).run(crypto.randomUUID(), fid, user.id, hash, expiresAt,
    req?.headers?.['user-agent']?.slice(0, 200), getIP(req));

  return { accessToken, refreshToken: raw, familyId: fid };
};

// Exchange refresh token
const exchangeRefreshToken = (raw, req) => {
  const hash   = hashToken(raw);
  const stored = db.prepare('SELECT * FROM refresh_tokens WHERE token_hash=?').get(hash);
  if (!stored) { logSecEvent('INVALID_REFRESH', 'warn', req); return null; }

  // Token theft detection
  if (stored.used) {
    db.prepare('DELETE FROM refresh_tokens WHERE family_id=?').run(stored.family_id);
    logSecEvent('TOKEN_THEFT', 'critical', req, { userId: stored.user_id });
    return null;
  }
  if (new Date(stored.expires_at) < new Date()) {
    db.prepare('DELETE FROM refresh_tokens WHERE id=?').run(stored.id);
    return null;
  }

  db.prepare('UPDATE refresh_tokens SET used=1 WHERE id=?').run(stored.id);
  const user = db.prepare('SELECT id,name,email,role,plan,status FROM users WHERE id=?').get(stored.user_id);
  if (!user || user.status !== 'active') {
    db.prepare('DELETE FROM refresh_tokens WHERE family_id=?').run(stored.family_id);
    return null;
  }
  return { tokens: issueTokens(user, req, stored.family_id), user };
};

// Role guard
const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user?.role)) {
    logSecEvent('UNAUTHORIZED_ROLE', 'warn', req, { required: roles });
    return res.status(403).json({ success: false, message: 'Akses ditolak.' });
  }
  next();
};

// Plan guard
const requirePlan = (...plans) => (req, res, next) => {
  if (!plans.includes(req.user?.plan)) {
    return res.status(403).json({
      success: false,
      message: `Fitur ini memerlukan paket ${plans.join(' atau ')}.`,
      code: 'UPGRADE_REQUIRED'
    });
  }
  next();
};

const revokeAllUserTokens = (userId) => {
  db.prepare('DELETE FROM refresh_tokens WHERE user_id=?').run(userId);
};

module.exports = { authenticate, issueTokens, exchangeRefreshToken, requireRole, requirePlan, revokeAllUserTokens };
