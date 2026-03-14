// security.js — Middleware keamanan

const crypto = require('crypto');
const db     = require('./db');

const getIP = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
  req.socket?.remoteAddress || 'unknown';

const logSecEvent = (type, severity, req, details = {}) => {
  const ip     = getIP(req);
  const userId = req.user?.id || null;
  try {
    db.prepare(`
      INSERT INTO security_events (id, event_type, severity, user_id, ip, user_agent, details)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(crypto.randomUUID(), type, severity, userId, ip,
      req.headers['user-agent']?.slice(0, 200), JSON.stringify(details));
  } catch {}
};

const blockIP = (ip, reason, hours = 24) => {
  const exp = hours === -1 ? null : new Date(Date.now() + hours * 3600000).toISOString();
  try {
    db.prepare(`
      INSERT INTO ip_blocks (ip, reason, expires_at, permanent) VALUES (?, ?, ?, ?)
      ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, expires_at=excluded.expires_at, permanent=excluded.permanent
    `).run(ip, reason, exp, hours === -1 ? 1 : 0);
  } catch {}
  console.log(`[SECURITY] IP blocked: ${ip} — ${reason}`);
};

// 1. Cek IP block
const checkIPBlock = (req, res, next) => {
  const ip = getIP(req);
  try {
    const block = db.prepare(`
      SELECT 1 FROM ip_blocks WHERE ip = ? AND (permanent=1 OR expires_at > datetime('now'))
    `).get(ip);
    if (block) {
      logSecEvent('BLOCKED_IP_ACCESS', 'warn', req);
      return res.status(403).json({ success: false, message: 'Akses ditolak.' });
    }
  } catch {}
  next();
};

// 2. Brute force per IP
const detectBruteForce = (req, res, next) => {
  const ip = getIP(req);
  try {
    const count = db.prepare(`
      SELECT COUNT(*) as c FROM auth_attempts
      WHERE ip=? AND success=0 AND created_at > datetime('now','-15 minutes')
    `).get(ip)?.c || 0;
    if (count >= 20) {
      blockIP(ip, `Brute force: ${count} gagal dalam 15 menit`, 24);
      logSecEvent('BRUTE_FORCE_BLOCKED', 'critical', req);
      return res.status(429).json({ success: false, message: 'Terlalu banyak percobaan. Coba lagi nanti.' });
    }
  } catch {}
  next();
};

// 3. Validasi user-agent
const validateUserAgent = (req, res, next) => {
  const ua = req.headers['user-agent'] || '';
  if (!ua || ua.length < 5) {
    logSecEvent('MISSING_UA', 'warn', req);
    return res.status(400).json({ success: false, message: 'Request tidak valid.' });
  }
  const malicious = [/sqlmap/i, /nikto/i, /masscan/i, /nmap/i, /acunetix/i, /burpsuite/i, /w3af/i];
  if (malicious.some(p => p.test(ua))) {
    blockIP(getIP(req), `Scanner: ${ua.slice(0, 80)}`, 168);
    logSecEvent('SCANNER_DETECTED', 'critical', req, { ua: ua.slice(0, 100) });
    return res.status(403).json({ success: false, message: 'Akses ditolak.' });
  }
  next();
};

// 4. Validasi ukuran request
const validateRequestSize = (req, res, next) => {
  const len = parseInt(req.headers['content-length'] || '0');
  if (len > 10 * 1024 * 1024) {
    logSecEvent('OVERSIZED_REQUEST', 'warn', req, { size: len });
    return res.status(413).json({ success: false, message: 'Request terlalu besar.' });
  }
  next();
};

// 5. Deteksi SQL injection
const detectSQLInjection = (req, res, next) => {
  const patterns = [
    /(\bUNION\b.*\bSELECT\b)/i, /(\bDROP\b|\bTRUNCATE\b)/i,
    /(--|\/\*|xp_|EXEC\s*\()/i, /SLEEP\s*\(\d+\)/i, /WAITFOR\s+DELAY/i
  ];
  const check = (v) => typeof v === 'string' ? patterns.some(p => p.test(v)) :
    typeof v === 'object' && v ? Object.values(v).some(check) : false;
  if (check({ ...req.body, ...req.query })) {
    blockIP(getIP(req), 'SQL injection attempt', 72);
    logSecEvent('SQL_INJECTION', 'critical', req);
    return res.status(400).json({ success: false, message: 'Input tidak valid.' });
  }
  next();
};

// 6. Deteksi XSS
const detectXSS = (req, res, next) => {
  const patterns = [/<script/i, /javascript:/i, /on\w+=\s*['"]/i, /<iframe/i, /eval\s*\(/i];
  const check = (v) => typeof v === 'string' ? patterns.some(p => p.test(v)) :
    typeof v === 'object' && v ? Object.values(v).some(check) : false;
  if (check(req.body) || check(req.query)) {
    blockIP(getIP(req), 'XSS attempt', 48);
    logSecEvent('XSS_ATTEMPT', 'critical', req);
    return res.status(400).json({ success: false, message: 'Input tidak valid.' });
  }
  next();
};

// 7. Path traversal
const preventPathTraversal = (req, res, next) => {
  if (/(\.\.[/\\]|%2e%2e)/i.test(req.path)) {
    blockIP(getIP(req), 'Path traversal', 48);
    return res.status(400).json({ success: false, message: 'Request tidak valid.' });
  }
  next();
};

// 8. Request ID
const addRequestId = (req, res, next) => {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.id);
  next();
};

// 9. Sanitize body
const sanitizeBody = (req, res, next) => {
  const clean = (obj) => {
    if (typeof obj !== 'object' || !obj) return obj;
    const r = {};
    for (const [k, v] of Object.entries(obj)) {
      r[k] = typeof v === 'string'
        ? v.replace(/[<>]/g, '').replace(/\0/g, '').trim().slice(0, 10000)
        : typeof v === 'object' ? clean(v) : v;
    }
    return r;
  };
  if (req.body) req.body = clean(req.body);
  next();
};

// Cleanup
const runCleanup = () => {
  try {
    db.prepare("DELETE FROM ip_blocks WHERE permanent=0 AND expires_at < datetime('now')").run();
    db.prepare("DELETE FROM auth_attempts WHERE created_at < datetime('now','-1 day')").run();
    db.prepare("DELETE FROM refresh_tokens WHERE expires_at < datetime('now')").run();
    db.prepare("DELETE FROM security_events WHERE created_at < datetime('now','-90 days')").run();
    console.log('[CLEANUP] Selesai.');
  } catch (err) { console.error('[CLEANUP] Error:', err.message); }
};

module.exports = {
  getIP, logSecEvent, blockIP,
  checkIPBlock, detectBruteForce, validateUserAgent,
  validateRequestSize, detectSQLInjection, detectXSS,
  preventPathTraversal, addRequestId, sanitizeBody, runCleanup
};
