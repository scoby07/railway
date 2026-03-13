// middleware/security.js — Lapisan keamanan utama

const crypto = require('crypto');
const db = require('../database/db');
const logger = require('../utils/logger');

// ── Helpers ───────────────────────────────────────────────────────────────────
const getIP = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
  req.socket?.remoteAddress || 'unknown';

const logSecurityEvent = (type, severity, req, details = {}) => {
  const ip = getIP(req);
  const userId = req.user?.id || null;
  logger.security(type, { severity, ip, userId, path: req.path, ...details });
  try {
    db.prepare(`
      INSERT INTO security_events (id, event_type, severity, user_id, ip, user_agent, details)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(crypto.randomUUID(), type, severity, userId, ip, req.headers['user-agent']?.slice(0, 255), JSON.stringify(details));
  } catch {}
};

// ── 1. IP BLOCK CHECK ─────────────────────────────────────────────────────────
const checkIPBlock = (req, res, next) => {
  const ip = getIP(req);
  const block = db.prepare(`
    SELECT * FROM ip_blocks WHERE ip = ?
    AND (permanent = 1 OR expires_at > datetime('now'))
  `).get(ip);

  if (block) {
    logSecurityEvent('BLOCKED_IP_ACCESS', 'warn', req, { reason: block.reason });
    return res.status(403).json({ success: false, message: 'Akses ditolak.' });
  }
  next();
};

// ── 2. AUTO IP BLOCK (dipanggil setelah deteksi anomali) ─────────────────────
const blockIP = (ip, reason, hours = 24) => {
  const expiresAt = hours === -1
    ? null
    : new Date(Date.now() + hours * 3600000).toISOString();

  db.prepare(`
    INSERT INTO ip_blocks (ip, reason, expires_at, permanent)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET reason=excluded.reason, expires_at=excluded.expires_at, permanent=excluded.permanent
  `).run(ip, reason, expiresAt, hours === -1 ? 1 : 0);

  logger.security('IP_BLOCKED', { ip, reason, hours });
};

// ── 3. BRUTE FORCE DETECTOR ───────────────────────────────────────────────────
const detectBruteForce = (req, res, next) => {
  const ip = getIP(req);
  const window = 15 * 60; // 15 menit

  // Hitung failed attempts dari IP ini dalam window
  const failedFromIP = db.prepare(`
    SELECT COUNT(*) as c FROM auth_attempts
    WHERE ip = ? AND success = 0
    AND created_at > datetime('now', '-${window} seconds')
  `).get(ip).c;

  // Jika >20 kali gagal dalam 15 menit → auto-block IP
  if (failedFromIP >= 20) {
    blockIP(ip, `Brute force: ${failedFromIP} failed attempts in 15min`, 24);
    logSecurityEvent('BRUTE_FORCE_BLOCKED', 'critical', req);
    return res.status(429).json({ success: false, message: 'Terlalu banyak percobaan. Akses diblokir sementara.' });
  }

  next();
};

// ── 4. USER AGENT VALIDATION ──────────────────────────────────────────────────
const validateUserAgent = (req, res, next) => {
  const ua = req.headers['user-agent'] || '';

  // Block jika tidak ada user agent (kemungkinan scanner)
  if (!ua || ua.length < 5) {
    logSecurityEvent('MISSING_USER_AGENT', 'warn', req);
    return res.status(400).json({ success: false, message: 'Request tidak valid.' });
  }

  // Block known malicious scanners
  const maliciousPatterns = [
    /sqlmap/i, /nikto/i, /masscan/i, /nmap/i, /acunetix/i,
    /burpsuite/i, /w3af/i, /havij/i, /pangolin/i, /dirbuster/i,
    /httpscan/i, /metasploit/i, /python-requests\/2\.2[0-5]/i
  ];

  if (maliciousPatterns.some(p => p.test(ua))) {
    blockIP(getIP(req), `Malicious scanner UA: ${ua.slice(0, 100)}`, 168); // 1 minggu
    logSecurityEvent('SCANNER_DETECTED', 'critical', req, { ua });
    return res.status(403).json({ success: false, message: 'Akses ditolak.' });
  }

  next();
};

// ── 5. REQUEST SIZE CHECK ─────────────────────────────────────────────────────
const validateRequestSize = (req, res, next) => {
  const contentLength = parseInt(req.headers['content-length'] || '0');
  const maxSize = 10 * 1024 * 1024; // 10MB untuk JSON

  if (contentLength > maxSize) {
    logSecurityEvent('OVERSIZED_REQUEST', 'warn', req, { size: contentLength });
    return res.status(413).json({ success: false, message: 'Request terlalu besar.' });
  }
  next();
};

// ── 6. SQL INJECTION DETECTOR (lapisan tambahan di atas prepared statements) ──
const detectSQLInjection = (req, res, next) => {
  const suspicious = [
    /(\bUNION\b.*\bSELECT\b|\bSELECT\b.*\bFROM\b)/i,
    /(\bDROP\b|\bTRUNCATE\b|\bDELETE\b.*\bFROM\b|\bINSERT\b.*\bINTO\b)/i,
    /(--|;|\/\*|\*\/|xp_|EXEC\s*\(|EXECUTE\s*\()/i,
    /(\bOR\b\s+[\d'"]\s*=\s*[\d'"]|\bAND\b\s+[\d'"]\s*=\s*[\d'"])/i,
    /SLEEP\s*\(\d+\)/i,
    /BENCHMARK\s*\(\d+/i,
    /WAITFOR\s+DELAY/i,
    /0x[0-9a-f]{4,}/i
  ];

  const checkStr = (val) => {
    if (typeof val === 'string') {
      return suspicious.some(p => p.test(val));
    }
    if (typeof val === 'object' && val !== null) {
      return Object.values(val).some(v => checkStr(v));
    }
    return false;
  };

  const inputs = { ...req.body, ...req.query, ...req.params };
  if (checkStr(inputs)) {
    logSecurityEvent('SQL_INJECTION_ATTEMPT', 'critical', req, { inputs: JSON.stringify(inputs).slice(0, 500) });
    blockIP(getIP(req), 'SQL injection attempt', 72);
    return res.status(400).json({ success: false, message: 'Input tidak valid.' });
  }
  next();
};

// ── 7. XSS DETECTOR ──────────────────────────────────────────────────────────
const detectXSS = (req, res, next) => {
  const xssPatterns = [
    /<script[\s>]/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe/i,
    /<object/i,
    /<embed/i,
    /eval\s*\(/i,
    /document\.cookie/i,
    /window\.location/i,
    /<svg.*?onload/i
  ];

  const checkStr = (val) => {
    if (typeof val === 'string') return xssPatterns.some(p => p.test(val));
    if (typeof val === 'object' && val !== null) return Object.values(val).some(v => checkStr(v));
    return false;
  };

  if (checkStr(req.body) || checkStr(req.query)) {
    logSecurityEvent('XSS_ATTEMPT', 'critical', req);
    blockIP(getIP(req), 'XSS attempt', 48);
    return res.status(400).json({ success: false, message: 'Input tidak valid.' });
  }
  next();
};

// ── 8. PATH TRAVERSAL PROTECTION ─────────────────────────────────────────────
const preventPathTraversal = (req, res, next) => {
  const dangerous = /(\.\.[/\\]|%2e%2e[/\\]|%252e%252e)/i;
  const path = decodeURIComponent(req.path);

  if (dangerous.test(path) || dangerous.test(req.originalUrl)) {
    logSecurityEvent('PATH_TRAVERSAL_ATTEMPT', 'critical', req);
    blockIP(getIP(req), 'Path traversal attempt', 48);
    return res.status(400).json({ success: false, message: 'Request tidak valid.' });
  }
  next();
};

// ── 9. REQUEST ID ─────────────────────────────────────────────────────────────
const addRequestId = (req, res, next) => {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-ID', req.id);
  next();
};

// ── 10. INPUT SANITIZER ───────────────────────────────────────────────────────
const sanitizeInput = (obj) => {
  if (typeof obj !== 'object' || obj === null) return obj;
  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      result[key] = value
        .replace(/[<>]/g, '')           // Basic HTML strip
        .replace(/\0/g, '')             // Null bytes
        .trim()
        .slice(0, 10000);               // Max length
    } else if (typeof value === 'object') {
      result[key] = sanitizeInput(value);
    } else {
      result[key] = value;
    }
  }
  return result;
};

const sanitizeBody = (req, res, next) => {
  if (req.body) req.body = sanitizeInput(req.body);
  next();
};

// ── 11. HONEYPOT ──────────────────────────────────────────────────────────────
const honeypot = (req, res, next) => {
  // Jika field tersembunyi ini diisi → bot
  if (req.body?.website || req.body?.fax || req.body?.company2) {
    logSecurityEvent('HONEYPOT_TRIGGERED', 'warn', req);
    // Kembalikan respons sukses palsu (jangan beri tahu bot bahwa dia terdeteksi)
    return res.json({ success: true, message: 'Permintaan sedang diproses.' });
  }
  next();
};

// ── 12. CLEANUP JOB ───────────────────────────────────────────────────────────
const runCleanup = () => {
  try {
    // Hapus IP block yang sudah expired
    db.prepare("DELETE FROM ip_blocks WHERE permanent=0 AND expires_at < datetime('now')").run();
    // Hapus auth attempts >24 jam
    db.prepare("DELETE FROM auth_attempts WHERE created_at < datetime('now','-1 day')").run();
    // Hapus refresh token expired
    db.prepare("DELETE FROM refresh_tokens WHERE expires_at < datetime('now')").run();
    // Hapus CSRF expired
    db.prepare("DELETE FROM csrf_tokens WHERE expires_at < datetime('now')").run();
    // Hapus security events >90 hari
    db.prepare("DELETE FROM security_events WHERE created_at < datetime('now','-90 days')").run();
  } catch (err) {
    logger.error('Cleanup job error', { error: err.message });
  }
};

module.exports = {
  getIP,
  logSecurityEvent,
  blockIP,
  checkIPBlock,
  detectBruteForce,
  validateUserAgent,
  validateRequestSize,
  detectSQLInjection,
  detectXSS,
  preventPathTraversal,
  addRequestId,
  sanitizeBody,
  honeypot,
  runCleanup
};
