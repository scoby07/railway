// routes/admin.js — Admin endpoints produksi

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../database/db');
const logger = require('../utils/logger');
const { authenticate, requireRole } = require('../middleware/auth');
const { logSecurityEvent, blockIP, getIP } = require('../middleware/security');
const { createUserAdminRules, updateUserAdminRules, uuidParamRules, paginationRules } = require('../middleware/validate');

router.use(authenticate, requireRole('admin', 'superadmin'));

// ── Audit helper ──────────────────────────────────────────────────────────────
const audit = (adminId, action, targetType, targetId, oldValues, newValues, req) => {
  db.prepare(`
    INSERT INTO audit_logs (id, admin_id, action, target_type, target_id, old_values, new_values, ip, user_agent)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    crypto.randomUUID(), adminId, action, targetType, targetId,
    JSON.stringify(oldValues), JSON.stringify(newValues),
    getIP(req), req.headers['user-agent']?.slice(0, 255)
  );
};

// ── GET /api/admin/stats ──────────────────────────────────────────────────────
router.get('/stats', (req, res) => {
  const totalUsers   = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const premiumUsers = db.prepare("SELECT COUNT(*) as c FROM users WHERE plan IN ('pro','ultra')").get().c;
  const totalJobs    = db.prepare('SELECT COUNT(*) as c FROM jobs').get().c;
  const jobsToday    = db.prepare("SELECT COUNT(*) as c FROM jobs WHERE DATE(created_at)=DATE('now')").get().c;
  const pendingJobs  = db.prepare("SELECT COUNT(*) as c FROM jobs WHERE status IN ('queued','processing')").get().c;
  const revenueMonth = db.prepare("SELECT COALESCE(SUM(amount_idr),0) as r FROM transactions WHERE status='paid' AND strftime('%Y-%m',created_at)=strftime('%Y-%m','now')").get().r;
  const totalRevenue = db.prepare("SELECT COALESCE(SUM(amount_idr),0) as r FROM transactions WHERE status='paid'").get().r;
  const bannedUsers  = db.prepare("SELECT COUNT(*) as c FROM users WHERE status='banned'").get().c;
  const recentEvents = db.prepare("SELECT COUNT(*) as c FROM security_events WHERE severity='critical' AND created_at > datetime('now','-24 hours')").get().c;
  const planDist     = db.prepare("SELECT plan, COUNT(*) as count FROM users GROUP BY plan").all();

  res.json({ success: true, data: { totalUsers, premiumUsers, totalJobs, jobsToday, pendingJobs, revenueMonth, totalRevenue, bannedUsers, recentEvents, planDist } });
});

// ── GET /api/admin/users ──────────────────────────────────────────────────────
router.get('/users', paginationRules, (req, res) => {
  const { search = '', plan = '', status = '', role = '', page = 1, limit = 20 } = req.query;
  const offset = (page - 1) * limit;

  let where = 'WHERE 1=1';
  const params = [];
  if (search) { where += ' AND (name LIKE ? OR email LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
  if (plan)   { where += ' AND plan = ?'; params.push(plan); }
  if (status) { where += ' AND status = ?'; params.push(status); }
  if (role)   { where += ' AND role = ?'; params.push(role); }

  const total = db.prepare(`SELECT COUNT(*) as c FROM users ${where}`).get(...params).c;
  const users = db.prepare(`
    SELECT id, name, email, role, plan, credits, status, created_at, last_login, last_ip,
           (SELECT COUNT(*) FROM jobs WHERE user_id=users.id) as total_jobs
    FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(...params, Number(limit), Number(offset));

  res.json({ success: true, data: { users, total, page: Number(page), limit: Number(limit) } });
});

// ── GET /api/admin/users/:id ──────────────────────────────────────────────────
router.get('/users/:id', uuidParamRules, (req, res) => {
  const user = db.prepare(`
    SELECT id, name, email, role, plan, credits, status, login_attempts, locked_until,
           created_at, last_login, last_ip,
           (SELECT COUNT(*) FROM jobs WHERE user_id=users.id) as total_jobs,
           (SELECT COALESCE(SUM(amount_idr),0) FROM transactions WHERE user_id=users.id AND status='paid') as total_spent
    FROM users WHERE id = ?
  `).get(req.params.id);

  if (!user) return res.status(404).json({ success: false, message: 'User tidak ditemukan.' });

  const recentJobs = db.prepare(`
    SELECT id, original_name, file_type, status, scale_mode, created_at
    FROM jobs WHERE user_id = ? ORDER BY created_at DESC LIMIT 5
  `).all(req.params.id);

  res.json({ success: true, data: { user, recentJobs } });
});

// ── POST /api/admin/users ─────────────────────────────────────────────────────
router.post('/users', createUserAdminRules, async (req, res) => {
  try {
    const { name, email, password, role = 'user', plan = 'free' } = req.body;

    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ success: false, message: 'Email sudah terdaftar.' });

    const hashed = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12);
    const userId = crypto.randomUUID();
    const credits = plan === 'ultra' ? 99999 : plan === 'pro' ? 500 : 10;

    db.prepare(`
      INSERT INTO users (id, name, email, password, role, plan, credits)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(userId, name, email, hashed, role, plan, credits);

    audit(req.user.id, 'CREATE_USER', 'user', userId, null, { name, email, role, plan }, req);
    logSecurityEvent('ADMIN_CREATE_USER', 'info', req, { adminId: req.user.id, userId, email });

    res.status(201).json({ success: true, message: 'User berhasil dibuat.', data: { userId } });
  } catch (err) {
    logger.error('Admin create user', { error: err.message });
    res.status(500).json({ success: false, message: 'Gagal membuat user.' });
  }
});

// ── PATCH /api/admin/users/:id ────────────────────────────────────────────────
router.patch('/users/:id', uuidParamRules, updateUserAdminRules, (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ success: false, message: 'User tidak ditemukan.' });

  if (target.role === 'superadmin' && req.user.role !== 'superadmin') {
    return res.status(403).json({ success: false, message: 'Tidak bisa mengubah superadmin.' });
  }

  const allowed = ['name', 'plan', 'role', 'status', 'credits'];
  const updates = {};
  for (const key of allowed) {
    if (req.body[key] !== undefined) updates[key] = req.body[key];
  }

  if (!Object.keys(updates).length) {
    return res.status(400).json({ success: false, message: 'Tidak ada field yang diperbarui.' });
  }

  const fields = Object.keys(updates).map(k => `${k} = ?`).join(', ');
  db.prepare(`UPDATE users SET ${fields}, updated_at = datetime('now') WHERE id = ?`).run(...Object.values(updates), req.params.id);

  // Jika di-ban → revoke semua token
  if (updates.status === 'banned' || updates.status === 'suspended') {
    db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(req.params.id);
    logSecurityEvent('ADMIN_BAN_USER', 'warn', req, { adminId: req.user.id, targetId: req.params.id, status: updates.status });
  }

  audit(req.user.id, 'UPDATE_USER', 'user', req.params.id, target, updates, req);
  res.json({ success: true, message: 'User berhasil diperbarui.' });
});

// ── DELETE /api/admin/users/:id ───────────────────────────────────────────────
router.delete('/users/:id', requireRole('superadmin'), uuidParamRules, (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ success: false, message: 'Tidak bisa menghapus akun sendiri.' });
  }
  const target = db.prepare('SELECT id, email, role FROM users WHERE id = ?').get(req.params.id);
  if (!target) return res.status(404).json({ success: false, message: 'User tidak ditemukan.' });
  if (target.role === 'superadmin') {
    return res.status(403).json({ success: false, message: 'Tidak bisa menghapus superadmin.' });
  }

  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  audit(req.user.id, 'DELETE_USER', 'user', req.params.id, { email: target.email }, null, req);
  logSecurityEvent('ADMIN_DELETE_USER', 'warn', req, { adminId: req.user.id, targetEmail: target.email });

  res.json({ success: true, message: 'User berhasil dihapus.' });
});

// ── GET /api/admin/transactions ───────────────────────────────────────────────
router.get('/transactions', paginationRules, (req, res) => {
  const { page = 1, limit = 20, status } = req.query;
  const offset = (page - 1) * limit;
  const where = status ? 'WHERE t.status = ?' : '';
  const params = status ? [status] : [];

  const transactions = db.prepare(`
    SELECT t.*, u.name as user_name, u.email as user_email
    FROM transactions t JOIN users u ON t.user_id = u.id
    ${where} ORDER BY t.created_at DESC LIMIT ? OFFSET ?
  `).all(...params, Number(limit), Number(offset));

  const totalRevenue = db.prepare("SELECT COALESCE(SUM(amount_idr),0) as r FROM transactions WHERE status='paid'").get().r;

  res.json({ success: true, data: { transactions, totalRevenue } });
});

// ── GET /api/admin/security-events ───────────────────────────────────────────
router.get('/security-events', (req, res) => {
  const { severity, page = 1, limit = 50 } = req.query;
  const offset = (page - 1) * limit;
  const where = severity ? 'WHERE severity = ?' : '';
  const params = severity ? [severity] : [];

  const events = db.prepare(`
    SELECT se.*, u.name as user_name, u.email as user_email
    FROM security_events se
    LEFT JOIN users u ON se.user_id = u.id
    ${where} ORDER BY se.created_at DESC LIMIT ? OFFSET ?
  `).all(...params, Number(limit), Number(offset));

  res.json({ success: true, data: { events } });
});

// ── GET /api/admin/blocked-ips ────────────────────────────────────────────────
router.get('/blocked-ips', (req, res) => {
  const blocks = db.prepare(`
    SELECT * FROM ip_blocks
    WHERE permanent=1 OR expires_at > datetime('now')
    ORDER BY blocked_at DESC
  `).all();
  res.json({ success: true, data: { blocks } });
});

// ── POST /api/admin/block-ip ──────────────────────────────────────────────────
router.post('/block-ip', (req, res) => {
  const { ip, reason, hours = 24 } = req.body;
  if (!ip || !reason) return res.status(400).json({ success: false, message: 'IP dan alasan wajib diisi.' });

  blockIP(ip, reason, hours === -1 ? -1 : Number(hours));
  audit(req.user.id, 'BLOCK_IP', 'ip', ip, null, { reason, hours }, req);

  res.json({ success: true, message: `IP ${ip} berhasil diblokir.` });
});

// ── DELETE /api/admin/block-ip/:ip ───────────────────────────────────────────
router.delete('/blocked-ips/:ip', (req, res) => {
  db.prepare('DELETE FROM ip_blocks WHERE ip = ?').run(req.params.ip);
  audit(req.user.id, 'UNBLOCK_IP', 'ip', req.params.ip, null, null, req);
  res.json({ success: true, message: `IP ${req.params.ip} berhasil dibuka.` });
});

// ── GET /api/admin/audit-logs ─────────────────────────────────────────────────
router.get('/audit-logs', paginationRules, (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  const offset = (page - 1) * limit;

  const logs = db.prepare(`
    SELECT al.*, u.name as admin_name FROM audit_logs al
    LEFT JOIN users u ON al.admin_id = u.id
    ORDER BY al.created_at DESC LIMIT ? OFFSET ?
  `).all(Number(limit), Number(offset));

  res.json({ success: true, data: { logs } });
});

// ── GET /api/admin/jobs ───────────────────────────────────────────────────────
router.get('/jobs', paginationRules, (req, res) => {
  const { status, page = 1, limit = 20 } = req.query;
  const offset = (page - 1) * limit;
  const where = status ? 'WHERE j.status = ?' : '';
  const params = status ? [status] : [];

  const jobs = db.prepare(`
    SELECT j.id, j.original_name, j.file_type, j.status, j.scale_mode, j.created_at,
           u.name as user_name, u.email as user_email
    FROM jobs j JOIN users u ON j.user_id = u.id
    ${where} ORDER BY j.created_at DESC LIMIT ? OFFSET ?
  `).all(...params, Number(limit), Number(offset));

  res.json({ success: true, data: { jobs } });
});

module.exports = router;
