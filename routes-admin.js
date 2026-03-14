// routes-admin.js

const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const crypto  = require('crypto');
const db      = require('./db');
const { authenticate, requireRole } = require('./auth');
const { logSecEvent, blockIP, getIP } = require('./security');
const { body, validationResult } = require('express-validator');

const v = (rules) => [...rules, (req, res, next) => {
  const e = validationResult(req);
  if (!e.isEmpty()) return res.status(422).json({ success: false, message: e.array()[0].msg });
  next();
}];

router.use(authenticate, requireRole('admin', 'superadmin'));

const audit = (adminId, action, targetType, targetId, old_, new_, req) => {
  try { db.prepare('INSERT INTO audit_logs (id,admin_id,action,target_type,target_id,old_values,new_values,ip) VALUES (?,?,?,?,?,?,?,?)').run(crypto.randomUUID(), adminId, action, targetType, targetId, JSON.stringify(old_), JSON.stringify(new_), getIP(req)); } catch {}
};

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
  const planDist     = db.prepare('SELECT plan, COUNT(*) as count FROM users GROUP BY plan').all();
  res.json({ success: true, data: { totalUsers, premiumUsers, totalJobs, jobsToday, pendingJobs, revenueMonth, totalRevenue, bannedUsers, recentEvents, planDist } });
});

router.get('/users', (req, res) => {
  const { search='', plan='', status='', page=1, limit=20 } = req.query;
  const offset = (page-1)*limit;
  let where = 'WHERE 1=1'; const params = [];
  if (search) { where += ' AND (name LIKE ? OR email LIKE ?)'; params.push(`%${search}%`,`%${search}%`); }
  if (plan)   { where += ' AND plan=?'; params.push(plan); }
  if (status) { where += ' AND status=?'; params.push(status); }
  const total = db.prepare(`SELECT COUNT(*) as c FROM users ${where}`).get(...params).c;
  const users = db.prepare(`SELECT id,name,email,role,plan,credits,status,created_at,last_login,last_ip,(SELECT COUNT(*) FROM jobs WHERE user_id=users.id) as total_jobs FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, Number(limit), Number(offset));
  res.json({ success: true, data: { users, total, page: Number(page), limit: Number(limit) } });
});

router.post('/users', v([
  body('name').trim().isLength({ min: 2, max: 80 }),
  body('email').trim().isEmail().normalizeEmail(),
  body('password').isLength({ min: 8, max: 128 }),
  body('role').isIn(['user','admin']),
  body('plan').isIn(['free','pro','ultra'])
]), async (req, res) => {
  try {
    const { name, email, password, role='user', plan='free' } = req.body;
    if (db.prepare('SELECT id FROM users WHERE email=?').get(email))
      return res.status(409).json({ success: false, message: 'Email sudah terdaftar.' });
    const hashed = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS)||12);
    const uid    = crypto.randomUUID();
    const credits = plan==='ultra'?99999:plan==='pro'?500:10;
    db.prepare('INSERT INTO users (id,name,email,password,role,plan,credits) VALUES (?,?,?,?,?,?,?)').run(uid,name,email,hashed,role,plan,credits);
    audit(req.user.id,'CREATE_USER','user',uid,null,{name,email,role,plan},req);
    res.status(201).json({ success: true, message: 'User dibuat.', data: { userId: uid } });
  } catch { res.status(500).json({ success: false, message: 'Gagal membuat user.' }); }
});

router.patch('/users/:id', (req, res) => {
  const target = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
  if (!target) return res.status(404).json({ success: false, message: 'User tidak ditemukan.' });
  if (target.role==='superadmin' && req.user.role!=='superadmin')
    return res.status(403).json({ success: false, message: 'Tidak bisa mengubah superadmin.' });
  const allowed = ['name','plan','role','status','credits'];
  const updates = {};
  for (const k of allowed) if (req.body[k] !== undefined) updates[k] = req.body[k];
  if (!Object.keys(updates).length) return res.status(400).json({ success: false, message: 'Tidak ada field yang diubah.' });
  const fields = Object.keys(updates).map(k=>`${k}=?`).join(',');
  db.prepare(`UPDATE users SET ${fields}, updated_at=datetime('now') WHERE id=?`).run(...Object.values(updates), req.params.id);
  if (updates.status==='banned'||updates.status==='suspended')
    db.prepare('DELETE FROM refresh_tokens WHERE user_id=?').run(req.params.id);
  audit(req.user.id,'UPDATE_USER','user',req.params.id,target,updates,req);
  res.json({ success: true, message: 'User diperbarui.' });
});

router.delete('/users/:id', requireRole('superadmin'), (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ success: false, message: 'Tidak bisa hapus akun sendiri.' });
  const t = db.prepare('SELECT id,email,role FROM users WHERE id=?').get(req.params.id);
  if (!t) return res.status(404).json({ success: false, message: 'User tidak ditemukan.' });
  if (t.role==='superadmin') return res.status(403).json({ success: false, message: 'Tidak bisa hapus superadmin.' });
  db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
  audit(req.user.id,'DELETE_USER','user',req.params.id,{email:t.email},null,req);
  res.json({ success: true, message: 'User dihapus.' });
});

router.get('/transactions', (req, res) => {
  const { page=1, limit=20 } = req.query;
  const offset = (page-1)*limit;
  const txns = db.prepare('SELECT t.*,u.name as user_name,u.email as user_email FROM transactions t JOIN users u ON t.user_id=u.id ORDER BY t.created_at DESC LIMIT ? OFFSET ?').all(Number(limit),Number(offset));
  const total = db.prepare("SELECT COALESCE(SUM(amount_idr),0) as r FROM transactions WHERE status='paid'").get().r;
  res.json({ success: true, data: { transactions: txns, totalRevenue: total } });
});

router.get('/security-events', (req, res) => {
  const { severity, limit=50 } = req.query;
  const where = severity ? 'WHERE severity=?' : '';
  const events = db.prepare(`SELECT se.*,u.name as user_name,u.email as user_email FROM security_events se LEFT JOIN users u ON se.user_id=u.id ${where} ORDER BY se.created_at DESC LIMIT ?`).all(...(severity?[severity]:[]), Number(limit));
  res.json({ success: true, data: { events } });
});

router.get('/blocked-ips', (req, res) => {
  const blocks = db.prepare("SELECT * FROM ip_blocks WHERE permanent=1 OR expires_at > datetime('now') ORDER BY blocked_at DESC").all();
  res.json({ success: true, data: { blocks } });
});

router.post('/block-ip', (req, res) => {
  const { ip, reason, hours=24 } = req.body;
  if (!ip||!reason) return res.status(400).json({ success: false, message: 'IP dan alasan wajib.' });
  blockIP(ip, reason, hours===-1?-1:Number(hours));
  audit(req.user.id,'BLOCK_IP','ip',ip,null,{reason,hours},req);
  res.json({ success: true, message: `IP ${ip} diblokir.` });
});

router.delete('/blocked-ips/:ip', (req, res) => {
  db.prepare('DELETE FROM ip_blocks WHERE ip=?').run(req.params.ip);
  audit(req.user.id,'UNBLOCK_IP','ip',req.params.ip,null,null,req);
  res.json({ success: true, message: `IP ${req.params.ip} dibuka.` });
});

router.get('/audit-logs', (req, res) => {
  const { limit=50 } = req.query;
  const logs = db.prepare('SELECT al.*,u.name as admin_name FROM audit_logs al LEFT JOIN users u ON al.admin_id=u.id ORDER BY al.created_at DESC LIMIT ?').all(Number(limit));
  res.json({ success: true, data: { logs } });
});

module.exports = router;
