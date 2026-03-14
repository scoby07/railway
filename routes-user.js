// routes-user.js

const express = require('express');
const router  = express.Router();
const bcrypt  = require('bcryptjs');
const crypto  = require('crypto');
const db      = require('./db');
const { authenticate, requirePlan } = require('./auth');
const { body, param, query, validationResult } = require('express-validator');

const v = (rules) => [...rules, (req, res, next) => {
  const e = validationResult(req);
  if (!e.isEmpty()) return res.status(422).json({ success: false, message: e.array()[0].msg });
  next();
}];

router.use(authenticate);

router.get('/profile', (req, res) => {
  const user = db.prepare('SELECT id,name,email,role,plan,credits,status,created_at,last_login FROM users WHERE id=?').get(req.user.id);
  const sub  = db.prepare('SELECT * FROM subscriptions WHERE user_id=?').get(req.user.id);
  const jobs = db.prepare('SELECT COUNT(*) as total, SUM(CASE WHEN status="done" THEN 1 ELSE 0 END) as done, SUM(CASE WHEN status="failed" THEN 1 ELSE 0 END) as failed FROM jobs WHERE user_id=?').get(req.user.id);
  res.json({ success: true, data: { user, subscription: sub, jobStats: jobs } });
});

router.patch('/profile', v([body('name').trim().isLength({ min: 2, max: 80 }).withMessage('Nama harus 2–80 karakter.')]), (req, res) => {
  db.prepare("UPDATE users SET name=?, updated_at=datetime('now') WHERE id=?").run(req.body.name, req.user.id);
  res.json({ success: true, message: 'Profil berhasil diperbarui.' });
});

router.get('/jobs', (req, res) => {
  const page   = Math.max(1, parseInt(req.query.page) || 1);
  const limit  = Math.min(50, parseInt(req.query.limit) || 10);
  const offset = (page - 1) * limit;
  const where  = req.query.status ? 'AND status=?' : '';
  const params = req.query.status ? [req.user.id, req.query.status] : [req.user.id];
  const jobs   = db.prepare(`SELECT id,original_name,file_type,file_size,status,scale_mode,out_width,out_height,process_ms,created_at FROM jobs WHERE user_id=? ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).all(...params, limit, offset);
  const total  = db.prepare(`SELECT COUNT(*) as c FROM jobs WHERE user_id=? ${where}`).get(...params).c;
  res.json({ success: true, data: { jobs, total, page, limit } });
});

router.post('/jobs', v([
  body('scale_mode').isIn(['2x','4x','8x']).withMessage('Mode tidak valid.'),
  body('content_type').isIn(['photo','portrait','anime','landscape']).withMessage('Tipe tidak valid.'),
  body('noise_level').isInt({ min: 0, max: 100 }).toInt(),
  body('sharpness').isInt({ min: 0, max: 100 }).toInt()
]), (req, res) => {
  const user = db.prepare('SELECT credits,plan FROM users WHERE id=?').get(req.user.id);
  const { scale_mode, content_type, noise_level, sharpness, filename, file_type, file_size } = req.body;

  if (user.plan === 'free' && user.credits <= 0)
    return res.status(403).json({ success: false, message: 'Kredit habis. Upgrade ke Pro.', code: 'NO_CREDITS' });
  if (scale_mode === '8x' && user.plan !== 'ultra')
    return res.status(403).json({ success: false, message: 'Upscale 8× memerlukan paket Ultra.', code: 'UPGRADE_REQUIRED' });
  if (scale_mode === '4x' && user.plan === 'free')
    return res.status(403).json({ success: false, message: 'Upscale 4× memerlukan paket Pro.', code: 'UPGRADE_REQUIRED' });

  const jobId = crypto.randomUUID();
  db.prepare("INSERT INTO jobs (id,user_id,filename,original_name,file_type,file_size,scale_mode,content_type,noise_level,sharpness) VALUES (?,?,?,?,?,?,?,?,?,?)").run(jobId, req.user.id, `upload_${jobId}`, filename || 'unknown', file_type || 'image', file_size || 0, scale_mode, content_type, noise_level, sharpness);
  if (user.plan === 'free') db.prepare('UPDATE users SET credits=credits-1 WHERE id=?').run(req.user.id);
  setTimeout(() => {
    const m = scale_mode === '8x' ? 8 : scale_mode === '4x' ? 4 : 2;
    db.prepare("UPDATE jobs SET status='done',out_width=?,out_height=?,process_ms=?,updated_at=datetime('now') WHERE id=?").run(1920*m/2, 1080*m/2, Math.floor(Math.random()*700+300), jobId);
  }, 2000);
  res.status(201).json({ success: true, message: 'Job dibuat.', data: { jobId } });
});

router.get('/api-keys', requirePlan('pro','ultra'), (req, res) => {
  const keys = db.prepare('SELECT id,name,key_prefix,status,request_count,monthly_limit,last_used,created_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC').all(req.user.id);
  res.json({ success: true, data: { keys } });
});

router.post('/api-keys', requirePlan('pro','ultra'), v([body('name').trim().isLength({ min: 2, max: 60 }).withMessage('Nama key harus 2–60 karakter.')]), async (req, res) => {
  try {
    const count = db.prepare('SELECT COUNT(*) as c FROM api_keys WHERE user_id=? AND status="active"').get(req.user.id).c;
    const max   = req.user.plan === 'ultra' ? 10 : 3;
    if (count >= max) return res.status(400).json({ success: false, message: `Maksimal ${max} API key.` });
    const rawKey = 'px_live_' + crypto.randomBytes(32).toString('hex');
    const prefix = rawKey.slice(0, 15);
    const hashed = await bcrypt.hash(rawKey, 10);
    const keyId  = crypto.randomUUID();
    db.prepare('INSERT INTO api_keys (id,user_id,name,key_prefix,key_hash,monthly_limit) VALUES (?,?,?,?,?,?)').run(keyId, req.user.id, req.body.name, prefix, hashed, req.user.plan === 'ultra' ? 0 : 1000);
    res.status(201).json({ success: true, message: 'API key dibuat. Simpan sekarang!', data: { keyId, rawKey, prefix } });
  } catch (err) { res.status(500).json({ success: false, message: 'Gagal membuat key.' }); }
});

router.delete('/api-keys/:id', (req, res) => {
  const key = db.prepare('SELECT id FROM api_keys WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!key) return res.status(404).json({ success: false, message: 'Key tidak ditemukan.' });
  db.prepare('DELETE FROM api_keys WHERE id=?').run(req.params.id);
  res.json({ success: true, message: 'API key dihapus.' });
});

module.exports = router;
