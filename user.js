// routes/user.js — User endpoints produksi

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../database/db');
const { authenticate, requirePlan } = require('../middleware/auth');
const { updateProfileRules, createJobRules, createApiKeyRules, uuidParamRules, paginationRules } = require('../middleware/validate');
const logger = require('../utils/logger');

router.use(authenticate);

// ── GET /api/user/profile ─────────────────────────────────────────────────────
router.get('/profile', (req, res) => {
  const user = db.prepare(`
    SELECT id, name, email, role, plan, credits, status, created_at, last_login
    FROM users WHERE id = ?
  `).get(req.user.id);

  const sub = db.prepare('SELECT * FROM subscriptions WHERE user_id = ?').get(req.user.id);
  const jobStats = db.prepare(`
    SELECT COUNT(*) as total,
           SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) as done,
           SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed
    FROM jobs WHERE user_id = ?
  `).get(req.user.id);

  res.json({ success: true, data: { user, subscription: sub, jobStats } });
});

// ── PATCH /api/user/profile ───────────────────────────────────────────────────
router.patch('/profile', updateProfileRules, (req, res) => {
  const { name } = req.body;
  db.prepare("UPDATE users SET name = ?, updated_at = datetime('now') WHERE id = ?").run(name, req.user.id);
  res.json({ success: true, message: 'Profil berhasil diperbarui.' });
});

// ── GET /api/user/jobs ────────────────────────────────────────────────────────
router.get('/jobs', paginationRules, (req, res) => {
  const { page = 1, limit = 10, status } = req.query;
  const offset = (page - 1) * limit;
  const where = status ? 'AND status = ?' : '';
  const params = status ? [req.user.id, status] : [req.user.id];

  const jobs = db.prepare(`
    SELECT id, original_name, file_type, file_size, status, scale_mode,
           content_type, orig_width, orig_height, out_width, out_height,
           process_ms, error_msg, created_at
    FROM jobs WHERE user_id = ? ${where}
    ORDER BY created_at DESC LIMIT ? OFFSET ?
  `).all(...params, Number(limit), Number(offset));

  const total = db.prepare(`SELECT COUNT(*) as c FROM jobs WHERE user_id = ? ${where}`).get(...params).c;
  res.json({ success: true, data: { jobs, total } });
});

// ── GET /api/user/jobs/:id ────────────────────────────────────────────────────
router.get('/jobs/:id', uuidParamRules, (req, res) => {
  const job = db.prepare('SELECT * FROM jobs WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!job) return res.status(404).json({ success: false, message: 'Job tidak ditemukan.' });
  res.json({ success: true, data: { job } });
});

// ── POST /api/user/jobs ───────────────────────────────────────────────────────
router.post('/jobs', createJobRules, (req, res) => {
  const user = db.prepare('SELECT credits, plan FROM users WHERE id = ?').get(req.user.id);
  const { scale_mode, content_type, noise_level, sharpness, filename, file_type, file_size } = req.body;

  if (user.plan === 'free' && user.credits <= 0)
    return res.status(403).json({ success: false, message: 'Kredit habis. Upgrade ke Pro.', code: 'NO_CREDITS' });

  if (scale_mode === '8x' && !['ultra'].includes(user.plan))
    return res.status(403).json({ success: false, message: 'Upscale 8× memerlukan paket Ultra.', code: 'UPGRADE_REQUIRED' });

  if (scale_mode === '4x' && user.plan === 'free')
    return res.status(403).json({ success: false, message: 'Upscale 4× memerlukan paket Pro atau Ultra.', code: 'UPGRADE_REQUIRED' });

  const jobId = crypto.randomUUID();

  db.prepare(`
    INSERT INTO jobs (id, user_id, filename, original_name, file_type, file_size, status, scale_mode, content_type, noise_level, sharpness)
    VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)
  `).run(jobId, req.user.id, `upload_${jobId}`, filename || 'unknown', file_type || 'image', file_size || 0, scale_mode, content_type, noise_level, sharpness);

  if (user.plan === 'free')
    db.prepare('UPDATE users SET credits = credits - 1 WHERE id = ?').run(req.user.id);

  // Simulasi proses (production: gunakan Bull/BullMQ queue)
  setTimeout(() => {
    const mult = scale_mode === '8x' ? 8 : scale_mode === '4x' ? 4 : 2;
    db.prepare(`
      UPDATE jobs SET status='done', out_width=?, out_height=?, process_ms=?, updated_at=datetime('now') WHERE id=?
    `).run(1920 * mult / 2, 1080 * mult / 2, Math.floor(Math.random() * 700 + 300), jobId);
  }, 2000);

  res.status(201).json({ success: true, message: 'Job ditambahkan ke antrian.', data: { jobId } });
});

// ── GET /api/user/api-keys ────────────────────────────────────────────────────
router.get('/api-keys', requirePlan('pro', 'ultra'), (req, res) => {
  const keys = db.prepare(`
    SELECT id, name, key_prefix, status, request_count, monthly_limit, last_used, created_at
    FROM api_keys WHERE user_id = ? ORDER BY created_at DESC
  `).all(req.user.id);
  res.json({ success: true, data: { keys } });
});

// ── POST /api/user/api-keys ───────────────────────────────────────────────────
router.post('/api-keys', requirePlan('pro', 'ultra'), createApiKeyRules, async (req, res) => {
  try {
    const { name } = req.body;
    const count = db.prepare('SELECT COUNT(*) as c FROM api_keys WHERE user_id = ? AND status="active"').get(req.user.id).c;
    const max = req.user.plan === 'ultra' ? 10 : 3;
    if (count >= max)
      return res.status(400).json({ success: false, message: `Maksimal ${max} API key untuk paket Anda.` });

    // Generate cryptographically secure key
    const rawKey = 'px_live_' + crypto.randomBytes(32).toString('hex');
    const prefix = rawKey.slice(0, 15);
    const hashed = await bcrypt.hash(rawKey, 10);
    const keyId = crypto.randomUUID();

    db.prepare(`
      INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, monthly_limit) VALUES (?, ?, ?, ?, ?, ?)
    `).run(keyId, req.user.id, name, prefix, hashed, req.user.plan === 'ultra' ? 0 : 1000);

    res.status(201).json({
      success: true,
      message: 'API key berhasil dibuat. Simpan key ini sekarang, tidak dapat dilihat lagi!',
      data: { keyId, rawKey, prefix }
    });
  } catch (err) {
    logger.error('Create API key', { error: err.message });
    res.status(500).json({ success: false, message: 'Gagal membuat API key.' });
  }
});

// ── DELETE /api/user/api-keys/:id ─────────────────────────────────────────────
router.delete('/api-keys/:id', uuidParamRules, (req, res) => {
  const key = db.prepare('SELECT id FROM api_keys WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!key) return res.status(404).json({ success: false, message: 'Key tidak ditemukan.' });
  db.prepare('DELETE FROM api_keys WHERE id = ?').run(req.params.id);
  res.json({ success: true, message: 'API key dihapus.' });
});

module.exports = router;
