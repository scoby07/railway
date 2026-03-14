// seed.js — Buat superadmin (aman dijalankan berkali-kali)

require('dotenv').config();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db     = require('./db');  // <── flat

async function seed() {
  // Jika sudah ada superadmin, skip
  const existing = db.prepare("SELECT id FROM users WHERE role='superadmin' LIMIT 1").get();
  if (existing) {
    console.log('[SEED] Superadmin sudah ada. Skip.');
    return;
  }

  const email    = (process.env.SEED_ADMIN_EMAIL || '').toLowerCase().trim();
  const password = process.env.SEED_ADMIN_PASSWORD || '';
  const name     = process.env.SEED_ADMIN_NAME || 'Administrator';

  if (!email || !password) {
    console.log('[SEED] SEED_ADMIN_EMAIL/PASSWORD tidak diset. Skip.');
    console.log('[SEED] Set di Railway Variables lalu redeploy untuk membuat admin.');
    return;
  }

  if (password.length < 12) {
    console.error('[SEED] ❌ SEED_ADMIN_PASSWORD minimal 12 karakter!');
    process.exit(1);
  }

  console.log('[SEED] Membuat superadmin:', email);
  const hashed = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12);
  const uid    = crypto.randomUUID();

  db.prepare("INSERT INTO users (id,name,email,password,role,plan,credits,email_verified) VALUES (?,?,?,?,'superadmin','ultra',99999,1)").run(uid, name, email, hashed);
  db.prepare("INSERT OR IGNORE INTO subscriptions (id,user_id,plan,price_idr,payment_method) VALUES (?,?,'ultra',299000,'manual')").run(crypto.randomUUID(), uid);

  console.log('[SEED] ✅ Superadmin berhasil dibuat:', email);
  console.log('[SEED] ⚠️  Hapus SEED_ADMIN_PASSWORD dari Railway Variables setelah login!');
}

seed().catch(err => { console.error('[SEED] Error:', err.message); });
