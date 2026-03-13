// seed.js — Setup admin (Railway-compatible, auto-skip jika sudah ada)

require('dotenv').config();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('./database/db');

// Validasi env
if (!process.env.SEED_ADMIN_EMAIL || !process.env.SEED_ADMIN_PASSWORD) {
  console.error('\n❌ Set SEED_ADMIN_EMAIL dan SEED_ADMIN_PASSWORD di .env terlebih dahulu.\n');
  process.exit(1);
}

const email    = process.env.SEED_ADMIN_EMAIL.toLowerCase();
const password = process.env.SEED_ADMIN_PASSWORD;
const name     = process.env.SEED_ADMIN_NAME || 'Super Admin';

// Validasi kekuatan password admin
const strongPwd = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{12,}$/;
if (!strongPwd.test(password)) {
  console.error('\n❌ Password admin harus minimal 12 karakter, mengandung huruf besar, kecil, angka, dan karakter khusus (!@#$%^&*).\n');
  process.exit(1);
}

async function seed() {
  console.log('\n🌱 Memulai seed...\n');

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (existing) {
    console.log(`ℹ️  Admin (${email}) sudah ada. Seed dilewati.\n`);
    process.exit(0);
  }

  const rounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
  console.log(`🔐 Hashing password dengan ${rounds} bcrypt rounds...`);
  const hashed = await bcrypt.hash(password, rounds);
  const userId = crypto.randomUUID();

  db.prepare(`
    INSERT INTO users (id, name, email, password, role, plan, credits, email_verified)
    VALUES (?, ?, ?, ?, 'superadmin', 'ultra', 99999, 1)
  `).run(userId, name, email, hashed);

  db.prepare(`
    INSERT INTO subscriptions (id, user_id, plan, price_idr, payment_method)
    VALUES (?, ?, 'ultra', 299000, 'manual')
  `).run(crypto.randomUUID(), userId);

  console.log(`\n✅ Superadmin berhasil dibuat.`);
  console.log(`   ID    : ${userId}`);
  console.log(`   Email : ${email}`);
  console.log(`   Role  : superadmin\n`);
  console.log('⚠️  PENTING: Hapus SEED_ADMIN_PASSWORD dari .env setelah seed selesai!\n');
  console.log('─'.repeat(50));
  console.log('🎉 Seed selesai. Jalankan: npm start\n');
}

seed().catch(err => { console.error('❌ Seed gagal:', err.message); process.exit(1); });
