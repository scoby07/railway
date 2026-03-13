# PixelUp AI — Production Setup

## 🏗️ Struktur Proyek

```
pixelup-production/
├── backend/
│   ├── server.js                ← Entry point + semua security layers
│   ├── seed.js                  ← Inisialisasi admin pertama kali
│   ├── package.json
│   ├── .env.example             ← Template environment
│   ├── database/db.js           ← SQLite schema + security tables
│   ├── middleware/
│   │   ├── auth.js              ← JWT + token theft detection
│   │   ├── security.js          ← 12 security middleware layers
│   │   └── validate.js          ← Input validation rules
│   ├── routes/
│   │   ├── auth.js              ← Login + account lockout
│   │   ├── user.js              ← Profile, jobs, API keys
│   │   └── admin.js             ← Admin endpoints
│   └── utils/logger.js          ← Winston structured logger
└── frontend/
    └── index.html               ← Production frontend
```

---

## 🚀 Setup & Deploy

### 1. Prerequisites
- Node.js ≥ 18.0.0
- npm ≥ 9.0.0

### 2. Install Dependencies
```bash
cd backend
npm install
```

### 3. Generate Secrets
```bash
# JWT Access Secret (64 bytes)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# JWT Refresh Secret (64 bytes, berbeda dari access)
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# Encryption Key (32 bytes)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 4. Konfigurasi .env
```bash
cp .env.example .env
# Edit .env dengan nilai yang sudah digenerate
# JANGAN gunakan nilai default!
```

### 5. Buat Akun Admin
```bash
# Set password admin kuat di .env terlebih dahulu
# SEED_ADMIN_PASSWORD=YourStr0ng!Password@2025
node seed.js
# Setelah seed selesai, HAPUS SEED_ADMIN_PASSWORD dari .env
```

### 6. Jalankan Server
```bash
# Development
npm run dev

# Production (dengan PM2)
npm install -g pm2
pm2 start server.js --name pixelup-api
pm2 save
pm2 startup
```

---

## 🔒 Lapisan Keamanan

### Layer 1 — HTTP Headers (Helmet)
- `Strict-Transport-Security`: Force HTTPS, 1 tahun preload
- `Content-Security-Policy`: Blokir inline scripts, framing
- `X-Frame-Options: DENY`: Anti-clickjacking
- `X-Content-Type-Options: nosniff`: Anti-MIME sniffing
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy`: Batasi fitur browser
- `X-XSS-Protection: 1; mode=block`

### Layer 2 — CORS
- Whitelist origin eksplisit (tidak `*`)
- Preflight caching 24 jam
- Blokir request tanpa Origin header

### Layer 3 — HTTP Parameter Pollution (hpp)
- Cegah duplikasi parameter query (`?id=1&id=2`)

### Layer 4 — Request Size Limit
- Body maksimal 5MB
- Parameter limit 50 keys

### Layer 5 — IP Blocking
- Pengecekan IP blocklist di setiap request
- Auto-expire untuk blokir sementara
- Blokir permanen tersedia

### Layer 6 — User Agent Validation
- Tolak request tanpa User-Agent
- Deteksi dan blokir scanner: sqlmap, nikto, masscan, nmap, acunetix, burpsuite, dll.

### Layer 7 — Brute Force Detection
- Hitung failed attempts per IP dalam 15 menit
- Auto-block IP setelah 20 gagal dalam 15 menit
- Account lockout setelah 5 gagal (konfigurasi via .env)

### Layer 8 — SQL Injection Detection (bonus di atas parameterized queries)
- Pattern matching untuk UNION SELECT, DROP, EXEC, SLEEP, BENCHMARK, dll.
- Auto-block IP yang mencoba SQL injection selama 72 jam

### Layer 9 — XSS Detection
- Pattern matching untuk `<script>`, `javascript:`, event handlers, dll.
- Auto-block IP yang mencoba XSS selama 48 jam

### Layer 10 — Path Traversal Prevention
- Deteksi `../`, `%2e%2e/`, `%252e%252e/`
- Auto-block IP

### Layer 11 — Input Sanitization
- Strip karakter `<>` dari semua input
- Hapus null bytes
- Trim whitespace
- Batas panjang 10.000 karakter per field

### Layer 12 — Honeypot Fields
- Field tersembunyi `website`, `fax`, `company2`
- Bot yang mengisi field ini mendapat respons sukses palsu

### Rate Limiting
- Global: 100 req / 15 menit per IP
- Auth: 5 req / 15 menit per IP+email
- SlowDown: delay bertahap setelah 2 req login

### JWT Security
- Access token: 15 menit (sangat pendek)
- Refresh token: 7 hari (random bytes, bukan JWT)
- Token disimpan sebagai SHA-256 hash di database
- **Token Family Tracking**: Deteksi token theft
  - Jika token yang sudah dipakai digunakan lagi → semua token sesi direvoke
  - Paksa logout semua device
- Algoritma HS256 dengan secret 64 bytes

### Password Security
- Bcrypt 12 rounds (konfigurasi via `BCRYPT_ROUNDS`)
- Minimum 8 karakter
- Wajib: huruf kapital, kecil, angka, karakter khusus
- Tidak boleh mengandung nama atau email user
- Tidak boleh sama dengan password lama

### Audit Logging
- Setiap aksi admin dicatat dengan: admin_id, action, target, old_values, new_values, IP, User-Agent
- Security events disimpan 90 hari
- Log file dirotasi harian, disimpan 30-90 hari
- Tiga file log terpisah: app, error, security

---

## 🔑 Credentials (Hanya setelah seed)

| Role        | Email (default)       | Password               |
|-------------|------------------------|------------------------|
| Super Admin | admin@pixelup.ai       | Sesuai SEED_ADMIN_PASSWORD |

> **Tidak ada credentials demo hardcoded di kode.** Password ditentukan via `.env` sebelum seed.

---

## 🛡️ Checklist Production

- [ ] Generate secrets baru (bukan nilai default)
- [ ] Set `NODE_ENV=production`
- [ ] Set `CORS_ORIGIN` ke domain frontend
- [ ] Gunakan HTTPS (reverse proxy: Nginx + Let's Encrypt)
- [ ] Hapus `SEED_ADMIN_PASSWORD` dari `.env` setelah seed
- [ ] Backup database secara rutin
- [ ] Monitor file `logs/security-*.log`
- [ ] Setup PM2 untuk auto-restart
- [ ] Aktifkan firewall (blokir semua kecuali 443 dan 22)
- [ ] Set up fail2ban sebagai layer tambahan

---

## 🌐 Nginx Config (contoh)

```nginx
server {
    listen 443 ssl http2;
    server_name api.pixelup.ai;

    ssl_certificate     /etc/letsencrypt/live/pixelup.ai/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pixelup.ai/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload";

    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
        client_max_body_size 210m;
    }
}
```
