/**
 * InnerVoice API Server
 * Single-file Express backend with JSON file persistence.
 * Deploy to Railway / Render / any Node.js host.
 */

// Load .env if present (local dev)
try { require('fs').readFileSync('.env','utf8').split('\n').forEach(line=>{ const [k,...v]=line.split('='); if(k&&k.trim()&&!k.startsWith('#')) process.env[k.trim()]=v.join('=').trim(); }); } catch(e){}

const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const rateLimit = require('express-rate-limit');

const app  = express();
const PORT = process.env.PORT || 3001;

// Trust Render's proxy (required for rate limiting to work correctly)
app.set('trust proxy', 1);

// â”€â”€â”€ Admin password (set via env var in production) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const ADMIN_PASS = process.env.ADMIN_PASS || 'adminonly';

// â”€â”€â”€ DB file path (Railway/Render: use /tmp or a persistent volume) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'db.json');

// â”€â”€â”€ Middleware â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.use(express.json({ limit: '1mb' }));

// CORS â€” allow your Netlify domain + localhost for dev
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '*').split(',');
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Rate limiting â€” prevent brute-force on login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: 'Terlalu banyak percobaan login. Coba lagi setelah 15 menit.' }
});
const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  message: { error: 'Terlalu banyak permintaan. Coba lagi nanti.' }
});
app.use('/api/', apiLimiter);

// â”€â”€â”€ DB helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function readDB() {
  try {
    if (!fs.existsSync(DB_PATH)) return { users: {}, stories: [] };
    return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
  } catch (e) {
    console.error('DB read error:', e.message);
    return { users: {}, stories: [] };
  }
}

function writeDB(db) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
  } catch (e) {
    console.error('DB write error:', e.message);
  }
}

// Seed initial users if DB is empty
function seedIfEmpty() {
  const db = readDB();
  if (Object.keys(db.users).length === 0) {
    // Import seed from seed-users.js
    try {
      const seed = require('./seed-users.js');
      db.users = seed;
      writeDB(db);
      console.log(`Seeded ${Object.keys(seed).length} users.`);
    } catch (e) {
      console.log('No seed file found, starting with empty user list.');
    }
  }
}
seedIfEmpty();

// â”€â”€â”€ Auth helper â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Simple btoa equivalent for Node.js
function encodePass(plain) {
  return Buffer.from(plain).toString('base64');
}
function decodePass(encoded) {
  return Buffer.from(encoded, 'base64').toString('utf8');
}

// â”€â”€â”€ Middleware: verify admin token â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function requireAdmin(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '');
  const db = readDB();
  const storedPass = db.meta && db.meta.adminPass ? db.meta.adminPass : encodePass(ADMIN_PASS);
  if (token !== storedPass) {
    return res.status(401).json({ error: 'Akses ditolak.' });
  }
  next();
}

// â”€â”€â”€ Middleware: verify user session token â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function requireUser(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Tidak terautentikasi.' });
  try {
    // token = base64(NIK:password_hash)
    const decoded = Buffer.from(token, 'base64').toString('utf8');
    const colonIdx = decoded.indexOf(':');
    if (colonIdx === -1) throw new Error('bad token');
    const nik = decoded.substring(0, colonIdx);
    const passHash = decoded.substring(colonIdx + 1);
    const db = readDB();
    const user = db.users[nik];
    if (!user || user.active === false || user.password !== passHash) {
      return res.status(401).json({ error: 'Sesi tidak valid. Silakan login ulang.' });
    }
    req.currentUser = { id: nik, ...user };
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Token tidak valid.' });
  }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// ROUTES
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

// Health check
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

// â”€â”€â”€ POST /api/login â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Body: { nik, password }
// Returns: { token, user } or { firstLogin: true } if no password set yet
app.post('/api/login', loginLimiter, (req, res) => {
  const { nik, password } = req.body || {};
  if (!nik) return res.status(400).json({ error: 'NIK wajib diisi.' });

  const db = readDB();
  const user = db.users[String(nik).trim().toUpperCase()];
  if (!user || user.active === false) {
    return res.status(404).json({ error: 'NIK tidak ditemukan atau akses telah dicabut.' });
  }

  // First login â€” no password set
  if (!user.password) {
    return res.json({ firstLogin: true, name: user.name });
  }

  if (!password) return res.status(400).json({ error: 'Kata sandi wajib diisi.' });

  if (user.password !== encodePass(password)) {
    return res.status(401).json({ error: 'Kata sandi salah.' });
  }

  // Build session token: base64(NIK:passwordHash)
  const token = Buffer.from(`${String(nik).trim().toUpperCase()}:${user.password}`).toString('base64');
  res.json({
    token,
    user: {
      id: String(nik).trim().toUpperCase(),
      name: user.name,
      position: user.position,
      store: user.store,
    }
  });
});

// â”€â”€â”€ POST /api/set-password â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Body: { nik, password } â€” for first-time login
app.post('/api/set-password', loginLimiter, (req, res) => {
  const { nik, password } = req.body || {};
  if (!nik || !password) return res.status(400).json({ error: 'NIK dan kata sandi wajib diisi.' });
  if (password.length < 4) return res.status(400).json({ error: 'Kata sandi minimal 4 karakter.' });

  const nikUpper = String(nik).trim().toUpperCase();
  const db = readDB();
  const user = db.users[nikUpper];
  if (!user || user.active === false) return res.status(404).json({ error: 'NIK tidak ditemukan.' });
  if (user.password) return res.status(400).json({ error: 'Kata sandi sudah diatur. Gunakan fitur ubah kata sandi.' });

  user.password = encodePass(password);
  writeDB(db);

  const token = Buffer.from(`${nikUpper}:${user.password}`).toString('base64');
  res.json({
    token,
    user: { id: nikUpper, name: user.name, position: user.position, store: user.store }
  });
});

// â”€â”€â”€ PUT /api/change-password â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Requires user auth. Body: { oldPassword, newPassword }
app.put('/api/change-password', requireUser, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Isi semua field.' });
  if (newPassword.length < 4) return res.status(400).json({ error: 'Kata sandi minimal 4 karakter.' });

  const db = readDB();
  const user = db.users[req.currentUser.id];
  if (user.password !== encodePass(oldPassword)) {
    return res.status(401).json({ error: 'Kata sandi lama tidak sesuai.' });
  }

  user.password = encodePass(newPassword);
  writeDB(db);

  const newToken = Buffer.from(`${req.currentUser.id}:${user.password}`).toString('base64');
  res.json({ token: newToken });
});

// â”€â”€â”€ GET /api/stories/mine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/stories/mine', requireUser, (req, res) => {
  const db = readDB();
  const mine = db.stories.filter(s => s.userId === req.currentUser.id);
  res.json(mine);
});

// â”€â”€â”€ POST /api/stories â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/stories', requireUser, (req, res) => {
  const { category, categoryIcon, text } = req.body || {};
  if (!category || !text || !text.trim()) {
    return res.status(400).json({ error: 'Kategori dan cerita wajib diisi.' });
  }
  if (text.trim().length > 2000) {
    return res.status(400).json({ error: 'Cerita maksimal 2000 karakter.' });
  }

  const db = readDB();
  const ticket = 'IV-' + Date.now().toString(36).toUpperCase();
  const story = {
    id: ticket,
    userId: req.currentUser.id,
    userNama: req.currentUser.name,
    userPosisi: req.currentUser.position,
    userToko: req.currentUser.store,
    category,
    categoryIcon: categoryIcon || '',
    text: text.trim(),
    time: new Date().toISOString(),
    reviewed: false,
  };
  db.stories.unshift(story);
  writeDB(db);
  res.json({ id: ticket });
});

// â”€â”€â”€ ADMIN: GET /api/admin/stories â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/admin/stories', requireAdmin, (req, res) => {
  const db = readDB();
  res.json(db.stories);
});

// â”€â”€â”€ ADMIN: PUT /api/admin/stories/:id/reviewed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.put('/api/admin/stories/:id/reviewed', requireAdmin, (req, res) => {
  const db = readDB();
  const s = db.stories.find(x => x.id === req.params.id);
  if (!s) return res.status(404).json({ error: 'Cerita tidak ditemukan.' });
  s.reviewed = true;
  writeDB(db);
  res.json({ ok: true });
});

// â”€â”€â”€ ADMIN: DELETE /api/admin/stories/:id â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.delete('/api/admin/stories/:id', requireAdmin, (req, res) => {
  const db = readDB();
  const before = db.stories.length;
  db.stories = db.stories.filter(x => x.id !== req.params.id);
  if (db.stories.length === before) return res.status(404).json({ error: 'Cerita tidak ditemukan.' });
  writeDB(db);
  res.json({ ok: true });
});

// â”€â”€â”€ ADMIN: GET /api/admin/users â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const db = readDB();
  // Never send passwords to client
  const safe = Object.entries(db.users).map(([id, u]) => ({
    id, name: u.name, position: u.position, store: u.store,
    active: u.active !== false,
    hasPassword: !!u.password,
  }));
  res.json(safe);
});

// â”€â”€â”€ ADMIN: POST /api/admin/users â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { id, name, position, store, password } = req.body || {};
  if (!id || !name) return res.status(400).json({ error: 'NIK dan Nama wajib diisi.' });
  const nik = String(id).trim().toUpperCase();
  const db = readDB();
  if (db.users[nik]) return res.status(409).json({ error: 'NIK sudah terdaftar.' });
  db.users[nik] = {
    name: name.trim(),
    position: (position || '').trim(),
    store: (store || '').trim(),
    password: password ? encodePass(password) : null,
    active: true,
  };
  writeDB(db);
  res.json({ ok: true, id: nik });
});

// â”€â”€â”€ ADMIN: PUT /api/admin/users/:id â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.put('/api/admin/users/:id', requireAdmin, (req, res) => {
  const oldId = req.params.id;
  const { id: newId, name, position, store, password } = req.body || {};
  const db = readDB();
  if (!db.users[oldId]) return res.status(404).json({ error: 'Pengguna tidak ditemukan.' });
  const finalId = newId ? String(newId).trim().toUpperCase() : oldId;
  if (finalId !== oldId && db.users[finalId]) {
    return res.status(409).json({ error: 'NIK baru sudah terdaftar.' });
  }
  const u = db.users[oldId];
  if (finalId !== oldId) { db.users[finalId] = u; delete db.users[oldId]; }
  db.users[finalId].name = (name || u.name).trim();
  db.users[finalId].position = (position !== undefined ? position : u.position || '').trim();
  db.users[finalId].store = (store !== undefined ? store : u.store || '').trim();
  if (password) db.users[finalId].password = encodePass(password);
  writeDB(db);
  res.json({ ok: true });
});

// â”€â”€â”€ ADMIN: PUT /api/admin/users/:id/toggle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.put('/api/admin/users/:id/toggle', requireAdmin, (req, res) => {
  const db = readDB();
  const u = db.users[req.params.id];
  if (!u) return res.status(404).json({ error: 'Pengguna tidak ditemukan.' });
  u.active = !(u.active !== false);
  writeDB(db);
  res.json({ ok: true, active: u.active });
});

// â”€â”€â”€ ADMIN: PUT /api/admin/users/:id/reset-password â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.put('/api/admin/users/:id/reset-password', requireAdmin, (req, res) => {
  const db = readDB();
  const u = db.users[req.params.id];
  if (!u) return res.status(404).json({ error: 'Pengguna tidak ditemukan.' });
  u.password = null;
  writeDB(db);
  res.json({ ok: true });
});

// â”€â”€â”€ ADMIN: DELETE /api/admin/users/:id â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const db = readDB();
  if (!db.users[req.params.id]) return res.status(404).json({ error: 'Pengguna tidak ditemukan.' });
  delete db.users[req.params.id];
  writeDB(db);
  res.json({ ok: true });
});

// â”€â”€â”€ ADMIN: POST /api/admin/users/import â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.post('/api/admin/users/import', requireAdmin, (req, res) => {
  const { users } = req.body || {};
  if (!Array.isArray(users)) return res.status(400).json({ error: 'Format tidak valid.' });
  const db = readDB();
  let added = 0, skipped = 0;
  users.forEach(u => {
    const nik = String(u.id || u.nik || '').trim().toUpperCase();
    const name = String(u.name || u.nama || '').trim();
    if (!nik || !name) return;
    if (db.users[nik]) { skipped++; return; }
    db.users[nik] = { name, position: (u.position || u.posisi || '').trim(), store: (u.store || u.toko || '').trim(), password: null, active: true };
    added++;
  });
  writeDB(db);
  res.json({ added, skipped });
});

// â”€â”€â”€ ADMIN: Change admin password â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.put('/api/admin/change-password', requireAdmin, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Semua field wajib diisi.' });
  if (newPassword.length < 4) return res.status(400).json({ error: 'Password minimal 4 karakter.' });
  if (encodePass(oldPassword) !== encodePass(ADMIN_PASS) && oldPassword !== ADMIN_PASS) {
    return res.status(401).json({ error: 'Password admin saat ini salah.' });
  }
  // Store new admin password in DB meta so it persists across deploys
  const db = readDB();
  if (!db.meta) db.meta = {};
  db.meta.adminPass = encodePass(newPassword);
  writeDB(db);
  // Update in-memory ADMIN_PASS for current session
  process.env.ADMIN_PASS = newPassword;
  res.json({ ok: true });
});

// â”€â”€â”€ ADMIN: Database (Toko & Posisi) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// DB stores a `meta` object: { toko: [...], posisi: [...] }

app.get('/api/admin/database', requireAdmin, (req, res) => {
  const db = readDB();
  res.json(db.meta || { toko: [], posisi: [] });
});

app.post('/api/admin/database', requireAdmin, (req, res) => {
  const { type, value } = req.body || {};
  if (!type || !value) return res.status(400).json({ error: 'type dan value wajib diisi.' });
  if (!['toko','posisi'].includes(type)) return res.status(400).json({ error: 'type tidak valid.' });
  const db = readDB();
  if (!db.meta) db.meta = { toko: [], posisi: [] };
  if (!db.meta[type]) db.meta[type] = [];
  if (db.meta[type].includes(value)) return res.status(409).json({ error: 'Sudah ada di database.' });
  db.meta[type].push(value);
  db.meta[type].sort();
  writeDB(db);
  res.json({ ok: true });
});

app.put('/api/admin/database', requireAdmin, (req, res) => {
  const { type, oldValue, newValue } = req.body || {};
  if (!type || !oldValue || !newValue) return res.status(400).json({ error: 'Semua field wajib diisi.' });
  if (!['toko','posisi'].includes(type)) return res.status(400).json({ error: 'type tidak valid.' });
  const db = readDB();
  if (!db.meta) db.meta = { toko: [], posisi: [] };
  // Update meta list
  if (db.meta[type]) {
    db.meta[type] = db.meta[type].filter(v => v !== oldValue);
    if (!db.meta[type].includes(newValue)) db.meta[type].push(newValue);
    db.meta[type].sort();
  }
  // Update all users that use this value
  const field = type === 'toko' ? 'store' : 'position';
  Object.values(db.users).forEach(u => {
    if ((u[field] || '').trim() === oldValue) u[field] = newValue;
  });
  writeDB(db);
  res.json({ ok: true });
});

app.delete('/api/admin/database', requireAdmin, (req, res) => {
  const { type, value } = req.body || {};
  if (!type || !value) return res.status(400).json({ error: 'type dan value wajib diisi.' });
  if (!['toko','posisi'].includes(type)) return res.status(400).json({ error: 'type tidak valid.' });
  const db = readDB();
  if (!db.meta) db.meta = { toko: [], posisi: [] };
  if (db.meta[type]) db.meta[type] = db.meta[type].filter(v => v !== value);
  // Clear from users
  const field = type === 'toko' ? 'store' : 'position';
  Object.values(db.users).forEach(u => {
    if ((u[field] || '').trim() === value) u[field] = '';
  });
  writeDB(db);
  res.json({ ok: true });
});

// â”€â”€â”€ Serve frontend â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const FRONTEND = path.join(__dirname, 'index.html');
app.get('/', (req, res) => {
  if (fs.existsSync(FRONTEND)) res.sendFile(FRONTEND);
  else res.json({ ok: true, message: 'InnerVoice API is running.' });
});

// â”€â”€â”€ Start server â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app.listen(PORT, () => {
  console.log(`InnerVoice API running on port ${PORT}`);
  console.log(`DB path: ${DB_PATH}`);
});

// updated 2026-06-20 13:31