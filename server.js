const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ============ CONFIG ============
// Persistent storage paths (override via env on Railway with mounted volume)
const DATA_DIR    = process.env.DATA_DIR    || path.join(__dirname, 'data');
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(DATA_DIR, 'uploads');
const BACKUP_DIR  = path.join(DATA_DIR, 'backups');

// Admin password — MUST be overridden via env on production
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const SESSION_TTL    = 24 * 60 * 60 * 1000; // 24h
const COOKIE_NAME    = 'cf_session';

// Ensure dirs
[DATA_DIR, UPLOADS_DIR, BACKUP_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// One-time migration: copy old ./data into DATA_DIR if DATA_DIR is empty
const legacyData = path.join(__dirname, 'data');
if (legacyData !== DATA_DIR && fs.existsSync(legacyData)) {
  ['settings.json', 'orders.json'].forEach(f => {
    const src = path.join(legacyData, f);
    const dst = path.join(DATA_DIR, f);
    if (fs.existsSync(src) && !fs.existsSync(dst)) {
      fs.copyFileSync(src, dst);
      console.log(`📦 Migrated ${f} → ${DATA_DIR}`);
    }
  });
}

// ============ MIDDLEWARE ============
app.set('trust proxy', 1); // Railway sits behind a proxy
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static('public'));
app.use('/uploads', express.static(UPLOADS_DIR));

// Rate limits
const writeLimiter = rateLimit({
  windowMs: 60 * 1000, max: 60,
  message: { error: 'الحد الأقصى للطلبات تم تجاوزه، حاول بعد دقيقة' },
  standardHeaders: true, legacyHeaders: false,
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 8,
  message: { error: 'محاولات دخول كتيرة، حاول بعد 15 دقيقة' },
  standardHeaders: true, legacyHeaders: false,
});

// ============ AUTH ============
const sessions = new Map(); // token -> expiresAt
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');

// Hash & verify (scrypt is built-in, no deps)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  // Constant-time comparison
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(test, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Get current password (from auth.json if exists, else hash the env var)
function getStoredPasswordHash() {
  if (fs.existsSync(AUTH_FILE)) {
    try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')).hash; }
    catch (e) { return null; }
  }
  return null;
}
function setStoredPasswordHash(newHash) {
  atomicWrite(AUTH_FILE, { hash: newHash, updatedAt: new Date().toISOString() });
}
function checkPassword(plain) {
  const stored = getStoredPasswordHash();
  if (stored) return verifyPassword(plain, stored);
  // First-time: compare against env var directly
  return plain === ADMIN_PASSWORD;
}

function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + SESSION_TTL);
  return token;
}
function isValidSession(token) {
  if (!token) return false;
  const exp = sessions.get(token);
  if (!exp) return false;
  if (exp < Date.now()) { sessions.delete(token); return false; }
  return true;
}
function requireAuth(req, res, next) {
  if (isValidSession(req.cookies[COOKIE_NAME])) return next();
  res.status(401).json({ error: 'غير مصرح', requireLogin: true });
}

// Cleanup expired sessions hourly
setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of sessions) if (exp < now) sessions.delete(t);
}, 60 * 60 * 1000);

// ============ INPUT SANITIZATION ============
function sanitizeStr(s, maxLen = 500) {
  if (typeof s !== 'string') return '';
  return s
    .replace(/<script[^>]*>.*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, '')               // strip HTML tags
    .replace(/javascript:/gi, '')           // strip js: protocol
    .slice(0, maxLen);
}
function sanitizeObj(obj, fields) {
  const out = {};
  for (const [k, max] of Object.entries(fields)) {
    if (obj[k] !== undefined) out[k] = sanitizeStr(obj[k], max);
  }
  return out;
}

// ============ FILE I/O (atomic + backup) ============
function backupFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  const name = path.basename(filePath);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dst = path.join(BACKUP_DIR, `${name}.${stamp}.bak`);
  try { fs.copyFileSync(filePath, dst); } catch (e) { console.error('Backup failed:', e.message); }
  // Keep only last 20 backups per file
  try {
    const all = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith(name + '.'))
      .sort();
    while (all.length > 20) {
      fs.unlinkSync(path.join(BACKUP_DIR, all.shift()));
    }
  } catch (e) {}
}
function atomicWrite(filePath, jsonData) {
  backupFile(filePath);
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(jsonData, null, 2));
  fs.renameSync(tmp, filePath);
}

// ============ SETTINGS ============
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const ORDERS_FILE   = path.join(DATA_DIR, 'orders.json');

const DEFAULT_SETTINGS = {
  factoryName: "مصنع الملابس",
  welcomeMessage: "مرحباً بكم في مصنعنا",
  welcomeSubMessage: "نصنع الجودة ونرتقي بالأناقة",
  logoUrl: "",
  contactPhone: "",
  contactEmail: "",
  contactAddress: "",
  contactWhatsapp: "",
  about: "نحن مصنع متخصص في صناعة الملابس بأعلى معايير الجودة",
  products: [
    { id: 1, name: "قمصان رجالية", description: "قمصان بأقمشة فاخرة وخياطة محكمة", image: "", category: "رجالي" },
    { id: 2, name: "فساتين نسائية", description: "تصميمات عصرية تجمع بين الأناقة والراحة", image: "", category: "نسائي" },
    { id: 3, name: "ملابس أطفال",   description: "ملابس ملونة وآمنة لأطفالنا الصغار",  image: "", category: "أطفال" }
  ],
  services: [
    { id: 1, title: "تصنيع بالجملة", icon: "🏭", desc: "إنتاج كميات كبيرة بأسعار تنافسية" },
    { id: 2, title: "تصميم مخصص",   icon: "✂️", desc: "تصميم حسب طلب العميل وذوقه" },
    { id: 3, title: "توصيل سريع",   icon: "🚚", desc: "نوصل لجميع أنحاء المملكة" }
  ],
  primaryColor: "#2c3e50",
  accentColor: "#e74c3c",
  heroBackground: "#1a1a2e",
  terms: [
    "يلتزم الطرف الأول (المصنع) بتسليم البضاعة في الموعد المحدد وبالمواصفات المتفق عليها.",
    "يلتزم الطرف الثاني (العميل) بسداد المبلغ المتبقي كاملاً عند استلام البضاعة.",
    "في حالة تأخر العميل عن استلام البضاعة أكثر من 7 أيام من الموعد، تُحتسب رسوم تخزين يومية.",
    "لا يحق للعميل إلغاء الطلب بعد بدء التصنيع، ويُعدّ المقدم المدفوع غير قابل للاسترداد.",
    "تعتبر المواصفات المثبتة في هذا العقد هي المرجع الوحيد في حالة أي نزاع.",
    "يُحكّم هذا العقد وفقاً لأحكام القانون المعمول به في جمهورية مصر العربية."
  ]
};

function loadSettings() {
  if (!fs.existsSync(SETTINGS_FILE)) {
    atomicWrite(SETTINGS_FILE, DEFAULT_SETTINGS);
    return DEFAULT_SETTINGS;
  }
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
  } catch (e) {
    console.error('Settings file corrupt, restoring defaults');
    atomicWrite(SETTINGS_FILE, DEFAULT_SETTINGS);
    return DEFAULT_SETTINGS;
  }
}
function saveSettings(data) {
  data.lastUpdated = Date.now();
  atomicWrite(SETTINGS_FILE, data);
}
function loadOrders() {
  if (!fs.existsSync(ORDERS_FILE)) { atomicWrite(ORDERS_FILE, []); return []; }
  try { return JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8')); }
  catch (e) { console.error('Orders file corrupt, restoring empty'); atomicWrite(ORDERS_FILE, []); return []; }
}
function saveOrders(orders) { atomicWrite(ORDERS_FILE, orders); }
function nextContractNumber(orders) {
  const year = new Date().getFullYear();
  const count = orders.filter(o => String(o.contractNumber || '').startsWith(String(year))).length + 1;
  return `${year}-${String(count).padStart(3, '0')}`;
}

// ============ MULTER ============
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().slice(0, 8);
    cb(null, Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(jpeg|jpg|png|gif|webp|svg\+xml)$/i.test(file.mimetype);
    cb(ok ? null : new Error('نوع الملف غير مدعوم'), ok);
  }
});

function deleteUploadedFile(urlPath) {
  if (!urlPath || !urlPath.startsWith('/uploads/')) return;
  const file = path.join(UPLOADS_DIR, path.basename(urlPath));
  if (fs.existsSync(file)) {
    try { fs.unlinkSync(file); } catch (e) {}
  }
}

// ============ AUTH ROUTES ============
app.post('/api/login', loginLimiter, (req, res) => {
  const { password } = req.body || {};
  if (typeof password !== 'string' || !checkPassword(password)) {
    return res.status(401).json({ error: 'كلمة سر خاطئة' });
  }
  const token = createSession();
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: SESSION_TTL,
  });
  res.json({ success: true });
});

// Change password (requires being logged in + correct old password)
app.post('/api/change-password', requireAuth, loginLimiter, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (typeof oldPassword !== 'string' || typeof newPassword !== 'string') {
    return res.status(400).json({ error: 'بيانات ناقصة' });
  }
  if (!checkPassword(oldPassword)) {
    return res.status(401).json({ error: 'كلمة السر القديمة غير صحيحة' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'كلمة السر الجديدة لازم تكون 8 أحرف على الأقل' });
  }
  if (newPassword.length > 128) {
    return res.status(400).json({ error: 'كلمة السر طويلة جداً' });
  }
  setStoredPasswordHash(hashPassword(newPassword));
  // Invalidate ALL existing sessions except the current one
  const currentToken = req.cookies[COOKIE_NAME];
  for (const t of sessions.keys()) if (t !== currentToken) sessions.delete(t);
  res.json({ success: true });
});

app.post('/api/logout', (req, res) => {
  const t = req.cookies[COOKIE_NAME];
  if (t) sessions.delete(t);
  res.clearCookie(COOKIE_NAME);
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  res.json({ authenticated: isValidSession(req.cookies[COOKIE_NAME]) });
});

// ============ PUBLIC API ============
app.get('/api/version', (req, res) => {
  res.json({ lastUpdated: loadSettings().lastUpdated || 0 });
});
app.get('/api/settings', (req, res) => res.json(loadSettings()));
app.get('/api/products', (req, res) => res.json(loadSettings().products));
app.get('/api/services', (req, res) => res.json(loadSettings().services));

// ============ PROTECTED API ============
const protect = [requireAuth, writeLimiter];

app.post('/api/settings', protect, (req, res) => {
  const settings = loadSettings();
  const stringFields = {
    factoryName: 100, welcomeMessage: 200, welcomeSubMessage: 200,
    contactPhone: 30, contactEmail: 100, contactAddress: 200, contactWhatsapp: 30,
    about: 2000, primaryColor: 20, accentColor: 20, heroBackground: 20,
  };
  Object.assign(settings, sanitizeObj(req.body, stringFields));
  if (Array.isArray(req.body.terms)) {
    settings.terms = req.body.terms.slice(0, 30).map(t => sanitizeStr(t, 500));
  }
  saveSettings(settings);
  res.json({ success: true, settings });
});

app.post('/api/upload-logo', protect, upload.single('logo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'لم يتم رفع أي ملف' });
  const settings = loadSettings();
  deleteUploadedFile(settings.logoUrl); // cleanup old logo
  settings.logoUrl = `/uploads/${req.file.filename}`;
  saveSettings(settings);
  res.json({ success: true, logoUrl: settings.logoUrl });
});

app.post('/api/upload-product-image', protect, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'لم يتم رفع أي ملف' });
  res.json({ success: true, imageUrl: `/uploads/${req.file.filename}` });
});

// PRODUCTS
app.post('/api/products', protect, (req, res) => {
  const settings = loadSettings();
  const newProduct = {
    id: Date.now(),
    name: sanitizeStr(req.body.name, 100) || 'منتج جديد',
    description: sanitizeStr(req.body.description, 500),
    image: sanitizeStr(req.body.image, 300),
    category: sanitizeStr(req.body.category, 50) || 'عام'
  };
  settings.products.push(newProduct);
  saveSettings(settings);
  res.json({ success: true, product: newProduct });
});
app.put('/api/products/:id', protect, (req, res) => {
  const settings = loadSettings();
  const idx = settings.products.findIndex(p => p.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'المنتج غير موجود' });
  const cleaned = sanitizeObj(req.body, { name: 100, description: 500, image: 300, category: 50 });
  settings.products[idx] = { ...settings.products[idx], ...cleaned, id: settings.products[idx].id };
  saveSettings(settings);
  res.json({ success: true, product: settings.products[idx] });
});
app.delete('/api/products/:id', protect, (req, res) => {
  const settings = loadSettings();
  const prod = settings.products.find(p => p.id == req.params.id);
  if (prod) deleteUploadedFile(prod.image);
  settings.products = settings.products.filter(p => p.id != req.params.id);
  saveSettings(settings);
  res.json({ success: true });
});

// SERVICES
app.post('/api/services', protect, (req, res) => {
  const settings = loadSettings();
  const newService = {
    id: Date.now(),
    title: sanitizeStr(req.body.title, 100) || 'خدمة جديدة',
    icon: sanitizeStr(req.body.icon, 10) || '⭐',
    desc: sanitizeStr(req.body.desc, 300)
  };
  settings.services.push(newService);
  saveSettings(settings);
  res.json({ success: true, service: newService });
});
app.put('/api/services/:id', protect, (req, res) => {
  const settings = loadSettings();
  const idx = settings.services.findIndex(s => s.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'الخدمة غير موجودة' });
  const cleaned = sanitizeObj(req.body, { title: 100, icon: 10, desc: 300 });
  settings.services[idx] = { ...settings.services[idx], ...cleaned, id: settings.services[idx].id };
  saveSettings(settings);
  res.json({ success: true });
});
app.delete('/api/services/:id', protect, (req, res) => {
  const settings = loadSettings();
  settings.services = settings.services.filter(s => s.id != req.params.id);
  saveSettings(settings);
  res.json({ success: true });
});

// ORDERS
app.get('/api/orders', requireAuth, (req, res) => res.json(loadOrders()));
app.get('/api/orders/:id', requireAuth, (req, res) => {
  const o = loadOrders().find(o => o.id == req.params.id);
  o ? res.json(o) : res.status(404).json({ error: 'غير موجود' });
});
app.post('/api/orders', protect, (req, res) => {
  const orders = loadOrders();
  const order = {
    id: Date.now(),
    contractNumber: nextContractNumber(orders),
    createdAt: new Date().toISOString(),
    status: 'pending',
    ...req.body
  };
  orders.unshift(order);
  saveOrders(orders);
  res.json({ success: true, order });
});
app.put('/api/orders/:id', protect, (req, res) => {
  const orders = loadOrders();
  const idx = orders.findIndex(o => o.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'غير موجود' });
  orders[idx] = { ...orders[idx], ...req.body, id: orders[idx].id, contractNumber: orders[idx].contractNumber };
  saveOrders(orders);
  res.json({ success: true, order: orders[idx] });
});
app.delete('/api/orders/:id', protect, (req, res) => {
  saveOrders(loadOrders().filter(o => o.id != req.params.id));
  res.json({ success: true });
});

// ============ PAGES ============
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/contract/:id', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'contract.html')));

// Generic error handler
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(err.status || 500).json({ error: err.message || 'خطأ داخلي' });
});

app.listen(PORT, () => {
  console.log(`\n✅ السيرفر شغال على: http://localhost:${PORT}`);
  console.log(`🔧 لوحة التحكم: http://localhost:${PORT}/admin`);
  console.log(`📁 DATA_DIR: ${DATA_DIR}`);
  console.log(`📷 UPLOADS_DIR: ${UPLOADS_DIR}`);
  if (ADMIN_PASSWORD === 'admin123') {
    console.log(`\n⚠️  تحذير: استخدم متغير البيئة ADMIN_PASSWORD لتغيير كلمة السر الافتراضية`);
  }
  console.log('');
});
