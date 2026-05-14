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
const DATA_DIR    = process.env.DATA_DIR    || path.join(__dirname, 'data');
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(DATA_DIR, 'uploads');
const BACKUP_DIR  = path.join(DATA_DIR, 'backups');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const SESSION_TTL    = 24 * 60 * 60 * 1000;
const COOKIE_NAME    = 'cf_session';

// ============ MONGODB ============
let useDB = false;
let mongo = null;

async function connectMongo() {
  const uri = process.env.MONGODB_URI;
  if (!uri) return;
  try {
    const { MongoClient } = require('mongodb');
    const client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
    await client.connect();
    mongo = client.db();
    useDB = true;
    console.log('✅ MongoDB متصل بنجاح');
  } catch (e) {
    console.error('⚠️ فشل MongoDB، سيتم استخدام الملفات:', e.message);
  }
}

// ============ FILE DIRS ============
function ensureDirs() {
  [DATA_DIR, UPLOADS_DIR, BACKUP_DIR].forEach(d => {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  });
}

// One-time migration: copy old ./data into DATA_DIR if DATA_DIR is different
function migrateFiles() {
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
}

// ============ MIDDLEWARE ============
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));

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

// ============ AUTH (sessions in-memory) ============
const sessions = new Map();

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex'), b = Buffer.from(test, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
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

setInterval(() => {
  const now = Date.now();
  for (const [t, exp] of sessions) if (exp < now) sessions.delete(t);
}, 60 * 60 * 1000);

// ============ INPUT SANITIZATION ============
function sanitizeStr(s, maxLen = 500) {
  if (typeof s !== 'string') return '';
  return s
    .replace(/<script[^>]*>.*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, '')
    .replace(/javascript:/gi, '')
    .slice(0, maxLen);
}
function sanitizeObj(obj, fields) {
  const out = {};
  for (const [k, max] of Object.entries(fields)) {
    if (obj[k] !== undefined) out[k] = sanitizeStr(obj[k], max);
  }
  return out;
}

// ============ FILE I/O (file mode only) ============
function backupFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  const name = path.basename(filePath);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dst = path.join(BACKUP_DIR, `${name}.${stamp}.bak`);
  try { fs.copyFileSync(filePath, dst); } catch (e) { console.error('Backup failed:', e.message); }
  try {
    const all = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith(name + '.')).sort();
    while (all.length > 20) fs.unlinkSync(path.join(BACKUP_DIR, all.shift()));
  } catch (e) {}
}
function atomicWrite(filePath, jsonData) {
  backupFile(filePath);
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(jsonData, null, 2));
  fs.renameSync(tmp, filePath);
}

// ============ DEFAULT SETTINGS ============
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const ORDERS_FILE   = path.join(DATA_DIR, 'orders.json');
const AUTH_FILE     = path.join(DATA_DIR, 'auth.json');

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

// ============ DATA LAYER ============

// --- Settings ---
async function loadSettings() {
  if (useDB) {
    const doc = await mongo.collection('settings').findOne({});
    if (!doc) { await saveSettings({ ...DEFAULT_SETTINGS }); return { ...DEFAULT_SETTINGS }; }
    const { _id, ...rest } = doc;
    for (const k of Object.keys(DEFAULT_SETTINGS)) {
      if (rest[k] === undefined) rest[k] = DEFAULT_SETTINGS[k];
    }
    return rest;
  }
  if (!fs.existsSync(SETTINGS_FILE)) { atomicWrite(SETTINGS_FILE, DEFAULT_SETTINGS); return { ...DEFAULT_SETTINGS }; }
  try {
    const s = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    for (const k of Object.keys(DEFAULT_SETTINGS)) {
      if (s[k] === undefined) s[k] = DEFAULT_SETTINGS[k];
    }
    return s;
  } catch (e) {
    console.error('Settings file corrupt, restoring defaults');
    atomicWrite(SETTINGS_FILE, DEFAULT_SETTINGS);
    return { ...DEFAULT_SETTINGS };
  }
}

async function saveSettings(data) {
  data.lastUpdated = Date.now();
  if (useDB) {
    const { _id, ...toSave } = data;
    await mongo.collection('settings').replaceOne({}, toSave, { upsert: true });
    return;
  }
  atomicWrite(SETTINGS_FILE, data);
}

// --- Orders ---
async function loadOrders() {
  if (useDB) {
    const docs = await mongo.collection('orders').find({}).sort({ createdAt: -1 }).toArray();
    return docs.map(({ _id, ...rest }) => rest);
  }
  if (!fs.existsSync(ORDERS_FILE)) { atomicWrite(ORDERS_FILE, []); return []; }
  try { return JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8')); }
  catch (e) { console.error('Orders file corrupt'); atomicWrite(ORDERS_FILE, []); return []; }
}

async function saveOrders(orders) {
  if (useDB) {
    const col = mongo.collection('orders');
    await col.deleteMany({});
    if (orders.length > 0) await col.insertMany(orders.map(o => ({ ...o })));
    return;
  }
  atomicWrite(ORDERS_FILE, orders);
}

// --- Auth ---
async function getStoredPasswordHash() {
  if (useDB) {
    const doc = await mongo.collection('auth').findOne({});
    return doc ? doc.hash : null;
  }
  if (fs.existsSync(AUTH_FILE)) {
    try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')).hash; }
    catch (e) { return null; }
  }
  return null;
}

async function setStoredPasswordHash(newHash) {
  if (useDB) {
    await mongo.collection('auth').replaceOne({}, { hash: newHash, updatedAt: new Date().toISOString() }, { upsert: true });
    return;
  }
  atomicWrite(AUTH_FILE, { hash: newHash, updatedAt: new Date().toISOString() });
}

async function checkPassword(plain) {
  const stored = await getStoredPasswordHash();
  if (stored) return verifyPassword(plain, stored);
  return plain === ADMIN_PASSWORD;
}

function nextContractNumber(orders) {
  const year = new Date().getFullYear();
  const count = orders.filter(o => String(o.contractNumber || '').startsWith(String(year))).length + 1;
  return `${year}-${String(count).padStart(3, '0')}`;
}

// ============ MULTER ============
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /^image\/(jpeg|jpg|png|gif|webp|svg\+xml)$/i.test(file.mimetype);
    cb(ok ? null : new Error('نوع الملف غير مدعوم'), ok);
  }
});

async function saveImage(file) {
  if (useDB) {
    const { Binary } = require('mongodb');
    const result = await mongo.collection('images').insertOne({
      filename: file.originalname,
      mimetype: file.mimetype,
      data: new Binary(file.buffer),
      uploadedAt: new Date()
    });
    return `/api/image/${result.insertedId}`;
  }
  ensureDirs();
  const ext = path.extname(file.originalname).toLowerCase().slice(0, 8);
  const filename = Date.now() + '-' + crypto.randomBytes(4).toString('hex') + ext;
  fs.writeFileSync(path.join(UPLOADS_DIR, filename), file.buffer);
  return `/uploads/${filename}`;
}

async function deleteImage(urlPath) {
  if (!urlPath) return;
  if (urlPath.startsWith('/api/image/') && useDB) {
    try {
      const { ObjectId } = require('mongodb');
      await mongo.collection('images').deleteOne({ _id: new ObjectId(urlPath.replace('/api/image/', '')) });
    } catch (e) {}
  } else if (urlPath.startsWith('/uploads/')) {
    const file = path.join(UPLOADS_DIR, path.basename(urlPath));
    try { if (fs.existsSync(file)) fs.unlinkSync(file); } catch (e) {}
  }
}

// ============ AUTH ROUTES ============
app.post('/api/login', loginLimiter, async (req, res) => {
  try {
    const { password } = req.body || {};
    if (typeof password !== 'string' || !(await checkPassword(password))) {
      return res.status(401).json({ error: 'كلمة سر خاطئة' });
    }
    const token = createSession();
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true, sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: SESSION_TTL,
    });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'خطأ داخلي' });
  }
});

app.post('/api/change-password', requireAuth, loginLimiter, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    if (typeof oldPassword !== 'string' || typeof newPassword !== 'string') {
      return res.status(400).json({ error: 'بيانات ناقصة' });
    }
    if (!(await checkPassword(oldPassword))) {
      return res.status(401).json({ error: 'كلمة السر القديمة غير صحيحة' });
    }
    if (newPassword.length < 8)  return res.status(400).json({ error: 'كلمة السر الجديدة لازم تكون 8 أحرف على الأقل' });
    if (newPassword.length > 128) return res.status(400).json({ error: 'كلمة السر طويلة جداً' });
    await setStoredPasswordHash(hashPassword(newPassword));
    const currentToken = req.cookies[COOKIE_NAME];
    for (const t of sessions.keys()) if (t !== currentToken) sessions.delete(t);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: 'خطأ داخلي' });
  }
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
app.get('/api/image/:id', async (req, res) => {
  if (!useDB) return res.status(404).end();
  try {
    const { ObjectId } = require('mongodb');
    const img = await mongo.collection('images').findOne({ _id: new ObjectId(req.params.id) });
    if (!img) return res.status(404).end();
    res.set('Content-Type', img.mimetype);
    res.set('Cache-Control', 'public, max-age=31536000');
    res.send(img.data.buffer);
  } catch (e) { res.status(404).end(); }
});

app.get('/api/version', async (req, res) => {
  try { res.json({ lastUpdated: (await loadSettings()).lastUpdated || 0 }); }
  catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});
app.get('/api/settings', async (req, res) => {
  try { res.json(await loadSettings()); }
  catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});
app.get('/api/products', async (req, res) => {
  try { res.json((await loadSettings()).products); }
  catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});
app.get('/api/services', async (req, res) => {
  try { res.json((await loadSettings()).services); }
  catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ============ PROTECTED API ============
const protect = [requireAuth, writeLimiter];

app.post('/api/settings', protect, async (req, res) => {
  try {
    const settings = await loadSettings();
    const stringFields = {
      factoryName: 100, welcomeMessage: 200, welcomeSubMessage: 200,
      contactPhone: 30, contactEmail: 100, contactAddress: 200, contactWhatsapp: 30,
      about: 2000, primaryColor: 20, accentColor: 20, heroBackground: 20,
    };
    Object.assign(settings, sanitizeObj(req.body, stringFields));
    if (Array.isArray(req.body.terms)) {
      settings.terms = req.body.terms.slice(0, 30).map(t => sanitizeStr(t, 500));
    }
    await saveSettings(settings);
    res.json({ success: true, settings });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post('/api/upload-logo', protect, upload.single('logo'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'لم يتم رفع أي ملف' });
    const settings = await loadSettings();
    await deleteImage(settings.logoUrl);
    settings.logoUrl = await saveImage(req.file);
    await saveSettings(settings);
    res.json({ success: true, logoUrl: settings.logoUrl });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post('/api/upload-product-image', protect, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'لم يتم رفع أي ملف' });
    res.json({ success: true, imageUrl: await saveImage(req.file) });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// PRODUCTS
app.post('/api/products', protect, async (req, res) => {
  try {
    const settings = await loadSettings();
    const newProduct = {
      id: Date.now(),
      name: sanitizeStr(req.body.name, 100) || 'منتج جديد',
      description: sanitizeStr(req.body.description, 500),
      image: sanitizeStr(req.body.image, 300),
      category: sanitizeStr(req.body.category, 50) || 'عام'
    };
    settings.products.push(newProduct);
    await saveSettings(settings);
    res.json({ success: true, product: newProduct });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.put('/api/products/:id', protect, async (req, res) => {
  try {
    const settings = await loadSettings();
    const idx = settings.products.findIndex(p => p.id == req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'المنتج غير موجود' });
    const cleaned = sanitizeObj(req.body, { name: 100, description: 500, image: 300, category: 50 });
    settings.products[idx] = { ...settings.products[idx], ...cleaned, id: settings.products[idx].id };
    await saveSettings(settings);
    res.json({ success: true, product: settings.products[idx] });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.delete('/api/products/:id', protect, async (req, res) => {
  try {
    const settings = await loadSettings();
    const prod = settings.products.find(p => p.id == req.params.id);
    if (prod) deleteUploadedFile(prod.image);
    settings.products = settings.products.filter(p => p.id != req.params.id);
    await saveSettings(settings);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// SERVICES
app.post('/api/services', protect, async (req, res) => {
  try {
    const settings = await loadSettings();
    const newService = {
      id: Date.now(),
      title: sanitizeStr(req.body.title, 100) || 'خدمة جديدة',
      icon: sanitizeStr(req.body.icon, 10) || '⭐',
      desc: sanitizeStr(req.body.desc, 300)
    };
    settings.services.push(newService);
    await saveSettings(settings);
    res.json({ success: true, service: newService });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.put('/api/services/:id', protect, async (req, res) => {
  try {
    const settings = await loadSettings();
    const idx = settings.services.findIndex(s => s.id == req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'الخدمة غير موجودة' });
    const cleaned = sanitizeObj(req.body, { title: 100, icon: 10, desc: 300 });
    settings.services[idx] = { ...settings.services[idx], ...cleaned, id: settings.services[idx].id };
    await saveSettings(settings);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.delete('/api/services/:id', protect, async (req, res) => {
  try {
    const settings = await loadSettings();
    settings.services = settings.services.filter(s => s.id != req.params.id);
    await saveSettings(settings);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ORDERS
app.get('/api/orders', requireAuth, async (req, res) => {
  try { res.json(await loadOrders()); }
  catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.get('/api/orders/:id', requireAuth, async (req, res) => {
  try {
    const orders = await loadOrders();
    const o = orders.find(o => o.id == req.params.id);
    o ? res.json(o) : res.status(404).json({ error: 'غير موجود' });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.post('/api/orders', protect, async (req, res) => {
  try {
    const orders = await loadOrders();
    const order = {
      id: Date.now(),
      contractNumber: nextContractNumber(orders),
      createdAt: new Date().toISOString(),
      status: 'pending',
      ...req.body
    };
    orders.unshift(order);
    await saveOrders(orders);
    res.json({ success: true, order });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.put('/api/orders/:id', protect, async (req, res) => {
  try {
    const orders = await loadOrders();
    const idx = orders.findIndex(o => o.id == req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'غير موجود' });
    orders[idx] = { ...orders[idx], ...req.body, id: orders[idx].id, contractNumber: orders[idx].contractNumber };
    await saveOrders(orders);
    res.json({ success: true, order: orders[idx] });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

app.delete('/api/orders/:id', protect, async (req, res) => {
  try {
    const orders = await loadOrders();
    await saveOrders(orders.filter(o => o.id != req.params.id));
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'خطأ داخلي' }); }
});

// ============ PAGES ============
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/contract/:id', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'public', 'contract.html')));

app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(err.status || 500).json({ error: err.message || 'خطأ داخلي' });
});

// ============ START ============
async function start() {
  await connectMongo();
  if (!useDB) {
    ensureDirs();
    migrateFiles();
  }
  app.listen(PORT, () => {
    const mode = useDB ? '🗄️  MongoDB' : '📁 ملفات محلية';
    console.log(`\n✅ السيرفر شغال على: http://localhost:${PORT}`);
    console.log(`🔧 لوحة التحكم: http://localhost:${PORT}/admin`);
    console.log(`💾 وضع التخزين: ${mode}`);
    if (!useDB) console.log(`📁 DATA_DIR: ${DATA_DIR}`);
    if (ADMIN_PASSWORD === 'admin123') {
      console.log(`\n⚠️  تحذير: استخدم متغير البيئة ADMIN_PASSWORD لتغيير كلمة السر الافتراضية`);
    }
    console.log('');
  });
}

start();
