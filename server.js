const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Ensure directories exist
['uploads', 'data'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});

// Default settings
const DEFAULT_SETTINGS = {
  factoryName: "مصنع الملابس",
  welcomeMessage: "مرحباً بكم في مصنعنا",
  welcomeSubMessage: "نصنع الجودة ونرتقي بالأناقة",
  logoUrl: "",
  contactPhone: "",
  contactEmail: "",
  contactAddress: "",
  about: "نحن مصنع متخصص في صناعة الملابس بأعلى معايير الجودة",
  products: [
    {
      id: 1,
      name: "قمصان رجالية",
      description: "قمصان بأقمشة فاخرة وخياطة محكمة",
      image: "",
      category: "رجالي"
    },
    {
      id: 2,
      name: "فساتين نسائية",
      description: "تصميمات عصرية تجمع بين الأناقة والراحة",
      image: "",
      category: "نسائي"
    },
    {
      id: 3,
      name: "ملابس أطفال",
      description: "ملابس ملونة وآمنة لأطفالنا الصغار",
      image: "",
      category: "أطفال"
    }
  ],
  services: [
    { id: 1, title: "تصنيع بالجملة", icon: "🏭", desc: "إنتاج كميات كبيرة بأسعار تنافسية" },
    { id: 2, title: "تصميم مخصص", icon: "✂️", desc: "تصميم حسب طلب العميل وذوقه" },
    { id: 3, title: "توصيل سريع", icon: "🚚", desc: "نوصل لجميع أنحاء المملكة" }
  ],
  primaryColor: "#2c3e50",
  accentColor: "#e74c3c",
  heroBackground: "#1a1a2e"
};

// Load settings
function loadSettings() {
  const settingsPath = 'data/settings.json';
  if (!fs.existsSync(settingsPath)) {
    fs.writeFileSync(settingsPath, JSON.stringify(DEFAULT_SETTINGS, null, 2));
    return DEFAULT_SETTINGS;
  }
  return JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
}

// Save settings
function saveSettings(data) {
  data.lastUpdated = Date.now();
  fs.writeFileSync('data/settings.json', JSON.stringify(data, null, 2));
}

// Lightweight version check endpoint
app.get('/api/version', (req, res) => {
  const s = loadSettings();
  res.json({ lastUpdated: s.lastUpdated || 0 });
});

// Multer config for image uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// ============ API Routes ============

// Get all settings (public)
app.get('/api/settings', (req, res) => {
  res.json(loadSettings());
});

// Update general settings
app.post('/api/settings', (req, res) => {
  const settings = loadSettings();
  const allowed = ['factoryName', 'welcomeMessage', 'welcomeSubMessage', 'contactPhone',
    'contactEmail', 'contactAddress', 'contactWhatsapp', 'about', 'primaryColor', 'accentColor', 'heroBackground'];
  allowed.forEach(key => {
    if (req.body[key] !== undefined) settings[key] = req.body[key];
  });
  saveSettings(settings);
  res.json({ success: true, settings });
});

// Upload logo
app.post('/api/upload-logo', upload.single('logo'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'لم يتم رفع أي ملف' });
  const settings = loadSettings();
  settings.logoUrl = `/uploads/${req.file.filename}`;
  saveSettings(settings);
  res.json({ success: true, logoUrl: settings.logoUrl });
});

// Upload product image
app.post('/api/upload-product-image', upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'لم يتم رفع أي ملف' });
  res.json({ success: true, imageUrl: `/uploads/${req.file.filename}` });
});

// Get products
app.get('/api/products', (req, res) => {
  res.json(loadSettings().products);
});

// Add product
app.post('/api/products', (req, res) => {
  const settings = loadSettings();
  const newProduct = {
    id: Date.now(),
    name: req.body.name || 'منتج جديد',
    description: req.body.description || '',
    image: req.body.image || '',
    category: req.body.category || 'عام'
  };
  settings.products.push(newProduct);
  saveSettings(settings);
  res.json({ success: true, product: newProduct });
});

// Update product
app.put('/api/products/:id', (req, res) => {
  const settings = loadSettings();
  const idx = settings.products.findIndex(p => p.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'المنتج غير موجود' });
  settings.products[idx] = { ...settings.products[idx], ...req.body, id: settings.products[idx].id };
  saveSettings(settings);
  res.json({ success: true, product: settings.products[idx] });
});

// Delete product
app.delete('/api/products/:id', (req, res) => {
  const settings = loadSettings();
  settings.products = settings.products.filter(p => p.id != req.params.id);
  saveSettings(settings);
  res.json({ success: true });
});

// Get services
app.get('/api/services', (req, res) => {
  res.json(loadSettings().services);
});

// Add service
app.post('/api/services', (req, res) => {
  const settings = loadSettings();
  const newService = {
    id: Date.now(),
    title: req.body.title || 'خدمة جديدة',
    icon: req.body.icon || '⭐',
    desc: req.body.desc || ''
  };
  settings.services.push(newService);
  saveSettings(settings);
  res.json({ success: true, service: newService });
});

// Update service
app.put('/api/services/:id', (req, res) => {
  const settings = loadSettings();
  const idx = settings.services.findIndex(s => s.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'الخدمة غير موجودة' });
  settings.services[idx] = { ...settings.services[idx], ...req.body, id: settings.services[idx].id };
  saveSettings(settings);
  res.json({ success: true });
});

// Delete service
app.delete('/api/services/:id', (req, res) => {
  const settings = loadSettings();
  settings.services = settings.services.filter(s => s.id != req.params.id);
  saveSettings(settings);
  res.json({ success: true });
});

// ============ ORDERS API ============

function loadOrders() {
  const p = 'data/orders.json';
  if (!fs.existsSync(p)) { fs.writeFileSync(p, '[]'); return []; }
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}
function saveOrders(orders) {
  fs.writeFileSync('data/orders.json', JSON.stringify(orders, null, 2));
}
function nextContractNumber(orders) {
  const year = new Date().getFullYear();
  const count = orders.filter(o => String(o.contractNumber || '').startsWith(String(year))).length + 1;
  return `${year}-${String(count).padStart(3, '0')}`;
}

app.get('/api/orders', (req, res) => res.json(loadOrders()));

app.get('/api/orders/:id', (req, res) => {
  const o = loadOrders().find(o => o.id == req.params.id);
  o ? res.json(o) : res.status(404).json({ error: 'غير موجود' });
});

app.post('/api/orders', (req, res) => {
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

app.put('/api/orders/:id', (req, res) => {
  const orders = loadOrders();
  const idx = orders.findIndex(o => o.id == req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'غير موجود' });
  orders[idx] = { ...orders[idx], ...req.body, id: orders[idx].id, contractNumber: orders[idx].contractNumber };
  saveOrders(orders);
  res.json({ success: true, order: orders[idx] });
});

app.delete('/api/orders/:id', (req, res) => {
  saveOrders(loadOrders().filter(o => o.id != req.params.id));
  res.json({ success: true });
});

// ============ PAGES ============

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/contract/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'contract.html')));

app.listen(PORT, () => {
  console.log(`\n✅ السيرفر شغال على: http://localhost:${PORT}`);
  console.log(`🔧 لوحة التحكم: http://localhost:${PORT}/admin\n`);
});
