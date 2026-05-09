// ============================================================
//  Mahaveer Mobiles — Node.js + Express + MongoDB Backend
//  Run: node app.js
//  Requires: npm install express mongoose cors bcryptjs jsonwebtoken dotenv
// ============================================================

require('dotenv').config();

const express  = require('express');
const mongoose = require('mongoose');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ── MongoDB Connection ──────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI;

console.log('🔗 Connecting to MongoDB...');

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('✅ MongoDB connected successfully!');
    seedDatabase();
  })
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    console.log('⚠️  Running in OFFLINE mode — using local JSON files');
  });

// ── Schemas ─────────────────────────────────────────────────
const phoneSchema = new mongoose.Schema({
  id:       Number,
  brand:    String,
  name:     String,
  price:    Number,
  oldPrice: Number,
  badge:    String,
  stock:    { type: String, default: 'in' },
  image:    String,
  imageUrl: String,
}, { timestamps: true });

const accessorySchema = new mongoose.Schema({
  id:       Number,
  brand:    String,
  name:     String,
  accType:  String,
  price:    Number,
  oldPrice: Number,
  badge:    String,
  stock:    { type: String, default: 'in' },
  image:    String,
  imageUrl: String,
}, { timestamps: true });

const adminSchema = new mongoose.Schema({
  adminId:  { type: String, unique: true },
  password: String,   // bcrypt hashed
});

const Phone     = mongoose.model('Phone',     phoneSchema);
const Accessory = mongoose.model('Accessory', accessorySchema);
const Admin     = mongoose.model('Admin',     adminSchema);

// ── Seed Database from JSON on first run ────────────────────
async function seedDatabase() {
  const phoneCount = await Phone.countDocuments();
  if (phoneCount === 0) {
    const phones = JSON.parse(fs.readFileSync(path.join(__dirname, 'products.json'), 'utf8'));
    await Phone.insertMany(phones);
    console.log(`✅ Seeded ${phones.length} phones`);
  }
  const accCount = await Accessory.countDocuments();
  if (accCount === 0) {
    const accs = JSON.parse(fs.readFileSync(path.join(__dirname, 'accessories.json'), 'utf8'));
    await Accessory.insertMany(accs);
    console.log(`✅ Seeded ${accs.length} accessories`);
  }
  const adminCount = await Admin.countDocuments();
  if (adminCount === 0) {
    const hashed = await bcrypt.hash('admin@123', 10);
    await Admin.create({ adminId: 'mahaveer', password: hashed });
    console.log('✅ Default admin created  →  ID: mahaveer  |  Password: admin@123');
  }
}

// ── JWT Auth Middleware ─────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.admin = jwt.verify(token, process.env.JWT_SECRET || 'mahaveer_secret_key');
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ══════════════════════════════════════════════════════════════
//  PUBLIC ROUTES  (customers use these)
// ══════════════════════════════════════════════════════════════

// GET all phones
app.get('/api/phones', async (req, res) => {
  try {
    const phones = await Phone.find().sort({ id: 1 });
    res.json(phones);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET all accessories
app.get('/api/accessories', async (req, res) => {
  try {
    const accs = await Accessory.find().sort({ id: 1 });
    res.json(accs);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════════════════════════════════════
//  ADMIN AUTH ROUTES
// ══════════════════════════════════════════════════════════════

// POST /api/admin/login
app.post('/api/admin/login', async (req, res) => {
  const { adminId, password } = req.body;
  if (!adminId || !password)
    return res.status(400).json({ error: 'ID and password required' });
  const admin = await Admin.findOne({ adminId });
  if (!admin)
    return res.status(401).json({ error: 'Invalid Admin ID' });
  const match = await bcrypt.compare(password, admin.password);
  if (!match)
    return res.status(401).json({ error: 'Wrong Password' });
  const token = jwt.sign(
    { adminId: admin.adminId },
    process.env.JWT_SECRET || 'mahaveer_secret_key',
    { expiresIn: '8h' }
  );
  res.json({ token, message: 'Login successful' });
});

// POST /api/admin/reset-credentials  (after OTP verified on frontend)
app.post('/api/admin/reset-credentials', authMiddleware, async (req, res) => {
  const { newAdminId, newPassword } = req.body;
  if (!newAdminId || !newPassword)
    return res.status(400).json({ error: 'New ID and password required' });
  if (newPassword.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const hashed = await bcrypt.hash(newPassword, 10);
  await Admin.findOneAndUpdate(
    { adminId: req.admin.adminId },
    { adminId: newAdminId, password: hashed }
  );
  res.json({ message: 'Credentials updated successfully' });
});

// ══════════════════════════════════════════════════════════════
//  ADMIN PRODUCT ROUTES  (protected)
// ══════════════════════════════════════════════════════════════

// PUT /api/phones/:id  — update price
app.put('/api/phones/:id', authMiddleware, async (req, res) => {
  try {
    const { price, oldPrice, badge, stock } = req.body;
    const updated = await Phone.findOneAndUpdate(
      { id: Number(req.params.id) },
      { price, oldPrice, badge, stock },
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Phone not found' });
    res.json({ message: 'Updated', phone: updated });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/phones  — add new phone
app.post('/api/phones', authMiddleware, async (req, res) => {
  try {
    const last  = await Phone.findOne().sort({ id: -1 });
    const newId = (last?.id || 100) + 1;
    const phone = await Phone.create({ ...req.body, id: newId });
    res.json({ message: 'Phone added', phone });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/phones/:id
app.delete('/api/phones/:id', authMiddleware, async (req, res) => {
  try {
    await Phone.findOneAndDelete({ id: Number(req.params.id) });
    res.json({ message: 'Deleted' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/accessories/:id  — update accessory price
app.put('/api/accessories/:id', authMiddleware, async (req, res) => {
  try {
    const { price, oldPrice, badge, stock } = req.body;
    const updated = await Accessory.findOneAndUpdate(
      { id: Number(req.params.id) },
      { price, oldPrice, badge, stock },
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Accessory not found' });
    res.json({ message: 'Updated', accessory: updated });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/accessories  — add new accessory
app.post('/api/accessories', authMiddleware, async (req, res) => {
  try {
    const last  = await Accessory.findOne().sort({ id: -1 });
    const newId = (last?.id || 200) + 1;
    const acc   = await Accessory.create({ ...req.body, id: newId });
    res.json({ message: 'Accessory added', accessory: acc });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/accessories/:id
app.delete('/api/accessories/:id', authMiddleware, async (req, res) => {
  try {
    await Accessory.findOneAndDelete({ id: Number(req.params.id) });
    res.json({ message: 'Deleted' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Serve index.html for all other routes ───────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── Start Server ────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Mahaveer Mobiles server running at http://localhost:${PORT}`);
});
