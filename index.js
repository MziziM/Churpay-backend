const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const nodemailer = require('nodemailer');
const adminRoutes = require('./routes/admin');

const app = express();

const allowedOrigins = [
  'http://localhost:3000',
  'https://churpay-web.onrender.com',
  'https://uat.churpay.com',
  ...(process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(o => o.trim()) : [])
];

app.use(cors({
  origin: allowedOrigins,
  credentials: true,
}));
app.use(express.json());

// --- DB SETUP ---
const db = new Database(process.env.DB_PATH || './churpay.db');
console.log('Connected to ChurPay SQLite database.');

// --- CREATE TABLES ---
db.prepare(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  church_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  is_admin INTEGER DEFAULT 0,
  suspended INTEGER DEFAULT 0
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  name TEXT NOT NULL,
  amount TEXT NOT NULL,
  status TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  church_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  goal_amount REAL,
  image_url TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(church_id) REFERENCES users(id)
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS payout_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  church_id INTEGER NOT NULL,
  amount REAL NOT NULL,
  status TEXT DEFAULT 'pending',
  date TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(church_id) REFERENCES users(id)
)`).run();

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'churpay_secret';

// --- EXAMPLE: REGISTER USER/CHURCH/MEMBER ---
app.post('/api/register', async (req, res) => {
  const { role, church_name, name, email, password } = req.body;
  let finalChurchName;
  if (role === 'church') {
    if (!church_name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    finalChurchName = church_name;
  } else if (role === 'member') {
    if (!name || !email || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }
    finalChurchName = name; // Store member's name in church_name column for consistency
  } else {
    return res.status(400).json({ message: 'Invalid role.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (church_name, email, password) VALUES (?, ?, ?)');
    const info = stmt.run(finalChurchName, email, hashedPassword);
    res.status(201).json({ message: 'Registration successful!', user_id: info.lastInsertRowid });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ message: 'Email already exists.' });
    res.status(500).json({ message: 'Database error.', error: err.message });
  }
});

// --- EXAMPLE: LOGIN ---
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'All fields required.' });
  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(400).json({ message: 'Invalid credentials.' });
    if (user.suspended) return res.status(403).json({ message: 'Account suspended.' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: 'Invalid credentials.' });
    const token = jwt.sign({ user_id: user.id, church_name: user.church_name, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ message: 'Login successful!', token, church_name: user.church_name });
  } catch (err) {
    res.status(500).json({ message: 'Server error.', error: err.message });
  }
});

// --- EXAMPLE: GET ALL TRANSACTIONS FOR LOGGED-IN USER ---
app.post('/api/my-transactions', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'No token provided.' });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    const rows = db.prepare('SELECT date, name, amount, status FROM transactions WHERE user_id = ? ORDER BY date DESC, id DESC').all(user.user_id);
    res.json(rows);
  } catch (err) {
    res.status(403).json({ message: 'Invalid token or server error.' });
  }
});

// --- ADMIN REGISTER ENDPOINT ---
app.post('/api/admin-register', async (req, res) => {
  const { admin_name, admin_email, password, role } = req.body;
  if (role !== 'admin') return res.status(400).json({ message: 'Invalid role.' });
  if (!admin_name || !admin_email || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (church_name, email, password, is_admin) VALUES (?, ?, ?, 1)');
    const info = stmt.run(admin_name, admin_email, hashedPassword);
    res.status(201).json({ message: 'Admin registration successful!', user_id: info.lastInsertRowid });
  } catch (err) {
    if (err.message.includes('UNIQUE')) return res.status(400).json({ message: 'Email already exists.' });
    res.status(500).json({ message: 'Database error.', error: err.message });
  }
});

// --- ADMIN LOGIN ENDPOINT ---
app.post('/api/admin-login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'All fields required.' });
  try {
    const user = db.prepare('SELECT * FROM users WHERE email = ? AND is_admin = 1').get(email);
    if (!user) return res.status(400).json({ message: 'Invalid credentials or not an admin.' });
    if (user.suspended) return res.status(403).json({ message: 'Account suspended.' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: 'Invalid credentials.' });
    const token = jwt.sign({ user_id: user.id, church_name: user.church_name, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ message: 'Admin login successful!', token, church_name: user.church_name });
  } catch (err) {
    res.status(500).json({ message: 'Server error.', error: err.message });
  }
});

app.listen(PORT, () => console.log(`ChurPay backend running on port ${PORT}`));

// --- Admin: Dashboard stats ---
app.post('/api/admin/stats', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: "No token provided." });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token." });

    // Only allow admin
    db.get('SELECT is_admin FROM users WHERE id = ?', [user.user_id], (err, admin) => {
      if (err || !admin || !admin.is_admin) return res.status(403).json({ message: "Not allowed." });

      // Get stats: total churches, total users, total transactions, total revenue
      db.serialize(() => {
        db.get('SELECT COUNT(*) as total_churches FROM users WHERE is_admin = 0', (err, cRow) => {
          db.get('SELECT COUNT(*) as total_members FROM users WHERE is_admin = 0', (err2, mRow) => {
            db.get('SELECT COUNT(*) as total_transactions, SUM(CAST(amount AS FLOAT)) as total_revenue FROM transactions WHERE status="Success"', (err3, tRow) => {
              res.json({
                total_churches: cRow?.total_churches || 0,
                total_members: mRow?.total_members || 0,
                total_transactions: tRow?.total_transactions || 0,
                total_revenue: tRow?.total_revenue || 0,
              });
            });
          });
        });
      });
    });
  });
});

// --- GET: Admin Dashboard Stats (for frontend GET request) ---
app.get('/api/admin/stats', (req, res) => {
  // Optionally, add authentication here if needed
  try {
    const totalChurches = db.prepare('SELECT COUNT(*) as count FROM users WHERE is_admin = 0').get().count;
    const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    const totalTransactions = db.prepare('SELECT COUNT(*) as count FROM transactions').get().count;
    const totalRevenue = db.prepare('SELECT SUM(CAST(amount AS FLOAT)) as sum FROM transactions WHERE status = "Success"').get().sum || 0;
    res.json({
      total_churches: totalChurches,
      total_users: totalUsers,
      total_transactions: totalTransactions,
      total_revenue: totalRevenue
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch admin stats', details: err.message });
  }
});

// --- GET: All Transactions (for frontend GET request) ---
app.get('/api/transactions', (req, res) => {
  try {
    const transactions = db.prepare('SELECT * FROM transactions ORDER BY date DESC, id DESC LIMIT 100').all();
    res.json(transactions);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions', details: err.message });
  }
});