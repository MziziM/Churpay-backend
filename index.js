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

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin) || !origin) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
  } else {
    return res.status(403).send('Not allowed by CORS');
  }
});
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

// ...continue for each endpoint using .prepare().run(), .get(), .all() as needed

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