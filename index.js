const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const nodemailer = require('nodemailer');
const adminRoutes = require('./routes/admin');
const path = require('path');

const app = express();

const allowedOrigins = [
  'http://localhost:3000',
  'https://churpay-web.onrender.com',
  'https://uat.churpay.com',
  // ...any other domains you use
  ...(process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(o => o.trim()) : [])
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true); // Allow requests with no origin (curl, Postman)
    if (allowedOrigins.indexOf(origin) !== -1) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // Preflight for all routes
app.use(express.json({ limit: '50mb' })); // Increased limit for large payloads
app.use(express.urlencoded({ limit: '50mb', extended: true })); // Also handle URL-encoded data with increased limit

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

const PORT = process.env.PORT || 5001; // Changed to port 5001 to avoid conflicts
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
  console.log('ADMIN REGISTER BODY:', req.body); // Debug log
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

// Try ports sequentially until one is available
const server = app.listen(PORT)
  .on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.log(`Port ${PORT} is already in use, trying port ${PORT+1}...`);
      // Try the next port
      app.listen(PORT+1)
        .on('error', (err) => {
          if (err.code === 'EADDRINUSE') {
            console.log(`Port ${PORT+1} is also in use, trying port ${PORT+2}...`);
            app.listen(PORT+2)
              .on('error', (err) => {
                console.error(`Failed to start server: ${err.message}`);
              })
              .on('listening', () => {
                console.log(`ChurPay backend running on port ${PORT+2}`);
              });
          } else {
            console.error(`Failed to start server: ${err.message}`);
          }
        })
        .on('listening', () => {
          console.log(`ChurPay backend running on port ${PORT+1}`);
        });
    } else {
      console.error(`Failed to start server: ${err.message}`);
    }
  })
  .on('listening', () => {
    console.log(`ChurPay backend running on port ${PORT}`);
  });

// --- Admin: Dashboard stats ---
app.get('/api/admin/stats', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    console.log('Missing Authorization header');
    return res.status(401).json({ error: 'No token provided (authHeader missing).' });
  }
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    console.log('Invalid Authorization header format:', authHeader);
    return res.status(401).json({ error: 'Invalid Authorization header format.' });
  }
  const token = parts[1];
  if (!token) {
    console.log('No token after Bearer');
    return res.status(401).json({ error: 'No token provided (after Bearer).' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('JWT error:', err);
      return res.status(403).json({ error: 'Invalid token.' });
    }
    console.log('Decoded user:', user);

    const admin = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(user.user_id);
    if (!admin || !admin.is_admin) {
      console.log('User not admin or not found:', user.user_id, admin);
      return res.status(403).json({ error: 'Not allowed (not admin).' });
    }
    try {
      // Check if required tables exist
      const usersTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").get();
      const transactionsTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='transactions'").get();
      if (!usersTable) {
        console.error('Users table does not exist!');
        return res.status(500).json({ error: 'Database error: users table does not exist.' });
      }
      if (!transactionsTable) {
        console.error('Transactions table does not exist!');
        return res.status(500).json({ error: 'Database error: transactions table does not exist.' });
      }
      // Check for required columns in users
      const userColumns = db.prepare("PRAGMA table_info(users)").all().map(col => col.name);
      const requiredUserCols = ['id', 'church_name', 'email', 'password', 'is_admin', 'suspended'];
      for (const col of requiredUserCols) {
        if (!userColumns.includes(col)) {
          console.error(`Missing column '${col}' in users table!`);
          return res.status(500).json({ error: `Database error: missing column '${col}' in users table.` });
        }
      }
      // Check for required columns in transactions
      const txColumns = db.prepare("PRAGMA table_info(transactions)").all().map(col => col.name);
      const requiredTxCols = ['id', 'user_id', 'date', 'name', 'amount', 'status'];
      for (const col of requiredTxCols) {
        if (!txColumns.includes(col)) {
          console.error(`Missing column '${col}' in transactions table!`);
          return res.status(500).json({ error: `Database error: missing column '${col}' in transactions table.` });
        }
      }
      // All checks passed, run queries
      let churches = 0, members = 0, totalTransactions = 0, totalRevenueRow = { sum: 0 }, totalRevenue = 0;
      try {
        churches = db.prepare('SELECT COUNT(*) as count FROM users WHERE is_admin = 0').get().count;
      } catch (e) {
        console.error('Error counting churches:', e);
        return res.status(500).json({ error: 'Error counting churches', details: e.message });
      }
      try {
        members = db.prepare('SELECT COUNT(*) as count FROM users WHERE is_admin = 0').get().count;
      } catch (e) {
        console.error('Error counting members:', e);
        return res.status(500).json({ error: 'Error counting members', details: e.message });
      }
      try {
        totalTransactions = db.prepare('SELECT COUNT(*) as count FROM transactions').get().count;
      } catch (e) {
        console.error('Error counting transactions:', e);
        return res.status(500).json({ error: 'Error counting transactions', details: e.message });
      }
      try {
        totalRevenueRow = db.prepare("SELECT SUM(CAST(amount AS FLOAT)) as sum FROM transactions WHERE status = 'Success'").get();
        totalRevenue = totalRevenueRow && totalRevenueRow.sum ? totalRevenueRow.sum : 0;
      } catch (e) {
        console.error('Error calculating total revenue:', e);
        return res.status(500).json({ error: 'Error calculating total revenue', details: e.message });
      }
      console.log('STATS DEBUG:', { churches, members, totalTransactions, totalRevenueRow });
      res.json({
        churches,
        members,
        totalTransactions,
        totalRevenue
      });
    } catch (err) {
      console.log('Stats error (detailed):', err, err.stack);
      res.status(500).json({ error: 'Failed to fetch admin stats', details: err.message, stack: err.stack });
    }
  });
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

// --- ADMIN: GET ALL PAYOUT REQUESTS ---
app.get('/api/admin/payout-requests', requireAdmin, (req, res) => {
  try {
    const requests = db.prepare(`SELECT pr.*, u.church_name FROM payout_requests pr LEFT JOIN users u ON pr.church_id = u.id ORDER BY pr.date DESC, pr.id DESC LIMIT 100`).all();
    res.json(requests);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch payout requests', details: err.message });
  }
});

// --- ADMIN: APPROVE/DENY PAYOUT REQUEST ---
app.post('/api/admin/payout-requests/:id/action', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided.' });
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization header format.' });
  const token = parts[1];
  if (!token) return res.status(401).json({ error: 'No token provided (after Bearer).' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token.' });
    const admin = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(user.user_id);
    if (!admin || !admin.is_admin) return res.status(403).json({ error: 'Not allowed (not admin).' });
    const payoutId = req.params.id;
    const { action } = req.body;
    if (!['approve', 'deny'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action. Must be approve or deny.' });
    }
    try {
      // Check if payout request exists and is pending
      const payout = db.prepare('SELECT * FROM payout_requests WHERE id = ?').get(payoutId);
      if (!payout) return res.status(404).json({ error: 'Payout request not found.' });
      if (payout.status !== 'pending') return res.status(400).json({ error: 'Payout request already processed.' });
      // Update status
      const newStatus = action === 'approve' ? 'approved' : 'denied';
      db.prepare('UPDATE payout_requests SET status = ? WHERE id = ?').run(newStatus, payoutId);
      // Optionally: send notification email here
      res.json({ message: `Payout request ${action}d successfully.` });
    } catch (err) {
      res.status(500).json({ error: 'Failed to process payout request', details: err.message });
    }
  });
});

// --- ADMIN: GET ALL CHURCHES ---
app.get('/api/admin/churches', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided.' });
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization header format.' });
  const token = parts[1];
  if (!token) return res.status(401).json({ error: 'No token provided (after Bearer).' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token.' });
    const admin = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(user.user_id);
    if (!admin || !admin.is_admin) return res.status(403).json({ error: 'Not allowed (not admin).' });
    try {
      const churches = db.prepare('SELECT id, church_name, email FROM users WHERE is_admin = 0').all();
      res.json(churches);
    } catch (err) {
      res.status(500).json({ error: 'Failed to fetch churches', details: err.message });
    }
  });
});

// --- ADMIN: ADD MEMBER ---
app.post('/api/admin/members', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided.' });
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization header format.' });
  const token = parts[1];
  if (!token) return res.status(401).json({ error: 'No token provided (after Bearer).' });
  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token.' });
    const admin = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(user.user_id);
    if (!admin || !admin.is_admin) return res.status(403).json({ error: 'Not allowed (not admin).' });
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const isAdmin = role === 'admin' ? 1 : 0;
      const stmt = db.prepare('INSERT INTO users (church_name, email, password, is_admin) VALUES (?, ?, ?, ?)');
      const info = stmt.run(name, email, hashedPassword, isAdmin);
      res.status(201).json({ message: 'Member added successfully!', user_id: info.lastInsertRowid });
    } catch (err) {
      if (err.message.includes('UNIQUE')) return res.status(400).json({ message: 'Email already exists.' });
      res.status(500).json({ message: 'Database error.', error: err.message });
    }
  });
});


// --- GET ALL MEMBERS (for admin) ---
app.get('/api/admin/members', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided.' });
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization header format.' });
  const token = parts[1];
  if (!token) return res.status(401).json({ error: 'No token provided (after Bearer).' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('JWT error:', err);
      return res.status(403).json({ error: 'Invalid token.' });
    }
    const admin = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(user.user_id);
    if (!admin || !admin.is_admin) {
      return res.status(403).json({ error: 'Not allowed (not admin).' });
    }
    try {
      // Only return users that are NOT admin
      const rows = db.prepare('SELECT id, church_name, email FROM users WHERE is_admin = 0').all();
      res.json(rows);
    } catch (err) {
      console.log('Failed to fetch members:', err);
      res.status(500).json({ error: 'Failed to fetch members', details: err.message });
    }
  });
});

// Middleware to require admin role
function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided.' });
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization header format.' });
  const token = parts[1];
  if (!token) return res.status(401).json({ error: 'No token provided (after Bearer).' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('JWT error:', err);
      return res.status(403).json({ error: 'Invalid token.' });
    }
    const admin = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(user.user_id);
    if (!admin || !admin.is_admin) {
      return res.status(403).json({ error: 'Not allowed (not admin).' });
    }
    req.adminUser = user; // Attach user info to request
    next();
  });
}

// Usage example with the requireAdmin middleware
app.get('/api/admin/members', requireAdmin, (req, res) => {
  try {
    const rows = db.prepare('SELECT id, church_name, email FROM users WHERE is_admin = 0').all();
    res.json(rows);
  } catch (err) {
    console.log('Failed to fetch members:', err);
    res.status(500).json({ error: 'Failed to fetch members', details: err.message });
  }
});

// --- ADMIN: GET ALL PROJECTS ---
app.get('/api/admin/projects', requireAdmin, (req, res) => {
  try {
    const projects = db.prepare(`
      SELECT p.*, u.church_name 
      FROM projects p 
      LEFT JOIN users u ON p.church_id = u.id 
      ORDER BY p.created_at DESC, p.id DESC
    `).all();
    res.json(projects);
  } catch (err) {
    console.log('Failed to fetch projects:', err);
    res.status(500).json({ error: 'Failed to fetch projects', details: err.message });
  }
});