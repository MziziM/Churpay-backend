const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const nodemailer = require('nodemailer');
const adminRoutes = require('./routes/admin');
const path = require('path');
const { getDatabase } = require('./config/database');
const { setupDatabase } = require('./config/schema');
const dataService = require('./services/dataService');

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
// Database setup is now handled in the config/database.js file
// This will automatically choose between SQLite and PostgreSQL based on the environment
// Initialize database schema
(async function initDatabase() {
  try {
    console.log('Setting up database...');
    await setupDatabase();
    console.log('Database setup complete');
  } catch (err) {
    console.error('Failed to set up database schema:', err);
    console.error('The application will continue to run, but some features may not work properly');
    // Not exiting process to allow the app to continue even if there are DB issues
  }
})();

// --- COMPATIBILITY LAYER ---
// This provides backward compatibility with the SQLite code
// while using our new database service under the hood
const db = {
  prepare: (sql) => {
    // Convert SQL to use $1, $2, etc. instead of ? for PostgreSQL
    let preparedSql = sql;
    let paramCount = 0;
    preparedSql = preparedSql.replace(/\?/g, () => `$${++paramCount}`);
    
    return {
      run: (...params) => {
        return dataService.query(preparedSql, params)
          .then(result => {
            // Mimic SQLite's run result
            return { 
              changes: result && result[0] ? result[0].changes || 0 : 0,
              lastInsertRowid: result && result[0] ? result[0].lastInsertRowid || result[0].id || null : null
            };
          })
          .catch(err => {
            console.error('Error executing query:', err);
            throw err;
          });
      },
      get: (...params) => {
        return dataService.query(preparedSql, params)
          .then(rows => rows && rows.length ? rows[0] : undefined)
          .catch(err => {
            console.error('Error executing query:', err);
            throw err;
          });
      },
      all: (...params) => {
        return dataService.query(preparedSql, params)
          .then(rows => rows || [])
          .catch(err => {
            console.error('Error executing query:', err);
            throw err;
          });
      }
    };
  }
};

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
    // Check if email already exists
    const existingUser = await dataService.findOne('users', { email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists.' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const userData = {
      church_name: finalChurchName,
      email,
      password: hashedPassword
    };
    
    const result = await dataService.insert('users', userData);
    const userId = result.id || result.lastInsertRowid;
    
    res.status(201).json({ message: 'Registration successful!', user_id: userId });
  } catch (err) {
    console.error('Registration error:', err);
    if (err.message && err.message.includes('duplicate') || err.message.includes('UNIQUE')) {
      return res.status(400).json({ message: 'Email already exists.' });
    }
    res.status(500).json({ message: 'Database error.', error: err.message });
  }
});

// --- EXAMPLE: LOGIN ---
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'All fields required.' });
  try {
    const users = await dataService.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = users.length ? users[0] : null;
    if (!user) return res.status(400).json({ message: 'Invalid credentials.' });
    if (user.suspended) return res.status(403).json({ message: 'Account suspended.' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: 'Invalid credentials.' });
    const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_123';
    const token = jwt.sign({ user_id: user.id, church_name: user.church_name, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ message: 'Login successful!', token, church_name: user.church_name });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error.', error: err.message });
  }
});

// --- EXAMPLE: GET ALL TRANSACTIONS FOR LOGGED-IN USER ---
app.post('/api/my-transactions', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'No token provided.' });
  try {
    const user = jwt.verify(token, JWT_SECRET);
    // Use the data service instead of direct db.prepare
    const rows = await dataService.query('SELECT date, name, amount, status FROM transactions WHERE user_id = $1 ORDER BY date DESC, id DESC', [user.user_id]);
    res.json(rows);
  } catch (err) {
    console.error('Error fetching transactions:', err);
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
    // Check if admin email already exists
    const existingUser = await dataService.findOne('users', { email: admin_email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email already exists.' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const userData = {
      church_name: admin_name,
      email: admin_email,
      password: hashedPassword,
      is_admin: 1
    };
    
    const result = await dataService.insert('users', userData);
    const userId = result.id || result.lastInsertRowid;
    
    res.status(201).json({ message: 'Admin registration successful!', user_id: userId });
  } catch (err) {
    console.error('Admin registration error:', err);
    if (err.message && (err.message.includes('duplicate') || err.message.includes('UNIQUE'))) {
      return res.status(400).json({ message: 'Email already exists.' });
    }
    res.status(500).json({ message: 'Database error.', error: err.message });
  }
});

// --- ADMIN LOGIN ENDPOINT ---
app.post('/api/admin-login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'All fields required.' });
  try {
    const users = await dataService.query('SELECT * FROM users WHERE email = $1 AND is_admin = 1', [email]);
    const user = users.length ? users[0] : null;
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

// --- MEMBER MIDDLEWARE: Require Member Authentication ---
function requireMember(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No authorization header provided.' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'Invalid authorization format.' });
  if (parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid authorization scheme.' });

  const token = parts[1];
  if (!token) return res.status(401).json({ error: 'No token provided (after Bearer).' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log('JWT error:', err);
      return res.status(403).json({ error: 'Invalid token.' });
    }
    req.user = user; // Attach user info to request
    next();
  });
}

// --- MEMBER: Get Dashboard Data ---
app.get('/api/member/dashboard', requireMember, (req, res) => {
  try {
    const userId = req.user.user_id;
    
    // Get member info
    const member = db.prepare(`
      SELECT id, name, email, church_id 
      FROM members 
      WHERE id = ?
    `).get(userId);
    
    if (!member) {
      return res.status(404).json({ error: 'Member not found' });
    }
    
    // Get church info
    const church = member.church_id ? db.prepare(`
      SELECT church_name
      FROM users 
      WHERE id = ?
    `).get(member.church_id) : null;
    
    // Get donations
    const donations = db.prepare(`
      SELECT d.id, d.amount, d.date, p.title as project
      FROM donations d
      LEFT JOIN projects p ON d.project_id = p.id
      WHERE d.member_id = ?
      ORDER BY d.date DESC
    `).all(userId);
    
    // Calculate statistics
    const donationStats = db.prepare(`
      SELECT SUM(amount) as totalGiven, COUNT(*) as transactions
      FROM donations
      WHERE member_id = ?
    `).get(userId);
    
    // Get member profile settings
    const memberSettings = db.prepare(`
      SELECT goal, 
             recurring_enabled as "recurring.enabled", 
             recurring_type as "recurring.type", 
             recurring_amount as "recurring.amount"
      FROM member_settings
      WHERE member_id = ?
    `).get(userId);
    
    // Default settings if none exist
    const settings = memberSettings || {
      goal: 5000,
      recurring: {
        enabled: false,
        type: "Tithe",
        amount: 500
      }
    };
    
    // Get badges (based on donation history)
    const badges = {
      firstGift: donations.length > 0,
      r1000Club: donationStats.totalGiven >= 1000,
      r5000Club: donationStats.totalGiven >= 5000,
      consistentGiver: donations.length >= 3,
      bigGift: donations.some(d => d.amount >= 1000)
    };
    
    // Calculate impact statistics (simplified example)
    const churchesHelped = db.prepare(`
      SELECT COUNT(DISTINCT p.church_id) as count
      FROM donations d
      JOIN projects p ON d.project_id = p.id
      WHERE d.member_id = ?
    `).get(userId).count;
    
    const projectsFunded = db.prepare(`
      SELECT COUNT(DISTINCT project_id) as count
      FROM donations
      WHERE member_id = ?
    `).get(userId).count;
    
    // Monthly trend (last 6 months)
    const monthlyTrend = []; 
    for (let i = 5; i >= 0; i--) {
      const date = new Date();
      date.setMonth(date.getMonth() - i);
      const month = date.getMonth() + 1;
      const year = date.getFullYear();
      
      const monthTotal = db.prepare(`
        SELECT COALESCE(SUM(amount), 0) as total
        FROM donations
        WHERE member_id = ? 
        AND strftime('%m', date) = ? 
        AND strftime('%Y', date) = ?
      `).get(userId, month.toString().padStart(2, '0'), year.toString()).total;
      
      monthlyTrend.push(monthTotal);
    }
    
    // Combine all data
    const responseData = {
      donations,
      stats: {
        totalGiven: donationStats.totalGiven || 0,
        transactions: donationStats.transactions || 0,
        activeGivers: '-', // Not relevant for individual member
        churchesHelped,
        projectsFunded,
        kidsSponsored: Math.floor(donationStats.totalGiven / 200) || 0, // Simplified calculation
        mealsProvided: Math.floor(donationStats.totalGiven / 50) || 0,  // Simplified calculation
        badges,
        goal: settings.goal,
        recurring: settings.recurring,
        monthlyTrend,
        memberName: member.name || 'Member',
        memberAccountNumber: userId + 1000000,
        churchName: church ? church.church_name : 'No church linked'
      }
    };
    
    res.json(responseData);
  } catch (err) {
    console.error('Failed to fetch member dashboard:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard data', details: err.message });
  }
});

// --- MEMBER: Update Goal ---
app.post('/api/member/goal', requireMember, (req, res) => {
  try {
    const userId = req.user.user_id;
    const { goal } = req.body;
    
    if (!goal || isNaN(goal) || goal <= 0) {
      return res.status(400).json({ error: 'Invalid goal amount' });
    }
    
    // Check if settings exist
    const existingSettings = db.prepare(`
      SELECT id FROM member_settings WHERE member_id = ?
    `).get(userId);
    
    if (existingSettings) {
      // Update existing settings
      db.prepare(`
        UPDATE member_settings 
        SET goal = ? 
        WHERE member_id = ?
      `).run(goal, userId);
    } else {
      // Create new settings
      db.prepare(`
        INSERT INTO member_settings (member_id, goal)
        VALUES (?, ?)
      `).run(userId, goal);
    }
    
    res.json({ success: true, goal });
  } catch (err) {
    console.error('Failed to update member goal:', err);
    res.status(500).json({ error: 'Failed to update goal', details: err.message });
  }
});

// --- MEMBER: Update Recurring Settings ---
app.post('/api/member/recurring', requireMember, (req, res) => {
  try {
    const userId = req.user.user_id;
    const { enabled, type, amount } = req.body;
    
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'Invalid enabled status' });
    }
    
    if (enabled) {
      if (!type || !amount || isNaN(amount) || amount <= 0) {
        return res.status(400).json({ error: 'Invalid recurring settings' });
      }
    }
    
    // Check if settings exist
    const existingSettings = db.prepare(`
      SELECT id FROM member_settings WHERE member_id = ?
    `).get(userId);
    
    if (existingSettings) {
      // Update existing settings
      db.prepare(`
        UPDATE member_settings 
        SET recurring_enabled = ?,
            recurring_type = ?,
            recurring_amount = ?
        WHERE member_id = ?
      `).run(enabled ? 1 : 0, type, amount, userId);
    } else {
      // Create new settings
      db.prepare(`
        INSERT INTO member_settings (
          member_id, recurring_enabled, recurring_type, recurring_amount
        )
        VALUES (?, ?, ?, ?)
      `).run(userId, enabled ? 1 : 0, type, amount);
    }
    
    res.json({ 
      success: true, 
      recurring: { enabled, type, amount } 
    });
  } catch (err) {
    console.error('Failed to update recurring settings:', err);
    res.status(500).json({ error: 'Failed to update recurring settings', details: err.message });
  }
});