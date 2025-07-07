const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const nodemailer = require('nodemailer');
const path = require('path');
const { getDatabase } = require('./config/database');
const { setupDatabase } = require('./config/schema');
const dataService = require('./services/dataService');

// Create router to be mounted on the main express server
const router = express.Router();

// --- DB SETUP ---
// Initialize database schema
(async function initDatabase() {
  try {
    console.log('Setting up database...');
    await setupDatabase();
    console.log('Database setup complete');
  } catch (err) {
    console.error('Failed to set up database schema:', err);
    console.error('The application will continue to run, but some features may not work properly');
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

const JWT_SECRET = process.env.JWT_SECRET || 'churpay_secret';

// --- REGISTER USER/CHURCH/MEMBER ---
router.post('/register', async (req, res) => {
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

// --- LOGIN ---
router.post('/login', async (req, res) => {
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

// --- GET ALL TRANSACTIONS FOR LOGGED-IN USER ---
router.post('/my-transactions', async (req, res) => {
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
router.post('/admin-register', async (req, res) => {
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
router.post('/admin-login', async (req, res) => {
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

// --- MIDDLEWARE: REQUIRE ADMIN ---
async function requireAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided.' });
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') 
    return res.status(401).json({ error: 'Invalid Authorization header format.' });
  
  const token = parts[1];
  if (!token) return res.status(401).json({ error: 'No token provided.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const users = await dataService.query('SELECT is_admin FROM users WHERE id = $1', [decoded.user_id]);
    const admin = users.length ? users[0] : null;
    
    if (!admin || !admin.is_admin) {
      return res.status(403).json({ error: 'Not allowed (not admin).' });
    }
    
    req.adminUser = decoded;
    next();
  } catch (err) {
    console.error('JWT verification error:', err);
    return res.status(403).json({ error: 'Invalid token.' });
  }
}

// --- MIDDLEWARE: REQUIRE MEMBER ---
async function requireMember(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No authorization header provided.' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') 
    return res.status(401).json({ error: 'Invalid authorization format.' });

  const token = parts[1];
  if (!token) return res.status(401).json({ error: 'No token provided.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('JWT verification error:', err);
    return res.status(403).json({ error: 'Invalid token.' });
  }
}

// --- ADMIN: Get All Transactions ---
router.get('/transactions', async (req, res) => {
  try {
    const transactions = await dataService.query('SELECT * FROM transactions ORDER BY date DESC, id DESC LIMIT 100');
    res.json(transactions);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch transactions', details: err.message });
  }
});

// --- ADMIN: GET DASHBOARD STATS ---
router.get('/admin/stats', requireAdmin, async (req, res) => {
  try {
    // Get counts and totals using data service
    const churchesResult = await dataService.query('SELECT COUNT(*) as count FROM users WHERE is_admin = 0');
    const churches = churchesResult[0].count;
    
    const membersResult = await dataService.query('SELECT COUNT(*) as count FROM users WHERE is_admin = 0');
    const members = membersResult[0].count;
    
    const transactionsResult = await dataService.query('SELECT COUNT(*) as count FROM transactions');
    const totalTransactions = transactionsResult[0].count;
    
    const revenueResult = await dataService.query('SELECT SUM(CAST(amount AS FLOAT)) as sum FROM transactions WHERE status = $1', ['Success']);
    const totalRevenue = revenueResult[0].sum || 0;
    
    res.json({
      churches,
      members,
      totalTransactions,
      totalRevenue
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to fetch admin stats', details: err.message });
  }
});

// --- ADMIN: GET ALL PAYOUT REQUESTS ---
router.get('/admin/payout-requests', requireAdmin, async (req, res) => {
  try {
    const requests = await dataService.query(`
      SELECT pr.*, u.church_name 
      FROM payout_requests pr 
      LEFT JOIN users u ON pr.church_id = u.id 
      ORDER BY pr.date DESC, pr.id DESC LIMIT 100
    `);
    res.json(requests);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch payout requests', details: err.message });
  }
});

// --- ADMIN: APPROVE/DENY PAYOUT REQUEST ---
router.post('/admin/payout-requests/:id/action', requireAdmin, async (req, res) => {
  const payoutId = req.params.id;
  const { action } = req.body;
  
  if (!['approve', 'deny'].includes(action)) {
    return res.status(400).json({ error: 'Invalid action. Must be approve or deny.' });
  }
  
  try {
    // Check if payout request exists and is pending
    const payoutResults = await dataService.query('SELECT * FROM payout_requests WHERE id = $1', [payoutId]);
    const payout = payoutResults.length ? payoutResults[0] : null;
    
    if (!payout) return res.status(404).json({ error: 'Payout request not found.' });
    if (payout.status !== 'pending') return res.status(400).json({ error: 'Payout request already processed.' });
    
    // Update status
    const newStatus = action === 'approve' ? 'approved' : 'denied';
    await dataService.query('UPDATE payout_requests SET status = $1 WHERE id = $2', [newStatus, payoutId]);
    
    res.json({ message: `Payout request ${action}d successfully.` });
  } catch (err) {
    res.status(500).json({ error: 'Failed to process payout request', details: err.message });
  }
});

// --- ADMIN: GET ALL CHURCHES ---
router.get('/admin/churches', requireAdmin, async (req, res) => {
  try {
    const churches = await dataService.query('SELECT id, church_name, email FROM users WHERE is_admin = 0');
    res.json(churches);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch churches', details: err.message });
  }
});

// --- ADMIN: ADD MEMBER ---
router.post('/admin/members', requireAdmin, async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password) return res.status(400).json({ message: 'All fields are required.' });
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const isAdmin = role === 'admin' ? 1 : 0;
    
    const result = await dataService.insert('users', {
      church_name: name,
      email,
      password: hashedPassword,
      is_admin: isAdmin
    });
    
    const userId = result.id || result.lastInsertRowid;
    res.status(201).json({ message: 'Member added successfully!', user_id: userId });
  } catch (err) {
    if (err.message && (err.message.includes('duplicate') || err.message.includes('UNIQUE'))) {
      return res.status(400).json({ message: 'Email already exists.' });
    }
    res.status(500).json({ message: 'Database error.', error: err.message });
  }
});

// --- ADMIN: GET ALL MEMBERS ---
router.get('/admin/members', requireAdmin, async (req, res) => {
  try {
    const members = await dataService.query('SELECT id, church_name, email FROM users WHERE is_admin = 0');
    res.json(members);
  } catch (err) {
    console.error('Failed to fetch members:', err);
    res.status(500).json({ error: 'Failed to fetch members', details: err.message });
  }
});

// --- ADMIN: GET ALL PROJECTS ---
router.get('/admin/projects', requireAdmin, async (req, res) => {
  try {
    const projects = await dataService.query(`
      SELECT p.*, u.church_name 
      FROM projects p 
      LEFT JOIN users u ON p.church_id = u.id 
      ORDER BY p.created_at DESC, p.id DESC
    `);
    res.json(projects);
  } catch (err) {
    console.error('Failed to fetch projects:', err);
    res.status(500).json({ error: 'Failed to fetch projects', details: err.message });
  }
});

// --- MEMBER: Get Dashboard Data ---
router.get('/member/dashboard', requireMember, async (req, res) => {
  try {
    const userId = req.user.user_id;
    
    // Get member info
    const memberResults = await dataService.query(`
      SELECT id, name, email, church_id 
      FROM members 
      WHERE id = $1
    `, [userId]);
    
    const member = memberResults.length ? memberResults[0] : null;
    
    if (!member) {
      return res.status(404).json({ error: 'Member not found' });
    }
    
    // Get church info
    let church = null;
    if (member.church_id) {
      const churchResults = await dataService.query(`
        SELECT church_name
        FROM users 
        WHERE id = $1
      `, [member.church_id]);
      
      church = churchResults.length ? churchResults[0] : null;
    }
    
    // Get donations
    const donations = await dataService.query(`
      SELECT d.id, d.amount, d.date, p.title as project
      FROM donations d
      LEFT JOIN projects p ON d.project_id = p.id
      WHERE d.member_id = $1
      ORDER BY d.date DESC
    `, [userId]);
    
    // Calculate statistics
    const donationStatsResults = await dataService.query(`
      SELECT SUM(amount) as totalGiven, COUNT(*) as transactions
      FROM donations
      WHERE member_id = $1
    `, [userId]);
    
    const donationStats = donationStatsResults[0] || { totalGiven: 0, transactions: 0 };
    
    // Get member profile settings
    const memberSettingsResults = await dataService.query(`
      SELECT goal, 
             recurring_enabled as "recurring.enabled", 
             recurring_type as "recurring.type", 
             recurring_amount as "recurring.amount"
      FROM member_settings
      WHERE member_id = $1
    `, [userId]);
    
    // Default settings if none exist
    const settings = memberSettingsResults.length ? memberSettingsResults[0] : {
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
    
    // Calculate impact statistics
    const churchesHelpedResults = await dataService.query(`
      SELECT COUNT(DISTINCT p.church_id) as count
      FROM donations d
      JOIN projects p ON d.project_id = p.id
      WHERE d.member_id = $1
    `, [userId]);
    
    const churchesHelped = churchesHelpedResults[0].count || 0;
    
    const projectsFundedResults = await dataService.query(`
      SELECT COUNT(DISTINCT project_id) as count
      FROM donations
      WHERE member_id = $1
    `, [userId]);
    
    const projectsFunded = projectsFundedResults[0].count || 0;
    
    // Monthly trend (last 6 months)
    const monthlyTrend = [];
    
    for (let i = 5; i >= 0; i--) {
      const date = new Date();
      date.setMonth(date.getMonth() - i);
      const month = date.getMonth() + 1;
      const year = date.getFullYear();
      
      // Adapt the date format extraction for PostgreSQL compatibility
      let dateFormat;
      const dbInfo = getDatabase();
      if (dbInfo.type === 'postgres') {
        dateFormat = `
          SELECT COALESCE(SUM(amount), 0) as total
          FROM donations
          WHERE member_id = $1 
          AND EXTRACT(MONTH FROM date) = $2 
          AND EXTRACT(YEAR FROM date) = $3
        `;
      } else {
        dateFormat = `
          SELECT COALESCE(SUM(amount), 0) as total
          FROM donations
          WHERE member_id = $1 
          AND strftime('%m', date) = $2 
          AND strftime('%Y', date) = $3
        `;
      }
      
      const monthTotalResults = await dataService.query(
        dateFormat, 
        [userId, month.toString().padStart(2, '0'), year.toString()]
      );
      
      const monthTotal = monthTotalResults.length ? monthTotalResults[0].total : 0;
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
router.post('/member/goal', requireMember, async (req, res) => {
  try {
    const userId = req.user.user_id;
    const { goal } = req.body;
    
    if (!goal || isNaN(goal) || goal <= 0) {
      return res.status(400).json({ error: 'Invalid goal amount' });
    }
    
    // Check if settings exist
    const existingSettingsResults = await dataService.query(`
      SELECT id FROM member_settings WHERE member_id = $1
    `, [userId]);
    
    const existingSettings = existingSettingsResults.length ? existingSettingsResults[0] : null;
    
    if (existingSettings) {
      // Update existing settings
      await dataService.query(`
        UPDATE member_settings 
        SET goal = $1 
        WHERE member_id = $2
      `, [goal, userId]);
    } else {
      // Create new settings
      await dataService.insert('member_settings', {
        member_id: userId,
        goal
      });
    }
    
    res.json({ success: true, goal });
  } catch (err) {
    console.error('Failed to update member goal:', err);
    res.status(500).json({ error: 'Failed to update goal', details: err.message });
  }
});

// --- MEMBER: Update Recurring Settings ---
router.post('/member/recurring', requireMember, async (req, res) => {
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
    const existingSettingsResults = await dataService.query(`
      SELECT id FROM member_settings WHERE member_id = $1
    `, [userId]);
    
    const existingSettings = existingSettingsResults.length ? existingSettingsResults[0] : null;
    
    if (existingSettings) {
      // Update existing settings
      await dataService.query(`
        UPDATE member_settings 
        SET recurring_enabled = $1,
            recurring_type = $2,
            recurring_amount = $3
        WHERE member_id = $4
      `, [enabled ? 1 : 0, type, amount, userId]);
    } else {
      // Create new settings
      await dataService.insert('member_settings', {
        member_id: userId,
        recurring_enabled: enabled ? 1 : 0,
        recurring_type: type,
        recurring_amount: amount
      });
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

module.exports = router;
