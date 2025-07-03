const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const nodemailer = require('nodemailer');
const adminRoutes = require('./routes/admin');

const app = express();

// --- Force 200 for all OPTIONS preflight requests ---
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin) || !origin) {
    res.header('Access-Control-Allow-Origin', origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');

    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }

    next();
  } else {
    return res.status(403).send('Not allowed by CORS');
  }
});

// --- CORS setup ---
const allowedOrigins = [
  'http://localhost:3000',
  'https://churpay-web.onrender.com',
  'https://uat.churpay.com', // Only the correct UAT domain
  ...(process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',').map(o => o.trim()) : [])
];
const corsOptions = {
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions), (req, res) => {
  res.sendStatus(200);
});
app.use(express.json());

// --- Set up SQLite DB ---
const db = new sqlite3.Database(process.env.DB_PATH || './churpay.db', (err) => {
  if (err) return console.error('Database error:', err.message);
  console.log('Connected to ChurPay SQLite database.');
});

// --- Create users table if not exists ---
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  church_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL
  
)`);
// --- Add donor_name and donor_email columns if not exist ---
db.run(`ALTER TABLE project_donations ADD COLUMN donor_name TEXT`, err => {});
db.run(`ALTER TABLE project_donations ADD COLUMN donor_email TEXT`, err => {});

// --- Add is_admin and suspended columns if not exist ---
db.run(`ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0`, err => {});
db.run(`ALTER TABLE users ADD COLUMN suspended INTEGER DEFAULT 0`, err => {});

// --- Create transactions table if not exists ---
db.run(`CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  name TEXT NOT NULL,
  amount TEXT NOT NULL,
  status TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`);

// --- Simple health route ---
app.get('/', (req, res) => {
  res.json({ message: 'ChurPay backend API is working! 🎉' });
});

const PORT = process.env.PORT || 5000;

// --- JWT secret for authentication ---
const JWT_SECRET = process.env.JWT_SECRET || 'churpay_secret';

// --- Register New Church/User ---
app.post('/api/register', async (req, res) => {
  const { church_name, email, password } = req.body;
  if (!church_name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save to database
    db.run(
      'INSERT INTO users (church_name, email, password) VALUES (?, ?, ?)',
      [church_name, email, hashedPassword],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ message: 'Email already exists.' });
          }
          return res.status(500).json({ message: 'Database error.', error: err.message });
        }
        res.status(201).json({ message: 'Registration successful!', user_id: this.lastID });
      }
    );
  } catch (err) {
    res.status(500).json({ message: 'Server error.', error: err.message });
  }
});

// --- Login Church/User ---
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ message: 'All fields required.' });

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.status(500).json({ message: 'Database error.' });
    if (!user) return res.status(400).json({ message: 'Invalid credentials.' });

    // Block suspended users
    if (user.suspended) {
      return res.status(403).json({ message: 'This church account is suspended. Please contact admin.' });
    }

    try {
      // Compare hashed password
      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return res.status(400).json({ message: 'Invalid credentials.' });

      // Generate JWT token
      const token = jwt.sign(
        { user_id: user.id, church_name: user.church_name },
        JWT_SECRET,
        { expiresIn: '12h' }
      );
      res.json({ message: 'Login successful!', token, church_name: user.church_name });
    } catch (err) {
      res.status(500).json({ message: 'Server error.', error: err.message });
    }
  });
});

// --- Add New Transaction ---
app.post('/api/transactions', (req, res) => {
  const { token, date, name, amount, status } = req.body;
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    db.run(
      `INSERT INTO transactions (user_id, date, name, amount, status) VALUES (?, ?, ?, ?, ?)`,
      [user.user_id, date, name, amount, status],
      function (err) {
        if (err) return res.status(500).json({ message: 'Database error.' });
        res.status(201).json({ message: 'Transaction saved!' });
      }
    );
  });
});

// --- Get All Transactions for Logged-in User ---
app.post('/api/my-transactions', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    db.all(
      `SELECT date, name, amount, status FROM transactions WHERE user_id = ? ORDER BY date DESC, id DESC`,
      [user.user_id],
      (err, rows) => {
        if (err) return res.status(500).json({ message: 'Database error.' });
        res.json(rows);
      }
    );
  });
});

// --- Get stats for dashboard ---
app.post('/api/dashboard-stats', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });

    db.all(
      `SELECT amount, date FROM transactions WHERE user_id = ? AND status = "Success"`,
      [user.user_id],
      (err, rows) => {
        if (err) return res.status(500).json({ message: 'Database error.' });

        // Calculate total and by month
        let total = 0;
        let byMonth = {};
        rows.forEach(tx => {
          const amt = Number(tx.amount.replace(/[^\d.]/g, ""));
          total += amt;
          const month = tx.date.slice(0, 7); // "YYYY-MM"
          byMonth[month] = (byMonth[month] || 0) + amt;
        });
        res.json({ total, byMonth });
      }
    );
  });
});

// --- Admin: Get all churches ---
app.post('/api/admin/churches', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err || !user) return res.status(403).json({ message: 'Invalid token.' });
    // Only allow admin
    db.get('SELECT is_admin FROM users WHERE id = ?', [user.user_id], (err, admin) => {
      if (err || !admin || !admin.is_admin) return res.status(403).json({ message: 'Not allowed.' });

      db.all('SELECT id, church_name, email, suspended FROM users WHERE is_admin = 0', [], (err, rows) => {
        if (err) return res.status(500).json({ message: 'Database error.' });
        res.json(rows);
      });
    });
  });
});

// --- Admin: Get all transactions ---
app.post('/api/admin/transactions', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err || !user) return res.status(403).json({ message: 'Invalid token.' });
    db.get('SELECT is_admin FROM users WHERE id = ?', [user.user_id], (err, admin) => {
      if (err || !admin || !admin.is_admin) return res.status(403).json({ message: 'Not allowed.' });

      db.all(
        `SELECT t.*, u.church_name FROM transactions t
         JOIN users u ON t.user_id = u.id
         ORDER BY t.date DESC, t.id DESC`,
        [],
        (err, rows) => {
          if (err) return res.status(500).json({ message: 'Database error.' });
          res.json(rows);
        }
      );
    });
  });
});

// --- Admin: Suspend a church ---
app.post('/api/admin/suspend-church', (req, res) => {
  const { token, church_id } = req.body;
  if (!token || !church_id) return res.status(400).json({ message: 'Token and church ID required.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    db.get('SELECT is_admin FROM users WHERE id = ?', [user.user_id], (err, admin) => {
      if (err || !admin || !admin.is_admin) return res.status(403).json({ message: 'Not allowed.' });

      db.run('UPDATE users SET suspended = 1 WHERE id = ?', [church_id], function (err) {
        if (err) return res.status(500).json({ message: 'Error suspending church.' });
        res.json({ message: 'Church suspended.' });
      });
    });
  });
});

// --- Admin: Reactivate a church ---
app.post('/api/admin/reactivate-church', (req, res) => {
  const { token, church_id } = req.body;
  if (!token || !church_id) return res.status(400).json({ message: 'Token and church ID required.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    db.get('SELECT is_admin FROM users WHERE id = ?', [user.user_id], (err, admin) => {
      if (err || !admin || !admin.is_admin) return res.status(403).json({ message: 'Not allowed.' });

      db.run('UPDATE users SET suspended = 0 WHERE id = ?', [church_id], function (err) {
        if (err) return res.status(500).json({ message: 'Error reactivating church.' });
        res.json({ message: 'Church reactivated.' });
      });
    });
  });
});

// --- Make a user admin (run once, then comment out or remove for safety) ---
// db.run('UPDATE users SET is_admin = 1 WHERE email = "youremail@domain.com"');
// --- Create projects table if not exists ---
db.run(`CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  church_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  goal_amount REAL,
  image_url TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(church_id) REFERENCES users(id)
)`);
// --- Public: Get all projects ---
app.get('/api/projects', (req, res) => {
  db.all(
    `SELECT p.*, u.church_name FROM projects p JOIN users u ON p.church_id = u.id ORDER BY p.created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ message: 'DB error.' });
      res.json(rows);
    }
  );
});
// --- Church: Create a new project ---
app.post('/api/church/create-project', (req, res) => {
  const { token, title, description, goal_amount, image_url } = req.body;
  if (!token || !title || !description) return res.status(400).json({ message: 'Missing info.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });

    db.run(
      `INSERT INTO projects (church_id, title, description, goal_amount, image_url) VALUES (?, ?, ?, ?, ?)`,
      [user.user_id, title, description, goal_amount || null, image_url || null],
      function (err) {
        if (err) return res.status(500).json({ message: 'DB error.' });
        res.json({ message: 'Project created!', project_id: this.lastID });
      }
    );
  });
});
app.post('/api/give', (req, res) => {
  const { project_id, amount, donor_name, donor_email } = req.body;
  if (!project_id || !amount) return res.status(400).json({ message: "Missing info." });

  db.run(
    `INSERT INTO project_donations (project_id, amount, date, status, donor_name, donor_email)
     VALUES (?, ?, datetime('now'), ?, ?, ?)`,
    [project_id, amount, "Success", donor_name || null, donor_email || null],
    function (err) {
      if (err) return res.status(500).json({ message: "DB error." });

      // ---- Mailgun Email Sending Block ----
      if (donor_email) {
        db.get('SELECT title FROM projects WHERE id = ?', [project_id], (err, project) => {
          const projectTitle = (project && project.title) || 'this project';
          const emailData = {
            from: 'ChurPay <noreply@YOUR_REAL_MAILGUN_DOMAIN>',
            to: donor_email,
            subject: 'Thank You for Your Gift!',
            html: `
              <h2>Thank you for supporting ${projectTitle}!</h2>
              <p>Dear ${donor_name || "Friend"},</p>
              <p>We appreciate your gift of <b>R${amount}</b>.</p>
              <p>Together, we're making a difference.</p>
              <br>
              <small>This receipt was auto-generated by ChurPay.</small>
            `
          };
          mg.messages().send(emailData, function (error, body) {
            if (error) console.log("Mailgun error:", error);
            else console.log("Mailgun sent:", body);
          });
        });
      }
      // ---- End Mailgun Block ----

      res.json({ message: "Gift received!" });
    }
  );
});
// --- Get donation totals per project ---
app.get('/api/project-donations-totals', (req, res) => {
  db.all(
    `SELECT project_id, SUM(amount) as total_raised FROM project_donations GROUP BY project_id`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "DB error." });
      // returns: [ { project_id: 2, total_raised: 1000 }, ... ]
      res.json(rows);
    }
  );
});
// --- Get recent donors for a project ---
app.get('/api/project-donors/:project_id', (req, res) => {
  const { project_id } = req.params;
  db.all(
    `SELECT donor_name, amount, date FROM project_donations WHERE project_id = ? ORDER BY date DESC LIMIT 5`,
    [project_id],
    (err, rows) => {
      if (err) return res.status(500).json({ message: "DB error." });
      res.json(rows);
    }
  );
});

app.use('/api/admin', adminRoutes);
app.listen(PORT, () => console.log(`ChurPay backend running on port ${PORT}`));

// --- Register New Member ---
app.post('/api/register-member', async (req, res) => {
  const { church_name, email, password } = req.body;
  if (!church_name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required.' });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save to database
    db.run(
      'INSERT INTO users (church_name, email, password) VALUES (?, ?, ?)',
      [church_name, email, hashedPassword],
      function (err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ message: 'Email already exists.' });
          }
          return res.status(500).json({ message: 'Database error.', error: err.message });
        }
        res.status(201).json({ message: 'Registration successful!', user_id: this.lastID });
      }
    );
  } catch (err) {
    res.status(500).json({ message: 'Server error.', error: err.message });
  }
});
// --- Approve Payout Request ---
app.post('/api/admin/approve-payout', (req, res) => {
  const { token, payout_id } = req.body;
  if (!token || !payout_id) return res.status(400).json({ message: 'Missing info.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    db.get('SELECT is_admin FROM users WHERE id = ?', [user.user_id], (err, admin) => {
      if (err || !admin || !admin.is_admin) return res.status(403).json({ message: 'Not allowed.' });
      db.get('SELECT * FROM payout_requests WHERE id = ?', [payout_id], (err, payout) => {
        if (err || !payout) return res.status(404).json({ message: 'Payout not found.' });
        db.run('UPDATE payout_requests SET status = "approved" WHERE id = ?', [payout_id], function (err) {
          if (err) return res.status(500).json({ message: 'DB error.' });
          db.get('SELECT email FROM users WHERE id = ?', [payout.church_id], (err, row) => {
            if (row && row.email) {
              transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: row.email,
                subject: "Churpay: Payout Approved",
                html: `
                  <h2>Payout Approved!</h2>
                  <p>Your payout request of <b>R${payout.amount}</b> has been approved and will be processed soon.</p>
                  <p>Thank you for using Churpay!</p>
                `
              }, (err, info) => {
                if (err) console.log("Email send error:", err);
                else console.log("Payout approval email sent:", info.response);
              });
            }
          });
          res.json({ message: 'Payout marked as approved.' });
        });
      });
    });
  });
});

// --- Reject Payout Request ---
app.post('/api/admin/reject-payout', (req, res) => {
  const { token, payout_id } = req.body;
  if (!token || !payout_id) return res.status(400).json({ message: 'Missing info.' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    db.get('SELECT is_admin FROM users WHERE id = ?', [user.user_id], (err, admin) => {
      if (err || !admin || !admin.is_admin) return res.status(403).json({ message: 'Not allowed.' });
      db.get('SELECT * FROM payout_requests WHERE id = ?', [payout_id], (err, payout) => {
        if (err || !payout) return res.status(404).json({ message: 'Payout not found.' });
        db.run('UPDATE payout_requests SET status = "rejected" WHERE id = ?', [payout_id], function (err) {
          if (err) return res.status(500).json({ message: 'DB error.' });
          db.get('SELECT email FROM users WHERE id = ?', [payout.church_id], (err, row) => {
            if (row && row.email) {
              transporter.sendMail({
                from: process.env.EMAIL_USER,
                to: row.email,
                subject: "Churpay: Payout Rejected",
                html: `
                  <h2>Payout Rejected</h2>
                  <p>Your payout request of <b>R${payout.amount}</b> has been rejected by admin.</p>
                  <p>If you have questions, please contact support.</p>
                `
              }, (err, info) => {
                if (err) console.log("Email send error:", err);
                else console.log("Payout rejection email sent:", info.response);
              });
            }
          });
          res.json({ message: 'Payout marked as rejected.' });
        });
      });
    });
  });
});
// --- Admin: Get all payout requests ---
app.post('/api/admin/payout-requests', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    db.get('SELECT is_admin FROM users WHERE id = ?', [user.user_id], (err, admin) => {
      if (err || !admin || !admin.is_admin) return res.status(403).json({ message: 'Not allowed.' });

      db.all(
        `SELECT p.*, u.church_name, u.email 
         FROM payout_requests p
         JOIN users u ON p.church_id = u.id
         ORDER BY p.date DESC, p.id DESC`,
        [],
        (err, rows) => {
          if (err) return res.status(500).json({ message: 'Database error.' });
          res.json(rows);
        }
      );
    });
  });
});
app.post('/api/church/payout-requests', (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: 'No token provided.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });

    db.all(
      `SELECT * FROM payout_requests WHERE church_id = ? ORDER BY date DESC, id DESC`,
      [user.user_id],
      (err, rows) => {
        if (err) return res.status(500).json({ message: 'Database error.' });
        res.json(rows);
      }
    );
  });
});