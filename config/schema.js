const { getDatabase } = require('./database');

/**
 * Creates database tables based on SQLite schema but adapted for PostgreSQL
 */
async function setupDatabase() {
  const db = getDatabase();
  
  if (db.type === 'postgres') {
    // PostgreSQL schema setup
    const client = await db.pg.connect();
    
    try {
      await client.query('BEGIN');
      
      // Users table
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          church_name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE,
          password TEXT NOT NULL,
          is_admin INTEGER DEFAULT 0,
          suspended INTEGER DEFAULT 0
        )
      `);
      
      // Check if admin user exists, if not create one
      const adminResult = await client.query("SELECT * FROM users WHERE email = $1 AND is_admin = 1", ['admin@churpay.com']);
      if (adminResult.rows.length === 0) {
        // Default admin password is 'admin123' - change in production!
        await client.query(`
          INSERT INTO users (church_name, email, password, is_admin)
          VALUES ('ChurPay Admin', 'admin@churpay.com', '$2a$10$mLK.rrdlvx9DCFb6Eck1t.TlltnGulepXnov3bBp5T.JwJ1p5kLry', 1)
        `);
        console.log('Admin user created');
      }

      // Add more tables as needed - convert from your SQLite schema
      // Churches table
      await client.query(`
        CREATE TABLE IF NOT EXISTS churches (
          id SERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE,
          phone TEXT,
          address TEXT,
          logo_url TEXT,
          verified INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Members table
      await client.query(`
        CREATE TABLE IF NOT EXISTS members (
          id SERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE,
          password TEXT NOT NULL,
          church_id INTEGER,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (church_id) REFERENCES churches(id)
        )
      `);

      // Projects table
      await client.query(`
        CREATE TABLE IF NOT EXISTS projects (
          id SERIAL PRIMARY KEY,
          title TEXT NOT NULL,
          description TEXT,
          goal_amount NUMERIC NOT NULL,
          current_amount NUMERIC DEFAULT 0,
          church_id INTEGER,
          image_url TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          end_date TIMESTAMP,
          FOREIGN KEY (church_id) REFERENCES churches(id)
        )
      `);

      // Transactions table
      await client.query(`
        CREATE TABLE IF NOT EXISTS transactions (
          id SERIAL PRIMARY KEY,
          amount NUMERIC NOT NULL,
          type TEXT NOT NULL,
          member_id INTEGER,
          church_id INTEGER,
          project_id INTEGER,
          reference TEXT,
          name TEXT,
          surname TEXT,
          receipt_url TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          FOREIGN KEY (member_id) REFERENCES members(id),
          FOREIGN KEY (church_id) REFERENCES churches(id),
          FOREIGN KEY (project_id) REFERENCES projects(id)
        )
      `);

      await client.query('COMMIT');
      console.log('PostgreSQL database tables created successfully');
    } catch (err) {
      await client.query('ROLLBACK');
      console.error('Error setting up PostgreSQL database tables:', err);
      throw err;
    } finally {
      client.release();
    }
  }
  // SQLite setup stays the same since we're already creating tables in index.js
}

module.exports = {
  setupDatabase
};
