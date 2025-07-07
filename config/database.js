const { Pool } = require('pg');
const SQLite = require('better-sqlite3');
require('dotenv').config();

// Detect environment
const isRenderEnvironment = process.env.RENDER === 'true';
const isProduction = process.env.NODE_ENV === 'production';

// Database configuration
let db;
let pgPool;

// PostgreSQL configuration
if (isRenderEnvironment || isProduction) {
  // Use PostgreSQL in production or on Render
  pgPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
      rejectUnauthorized: false // Required for Render PostgreSQL
    }
  });
  
  // Test the PostgreSQL connection
  pgPool.connect()
    .then(client => {
      console.log('Connected to PostgreSQL database');
      client.release();
    })
    .catch(err => {
      console.error('Error connecting to PostgreSQL:', err);
      process.exit(1);
    });
} else {
  // Use SQLite for local development
  try {
    db = new SQLite(process.env.DB_PATH || './churpay.db');
    console.log('Connected to SQLite database');
  } catch (err) {
    console.error('Failed to connect to SQLite database:', err.message);
    process.exit(1);
  }
}

// Helper function to determine which database to use
function getDatabase() {
  if (isRenderEnvironment || isProduction) {
    return { type: 'postgres', pg: pgPool };
  } else {
    return { type: 'sqlite', sqlite: db };
  }
}

module.exports = {
  getDatabase
};
