const express = require('express');
const path = require('path');
require('dotenv').config();

// Import your main router (assumes index.js exports a router)
const router = require('./index');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// API routes
app.use('/api', router);

// Serve static files from the React app (if you build frontend here)
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../build')));
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../build', 'index.html'));
  });
}

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`ChurPay server running on port ${PORT}`);
});
