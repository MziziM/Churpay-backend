const express = require('express');
const cors = require('cors');
const path = require('path');
const backendApi = require('./churpay-backend/index');

const app = express();

// Enable CORS
app.use(cors());

// Parse JSON bodies
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// API routes
app.use('/api', backendApi);

// Static files
app.use(express.static(path.join(__dirname, 'build')));

// SPA fallback - this should be after all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ChurPay server running on port ${PORT}`);
});
