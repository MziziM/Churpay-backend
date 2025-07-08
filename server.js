<<<<<<< HEAD
=======
<<<<<<< HEAD

=======
>>>>>>> 2e0f7e0 (Add React build folder for deployment)
const express = require('express');
const cors = require('cors');
const path = require('path');
let backendApi;

try {
  backendApi = require('./index');
} catch (err) {
  console.error('Failed to load backend API (./index.js):', err);
  process.exit(1);
}

const fs = require('fs');
const app = express();

// Enable CORS
app.use(cors());

// Parse JSON bodies
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// API routes
app.use('/api', backendApi);

// Static files
const buildPath = path.join(__dirname, 'build');
if (!fs.existsSync(buildPath)) {
  console.error('ERROR: React build directory not found at', buildPath);
  console.error('Please ensure the React app is built and the build folder is present in the backend directory.');
  process.exit(1);
}
app.use(express.static(buildPath));

// SPA fallback - this should be after all other routes
app.get('*', (req, res) => {
  res.sendFile(path.join(buildPath, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`ChurPay server running on port ${PORT}`);
});
<<<<<<< HEAD
=======
>>>>>>> 1570770 (Add error handling for missing build directory and backendApi import in server.js)
>>>>>>> 2e0f7e0 (Add React build folder for deployment)
