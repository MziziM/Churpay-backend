const express = require('express');
const router = express.Router();

// Always start with a "/" in the route path!
router.get('/health', (req, res) => res.json({ status: 'ok' }));

module.exports = router;