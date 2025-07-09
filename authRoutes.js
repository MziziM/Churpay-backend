const express = require("express");
const router = express.Router();

// Example route
router.get("/test-auth", (req, res) => {
  res.json({ message: "Auth route working" });
});

module.exports = router;
