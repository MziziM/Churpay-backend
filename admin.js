const express = require("express");
const router = express.Router();
const db = require("../db"); // adjust this path if your db file is somewhere else

// Refund Transaction Route
router.post("/api/admin/refund-transaction", async (req, res) => {
  try {
    const { token, transaction_id } = req.body;

    // 1. Authenticate admin
    const admin = await db.get("SELECT * FROM admins WHERE token=?", [token]);
    if (!admin) return res.status(401).json({ error: "Unauthorized" });

    // 2. Get transaction
    const tx = await db.get("SELECT * FROM transactions WHERE id=?", [transaction_id]);
    if (!tx) return res.status(404).json({ error: "Transaction not found" });

    // 3. Check if already refunded
    if (tx.status === "Refunded") return res.json({ ok: true, msg: "Already refunded" });

    // 4. Mark as refunded
    await db.run(
      "UPDATE transactions SET status='Refunded', refund_admin=?, refund_date=datetime('now') WHERE id=?",
      [admin.id, transaction_id]
    );

    // 5. Log action in activity log
    await db.run(
      "INSERT INTO activity_log (admin, action, details, timestamp) VALUES (?, ?, ?, datetime('now'))",
      [admin.username, "Refunded Transaction", `TxID: ${transaction_id}`]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error("Refund error:", err);
    res.status(500).json({ error: "Refund failed" });
  }
});

module.exports = router;