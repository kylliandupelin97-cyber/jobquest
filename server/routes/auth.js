// server/routes/auth.js
const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const db = require("../../db/database");
const { authMiddleware } = require("../middleware/auth");

// POST /api/auth/register
router.post("/register", async (req, res) => {
  try {
    const { username, email, password, location_allowed, location_lat, location_lng } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ error: "Champs obligatoires manquants" });
    if (password.length < 6)
      return res.status(400).json({ error: "Mot de passe trop court (min 6 caractères)" });

    const exists = db.get("SELECT id FROM users WHERE email = ? OR username = ?", [email, username]);
    if (exists) return res.status(409).json({ error: "Email ou pseudo déjà utilisé" });

    const hash = bcrypt.hashSync(password, 10);
    const id = uuidv4();
    db.run(
      `INSERT INTO users (id, username, email, password, location_allowed, location_lat, location_lng) VALUES (?,?,?,?,?,?,?)`,
      [id, username, email, hash, location_allowed ? 1 : 0, location_lat || null, location_lng || null]
    );

    const token = jwt.sign({ id, email, is_admin: 0 }, process.env.JWT_SECRET, { expiresIn: "30d" });
    const user = db.get("SELECT id, username, email, rank, stars_avg, wallet_balance, is_admin, badges, pseudo_color, is_certified FROM users WHERE id = ?", [id]);
    res.status(201).json({ token, user });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/login
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Champs manquants" });

    const user = db.get("SELECT * FROM users WHERE email = ?", [email]);
    if (!user) return res.status(401).json({ error: "Email ou mot de passe incorrect" });
    if (user.is_banned) return res.status(403).json({ error: "Compte banni" });

    const valid = bcrypt.compareSync(password, user.password);
    if (!valid) return res.status(401).json({ error: "Email ou mot de passe incorrect" });

    const token = jwt.sign({ id: user.id, email: user.email, is_admin: user.is_admin }, process.env.JWT_SECRET, { expiresIn: "30d" });
    const { password: _, ...safeUser } = user;
    res.json({ token, user: safeUser });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/auth/me
router.get("/me", authMiddleware, (req, res) => {
  const { password: _, ...safeUser } = req.user;
  res.json(safeUser);
});

// PUT /api/auth/update
router.put("/update", authMiddleware, (req, res) => {
  const { username, bio, pseudo_color, active_badge } = req.body;
  db.run(
    `UPDATE users SET username=COALESCE(?,username), bio=COALESCE(?,bio), pseudo_color=COALESCE(?,pseudo_color), active_badge=COALESCE(?,active_badge), updated_at=datetime('now') WHERE id=?`,
    [username, bio, pseudo_color, active_badge, req.user.id]
  );
  res.json({ success: true });
});

module.exports = router;
