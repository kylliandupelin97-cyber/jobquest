// server/middleware/auth.js
const jwt = require("jsonwebtoken");
const db = require("../../db/database");

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token manquant" });
  }
  try {
    const decoded = jwt.verify(header.split(" ")[1], process.env.JWT_SECRET);
    const user = db.get("SELECT * FROM users WHERE id = ? AND is_banned = 0", [decoded.id]);
    if (!user) return res.status(401).json({ error: "Utilisateur introuvable ou banni" });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Token invalide" });
  }
}

function adminMiddleware(req, res, next) {
  authMiddleware(req, res, () => {
    if (!req.user.is_admin) return res.status(403).json({ error: "Accès admin requis" });
    next();
  });
}

module.exports = { authMiddleware, adminMiddleware };
