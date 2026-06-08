'use strict';
const jwt = require('jsonwebtoken');
const { findId } = require('./db');

const SECRET = process.env.JWT_SECRET || 'jobquest_secret_2026_dev';

function signToken(user) {
  return jwt.sign(
    { id: user.id, is_admin: user.is_admin },
    SECRET,
    { expiresIn: '30d' }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token manquant' });
  try {
    const payload = jwt.verify(token, SECRET);
    const user    = findId('users', payload.id);
    if (!user) return res.status(401).json({ error: 'Utilisateur introuvable' });
    req.user = user;
    next();
  } catch(_) {
    return res.status(401).json({ error: 'Token invalide' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Admin requis' });
  next();
}

module.exports = { signToken, authMiddleware, adminOnly, SECRET };
