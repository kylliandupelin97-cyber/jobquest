'use strict';
require('dotenv').config();
const express = require('express');
const cors    = require('cors');
const path    = require('path');

const routes  = require('./server/routes');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ──────────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// ─── Static files (admin panel) ──────────────────────────────────────────────
app.use('/admin', express.static(path.join(__dirname, 'admin')));

// ─── API routes ──────────────────────────────────────────────────────────────
app.use('/api', routes);

// ─── Health check ────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', app: 'JobQuest API', version: '1.0.0' }));

// ─── 404 ─────────────────────────────────────────────────────────────────────
app.use((_, res) => res.status(404).json({ error: 'Route introuvable' }));

// ─── Error handler ───────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Erreur interne du serveur' });
});

// ─── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n⚡ JobQuest Server running on http://localhost:${PORT}`);
  console.log(`📊 Admin Panel: http://localhost:${PORT}/admin`);
  console.log(`🔌 API Base:    http://localhost:${PORT}/api`);
  console.log(`🩺 Health:      http://localhost:${PORT}/health\n`);
});

module.exports = app;
