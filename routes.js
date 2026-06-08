'use strict';
const express  = require('express');
const bcrypt   = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const router   = express.Router();

const db       = require('./db');
const { signToken, authMiddleware, adminOnly } = require('./auth');

// ─── Helpers ─────────────────────────────────────────────────────────────────
const ok  = (res, data, code = 200) => res.status(code).json({ ok: true, ...data });
const err = (res, msg, code = 400)  => res.status(code).json({ ok: false, error: msg });
const sanitizeUser = u => {
  const { password, ...rest } = u;
  return rest;
};

// ════════════════════════════════════════════════════════════════════════════
// AUTH
// ════════════════════════════════════════════════════════════════════════════
// POST /api/auth/register
router.post('/auth/register', (req, res) => {
  const { username, email, password, geo_allowed, lat, lng } = req.body;
  if (!username || !email || !password)
    return err(res, 'Champs requis manquants');
  if (db.find('users', u => u.email === email))
    return err(res, 'Email déjà utilisé');

  const hash = bcrypt.hashSync(password, 10);
  const user = db.insert('users', {
    username, email,
    password:      hash,
    is_admin:      false,
    is_certified:  false,
    can_live:      false,
    can_color:     false,
    in_top100:     false,
    rank:          9999,
    avg_rating:    0,
    rating_count:  0,
    total_earned:  0,
    wallet:        0,
    wallet_cash:   0,
    badges:        [],
    profile_color: '#ffffff',
    geo_allowed:   !!geo_allowed,
    location:      geo_allowed && lat && lng ? { lat: +lat, lng: +lng } : null,
    bio:           '',
    avatar_color:  `hsl(${Math.floor(Math.random()*360)},60%,50%)`,
  });

  const token = signToken(user);
  ok(res, { token, user: sanitizeUser(user) }, 201);
});

// POST /api/auth/login
router.post('/auth/login', (req, res) => {
  const { email, password } = req.body;
  const user = db.find('users', u => u.email === email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return err(res, 'Email ou mot de passe incorrect', 401);

  const token = signToken(user);
  ok(res, { token, user: sanitizeUser(user) });
});

// GET /api/auth/me
router.get('/auth/me', authMiddleware, (req, res) => {
  ok(res, { user: sanitizeUser(req.user) });
});

// ════════════════════════════════════════════════════════════════════════════
// USERS
// ════════════════════════════════════════════════════════════════════════════
// GET /api/users/:id
router.get('/users/:id', authMiddleware, (req, res) => {
  const user = db.findId('users', req.params.id);
  if (!user) return err(res, 'Utilisateur introuvable', 404);
  ok(res, { user: sanitizeUser(user) });
});

// PATCH /api/users/me  — update own profile
router.patch('/users/me', authMiddleware, (req, res) => {
  const allowed = ['username', 'bio', 'geo_allowed', 'location', 'profile_color'];
  const patch = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) patch[k] = req.body[k]; });
  // color lock
  if (patch.profile_color && !req.user.can_color) {
    delete patch.profile_color;
  }
  const updated = db.update('users', req.user.id, patch);
  ok(res, { user: sanitizeUser(updated) });
});

// ════════════════════════════════════════════════════════════════════════════
// MISSIONS
// ════════════════════════════════════════════════════════════════════════════
// GET /api/missions   ?lat=&lng=&radius=km
router.get('/missions', authMiddleware, (req, res) => {
  let missions = db.all('missions');
  // geo filter
  if (req.query.lat && req.query.lng) {
    const { lat, lng, radius = 10 } = req.query;
    missions = missions.filter(m => {
      if (!m.location) return true;
      const d = haversine(+lat, +lng, m.location.lat, m.location.lng);
      return d <= +radius;
    });
  }
  // enrich owner name
  missions = missions.map(m => {
    const owner = db.findId('users', m.owner_id);
    return { ...m, owner_name: owner?.username || '?' };
  });
  ok(res, { missions });
});

// GET /api/missions/:id
router.get('/missions/:id', authMiddleware, (req, res) => {
  const m = db.findId('missions', req.params.id);
  if (!m) return err(res, 'Mission introuvable', 404);
  const owner = db.findId('users', m.owner_id);
  ok(res, { mission: { ...m, owner_name: owner?.username || '?' } });
});

// POST /api/missions
router.post('/missions', authMiddleware, (req, res) => {
  const { title, description, price, location, tags, available } = req.body;
  if (!title || !price) return err(res, 'Titre et prix requis');
  const mission = db.insert('missions', {
    title, description: description || '',
    price: +price, location: location || null,
    tags: tags || [],
    available: available !== false,
    owner_id: req.user.id,
    status: 'open',
  });
  ok(res, { mission }, 201);
});

// PATCH /api/missions/:id
router.patch('/missions/:id', authMiddleware, (req, res) => {
  const m = db.findId('missions', req.params.id);
  if (!m) return err(res, 'Mission introuvable', 404);
  if (m.owner_id !== req.user.id && !req.user.is_admin)
    return err(res, 'Non autorisé', 403);
  const allowed = ['title','description','price','location','tags','available','status'];
  const patch = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) patch[k] = req.body[k]; });
  const updated = db.update('missions', m.id, patch);
  ok(res, { mission: updated });
});

// DELETE /api/missions/:id
router.delete('/missions/:id', authMiddleware, (req, res) => {
  const m = db.findId('missions', req.params.id);
  if (!m) return err(res, 'Mission introuvable', 404);
  if (m.owner_id !== req.user.id && !req.user.is_admin)
    return err(res, 'Non autorisé', 403);
  db.remove('missions', m.id);
  ok(res, { deleted: true });
});

// ════════════════════════════════════════════════════════════════════════════
// APPLICATIONS (Postuler)
// ════════════════════════════════════════════════════════════════════════════
// POST /api/missions/:id/apply
router.post('/missions/:id/apply', authMiddleware, (req, res) => {
  const mission = db.findId('missions', req.params.id);
  if (!mission) return err(res, 'Mission introuvable', 404);
  if (mission.owner_id === req.user.id)
    return err(res, 'Vous ne pouvez pas postuler à votre propre mission');
  const existing = db.find('applications', a =>
    a.mission_id === mission.id && a.applicant_id === req.user.id
  );
  if (existing) return err(res, 'Candidature déjà envoyée');

  const app = db.insert('applications', {
    mission_id:   mission.id,
    applicant_id: req.user.id,
    status:       'pending',
  });

  // Auto-create conversation + first message
  let conv = db.find('conversations', c =>
    c.mission_id === mission.id &&
    ((c.user_a === req.user.id && c.user_b === mission.owner_id) ||
     (c.user_b === req.user.id && c.user_a === mission.owner_id))
  );
  if (!conv) {
    conv = db.insert('conversations', {
      mission_id:    mission.id,
      user_a:        req.user.id,
      user_b:        mission.owner_id,
      accepted:      false,
      app_id:        app.id,
    });
  }
  db.insert('messages', {
    conv_id:   conv.id,
    sender_id: req.user.id,
    text:      `Bonjour, je suis intéressé(e) par votre mission "${mission.title}" et je souhaite postuler.`,
    system:    true,
  });

  // Notification au propriétaire
  db.insert('notifications', {
    user_id: mission.owner_id,
    type:    'new_application',
    text:    `${req.user.username} a postulé pour "${mission.title}"`,
    ref_id:  app.id,
    read:    false,
  });

  ok(res, { application: app, conversation: conv }, 201);
});

// GET /api/applications/mine
router.get('/applications/mine', authMiddleware, (req, res) => {
  const apps = db.all('applications', a => a.applicant_id === req.user.id);
  const enriched = apps.map(a => {
    const m = db.findId('missions', a.mission_id);
    return { ...a, mission: m };
  });
  ok(res, { applications: enriched });
});

// ════════════════════════════════════════════════════════════════════════════
// CONVERSATIONS & MESSAGES
// ════════════════════════════════════════════════════════════════════════════
// GET /api/conversations
router.get('/conversations', authMiddleware, (req, res) => {
  const convs = db.all('conversations', c =>
    c.user_a === req.user.id || c.user_b === req.user.id
  );
  const enriched = convs.map(c => {
    const other_id = c.user_a === req.user.id ? c.user_b : c.user_a;
    const other = db.findId('users', other_id);
    const mission = db.findId('missions', c.mission_id);
    const messages = db.all('messages', m => m.conv_id === c.id);
    const last = messages[messages.length - 1];
    return {
      ...c,
      other_user: other ? sanitizeUser(other) : null,
      mission_title: mission?.title,
      last_message: last || null,
      unread: messages.filter(m => !m.read && m.sender_id !== req.user.id).length,
    };
  });
  ok(res, { conversations: enriched });
});

// GET /api/conversations/:id/messages
router.get('/conversations/:id/messages', authMiddleware, (req, res) => {
  const conv = db.findId('conversations', req.params.id);
  if (!conv) return err(res, 'Conversation introuvable', 404);
  if (conv.user_a !== req.user.id && conv.user_b !== req.user.id)
    return err(res, 'Non autorisé', 403);

  // Mark as read
  db.db.messages
    .filter(m => m.conv_id === conv.id && m.sender_id !== req.user.id && !m.read)
    .forEach(m => db.update('messages', m.id, { read: true }));

  const messages = db.all('messages', m => m.conv_id === conv.id);
  ok(res, { messages, conversation: conv });
});

// POST /api/conversations/:id/messages
router.post('/conversations/:id/messages', authMiddleware, (req, res) => {
  const conv = db.findId('conversations', req.params.id);
  if (!conv) return err(res, 'Conversation introuvable', 404);
  if (conv.user_a !== req.user.id && conv.user_b !== req.user.id)
    return err(res, 'Non autorisé', 403);
  if (!conv.accepted && conv.user_a !== req.user.id)
    return err(res, 'Le propriétaire doit accepter la demande d\'abord');

  const { text } = req.body;
  if (!text?.trim()) return err(res, 'Message vide');

  const msg = db.insert('messages', {
    conv_id:   conv.id,
    sender_id: req.user.id,
    text:      text.trim(),
    read:      false,
    system:    false,
  });
  ok(res, { message: msg });
});

// POST /api/conversations/:id/accept  — owner accepts chat
router.post('/conversations/:id/accept', authMiddleware, (req, res) => {
  const conv = db.findId('conversations', req.params.id);
  if (!conv) return err(res, 'Conversation introuvable', 404);
  const mission = db.findId('missions', conv.mission_id);
  if (mission?.owner_id !== req.user.id)
    return err(res, 'Non autorisé', 403);
  db.update('conversations', conv.id, { accepted: true });

  db.insert('notifications', {
    user_id: conv.user_a,
    type:    'chat_accepted',
    text:    'Votre demande de messagerie a été acceptée.',
    ref_id:  conv.id,
    read:    false,
  });
  ok(res, { accepted: true });
});

// POST /api/conversations/:id/hire  — owner hires candidate
router.post('/conversations/:id/hire', authMiddleware, (req, res) => {
  const conv = db.findId('conversations', req.params.id);
  if (!conv) return err(res, 'Conversation introuvable', 404);
  const mission = db.findId('missions', conv.mission_id);
  if (mission?.owner_id !== req.user.id)
    return err(res, 'Non autorisé', 403);

  db.update('applications', conv.app_id, { status: 'accepted' });
  db.update('missions', mission.id, { status: 'in_progress', hired_user: conv.user_a });

  db.insert('notifications', {
    user_id: conv.user_a,
    type:    'hired',
    text:    `Vous avez été accepté(e) pour la mission "${mission.title}" !`,
    ref_id:  mission.id,
    read:    false,
  });

  // Add to in_progress on candidate account
  ok(res, { hired: true });
});

// ════════════════════════════════════════════════════════════════════════════
// RATINGS
// ════════════════════════════════════════════════════════════════════════════
// POST /api/ratings
router.post('/ratings', authMiddleware, (req, res) => {
  const { target_id, mission_id, stars, comment } = req.body;
  if (!target_id || !stars) return err(res, 'Champs requis');
  if (+stars < 1 || +stars > 5) return err(res, 'Note entre 1 et 5');

  const existing = db.find('ratings', r =>
    r.rater_id === req.user.id && r.mission_id === mission_id
  );
  if (existing) return err(res, 'Déjà noté pour cette mission');

  const rating = db.insert('ratings', {
    rater_id:  req.user.id,
    target_id,
    mission_id: mission_id || null,
    stars:     +stars,
    comment:   comment || '',
  });

  // Recompute avg_rating for target
  const allRatings = db.all('ratings', r => r.target_id === target_id);
  const avg = allRatings.reduce((s, r) => s + r.stars, 0) / allRatings.length;
  db.update('users', target_id, {
    avg_rating:   Math.round(avg * 100) / 100,
    rating_count: allRatings.length,
  });

  db.recomputeRankings();

  ok(res, { rating }, 201);
});

// GET /api/ratings/:user_id
router.get('/ratings/:user_id', authMiddleware, (req, res) => {
  const ratings = db.all('ratings', r => r.target_id === req.params.user_id);
  const enriched = ratings.map(r => {
    const rater = db.findId('users', r.rater_id);
    return { ...r, rater_name: rater?.username || '?' };
  });
  ok(res, { ratings: enriched });
});

// ════════════════════════════════════════════════════════════════════════════
// RANKING
// ════════════════════════════════════════════════════════════════════════════
router.get('/ranking', authMiddleware, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 100);
  const ranked = db.all('users', u => !u.is_admin)
    .sort((a, b) => (b.avg_rating || 0) - (a.avg_rating || 0))
    .slice(0, limit)
    .map((u, i) => ({
      rank:          i + 1,
      id:            u.id,
      username:      u.username,
      avg_rating:    u.avg_rating || 0,
      profile_color: u.profile_color,
      badges:        u.badges,
      is_certified:  u.is_certified,
      can_live:      u.can_live,
    }));
  ok(res, { ranking: ranked });
});

// ════════════════════════════════════════════════════════════════════════════
// WALLET & TRANSACTIONS
// ════════════════════════════════════════════════════════════════════════════
// GET /api/wallet
router.get('/wallet', authMiddleware, (req, res) => {
  const txs = db.all('transactions', t => t.user_id === req.user.id);
  ok(res, {
    wallet:       req.user.wallet || 0,
    wallet_cash:  req.user.wallet_cash || 0,
    total_earned: req.user.total_earned || 0,
    transactions: txs,
  });
});

// POST /api/wallet/declare-cash  — declare cash earned
router.post('/wallet/declare-cash', authMiddleware, (req, res) => {
  const { mission_id, amount } = req.body;
  if (!amount || +amount <= 0) return err(res, 'Montant invalide');

  const tx = db.insert('transactions', {
    user_id:    req.user.id,
    type:       'cash_in',
    amount:     +amount,
    mission_id: mission_id || null,
    label:      'Paiement en espèces',
    method:     'cash',
  });

  const newCash  = (req.user.wallet_cash || 0) + +amount;
  const newEarned= (req.user.total_earned || 0) + +amount;
  db.update('users', req.user.id, { wallet_cash: newCash, total_earned: newEarned });
  ok(res, { transaction: tx, wallet_cash: newCash });
});

// POST /api/wallet/withdraw
router.post('/wallet/withdraw', authMiddleware, (req, res) => {
  const { amount, method } = req.body; // method: revolut|paypal|mastercard
  const methods = ['revolut','paypal','mastercard'];
  if (!amount || +amount <= 0) return err(res, 'Montant invalide');
  if (!methods.includes(method)) return err(res, 'Méthode invalide');
  if ((req.user.wallet || 0) < +amount) return err(res, 'Solde insuffisant');

  const tx = db.insert('transactions', {
    user_id: req.user.id,
    type:    'withdrawal',
    amount:  -amount,
    label:   `Retrait via ${method}`,
    method,
  });

  db.update('users', req.user.id, { wallet: req.user.wallet - +amount });
  ok(res, { transaction: tx, wallet: req.user.wallet - +amount });
});

// ════════════════════════════════════════════════════════════════════════════
// NOTIFICATIONS
// ════════════════════════════════════════════════════════════════════════════
router.get('/notifications', authMiddleware, (req, res) => {
  const notifs = db.all('notifications', n => n.user_id === req.user.id)
    .sort((a,b) => new Date(b.created_at) - new Date(a.created_at));
  ok(res, { notifications: notifs });
});

router.post('/notifications/read-all', authMiddleware, (req, res) => {
  db.all('notifications', n => n.user_id === req.user.id && !n.read)
    .forEach(n => db.update('notifications', n.id, { read: true }));
  ok(res, { done: true });
});

// ════════════════════════════════════════════════════════════════════════════
// BADGES
// ════════════════════════════════════════════════════════════════════════════
router.get('/badges', authMiddleware, (req, res) => {
  ok(res, { badges: db.all('badges') });
});

// ════════════════════════════════════════════════════════════════════════════
// ADMIN — all routes require admin token
// ════════════════════════════════════════════════════════════════════════════
const A = [authMiddleware, adminOnly];

// GET /api/admin/stats
router.get('/admin/stats', ...A, (req, res) => {
  const users    = db.all('users');
  const missions = db.all('missions');
  const apps     = db.all('applications');
  const txs      = db.all('transactions');
  const totalRevenue = txs.filter(t => t.type === 'cash_in').reduce((s,t) => s + t.amount, 0);

  ok(res, {
    stats: {
      total_users:     users.filter(u => !u.is_admin).length,
      total_missions:  missions.length,
      open_missions:   missions.filter(m => m.status === 'open').length,
      total_apps:      apps.length,
      total_revenue:   totalRevenue,
      online_users:    Math.floor(Math.random() * 20), // placeholder
    }
  });
});

// GET /api/admin/users
router.get('/admin/users', ...A, (req, res) => {
  const users = db.all('users').map(sanitizeUser);
  ok(res, { users });
});

// PATCH /api/admin/users/:id
router.patch('/admin/users/:id', ...A, (req, res) => {
  const allowed = ['is_certified','can_live','can_color','in_top100','rank',
                   'avg_rating','wallet','badges','profile_color','banned'];
  const patch = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) patch[k] = req.body[k]; });
  const updated = db.update('users', req.params.id, patch);
  if (!updated) return err(res, 'Utilisateur introuvable', 404);
  ok(res, { user: sanitizeUser(updated) });
});

// DELETE /api/admin/users/:id
router.delete('/admin/users/:id', ...A, (req, res) => {
  const user = db.findId('users', req.params.id);
  if (!user) return err(res, 'Introuvable', 404);
  if (user.is_admin) return err(res, 'Impossible de supprimer un admin', 403);
  db.remove('users', req.params.id);
  ok(res, { deleted: true });
});

// GET /api/admin/missions
router.get('/admin/missions', ...A, (req, res) => {
  const missions = db.all('missions').map(m => {
    const owner = db.findId('users', m.owner_id);
    return { ...m, owner_name: owner?.username };
  });
  ok(res, { missions });
});

// DELETE /api/admin/missions/:id
router.delete('/admin/missions/:id', ...A, (req, res) => {
  if (!db.findId('missions', req.params.id)) return err(res, 'Introuvable', 404);
  db.remove('missions', req.params.id);
  ok(res, { deleted: true });
});

// GET /api/admin/transactions
router.get('/admin/transactions', ...A, (req, res) => {
  const txs = db.all('transactions').map(t => {
    const u = db.findId('users', t.user_id);
    return { ...t, username: u?.username };
  });
  ok(res, { transactions: txs });
});

// POST /api/admin/rankings/recompute
router.post('/admin/rankings/recompute', ...A, (req, res) => {
  db.recomputeRankings();
  ok(res, { done: true });
});

// POST /api/admin/broadcast  — send notification to all users
router.post('/admin/broadcast', ...A, (req, res) => {
  const { text } = req.body;
  if (!text) return err(res, 'Texte requis');
  db.all('users', u => !u.is_admin).forEach(u => {
    db.insert('notifications', {
      user_id: u.id, type: 'broadcast',
      text, ref_id: null, read: false,
    });
  });
  ok(res, { sent: true });
});

// ─── Haversine ───────────────────────────────────────────────────────────────
function haversine(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2)**2 +
    Math.cos(lat1 * Math.PI/180) * Math.cos(lat2 * Math.PI/180) * Math.sin(dLon/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

module.exports = router;
