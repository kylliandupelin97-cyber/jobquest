'use strict';
const fs   = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, '..', 'data', 'jobquest.json');

// ─── Ensure data dir ─────────────────────────────────────────────────────────
if (!fs.existsSync(path.dirname(DB_PATH))) {
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
}

// ─── Default structure ───────────────────────────────────────────────────────
const DEFAULT = {
  users:        [],
  missions:     [],
  applications: [],
  messages:     [],
  conversations:[],
  ratings:      [],
  transactions: [],
  notifications:[],
  badges:       [
    { id:'b1', icon:'🦁', name:'Lion',     req_rank:100 },
    { id:'b2', icon:'🦅', name:'Aigle',    req_rank:100 },
    { id:'b3', icon:'🐬', name:'Dauphin',  req_rank:100 },
    { id:'b4', icon:'🐯', name:'Tigre',    req_rank:50  },
    { id:'b5', icon:'🐉', name:'Dragon',   req_rank:50  },
    { id:'b6', icon:'🌟', name:'Étoile',   req_rank:10  },
    { id:'b7', icon:'🦊', name:'Renard',   req_rank:100 },
    { id:'b8', icon:'🦋', name:'Papillon', req_rank:100 },
  ],
};

// ─── Load / Save ─────────────────────────────────────────────────────────────
function load() {
  try {
    if (fs.existsSync(DB_PATH)) {
      const raw = fs.readFileSync(DB_PATH, 'utf8');
      return { ...DEFAULT, ...JSON.parse(raw) };
    }
  } catch(_) {}
  return structuredClone(DEFAULT);
}

function save(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// ─── In-memory state (sync on every write) ──────────────────────────────────
let db = load();

// ─── Generic helpers ─────────────────────────────────────────────────────────
const col   = (name) => db[name];
const find  = (name, pred) => db[name].find(pred) || null;
const findId= (name, id) => db[name].find(x => x.id === id) || null;
const all   = (name, pred) => pred ? db[name].filter(pred) : db[name];

function insert(name, obj) {
  const item = { id: uuidv4(), created_at: new Date().toISOString(), ...obj };
  db[name].push(item);
  save(db);
  return item;
}

function update(name, id, patch) {
  const idx = db[name].findIndex(x => x.id === id);
  if (idx === -1) return null;
  db[name][idx] = { ...db[name][idx], ...patch, updated_at: new Date().toISOString() };
  save(db);
  return db[name][idx];
}

function remove(name, id) {
  const before = db[name].length;
  db[name] = db[name].filter(x => x.id !== id);
  save(db);
  return db[name].length < before;
}

// ─── Ranking helper ──────────────────────────────────────────────────────────
function recomputeRankings() {
  const users = db.users.filter(u => !u.is_admin);
  users.sort((a, b) => (b.avg_rating || 0) - (a.avg_rating || 0));
  users.forEach((u, i) => {
    const rank = i + 1;
    const prev = u.rank;
    db.users.find(x => x.id === u.id).rank = rank;
    // unlock/lock privileges
    const user = db.users.find(x => x.id === u.id);
    user.can_live    = rank <= 50;
    user.can_color   = rank <= 10;
    user.is_certified= rank <= 10;
    user.in_top100   = rank <= 100;
  });
  save(db);
}

// ─── Seed admin account ───────────────────────────────────────────────────────
function seedAdmin() {
  const exists = db.users.find(u => u.is_admin);
  if (!exists) {
    const hash = bcrypt.hashSync('Admin@JobQuest2026!', 10);
    insert('users', {
      username:     'AdminDev',
      email:        'admin@jobquest.app',
      password:     hash,
      is_admin:     true,
      is_certified: true,
      can_live:     true,
      can_color:    true,
      rank:         0,
      avg_rating:   5,
      total_earned: 0,
      wallet:       0,
      badges:       ['b1','b2','b3','b4','b5','b6','b7','b8'],
      profile_color:'#00ff88',
      geo_allowed:  true,
      location:     null,
    });
    console.log('✅ Admin account seeded: admin@jobquest.app / Admin@JobQuest2026!');
  }
}

seedAdmin();

module.exports = {
  db, load, save,
  col, find, findId, all, insert, update, remove,
  recomputeRankings,
};
