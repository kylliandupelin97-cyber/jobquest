"""
JOBQUEST - Serveur API REST complet
Flask + SQLite | Port 5000
"""
import os, sqlite3, json, uuid, math
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
import jwt
from flask import Flask, request, jsonify, g
from flask_cors import CORS

# ─── CONFIG ───────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, "../db/jobquest.db")
SECRET_KEY  = os.environ.get("JWT_SECRET", "jobquest_super_secret_key_2026_change_in_prod")
JWT_EXPIRY  = int(os.environ.get("JWT_EXPIRY_HOURS", 72))
PORT        = int(os.environ.get("PORT", 5000))
DEBUG       = os.environ.get("DEBUG", "true").lower() == "true"

app = Flask(__name__)
CORS(app, origins="*", supports_credentials=True)

# ─── DB ───────────────────────────────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db: db.close()

def db_fetchone(sql, params=()):
    row = get_db().execute(sql, params).fetchone()
    return dict(row) if row else None

def db_fetchall(sql, params=()):
    rows = get_db().execute(sql, params).fetchall()
    return [dict(r) for r in rows]

def db_run(sql, params=()):
    db = get_db()
    cur = db.execute(sql, params)
    db.commit()
    return cur

def new_id(prefix=""):
    return (prefix + "_" if prefix else "") + uuid.uuid4().hex[:16]

def now():
    return datetime.utcnow().isoformat()

# ─── AUTH HELPERS ─────────────────────────────────────────────────────────────
def make_token(user_id, role):
    payload = {
        "sub": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Token manquant"}), 401
        try:
            data = decode_token(auth.split(" ", 1)[1])
            g.user_id = data["sub"]
            g.user_role = data["role"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expiré"}), 401
        except Exception:
            return jsonify({"error": "Token invalide"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if g.user_role != "admin":
            return jsonify({"error": "Accès refusé — admin uniquement"}), 403
        return f(*args, **kwargs)
    return decorated

def err(msg, code=400):
    return jsonify({"error": msg}), code

def ok(data=None, msg="ok", **extra):
    resp = {"success": True, "message": msg}
    if data is not None:
        resp["data"] = data
    resp.update(extra)
    return jsonify(resp)

# ─── GEO ──────────────────────────────────────────────────────────────────────
def haversine(lat1, lon1, lat2, lon2):
    """Retourne distance en km"""
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return R * 2 * math.asin(math.sqrt(a))

# ─── ROUTES : SANTÉ ───────────────────────────────────────────────────────────
@app.get("/")
def root():
    return ok({"server": "JOBQUEST API", "version": "1.0.0", "status": "running"})

@app.get("/health")
def health():
    try:
        db_fetchone("SELECT 1")
        return ok({"db": "ok", "time": now()})
    except Exception as e:
        return jsonify({"db": "error", "detail": str(e)}), 500

# ─── ROUTES : AUTH ────────────────────────────────────────────────────────────
@app.post("/auth/register")
def register():
    d = request.json or {}
    username = (d.get("username") or "").strip()
    email    = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    geo      = int(bool(d.get("geolocation_allowed", False)))
    lat      = d.get("latitude")
    lon      = d.get("longitude")

    if not username or not email or not password:
        return err("username, email et password sont requis")
    if len(password) < 6:
        return err("Mot de passe trop court (min 6 caractères)")
    if db_fetchone("SELECT id FROM users WHERE email=?", (email,)):
        return err("Email déjà utilisé")
    if db_fetchone("SELECT id FROM users WHERE username=?", (username,)):
        return err("Nom d'utilisateur déjà pris")

    uid      = new_id("usr")
    pw_hash  = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db_run("""
        INSERT INTO users(id,username,email,password_hash,geolocation_allowed,latitude,longitude)
        VALUES(?,?,?,?,?,?,?)
    """, (uid, username, email, pw_hash, geo, lat, lon))
    db_run("INSERT INTO user_settings(user_id) VALUES(?)", (uid,))

    user = db_fetchone("SELECT id,username,email,role,ranking_pos,stars_avg,certified FROM users WHERE id=?", (uid,))
    token = make_token(uid, "user")
    return ok({"user": user, "token": token}, "Compte créé avec succès"), 201

@app.post("/auth/login")
def login():
    d = request.json or {}
    email    = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""

    if not email or not password:
        return err("Email et password requis")

    user = db_fetchone("SELECT * FROM users WHERE email=? AND is_active=1", (email,))
    if not user:
        return err("Identifiants incorrects", 401)
    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return err("Identifiants incorrects", 401)

    db_run("UPDATE users SET last_seen=? WHERE id=?", (now(), user["id"]))
    token = make_token(user["id"], user["role"])

    safe = {k: v for k, v in user.items() if k != "password_hash"}
    return ok({"user": safe, "token": token})

@app.get("/auth/me")
@token_required
def me():
    user = db_fetchone("SELECT * FROM users WHERE id=?", (g.user_id,))
    if not user:
        return err("Utilisateur introuvable", 404)
    safe = {k: v for k, v in user.items() if k != "password_hash"}
    badges = db_fetchall("""
        SELECT b.*, ub.equipped, ub.earned_at FROM user_badges ub
        JOIN badges b ON b.id = ub.badge_id
        WHERE ub.user_id=?
    """, (g.user_id,))
    settings = db_fetchone("SELECT * FROM user_settings WHERE user_id=?", (g.user_id,))
    return ok({"user": safe, "badges": badges, "settings": settings})

# ─── ROUTES : USERS ───────────────────────────────────────────────────────────
@app.get("/users/<uid>")
@token_required
def get_user(uid):
    user = db_fetchone("""
        SELECT id,username,email,role,avatar_url,bio,pseudo_color,ranking_pos,
               stars_avg,stars_count,certified,wallet_balance,created_at,geolocation_allowed
        FROM users WHERE id=? AND is_active=1
    """, (uid,))
    if not user:
        return err("Utilisateur introuvable", 404)
    badges = db_fetchall("""
        SELECT b.* FROM user_badges ub JOIN badges b ON b.id=ub.badge_id
        WHERE ub.user_id=? AND ub.equipped=1
    """, (uid,))
    ratings = db_fetchall("""
        SELECT r.*, u.username as from_username FROM ratings r
        JOIN users u ON u.id=r.from_user_id
        WHERE r.to_user_id=? ORDER BY r.created_at DESC LIMIT 20
    """, (uid,))
    return ok({"user": user, "badges": badges, "ratings": ratings})

@app.patch("/users/me")
@token_required
def update_me():
    d = request.json or {}
    allowed = ["username", "bio", "avatar_url", "pseudo_color",
               "geolocation_allowed", "latitude", "longitude"]
    updates = {k: d[k] for k in allowed if k in d}
    if not updates:
        return err("Rien à mettre à jour")

    # vérif pseudo_color : uniquement top 10
    if "pseudo_color" in updates:
        user = db_fetchone("SELECT ranking_pos FROM users WHERE id=?", (g.user_id,))
        if user["ranking_pos"] > 10:
            return err("Couleur de pseudo réservée au Top 10", 403)

    sets = ", ".join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [now(), g.user_id]
    db_run(f"UPDATE users SET {sets}, updated_at=? WHERE id=?", vals)
    return ok(msg="Profil mis à jour")

@app.patch("/users/me/password")
@token_required
def change_password():
    d = request.json or {}
    old_pwd = d.get("old_password", "")
    new_pwd = d.get("new_password", "")
    if len(new_pwd) < 6:
        return err("Nouveau mot de passe trop court")
    user = db_fetchone("SELECT password_hash FROM users WHERE id=?", (g.user_id,))
    if not bcrypt.checkpw(old_pwd.encode(), user["password_hash"].encode()):
        return err("Ancien mot de passe incorrect", 401)
    new_hash = bcrypt.hashpw(new_pwd.encode(), bcrypt.gensalt()).decode()
    db_run("UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
           (new_hash, now(), g.user_id))
    return ok(msg="Mot de passe modifié")

# ─── ROUTES : MISSIONS ────────────────────────────────────────────────────────
@app.get("/missions")
@token_required
def list_missions():
    lat  = request.args.get("lat", type=float)
    lon  = request.args.get("lon", type=float)
    radius = request.args.get("radius", 50, type=float)   # km
    status = request.args.get("status", "open")
    tag    = request.args.get("tag")
    limit  = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)

    sql = """
        SELECT m.*, u.username as owner_name, u.stars_avg as owner_stars,
               u.certified as owner_certified
        FROM missions m
        JOIN users u ON u.id=m.owner_id
        WHERE m.status=? AND m.available=1
    """
    params = [status]
    if tag:
        sql += " AND m.tags LIKE ?"
        params.append(f"%{tag}%")
    sql += " ORDER BY m.created_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    missions = db_fetchall(sql, params)

    # Filtrer par distance si géoloc disponible
    if lat and lon:
        def with_dist(m):
            if m["latitude"] and m["longitude"]:
                m["distance_km"] = round(haversine(lat, lon, m["latitude"], m["longitude"]), 2)
            else:
                m["distance_km"] = None
            return m
        missions = [with_dist(m) for m in missions]
        missions = [m for m in missions if m["distance_km"] is None or m["distance_km"] <= radius]
        missions.sort(key=lambda m: m["distance_km"] or 9999)

    return ok(missions, total=len(missions))

@app.get("/missions/<mid>")
@token_required
def get_mission(mid):
    m = db_fetchone("""
        SELECT m.*, u.username as owner_name, u.stars_avg as owner_stars,
               u.certified as owner_certified, u.avatar_url as owner_avatar
        FROM missions m JOIN users u ON u.id=m.owner_id
        WHERE m.id=?
    """, (mid,))
    if not m:
        return err("Mission introuvable", 404)
    db_run("UPDATE missions SET views=views+1 WHERE id=?", (mid,))
    apps = db_fetchall("""
        SELECT a.*, u.username FROM applications a
        JOIN users u ON u.id=a.applicant_id
        WHERE a.mission_id=?
    """, (mid,))
    return ok({"mission": m, "applications": apps})

@app.post("/missions")
@token_required
def create_mission():
    d = request.json or {}
    required = ["title", "price"]
    for r in required:
        if not d.get(r):
            return err(f"'{r}' est requis")

    mid = new_id("msn")
    tags = json.dumps(d.get("tags", []))
    db_run("""
        INSERT INTO missions(id,owner_id,title,description,requirements,price,price_type,
        payment_method,latitude,longitude,address,available,tags)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?)
    """, (mid, g.user_id,
          d["title"], d.get("description",""), d.get("requirements",""),
          float(d["price"]), d.get("price_type","fixed"),
          d.get("payment_method","both"),
          d.get("latitude"), d.get("longitude"), d.get("address",""), tags))
    m = db_fetchone("SELECT * FROM missions WHERE id=?", (mid,))
    return ok(m, "Mission publiée"), 201

@app.patch("/missions/<mid>")
@token_required
def update_mission(mid):
    m = db_fetchone("SELECT * FROM missions WHERE id=?", (mid,))
    if not m:
        return err("Mission introuvable", 404)
    if m["owner_id"] != g.user_id and g.user_role != "admin":
        return err("Non autorisé", 403)

    d = request.json or {}
    allowed = ["title","description","requirements","price","available","status","tags",
               "latitude","longitude","address","payment_method"]
    updates = {k: d[k] for k in allowed if k in d}
    if "tags" in updates:
        updates["tags"] = json.dumps(updates["tags"])
    if not updates:
        return err("Rien à mettre à jour")

    sets = ", ".join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [now(), mid]
    db_run(f"UPDATE missions SET {sets}, updated_at=? WHERE id=?", vals)
    return ok(msg="Mission mise à jour")

@app.delete("/missions/<mid>")
@token_required
def delete_mission(mid):
    m = db_fetchone("SELECT owner_id FROM missions WHERE id=?", (mid,))
    if not m:
        return err("Mission introuvable", 404)
    if m["owner_id"] != g.user_id and g.user_role != "admin":
        return err("Non autorisé", 403)
    db_run("UPDATE missions SET status='cancelled' WHERE id=?", (mid,))
    return ok(msg="Mission annulée")

# ─── ROUTES : CANDIDATURES ────────────────────────────────────────────────────
@app.post("/missions/<mid>/apply")
@token_required
def apply_mission(mid):
    m = db_fetchone("SELECT * FROM missions WHERE id=? AND available=1", (mid,))
    if not m:
        return err("Mission indisponible", 404)
    if m["owner_id"] == g.user_id:
        return err("Vous ne pouvez pas postuler à votre propre mission")
    if db_fetchone("SELECT id FROM applications WHERE mission_id=? AND applicant_id=?",
                   (mid, g.user_id)):
        return err("Candidature déjà envoyée")

    aid = new_id("app")
    db_run("""
        INSERT INTO applications(id,mission_id,applicant_id,status,message)
        VALUES(?,?,?,?,?)
    """, (aid, mid, g.user_id, "pending", request.json.get("message","") if request.json else ""))

    # Conversation auto
    conv_id = new_id("conv")
    msg_id  = new_id("msg")
    applicant = db_fetchone("SELECT username FROM users WHERE id=?", (g.user_id,))
    auto_msg = f"👋 Bonjour ! {applicant['username']} postule pour votre mission \"{m['title']}\"."
    try:
        db_run("""
            INSERT INTO conversations(id,mission_id,user1_id,user2_id,unlocked,last_msg,last_msg_at)
            VALUES(?,?,?,?,0,?,?)
        """, (conv_id, mid, m["owner_id"], g.user_id, auto_msg, now()))
        db_run("""
            INSERT INTO messages(id,conversation_id,sender_id,receiver_id,content,msg_type)
            VALUES(?,?,?,?,?,'application')
        """, (msg_id, conv_id, g.user_id, m["owner_id"], auto_msg))
    except Exception:
        pass  # Conversation déjà existante

    # Notification au propriétaire
    nid = new_id("notif")
    db_run("""
        INSERT INTO notifications(id,user_id,type,title,body,data)
        VALUES(?,?,?,?,?,?)
    """, (nid, m["owner_id"], "application",
          f"Nouvelle candidature",
          f"{applicant['username']} postule pour \"{m['title']}\"",
          json.dumps({"mission_id": mid, "applicant_id": g.user_id})))

    return ok({"application_id": aid}, "Candidature envoyée"), 201

@app.post("/applications/<aid>/accept")
@token_required
def accept_application(aid):
    app_row = db_fetchone("SELECT * FROM applications WHERE id=?", (aid,))
    if not app_row:
        return err("Candidature introuvable", 404)

    m = db_fetchone("SELECT * FROM missions WHERE id=?", (app_row["mission_id"],))
    if m["owner_id"] != g.user_id:
        return err("Non autorisé", 403)

    db_run("UPDATE applications SET status='accepted', owner_accepted=1, updated_at=? WHERE id=?",
           (now(), aid))
    db_run("UPDATE missions SET status='in_progress', updated_at=? WHERE id=?",
           (now(), app_row["mission_id"]))

    # Déverrouiller conversation
    db_run("""
        UPDATE conversations SET unlocked=1
        WHERE mission_id=? AND (user1_id=? OR user2_id=?)
    """, (app_row["mission_id"], app_row["applicant_id"], app_row["applicant_id"]))

    # Notif candidat
    nid = new_id("notif")
    db_run("""
        INSERT INTO notifications(id,user_id,type,title,body,data)
        VALUES(?,?,?,?,?,?)
    """, (nid, app_row["applicant_id"], "mission_accepted",
          "Candidature acceptée !",
          f"Vous avez été accepté pour \"{m['title']}\" !",
          json.dumps({"mission_id": m["id"]})))

    return ok(msg="Candidature acceptée — conversation déverrouillée")

# ─── ROUTES : MESSAGES ────────────────────────────────────────────────────────
@app.get("/conversations")
@token_required
def get_conversations():
    convs = db_fetchall("""
        SELECT c.*,
               u1.username as user1_name, u2.username as user2_name,
               m.title as mission_title
        FROM conversations c
        JOIN users u1 ON u1.id=c.user1_id
        JOIN users u2 ON u2.id=c.user2_id
        LEFT JOIN missions m ON m.id=c.mission_id
        WHERE c.user1_id=? OR c.user2_id=?
        ORDER BY c.last_msg_at DESC
    """, (g.user_id, g.user_id))
    return ok(convs)

@app.get("/conversations/<cid>/messages")
@token_required
def get_messages(cid):
    conv = db_fetchone("SELECT * FROM conversations WHERE id=?", (cid,))
    if not conv:
        return err("Conversation introuvable", 404)
    if g.user_id not in [conv["user1_id"], conv["user2_id"]]:
        return err("Accès refusé", 403)

    msgs = db_fetchall("""
        SELECT msg.*, u.username as sender_name FROM messages msg
        JOIN users u ON u.id=msg.sender_id
        WHERE msg.conversation_id=? ORDER BY msg.created_at ASC
    """, (cid,))
    # Marquer comme lus
    db_run("UPDATE messages SET read=1 WHERE conversation_id=? AND receiver_id=?",
           (cid, g.user_id))
    return ok({"conversation": conv, "messages": msgs})

@app.post("/conversations/<cid>/messages")
@token_required
def send_message(cid):
    conv = db_fetchone("SELECT * FROM conversations WHERE id=?", (cid,))
    if not conv:
        return err("Conversation introuvable", 404)
    if g.user_id not in [conv["user1_id"], conv["user2_id"]]:
        return err("Accès refusé", 403)
    if not conv["unlocked"] and g.user_role != "admin":
        return err("Conversation verrouillée — en attente d'acceptation")

    content = (request.json or {}).get("content", "").strip()
    if not content:
        return err("Message vide")

    receiver = conv["user2_id"] if g.user_id == conv["user1_id"] else conv["user1_id"]
    mid = new_id("msg")
    db_run("""
        INSERT INTO messages(id,conversation_id,sender_id,receiver_id,content)
        VALUES(?,?,?,?,?)
    """, (mid, cid, g.user_id, receiver, content))
    db_run("UPDATE conversations SET last_msg=?, last_msg_at=? WHERE id=?",
           (content, now(), cid))
    return ok({"message_id": mid}, "Message envoyé"), 201

# ─── ROUTES : NOTES ───────────────────────────────────────────────────────────
@app.post("/users/<uid>/rate")
@token_required
def rate_user(uid):
    if uid == g.user_id:
        return err("Impossible de se noter soi-même")
    d = request.json or {}
    stars = int(d.get("stars", 0))
    if stars < 1 or stars > 5:
        return err("Note entre 1 et 5")
    mid = d.get("mission_id")

    rid = new_id("rat")
    try:
        db_run("""
            INSERT INTO ratings(id,from_user_id,to_user_id,mission_id,stars,comment)
            VALUES(?,?,?,?,?,?)
        """, (rid, g.user_id, uid, mid, stars, d.get("comment","")))
    except sqlite3.IntegrityError:
        return err("Vous avez déjà noté cet utilisateur pour cette mission")

    # Recalculer moyenne
    avg = db_fetchone("SELECT AVG(stars) as avg, COUNT(*) as cnt FROM ratings WHERE to_user_id=?", (uid,))
    db_run("UPDATE users SET stars_avg=?, stars_count=?, updated_at=? WHERE id=?",
           (round(avg["avg"], 2), avg["cnt"], now(), uid))

    # Recalcul ranking (score = stars_avg * log(stars_count+1))
    _recalculate_ranking()
    return ok(msg="Note enregistrée"), 201

def _recalculate_ranking():
    users = db_fetchall("SELECT id, stars_avg, stars_count FROM users WHERE is_active=1 AND role='user'")
    scored = []
    for u in users:
        score = (u["stars_avg"] or 0) * math.log(max((u["stars_count"] or 0) + 1, 1))
        scored.append((score, u["id"]))
    scored.sort(reverse=True)
    db = get_db()
    for pos, (score, uid) in enumerate(scored, 1):
        db.execute("UPDATE users SET ranking_pos=?, ranking_score=? WHERE id=?",
                   (pos, round(score, 4), uid))
        # Certification auto Top 10
        certified = 1 if pos <= 10 else 0
        db.execute("UPDATE users SET certified=? WHERE id=?", (certified, uid))
    db.commit()

# ─── ROUTES : CLASSEMENT ─────────────────────────────────────────────────────
@app.get("/ranking")
@token_required
def get_ranking():
    top = request.args.get("top", 100, type=int)
    users = db_fetchall("""
        SELECT id, username, stars_avg, stars_count, ranking_pos, ranking_score,
               certified, pseudo_color, avatar_url
        FROM users
        WHERE is_active=1 AND role='user'
        ORDER BY ranking_pos ASC
        LIMIT ?
    """, (top,))
    for u in users:
        badges = db_fetchall("""
            SELECT b.icon, b.name FROM user_badges ub
            JOIN badges b ON b.id=ub.badge_id
            WHERE ub.user_id=? AND ub.equipped=1
        """, (u["id"],))
        u["badges"] = badges
    return ok(users)

# ─── ROUTES : PORTE-MONNAIE ───────────────────────────────────────────────────
@app.get("/wallet")
@token_required
def get_wallet():
    user = db_fetchone("SELECT wallet_balance, cash_balance FROM users WHERE id=?", (g.user_id,))
    transactions = db_fetchall("""
        SELECT t.*, m.title as mission_title FROM transactions t
        LEFT JOIN missions m ON m.id=t.mission_id
        WHERE t.user_id=? ORDER BY t.created_at DESC LIMIT 50
    """, (g.user_id,))
    return ok({"balance": user["wallet_balance"], "cash": user["cash_balance"],
               "transactions": transactions})

@app.post("/wallet/withdraw")
@token_required
def withdraw():
    d = request.json or {}
    amount = float(d.get("amount", 0))
    method = d.get("method", "")  # paypal | revolut | mastercard
    if amount <= 0:
        return err("Montant invalide")
    if method not in ["paypal", "revolut", "mastercard"]:
        return err("Méthode invalide")

    user = db_fetchone("SELECT wallet_balance FROM users WHERE id=?", (g.user_id,))
    if user["wallet_balance"] < amount:
        return err("Solde insuffisant")

    db_run("UPDATE users SET wallet_balance=wallet_balance-? WHERE id=?", (amount, g.user_id))
    tid = new_id("txn")
    db_run("""
        INSERT INTO transactions(id,user_id,type,amount,method,status,note)
        VALUES(?,?,'withdraw',?,?,'completed',?)
    """, (tid, g.user_id, amount, method, f"Retrait via {method}"))
    return ok({"transaction_id": tid}, f"Retrait de {amount}€ effectué")

@app.post("/wallet/cash-declare")
@token_required
def declare_cash():
    d = request.json or {}
    amount = float(d.get("amount", 0))
    mid    = d.get("mission_id")
    if amount <= 0:
        return err("Montant invalide")

    app_check = db_fetchone("""
        SELECT a.id FROM applications a
        JOIN missions m ON m.id=a.mission_id
        WHERE a.applicant_id=? AND m.id=? AND a.status='accepted'
    """, (g.user_id, mid)) if mid else None

    db_run("UPDATE users SET cash_balance=cash_balance+? WHERE id=?", (amount, g.user_id))
    db_run("UPDATE applications SET amount_earned=? WHERE applicant_id=? AND mission_id=?",
           (amount, g.user_id, mid))
    tid = new_id("txn")
    db_run("""
        INSERT INTO transactions(id,user_id,type,amount,method,mission_id,status,note)
        VALUES(?,?,'cash_declare',?,'cash',?,'completed',?)
    """, (tid, g.user_id, amount, mid, "Déclaration espèces"))
    return ok(msg=f"{amount}€ enregistrés en espèces")

# ─── ROUTES : NOTIFICATIONS ───────────────────────────────────────────────────
@app.get("/notifications")
@token_required
def get_notifications():
    notifs = db_fetchall("""
        SELECT * FROM notifications WHERE user_id=?
        ORDER BY created_at DESC LIMIT 50
    """, (g.user_id,))
    unread = sum(1 for n in notifs if not n["read"])
    db_run("UPDATE notifications SET read=1 WHERE user_id=?", (g.user_id,))
    return ok({"notifications": notifs, "unread": unread})

# ─── ROUTES : BADGES ──────────────────────────────────────────────────────────
@app.get("/badges")
@token_required
def list_badges():
    return ok(db_fetchall("SELECT * FROM badges ORDER BY required_rank ASC"))

@app.post("/badges/<bid>/equip")
@token_required
def equip_badge(bid):
    ub = db_fetchone("SELECT * FROM user_badges WHERE user_id=? AND badge_id=?",
                     (g.user_id, bid))
    if not ub:
        return err("Badge non possédé")
    db_run("UPDATE user_badges SET equipped=1-equipped WHERE user_id=? AND badge_id=?",
           (g.user_id, bid))
    return ok(msg="Badge mis à jour")

# ─── ROUTES : SETTINGS ────────────────────────────────────────────────────────
@app.get("/settings")
@token_required
def get_settings():
    return ok(db_fetchone("SELECT * FROM user_settings WHERE user_id=?", (g.user_id,)))

@app.patch("/settings")
@token_required
def update_settings():
    d = request.json or {}
    allowed = ["notif_missions","notif_messages","notif_ranking","notif_lives",
               "profile_visible","language","sounds","animations",
               "paypal_email","revolut_tag","mastercard_last4"]
    updates = {k: d[k] for k in allowed if k in d}
    if not updates:
        return err("Rien à mettre à jour")
    sets = ", ".join(f"{k}=?" for k in updates)
    db_run(f"UPDATE user_settings SET {sets} WHERE user_id=?",
           list(updates.values()) + [g.user_id])
    return ok(msg="Paramètres mis à jour")

# ─── ROUTES : LIVES ───────────────────────────────────────────────────────────
@app.get("/lives")
@token_required
def get_lives():
    return ok(db_fetchall("""
        SELECT l.*, u.username, u.ranking_pos FROM lives l
        JOIN users u ON u.id=l.host_id
        WHERE l.status='live' ORDER BY l.viewers DESC
    """))

@app.post("/lives/start")
@token_required
def start_live():
    user = db_fetchone("SELECT ranking_pos FROM users WHERE id=?", (g.user_id,))
    if user["ranking_pos"] > 50:
        return err("Lives réservés au Top 50", 403)
    lid = new_id("live")
    db_run("""
        INSERT INTO lives(id,host_id,title,status)
        VALUES(?,?,?,'live')
    """, (lid, g.user_id, (request.json or {}).get("title","Live")))
    return ok({"live_id": lid}, "Live démarré"), 201

@app.post("/lives/<lid>/end")
@token_required
def end_live(lid):
    db_run("UPDATE lives SET status='ended', ended_at=? WHERE id=? AND host_id=?",
           (now(), lid, g.user_id))
    return ok(msg="Live terminé")

@app.post("/lives/<lid>/like")
@token_required
def like_live(lid):
    try:
        db_run("INSERT INTO live_likes(live_id,user_id) VALUES(?,?)", (lid, g.user_id))
        db_run("UPDATE lives SET likes=likes+1 WHERE id=?", (lid,))
    except sqlite3.IntegrityError:
        db_run("DELETE FROM live_likes WHERE live_id=? AND user_id=?", (lid, g.user_id))
        db_run("UPDATE lives SET likes=MAX(0,likes-1) WHERE id=?", (lid,))
    return ok(msg="Mis à jour")

# ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────
@app.get("/admin/dashboard")
@admin_required
def admin_dashboard():
    stats = {
        "users":        db_fetchone("SELECT COUNT(*) as n FROM users WHERE role='user'")["n"],
        "admins":       db_fetchone("SELECT COUNT(*) as n FROM users WHERE role='admin'")["n"],
        "missions":     db_fetchone("SELECT COUNT(*) as n FROM missions")["n"],
        "missions_open":db_fetchone("SELECT COUNT(*) as n FROM missions WHERE status='open'")["n"],
        "applications": db_fetchone("SELECT COUNT(*) as n FROM applications")["n"],
        "messages":     db_fetchone("SELECT COUNT(*) as n FROM messages")["n"],
        "ratings":      db_fetchone("SELECT COUNT(*) as n FROM ratings")["n"],
        "transactions": db_fetchone("SELECT COUNT(*) as n FROM transactions")["n"],
        "total_volume": db_fetchone("SELECT COALESCE(SUM(amount),0) as n FROM transactions WHERE type='earn'")["n"],
        "live_sessions":db_fetchone("SELECT COUNT(*) as n FROM lives")["n"],
    }
    recent_users = db_fetchall("""
        SELECT id,username,email,role,ranking_pos,stars_avg,created_at,is_active
        FROM users ORDER BY created_at DESC LIMIT 10
    """)
    return ok({"stats": stats, "recent_users": recent_users})

@app.get("/admin/users")
@admin_required
def admin_users():
    page   = request.args.get("page", 1, type=int)
    limit  = request.args.get("limit", 20, type=int)
    search = request.args.get("q", "")
    offset = (page-1)*limit

    sql = "SELECT id,username,email,role,ranking_pos,stars_avg,certified,is_active,created_at,last_seen FROM users"
    params = []
    if search:
        sql += " WHERE username LIKE ? OR email LIKE ?"
        params = [f"%{search}%", f"%{search}%"]
    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params += [limit, offset]

    users = db_fetchall(sql, params)
    total = db_fetchone("SELECT COUNT(*) as n FROM users")["n"]
    return ok(users, total=total, page=page)

@app.patch("/admin/users/<uid>")
@admin_required
def admin_update_user(uid):
    d = request.json or {}
    allowed = ["role", "is_active", "certified", "ranking_pos", "wallet_balance"]
    updates = {k: d[k] for k in allowed if k in d}
    if not updates:
        return err("Rien à modifier")
    sets = ", ".join(f"{k}=?" for k in updates)
    db_run(f"UPDATE users SET {sets}, updated_at=? WHERE id=?",
           list(updates.values()) + [now(), uid])
    # Log
    lid = new_id("log")
    db_run("""
        INSERT INTO admin_logs(id,admin_id,action,target_type,target_id,details)
        VALUES(?,?,'update_user','user',?,?)
    """, (lid, g.user_id, uid, json.dumps(updates)))
    return ok(msg="Utilisateur mis à jour")

@app.delete("/admin/users/<uid>")
@admin_required
def admin_ban_user(uid):
    db_run("UPDATE users SET is_active=0, updated_at=? WHERE id=?", (now(), uid))
    lid = new_id("log")
    db_run("""
        INSERT INTO admin_logs(id,admin_id,action,target_type,target_id,details)
        VALUES(?,?,'ban_user','user',?,?)
    """, (lid, g.user_id, uid, "Compte désactivé par admin"))
    return ok(msg="Utilisateur banni")

@app.get("/admin/missions")
@admin_required
def admin_missions():
    missions = db_fetchall("""
        SELECT m.*, u.username as owner_name FROM missions m
        JOIN users u ON u.id=m.owner_id
        ORDER BY m.created_at DESC LIMIT 100
    """)
    return ok(missions)

@app.delete("/admin/missions/<mid>")
@admin_required
def admin_delete_mission(mid):
    db_run("UPDATE missions SET status='cancelled' WHERE id=?", (mid,))
    return ok(msg="Mission annulée")

@app.get("/admin/ratings")
@admin_required
def admin_ratings():
    ratings = db_fetchall("""
        SELECT r.*, uf.username as from_name, ut.username as to_name
        FROM ratings r
        JOIN users uf ON uf.id=r.from_user_id
        JOIN users ut ON ut.id=r.to_user_id
        ORDER BY r.created_at DESC LIMIT 100
    """)
    return ok(ratings)

@app.delete("/admin/ratings/<rid>")
@admin_required
def admin_delete_rating(rid):
    r = db_fetchone("SELECT to_user_id FROM ratings WHERE id=?", (rid,))
    if not r:
        return err("Note introuvable", 404)
    db_run("DELETE FROM ratings WHERE id=?", (rid,))
    # Recalcul
    avg = db_fetchone("SELECT AVG(stars) as avg, COUNT(*) as cnt FROM ratings WHERE to_user_id=?",
                      (r["to_user_id"],))
    db_run("UPDATE users SET stars_avg=?, stars_count=? WHERE id=?",
           (round(avg["avg"] or 0, 2), avg["cnt"], r["to_user_id"]))
    _recalculate_ranking()
    return ok(msg="Note supprimée")

@app.get("/admin/logs")
@admin_required
def admin_logs():
    logs = db_fetchall("""
        SELECT l.*, u.username as admin_name FROM admin_logs l
        JOIN users u ON u.id=l.admin_id
        ORDER BY l.created_at DESC LIMIT 200
    """)
    return ok(logs)

@app.post("/admin/badges/grant")
@admin_required
def admin_grant_badge():
    d = request.json or {}
    uid = d.get("user_id")
    bid = d.get("badge_id")
    if not uid or not bid:
        return err("user_id et badge_id requis")
    try:
        db_run("INSERT INTO user_badges(user_id,badge_id) VALUES(?,?)", (uid, bid))
    except sqlite3.IntegrityError:
        return err("Badge déjà attribué")
    return ok(msg="Badge attribué")

# ─── ERROR HANDLERS ───────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route introuvable"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Erreur serveur interne", "detail": str(e)}), 500

# ─── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════╗
║          JOBQUEST API SERVER v1.0.0          ║
║   http://localhost:{PORT}                      ║
╚══════════════════════════════════════════════╝
""")
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
