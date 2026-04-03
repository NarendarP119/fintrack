"""
FinTrack - Python Finance System Backend
Framework: Flask | DB: SQLite via sqlite3 | Auth: JWT (PyJWT)
Author: Narendar Reddy Pathakuntla
"""

import sqlite3, json, hashlib, os, csv, io
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory
import jwt

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────
app = Flask(__name__, static_folder="static", template_folder="templates")
SECRET_KEY = "fintrack_super_secret_2024"
DB_PATH = "fintrack.db"
TOKEN_EXP_HOURS = 24

# ─────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()

def query(sql, params=(), one=False, commit=False):
    db = get_db()
    cur = db.execute(sql, params)
    if commit:
        db.commit()
        return cur.lastrowid
    rows = cur.fetchone() if one else cur.fetchall()
    return [dict(r) for r in rows] if not one else (dict(rows) if rows else None)

# ─────────────────────────────────────────────
# DB Init & Seed
# ─────────────────────────────────────────────
def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('income','expense')),
            category TEXT NOT NULL,
            date TEXT NOT NULL,
            notes TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)
    db.commit()

    # Seed default users
    users = [
        ("Admin User",   "admin@fintrack.com",   "admin123",   "admin"),
        ("Ana Analyst",  "analyst@fintrack.com", "analyst123", "analyst"),
        ("Viewer User",  "viewer@fintrack.com",  "viewer123",  "viewer"),
    ]
    for name, email, pw, role in users:
        existing = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not existing:
            h = hashlib.sha256(pw.encode()).hexdigest()
            db.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)", (name,email,h,role))
    db.commit()

    # Seed sample transactions for admin
    admin = db.execute("SELECT id FROM users WHERE email='admin@fintrack.com'").fetchone()
    count = db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
    if admin and count == 0:
        uid = admin[0]
        import random
        cats_income  = ["Salary","Freelance","Investment","Bonus","Rental"]
        cats_expense = ["Food","Rent","Transport","Shopping","Utilities","Healthcare","Entertainment","Education"]
        entries = []
        for i in range(60):
            mo = (i % 6) + 1
            day = random.randint(1, 28)
            date = f"2024-{mo:02d}-{day:02d}"
            if random.random() > 0.4:
                entries.append((uid, round(random.uniform(500,8000),2), "income",
                                random.choice(cats_income), date, "Auto-generated seed"))
            else:
                entries.append((uid, round(random.uniform(50,3000),2), "expense",
                                random.choice(cats_expense), date, "Auto-generated seed"))
        db.executemany(
            "INSERT INTO transactions(user_id,amount,type,category,date,notes) VALUES(?,?,?,?,?,?)",
            entries
        )
        db.commit()
    db.close()

# ─────────────────────────────────────────────
# Auth helpers
# ─────────────────────────────────────────────
def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def make_token(user):
    payload = {
        "user_id": user["id"],
        "role": user["role"],
        "name": user["name"],
        "exp": datetime.utcnow() + timedelta(hours=TOKEN_EXP_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
        if not token:
            return jsonify({"error": "Token missing"}), 401
        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        g.current_user = payload
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if g.current_user.get("role") not in roles:
                return jsonify({"error": f"Access denied. Required role: {', '.join(roles)}"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator

# ─────────────────────────────────────────────
# Validation helpers
# ─────────────────────────────────────────────
VALID_CATEGORIES = [
    "Salary","Freelance","Investment","Bonus","Rental",
    "Food","Rent","Transport","Shopping","Utilities",
    "Healthcare","Entertainment","Education","Other"
]

def validate_transaction(data, partial=False):
    errors = {}
    if not partial or "amount" in data:
        try:
            amt = float(data.get("amount", 0))
            if amt <= 0:
                errors["amount"] = "Amount must be positive"
        except (TypeError, ValueError):
            errors["amount"] = "Amount must be a number"
    if not partial or "type" in data:
        if data.get("type") not in ("income", "expense"):
            errors["type"] = "Type must be 'income' or 'expense'"
    if not partial or "category" in data:
        if data.get("category") not in VALID_CATEGORIES:
            errors["category"] = f"Category must be one of: {', '.join(VALID_CATEGORIES)}"
    if not partial or "date" in data:
        try:
            datetime.strptime(data.get("date", ""), "%Y-%m-%d")
        except ValueError:
            errors["date"] = "Date must be in YYYY-MM-DD format"
    return errors

# ─────────────────────────────────────────────
# Routes: Auth
# ─────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    user = query("SELECT * FROM users WHERE email=? AND password_hash=?",
                 (email, hash_pw(password)), one=True)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    token = make_token(user)
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "name": user["name"],
                 "email": user["email"], "role": user["role"]}
    })

@app.route("/api/auth/me", methods=["GET"])
@token_required
def me():
    user = query("SELECT id,name,email,role,created_at FROM users WHERE id=?",
                 (g.current_user["user_id"],), one=True)
    return jsonify(user)

# ─────────────────────────────────────────────
# Routes: Transactions (CRUD + Filter)
# ─────────────────────────────────────────────
@app.route("/api/transactions", methods=["GET"])
@token_required
def list_transactions():
    role = g.current_user["role"]
    uid  = g.current_user["user_id"]

    # Build query
    filters, params = [], []
    if role != "admin":
        filters.append("t.user_id = ?"); params.append(uid)

    # Query params
    tx_type   = request.args.get("type")
    category  = request.args.get("category")
    date_from = request.args.get("date_from")
    date_to   = request.args.get("date_to")
    search    = request.args.get("search")
    sort_by   = request.args.get("sort_by", "date")
    order     = "DESC" if request.args.get("order", "desc") == "desc" else "ASC"
    page      = max(1, int(request.args.get("page", 1)))
    per_page  = min(100, max(1, int(request.args.get("per_page", 20))))

    if tx_type in ("income", "expense"):
        filters.append("t.type = ?"); params.append(tx_type)
    if category:
        filters.append("t.category = ?"); params.append(category)
    if date_from:
        filters.append("t.date >= ?"); params.append(date_from)
    if date_to:
        filters.append("t.date <= ?"); params.append(date_to)
    if search:
        filters.append("(t.notes LIKE ? OR t.category LIKE ?)"); params += [f"%{search}%", f"%{search}%"]

    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    allowed_sorts = {"date", "amount", "category", "type", "created_at"}
    sort_col = sort_by if sort_by in allowed_sorts else "date"

    count_sql = f"SELECT COUNT(*) as c FROM transactions t {where}"
    total = query(count_sql, params, one=True)["c"]

    offset = (page - 1) * per_page
    sql = f"""
        SELECT t.*, u.name as user_name
        FROM transactions t
        JOIN users u ON t.user_id = u.id
        {where}
        ORDER BY t.{sort_col} {order}
        LIMIT ? OFFSET ?
    """
    rows = query(sql, params + [per_page, offset])

    return jsonify({
        "data": rows,
        "pagination": {
            "total": total, "page": page,
            "per_page": per_page, "pages": -(-total // per_page)
        }
    })

@app.route("/api/transactions/<int:tid>", methods=["GET"])
@token_required
def get_transaction(tid):
    role, uid = g.current_user["role"], g.current_user["user_id"]
    row = query("SELECT t.*, u.name as user_name FROM transactions t JOIN users u ON t.user_id=u.id WHERE t.id=?", (tid,), one=True)
    if not row:
        return jsonify({"error": "Transaction not found"}), 404
    if role != "admin" and row["user_id"] != uid:
        return jsonify({"error": "Forbidden"}), 403
    return jsonify(row)

@app.route("/api/transactions", methods=["POST"])
@token_required
@role_required("admin", "analyst")
def create_transaction():
    data = request.get_json() or {}
    errs = validate_transaction(data)
    if errs:
        return jsonify({"error": "Validation failed", "details": errs}), 422

    uid = g.current_user["user_id"]
    notes = data.get("notes", "")
    tid = query(
        "INSERT INTO transactions(user_id,amount,type,category,date,notes) VALUES(?,?,?,?,?,?)",
        (uid, float(data["amount"]), data["type"], data["category"], data["date"], notes),
        commit=True
    )
    row = query("SELECT * FROM transactions WHERE id=?", (tid,), one=True)
    return jsonify(row), 201

@app.route("/api/transactions/<int:tid>", methods=["PUT"])
@token_required
@role_required("admin", "analyst")
def update_transaction(tid):
    role, uid = g.current_user["role"], g.current_user["user_id"]
    row = query("SELECT * FROM transactions WHERE id=?", (tid,), one=True)
    if not row:
        return jsonify({"error": "Transaction not found"}), 404
    if role != "admin" and row["user_id"] != uid:
        return jsonify({"error": "Forbidden"}), 403

    data = request.get_json() or {}
    errs = validate_transaction(data, partial=True)
    if errs:
        return jsonify({"error": "Validation failed", "details": errs}), 422

    fields = {k: data[k] for k in ("amount","type","category","date","notes") if k in data}
    if not fields:
        return jsonify({"error": "No fields to update"}), 400

    set_clause = ", ".join(f"{k}=?" for k in fields) + ", updated_at=datetime('now')"
    query(f"UPDATE transactions SET {set_clause} WHERE id=?",
          list(fields.values()) + [tid], commit=True)
    return jsonify(query("SELECT * FROM transactions WHERE id=?", (tid,), one=True))

@app.route("/api/transactions/<int:tid>", methods=["DELETE"])
@token_required
@role_required("admin")
def delete_transaction(tid):
    row = query("SELECT id FROM transactions WHERE id=?", (tid,), one=True)
    if not row:
        return jsonify({"error": "Transaction not found"}), 404
    query("DELETE FROM transactions WHERE id=?", (tid,), commit=True)
    return jsonify({"message": "Deleted successfully"}), 200

# ─────────────────────────────────────────────
# Routes: Analytics & Summary
# ─────────────────────────────────────────────
@app.route("/api/summary", methods=["GET"])
@token_required
def summary():
    role, uid = g.current_user["role"], g.current_user["user_id"]
    where = "" if role == "admin" else f"WHERE user_id = {uid}"

    totals = query(f"""
        SELECT
          SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) as total_income,
          SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as total_expenses,
          COUNT(*) as total_transactions,
          COUNT(CASE WHEN type='income'  THEN 1 END) as income_count,
          COUNT(CASE WHEN type='expense' THEN 1 END) as expense_count
        FROM transactions {where}
    """, one=True)

    totals["balance"] = (totals["total_income"] or 0) - (totals["total_expenses"] or 0)

    # Category breakdown
    cat_data = query(f"""
        SELECT category, type,
               SUM(amount) as total, COUNT(*) as count
        FROM transactions {where}
        GROUP BY category, type
        ORDER BY total DESC
    """)

    # Monthly totals (last 6 months)
    month_cond = f"{where} AND date >= date('now','-6 months')" if where else "WHERE date >= date('now','-6 months')"
    monthly = query(f"""
        SELECT strftime('%Y-%m', date) as month,
               SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) as income,
               SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as expenses,
               COUNT(*) as count
        FROM transactions {month_cond}
        GROUP BY month ORDER BY month ASC
    """)

    # Recent transactions
    recent = query(f"""
        SELECT t.*, u.name as user_name
        FROM transactions t JOIN users u ON t.user_id=u.id
        {where}
        ORDER BY t.date DESC, t.created_at DESC LIMIT 5
    """)

    # Top categories
    top_expense_cats = query(f"""
        SELECT category, SUM(amount) as total
        FROM transactions {where if where else ''} {'AND' if where else 'WHERE'} type='expense'
        GROUP BY category ORDER BY total DESC LIMIT 5
    """)

    return jsonify({
        "totals": totals,
        "category_breakdown": cat_data,
        "monthly_totals": monthly,
        "recent_transactions": recent,
        "top_expense_categories": top_expense_cats
    })

@app.route("/api/analytics/monthly", methods=["GET"])
@token_required
@role_required("admin", "analyst")
def analytics_monthly():
    role, uid = g.current_user["role"], g.current_user["user_id"]
    where = f"WHERE user_id={uid}" if role != "admin" else ""
    year = request.args.get("year", datetime.now().year)
    cond = f"{'AND' if where else 'WHERE'} strftime('%Y',date)='{year}'"
    rows = query(f"""
        SELECT strftime('%m', date) as month,
               SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) as income,
               SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) as expenses
        FROM transactions {where} {cond}
        GROUP BY month ORDER BY month
    """)
    return jsonify(rows)

# ─────────────────────────────────────────────
# Routes: Users (Admin only)
# ─────────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
@token_required
@role_required("admin")
def list_users():
    users = query("SELECT id, name, email, role, created_at FROM users ORDER BY id")
    return jsonify(users)

@app.route("/api/users", methods=["POST"])
@token_required
@role_required("admin")
def create_user():
    data = request.get_json() or {}
    name  = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    pw    = (data.get("password") or "").strip()
    role  = data.get("role", "viewer")
    if not name or not email or not pw:
        return jsonify({"error": "name, email, password required"}), 400
    if role not in ("admin","analyst","viewer"):
        return jsonify({"error": "Role must be admin, analyst, or viewer"}), 400
    existing = query("SELECT id FROM users WHERE email=?", (email,), one=True)
    if existing:
        return jsonify({"error": "Email already registered"}), 409
    uid = query("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                (name, email, hash_pw(pw), role), commit=True)
    return jsonify({"id": uid, "name": name, "email": email, "role": role}), 201

@app.route("/api/users/<int:uid>", methods=["DELETE"])
@token_required
@role_required("admin")
def delete_user(uid):
    if uid == g.current_user["user_id"]:
        return jsonify({"error": "Cannot delete yourself"}), 400
    row = query("SELECT id FROM users WHERE id=?", (uid,), one=True)
    if not row:
        return jsonify({"error": "User not found"}), 404
    query("DELETE FROM users WHERE id=?", (uid,), commit=True)
    return jsonify({"message": "User deleted"})

# ─────────────────────────────────────────────
# Routes: Export
# ─────────────────────────────────────────────
@app.route("/api/export/csv", methods=["GET"])
@token_required
def export_csv():
    role, uid = g.current_user["role"], g.current_user["user_id"]
    where = "" if role == "admin" else f"WHERE t.user_id={uid}"
    rows = query(f"""
        SELECT t.id, u.name as user, t.amount, t.type, t.category, t.date, t.notes, t.created_at
        FROM transactions t JOIN users u ON t.user_id=u.id {where}
        ORDER BY t.date DESC
    """)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id","user","amount","type","category","date","notes","created_at"])
    writer.writeheader()
    writer.writerows(rows)
    from flask import Response
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=transactions.csv"})


# ─────────────────────────────────────────────
# Serve frontend (inline - no static folder needed)
# ─────────────────────────────────────────────
FRONTEND_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FinTrack</title>
<link href="https://fonts.googleapis.com/css2?family=Libre+Baskerville:ital,wght@0,400;0,700;1,400&family=JetBrains+Mono:wght@300;400;500&family=Instrument+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --paper: #f5f0e8;
  --paper2: #ede8dc;
  --paper3: #e4ddd0;
  --ink: #1a1714;
  --ink2: #4a4540;
  --ink3: #8a8278;
  --ink4: #b8b0a4;
  --rule: #d4cdc0;
  --green: #2d6a4f;
  --green-bg: #d8f3dc;
  --red: #9b2335;
  --red-bg: #fce4e8;
  --blue: #1a4a7a;
  --blue-bg: #dceefb;
  --amber: #7a4f1a;
  --amber-bg: #fdf0d5;
  --accent: #c94f2a;
}

html { font-size: 14px; }
body {
  background: var(--paper);
  color: var(--ink);
  font-family: 'Instrument Sans', sans-serif;
  min-height: 100vh;
  overflow-x: hidden;
}

/* ── scrollbar ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--paper2); }
::-webkit-scrollbar-thumb { background: var(--rule); border-radius: 2px; }

/* ══════════════════════════════════════════
   LOGIN
══════════════════════════════════════════ */
#login-page {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--paper);
  position: relative;
}

/* ruled lines background */
#login-page::before {
  content: '';
  position: absolute;
  inset: 0;
  background-image: repeating-linear-gradient(
    to bottom,
    transparent,
    transparent 27px,
    var(--rule) 27px,
    var(--rule) 28px
  );
  opacity: 0.4;
}

.login-wrap {
  position: relative;
  z-index: 1;
  width: min(420px, 92vw);
}

.login-header {
  margin-bottom: 2.5rem;
}

.login-wordmark {
  font-family: 'Libre Baskerville', Georgia, serif;
  font-size: 2rem;
  font-weight: 700;
  letter-spacing: -0.5px;
  color: var(--ink);
  line-height: 1;
}

.login-wordmark em {
  font-style: italic;
  color: var(--accent);
}

.login-tagline {
  font-size: 0.82rem;
  color: var(--ink3);
  margin-top: 0.4rem;
  font-style: italic;
  font-family: 'Libre Baskerville', serif;
}

.login-card {
  background: #fff;
  border: 1px solid var(--rule);
  border-radius: 4px;
  padding: 2rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.06), 0 4px 16px rgba(0,0,0,0.05);
}

.demo-box {
  background: var(--paper2);
  border-left: 3px solid var(--accent);
  padding: 0.75rem 1rem;
  margin-bottom: 1.75rem;
  border-radius: 0 3px 3px 0;
}

.demo-box p {
  font-size: 0.78rem;
  color: var(--ink2);
  line-height: 1.9;
  font-family: 'JetBrains Mono', monospace;
}

.demo-box p strong {
  color: var(--accent);
  font-weight: 500;
}

.field-group { margin-bottom: 1.25rem; }

.field-label {
  display: block;
  font-size: 0.72rem;
  font-weight: 600;
  color: var(--ink3);
  text-transform: uppercase;
  letter-spacing: 0.8px;
  margin-bottom: 0.4rem;
}

.field-input {
  width: 100%;
  background: var(--paper);
  border: 1px solid var(--rule);
  border-radius: 3px;
  padding: 0.65rem 0.85rem;
  color: var(--ink);
  font-size: 0.9rem;
  font-family: 'Instrument Sans', sans-serif;
  outline: none;
  transition: border-color 0.15s;
}

.field-input:focus { border-color: var(--ink2); }

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 0.65rem 1.25rem;
  border-radius: 3px;
  border: 1px solid transparent;
  cursor: pointer;
  font-family: 'Instrument Sans', sans-serif;
  font-size: 0.88rem;
  font-weight: 500;
  transition: all 0.15s;
  text-decoration: none;
  white-space: nowrap;
}

.btn-ink {
  background: var(--ink);
  color: var(--paper);
  border-color: var(--ink);
  width: 100%;
  margin-top: 0.5rem;
  font-size: 0.9rem;
  padding: 0.75rem;
}
.btn-ink:hover { background: var(--ink2); border-color: var(--ink2); }

.btn-outline {
  background: transparent;
  color: var(--ink2);
  border-color: var(--rule);
}
.btn-outline:hover { border-color: var(--ink3); color: var(--ink); }

.btn-ghost {
  background: transparent;
  color: var(--ink3);
  border-color: transparent;
  padding: 0.5rem 0.75rem;
  font-size: 0.82rem;
}
.btn-ghost:hover { color: var(--ink); background: var(--paper2); }

.btn-danger-soft {
  background: var(--red-bg);
  color: var(--red);
  border-color: transparent;
  font-size: 0.78rem;
  padding: 0.35rem 0.7rem;
}
.btn-danger-soft:hover { border-color: var(--red); }

.btn-sm { padding: 0.4rem 0.85rem; font-size: 0.8rem; }

.error-line {
  color: var(--red);
  font-size: 0.8rem;
  margin-top: 0.5rem;
  display: none;
  font-style: italic;
}

/* ══════════════════════════════════════════
   APP SHELL
══════════════════════════════════════════ */
#app { display: none; height: 100vh; flex-direction: column; }
#app.on { display: flex; }

.topbar {
  height: 52px;
  background: var(--ink);
  color: var(--paper);
  display: flex;
  align-items: center;
  padding: 0 1.25rem;
  gap: 1.25rem;
  flex-shrink: 0;
  border-bottom: 2px solid var(--accent);
}

.topbar-brand {
  font-family: 'Libre Baskerville', serif;
  font-size: 1.05rem;
  font-weight: 700;
  letter-spacing: -0.3px;
  color: var(--paper);
  margin-right: auto;
}
.topbar-brand em { font-style: italic; color: #f0a080; }

.topbar-meta {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  font-size: 0.8rem;
  color: #a09888;
}

.role-chip {
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.68rem;
  padding: 0.18rem 0.55rem;
  border-radius: 2px;
  border: 1px solid;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.role-admin   { color: #f0a080; border-color: #f0a080; }
.role-analyst { color: #80c8f0; border-color: #80c8f0; }
.role-viewer  { color: #a0c880; border-color: #a0c880; }

.logout-btn {
  background: transparent;
  border: 1px solid #403c38;
  color: #a09888;
  padding: 0.3rem 0.75rem;
  border-radius: 2px;
  cursor: pointer;
  font-family: 'Instrument Sans', sans-serif;
  font-size: 0.78rem;
  transition: all 0.15s;
}
.logout-btn:hover { border-color: #a09888; color: var(--paper); }

/* ── Layout ── */
.layout { display: flex; flex: 1; overflow: hidden; }

.sidebar {
  width: 200px;
  background: #fff;
  border-right: 1px solid var(--rule);
  display: flex;
  flex-direction: column;
  padding: 1.5rem 0;
  flex-shrink: 0;
  overflow-y: auto;
}

.nav-group { padding: 0 0.75rem; margin-bottom: 1.5rem; }

.nav-group-label {
  font-size: 0.65rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--ink4);
  padding: 0.25rem 0.5rem;
  margin-bottom: 0.25rem;
}

.nav-btn {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  width: 100%;
  padding: 0.55rem 0.6rem;
  background: none;
  border: none;
  border-radius: 3px;
  cursor: pointer;
  color: var(--ink2);
  font-size: 0.84rem;
  font-family: 'Instrument Sans', sans-serif;
  text-align: left;
  transition: all 0.1s;
}
.nav-btn:hover { background: var(--paper2); color: var(--ink); }
.nav-btn.active { background: var(--ink); color: var(--paper); font-weight: 500; }
.nav-btn.active .nav-ico { filter: invert(1); }

.nav-ico { width: 16px; text-align: center; font-size: 13px; flex-shrink: 0; opacity: 0.7; }
.nav-btn.active .nav-ico { opacity: 1; }

.content { flex: 1; overflow-y: auto; padding: 1.75rem; }

/* ── Pages ── */
.page { display: none; }
.page.on { display: block; }

/* ── Page header ── */
.pg-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  margin-bottom: 1.75rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--rule);
  flex-wrap: wrap;
  gap: 0.75rem;
}

.pg-title {
  font-family: 'Libre Baskerville', serif;
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--ink);
  line-height: 1.1;
}

.pg-sub {
  font-size: 0.78rem;
  color: var(--ink3);
  margin-top: 0.25rem;
  font-style: italic;
  font-family: 'Libre Baskerville', serif;
}

/* ── Stat cards ── */
.stats-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; margin-bottom: 1.5rem; background: var(--rule); border: 1px solid var(--rule); border-radius: 4px; overflow: hidden; }

.stat-box {
  background: #fff;
  padding: 1.25rem 1.35rem;
  position: relative;
}

.stat-box-label {
  font-size: 0.7rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  color: var(--ink3);
  margin-bottom: 0.5rem;
}

.stat-box-val {
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.55rem;
  font-weight: 400;
  line-height: 1;
  color: var(--ink);
  font-variant-numeric: tabular-nums;
}

.stat-box-val.pos { color: var(--green); }
.stat-box-val.neg { color: var(--red); }
.stat-box-val.neu { color: var(--blue); }

.stat-box-foot {
  font-size: 0.72rem;
  color: var(--ink4);
  margin-top: 0.4rem;
  font-family: 'JetBrains Mono', monospace;
}

.stat-box-accent {
  position: absolute;
  top: 0; left: 0;
  width: 3px;
  height: 100%;
}

/* ── Two col ── */
.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }
@media (max-width: 860px) { .two-col { grid-template-columns: 1fr; } .stats-row { grid-template-columns: 1fr 1fr; } }

/* ── Cards ── */
.card {
  background: #fff;
  border: 1px solid var(--rule);
  border-radius: 4px;
  overflow: hidden;
}

.card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.9rem 1.1rem;
  border-bottom: 1px solid var(--rule);
  flex-wrap: wrap;
  gap: 0.5rem;
}

.card-title {
  font-family: 'Libre Baskerville', serif;
  font-size: 0.88rem;
  font-weight: 700;
  color: var(--ink);
}

.card-body { padding: 1.1rem; }

.chart-area { position: relative; height: 200px; }
.chart-area.tall { height: 260px; }

/* ── Table ── */
.tbl-wrap { overflow-x: auto; }

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.83rem;
}

th {
  padding: 0.6rem 0.9rem;
  text-align: left;
  font-size: 0.67rem;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  font-weight: 600;
  color: var(--ink3);
  background: var(--paper2);
  border-bottom: 1px solid var(--rule);
  white-space: nowrap;
}

td {
  padding: 0.72rem 0.9rem;
  border-bottom: 1px solid var(--paper2);
  color: var(--ink2);
  vertical-align: middle;
}

tr:last-child td { border-bottom: none; }
tr:hover td { background: var(--paper); }

.mono { font-family: 'JetBrains Mono', monospace; font-variant-numeric: tabular-nums; }

.type-pill {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 0.72rem;
  font-weight: 600;
  padding: 0.18rem 0.55rem;
  border-radius: 2px;
  text-transform: uppercase;
  letter-spacing: 0.4px;
  font-family: 'JetBrains Mono', monospace;
}
.type-pill.inc { background: var(--green-bg); color: var(--green); }
.type-pill.exp { background: var(--red-bg); color: var(--red); }

.cat-tag {
  font-size: 0.75rem;
  background: var(--paper2);
  color: var(--ink3);
  padding: 0.15rem 0.5rem;
  border-radius: 2px;
  border: 1px solid var(--rule);
}

.amt-cell { font-family: 'JetBrains Mono', monospace; font-weight: 500; font-size: 0.85rem; }
.amt-cell.inc { color: var(--green); }
.amt-cell.exp { color: var(--red); }

.act-row { display: flex; gap: 0.35rem; }

/* ── Filters ── */
.filters { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }

.f-inp {
  background: var(--paper);
  border: 1px solid var(--rule);
  border-radius: 3px;
  padding: 0.4rem 0.7rem;
  color: var(--ink);
  font-size: 0.8rem;
  font-family: 'Instrument Sans', sans-serif;
  outline: none;
  transition: border-color 0.15s;
}
.f-inp:focus { border-color: var(--ink2); }
select.f-inp option { background: #fff; }

/* ── Pagination ── */
.pager {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.65rem 1rem;
  border-top: 1px solid var(--rule);
  font-size: 0.78rem;
  color: var(--ink3);
  background: var(--paper);
}

.page-btns { display: flex; gap: 0.25rem; }

.pg-btn {
  min-width: 28px;
  height: 28px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 2px;
  border: 1px solid var(--rule);
  background: #fff;
  color: var(--ink2);
  cursor: pointer;
  font-size: 0.78rem;
  font-family: 'JetBrains Mono', monospace;
  transition: all 0.1s;
  padding: 0 6px;
}
.pg-btn:hover { border-color: var(--ink2); color: var(--ink); }
.pg-btn.cur { background: var(--ink); color: var(--paper); border-color: var(--ink); }
.pg-btn:disabled { opacity: 0.3; cursor: default; pointer-events: none; }

/* ── Modal ── */
.overlay {
  position: fixed;
  inset: 0;
  background: rgba(26, 23, 20, 0.65);
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.2s;
}
.overlay.open { opacity: 1; pointer-events: all; }

.modal {
  background: #fff;
  border: 1px solid var(--rule);
  border-radius: 4px;
  padding: 1.75rem;
  width: min(500px, 92vw);
  max-height: 90vh;
  overflow-y: auto;
  transform: translateY(8px);
  transition: transform 0.2s;
  box-shadow: 0 8px 40px rgba(0,0,0,0.18);
}
.overlay.open .modal { transform: translateY(0); }

.modal-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 1.4rem;
  padding-bottom: 0.9rem;
  border-bottom: 1px solid var(--rule);
}

.modal-title {
  font-family: 'Libre Baskerville', serif;
  font-size: 1.05rem;
  font-weight: 700;
}

.modal-x {
  background: none;
  border: none;
  cursor: pointer;
  color: var(--ink3);
  font-size: 1.1rem;
  line-height: 1;
  padding: 0.2rem;
}
.modal-x:hover { color: var(--ink); }

.form-2col { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.form-2col .field-group { margin-bottom: 0; }

.modal-foot {
  display: flex;
  gap: 0.6rem;
  justify-content: flex-end;
  margin-top: 1.4rem;
  padding-top: 1rem;
  border-top: 1px solid var(--rule);
}

/* ── Recent items ── */
.recent-list { display: flex; flex-direction: column; }

.recent-row {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 0;
  border-bottom: 1px solid var(--paper2);
}
.recent-row:last-child { border-bottom: none; }

.recent-dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.recent-dot.inc { background: var(--green); }
.recent-dot.exp { background: var(--red); }

.recent-info { flex: 1; min-width: 0; }
.recent-cat { font-size: 0.85rem; font-weight: 500; color: var(--ink); }
.recent-date { font-size: 0.73rem; color: var(--ink4); font-family: 'JetBrains Mono', monospace; margin-top: 1px; }

.recent-amt { font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; font-weight: 500; }
.recent-amt.inc { color: var(--green); }
.recent-amt.exp { color: var(--red); }

/* ── Category bars ── */
.cat-rows { display: flex; flex-direction: column; gap: 0.7rem; }
.cat-r { display: flex; align-items: center; gap: 0.75rem; }
.cat-nm { font-size: 0.8rem; color: var(--ink2); width: 96px; flex-shrink: 0; }
.cat-track { flex: 1; height: 5px; background: var(--paper2); border-radius: 2px; overflow: hidden; }
.cat-fill { height: 100%; background: var(--accent); border-radius: 2px; transition: width 0.5s ease; }
.cat-val { font-size: 0.78rem; font-family: 'JetBrains Mono', monospace; color: var(--ink2); min-width: 72px; text-align: right; }

/* ── User cards ── */
.user-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px, 1fr)); gap: 0.75rem; }

.user-card {
  background: #fff;
  border: 1px solid var(--rule);
  border-radius: 4px;
  padding: 1.1rem;
}

.user-card-top { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.85rem; }

.avatar {
  width: 36px; height: 36px;
  border-radius: 50%;
  background: var(--ink);
  color: var(--paper);
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: 'Libre Baskerville', serif;
  font-size: 0.9rem;
  font-weight: 700;
  flex-shrink: 0;
}

.user-name { font-size: 0.88rem; font-weight: 600; color: var(--ink); }
.user-email { font-size: 0.73rem; color: var(--ink3); margin-top: 1px; font-family: 'JetBrains Mono', monospace; }

.user-card-foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding-top: 0.75rem;
  border-top: 1px solid var(--paper2);
}

/* ── Toast ── */
.toast {
  position: fixed;
  bottom: 1.25rem;
  right: 1.25rem;
  z-index: 9999;
  background: var(--ink);
  color: var(--paper);
  border-radius: 3px;
  padding: 0.65rem 1.1rem;
  font-size: 0.82rem;
  font-family: 'JetBrains Mono', monospace;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  transform: translateY(12px);
  opacity: 0;
  transition: all 0.22s;
  pointer-events: none;
  max-width: 300px;
  border-left: 3px solid var(--ink4);
}
.toast.show { transform: translateY(0); opacity: 1; }
.toast.ok { border-left-color: var(--green); }
.toast.err { border-left-color: var(--red); }

/* ── Empty ── */
.empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 2.5rem;
  color: var(--ink4);
  text-align: center;
  gap: 0.4rem;
  font-style: italic;
  font-family: 'Libre Baskerville', serif;
  font-size: 0.88rem;
}

/* ── Spinner ── */
.spin {
  width: 16px; height: 16px;
  border: 2px solid var(--rule);
  border-top-color: var(--ink2);
  border-radius: 50%;
  animation: spin 0.65s linear infinite;
  display: inline-block;
}
@keyframes spin { to { transform: rotate(360deg); } }

/* ── divider ── */
.hr { height: 1px; background: var(--rule); margin: 1rem 0; }
</style>
</head>
<body>

<!-- ════ LOGIN ════ -->
<div id="login-page">
  <div class="login-wrap">
    <div class="login-header">
      <div class="login-wordmark">Fin<em>Track</em></div>
      <div class="login-tagline">Personal finance ledger & analytics</div>
    </div>
    <div class="login-card">
      <div class="demo-box">
        <p>
          <strong>admin@fintrack.com</strong> · admin123 · Admin<br>
          <strong>analyst@fintrack.com</strong> · analyst123 · Analyst<br>
          <strong>viewer@fintrack.com</strong> · viewer123 · Viewer
        </p>
      </div>
      <div class="field-group">
        <label class="field-label">Email address</label>
        <input class="field-input" type="email" id="li-email" value="admin@fintrack.com">
      </div>
      <div class="field-group">
        <label class="field-label">Password</label>
        <input class="field-input" type="password" id="li-pw" value="admin123">
      </div>
      <p class="error-line" id="li-err">Incorrect email or password.</p>
      <button class="btn btn-ink" onclick="doLogin()">
        Sign in &nbsp;<span id="li-spin" style="display:none"><span class="spin"></span></span>
      </button>
    </div>
  </div>
</div>

<!-- ════ APP ════ -->
<div id="app">
  <div class="topbar">
    <div class="topbar-brand">Fin<em>Track</em></div>
    <div class="topbar-meta">
      <span id="tb-name">—</span>
      <span id="tb-chip" class="role-chip">—</span>
      <button class="logout-btn" onclick="doLogout()">Sign out</button>
    </div>
  </div>

  <div class="layout">
    <nav class="sidebar">
      <div class="nav-group">
        <div class="nav-group-label">Main</div>
        <button class="nav-btn active" onclick="goPage('dashboard',this)">
          <span class="nav-ico">▤</span> Dashboard
        </button>
        <button class="nav-btn" onclick="goPage('transactions',this)">
          <span class="nav-ico">≡</span> Transactions
        </button>
        <button class="nav-btn" onclick="goPage('analytics',this)">
          <span class="nav-ico">◎</span> Analytics
        </button>
      </div>
      <div class="nav-group" id="admin-nav" style="display:none">
        <div class="nav-group-label">Admin</div>
        <button class="nav-btn" onclick="goPage('users',this)">
          <span class="nav-ico">◉</span> Users
        </button>
      </div>
      <div class="nav-group" style="margin-top:auto">
        <div class="nav-group-label">Tools</div>
        <button class="nav-btn" onclick="doExport()">
          <span class="nav-ico">↓</span> Export CSV
        </button>
      </div>
    </nav>

    <main class="content">

      <!-- ── DASHBOARD ── -->
      <div class="page on" id="pg-dashboard">
        <div class="pg-header">
          <div>
            <h1 class="pg-title">Overview</h1>
            <p class="pg-sub">Your financial summary at a glance</p>
          </div>
          <button class="btn btn-ink btn-sm" id="dash-add" onclick="openTxModal()" style="display:none">+ New entry</button>
        </div>

        <div class="stats-row">
          <div class="stat-box">
            <div class="stat-box-accent" style="background:var(--green)"></div>
            <div class="stat-box-label">Total Income</div>
            <div class="stat-box-val pos mono" id="s-income">—</div>
            <div class="stat-box-foot" id="s-income-ct">0 records</div>
          </div>
          <div class="stat-box">
            <div class="stat-box-accent" style="background:var(--red)"></div>
            <div class="stat-box-label">Total Expenses</div>
            <div class="stat-box-val neg mono" id="s-exp">—</div>
            <div class="stat-box-foot" id="s-exp-ct">0 records</div>
          </div>
          <div class="stat-box">
            <div class="stat-box-accent" id="s-bal-bar" style="background:var(--blue)"></div>
            <div class="stat-box-label">Net Balance</div>
            <div class="stat-box-val neu mono" id="s-bal">—</div>
            <div class="stat-box-foot">income − expenses</div>
          </div>
          <div class="stat-box">
            <div class="stat-box-accent" style="background:var(--amber)"></div>
            <div class="stat-box-label">Total Records</div>
            <div class="stat-box-val mono" id="s-tot">—</div>
            <div class="stat-box-foot">all transactions</div>
          </div>
        </div>

        <div class="two-col" style="margin-bottom:1rem">
          <div class="card">
            <div class="card-head">
              <span class="card-title">Monthly cash flow</span>
              <span style="font-size:0.72rem;color:var(--ink4);font-family:'JetBrains Mono',monospace">last 6 months</span>
            </div>
            <div class="card-body">
              <div class="chart-area"><canvas id="ch-monthly"></canvas></div>
            </div>
          </div>
          <div class="card">
            <div class="card-head">
              <span class="card-title">Expense breakdown</span>
              <span style="font-size:0.72rem;color:var(--ink4);font-family:'JetBrains Mono',monospace">by category</span>
            </div>
            <div class="card-body">
              <div class="chart-area"><canvas id="ch-donut"></canvas></div>
            </div>
          </div>
        </div>

        <div class="two-col">
          <div class="card">
            <div class="card-head"><span class="card-title">Recent activity</span></div>
            <div class="card-body" style="padding:0.5rem 1.1rem">
              <div class="recent-list" id="recent-list">
                <div class="empty"><span class="spin"></span></div>
              </div>
            </div>
          </div>
          <div class="card">
            <div class="card-head"><span class="card-title">Top spending</span></div>
            <div class="card-body">
              <div class="cat-rows" id="cat-rows">
                <div class="empty"><span class="spin"></span></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- ── TRANSACTIONS ── -->
      <div class="page" id="pg-transactions">
        <div class="pg-header">
          <div>
            <h1 class="pg-title">Transactions</h1>
            <p class="pg-sub">Full ledger of all financial entries</p>
          </div>
          <button class="btn btn-ink btn-sm" id="tx-add" onclick="openTxModal()" style="display:none">+ New entry</button>
        </div>
        <div class="card">
          <div class="card-head">
            <span class="card-title">All records</span>
            <div class="filters">
              <input class="f-inp" type="text" id="f-q" placeholder="Search notes / category…" style="width:190px" oninput="debounceLoad()">
              <select class="f-inp" id="f-type" onchange="loadTx()">
                <option value="">All types</option>
                <option value="income">Income</option>
                <option value="expense">Expense</option>
              </select>
              <select class="f-inp" id="f-cat" onchange="loadTx()">
                <option value="">All categories</option>
              </select>
              <input class="f-inp" type="date" id="f-from" onchange="loadTx()">
              <input class="f-inp" type="date" id="f-to" onchange="loadTx()">
              <button class="btn btn-ghost btn-sm" onclick="clearF()">Clear</button>
            </div>
          </div>
          <div class="tbl-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th><th>Date</th><th>Type</th><th>Category</th>
                  <th>Amount</th><th>Notes</th><th></th>
                </tr>
              </thead>
              <tbody id="tx-body">
                <tr><td colspan="7"><div class="empty"><span class="spin"></span></div></td></tr>
              </tbody>
            </table>
          </div>
          <div class="pager">
            <span id="pager-info">—</span>
            <div class="page-btns" id="pager-btns"></div>
          </div>
        </div>
      </div>

      <!-- ── ANALYTICS ── -->
      <div class="page" id="pg-analytics">
        <div class="pg-header">
          <div>
            <h1 class="pg-title">Analytics</h1>
            <p class="pg-sub">Detailed income and expense analysis</p>
          </div>
          <select class="f-inp" id="ana-year" onchange="loadAnalytics()">
            <option value="2024">2024</option>
            <option value="2025">2025</option>
            <option value="2026">2026</option>
          </select>
        </div>
        <div class="card" style="margin-bottom:1rem">
          <div class="card-head"><span class="card-title">Monthly income vs expenses — full year</span></div>
          <div class="card-body"><div class="chart-area tall"><canvas id="ch-bar-yr"></canvas></div></div>
        </div>
        <div class="two-col">
          <div class="card">
            <div class="card-head"><span class="card-title">Income sources</span></div>
            <div class="card-body"><div class="chart-area"><canvas id="ch-inc-pie"></canvas></div></div>
          </div>
          <div class="card">
            <div class="card-head"><span class="card-title">Expense categories</span></div>
            <div class="card-body"><div class="chart-area"><canvas id="ch-exp-pie"></canvas></div></div>
          </div>
        </div>
      </div>

      <!-- ── USERS ── -->
      <div class="page" id="pg-users">
        <div class="pg-header">
          <div>
            <h1 class="pg-title">Users</h1>
            <p class="pg-sub">Manage system accounts and roles</p>
          </div>
          <button class="btn btn-ink btn-sm" onclick="openUserModal()">+ Add user</button>
        </div>
        <div class="user-grid" id="user-grid">
          <div class="empty" style="grid-column:1/-1"><span class="spin"></span></div>
        </div>
      </div>

    </main>
  </div>
</div>

<!-- ════ TX MODAL ════ -->
<div class="overlay" id="tx-modal" onclick="closeTxOnBg(event)">
  <div class="modal">
    <div class="modal-head">
      <span class="modal-title" id="tx-modal-title">New transaction</span>
      <button class="modal-x" onclick="closeTx()">✕</button>
    </div>
    <input type="hidden" id="tx-id">
    <div class="form-2col" style="margin-bottom:1rem">
      <div class="field-group">
        <label class="field-label">Amount (₹)</label>
        <input class="field-input" type="number" id="tx-amt" placeholder="0.00" min="0.01" step="0.01">
      </div>
      <div class="field-group">
        <label class="field-label">Type</label>
        <select class="field-input" id="tx-type">
          <option value="income">Income</option>
          <option value="expense">Expense</option>
        </select>
      </div>
    </div>
    <div class="form-2col" style="margin-bottom:1rem">
      <div class="field-group">
        <label class="field-label">Category</label>
        <select class="field-input" id="tx-cat">
          <optgroup label="Income">
            <option>Salary</option><option>Freelance</option>
            <option>Investment</option><option>Bonus</option><option>Rental</option>
          </optgroup>
          <optgroup label="Expense">
            <option>Food</option><option>Rent</option><option>Transport</option>
            <option>Shopping</option><option>Utilities</option><option>Healthcare</option>
            <option>Entertainment</option><option>Education</option>
          </optgroup>
          <option>Other</option>
        </select>
      </div>
      <div class="field-group">
        <label class="field-label">Date</label>
        <input class="field-input" type="date" id="tx-date">
      </div>
    </div>
    <div class="field-group">
      <label class="field-label">Notes</label>
      <input class="field-input" type="text" id="tx-notes" placeholder="Optional description…">
    </div>
    <p class="error-line" id="tx-err">Please check the fields above.</p>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="closeTx()">Cancel</button>
      <button class="btn btn-ink" onclick="saveTx()" id="tx-save-btn">Save entry</button>
    </div>
  </div>
</div>

<!-- ════ USER MODAL ════ -->
<div class="overlay" id="u-modal" onclick="closeUOnBg(event)">
  <div class="modal">
    <div class="modal-head">
      <span class="modal-title">New user</span>
      <button class="modal-x" onclick="closeU()">✕</button>
    </div>
    <div class="field-group">
      <label class="field-label">Full name</label>
      <input class="field-input" type="text" id="u-name" placeholder="Jane Doe">
    </div>
    <div class="field-group">
      <label class="field-label">Email address</label>
      <input class="field-input" type="email" id="u-email" placeholder="jane@example.com">
    </div>
    <div class="form-2col">
      <div class="field-group">
        <label class="field-label">Password</label>
        <input class="field-input" type="password" id="u-pw" placeholder="••••••••">
      </div>
      <div class="field-group">
        <label class="field-label">Role</label>
        <select class="field-input" id="u-role">
          <option value="viewer">Viewer</option>
          <option value="analyst">Analyst</option>
          <option value="admin">Admin</option>
        </select>
      </div>
    </div>
    <p class="error-line" id="u-err">Error creating user.</p>
    <div class="modal-foot">
      <button class="btn btn-outline" onclick="closeU()">Cancel</button>
      <button class="btn btn-ink" onclick="saveUser()">Create user</button>
    </div>
  </div>
</div>

<!-- ════ TOAST ════ -->
<div class="toast" id="toast"></div>

<script>
// ─── globals ───────────────────────────────
let token = null, me = null;
let txPage = 1, txPages = 1, txTotal = 0;
let chMonthly=null, chDonut=null, chBarYr=null, chIncPie=null, chExpPie=null;

const CATS = ["Salary","Freelance","Investment","Bonus","Rental","Food","Rent","Transport","Shopping","Utilities","Healthcare","Entertainment","Education","Other"];

// warm earthy palette — hand-picked, not generated
const PAL = ["#c94f2a","#2d6a4f","#1a4a7a","#7a4f1a","#6b3fa0","#2a6a6a","#8b3a4a","#4a6b2a","#3a4a8b","#7a6b1a"];

// ─── helpers ───────────────────────────────
const $  = id => document.getElementById(id);
const rupee = n => '₹' + (n||0).toLocaleString('en-IN', {minimumFractionDigits:2, maximumFractionDigits:2});

async function api(path, opts={}) {
  const h = {'Content-Type':'application/json'};
  if (token) h['Authorization'] = 'Bearer ' + token;
  const r = await fetch('/api' + path, {...opts, headers: h});
  const d = await r.json();
  if (!r.ok) throw new Error(d.error || 'Request failed');
  return d;
}

function toast(msg, type='ok') {
  const t = $('toast');
  t.textContent = msg;
  t.className = 'toast show ' + type;
  setTimeout(() => t.className = 'toast', 2800);
}

function goPage(name, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('on'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  $('pg-'+name).classList.add('on');
  if (el) el.classList.add('active');
  if (name === 'transactions') loadTx();
  if (name === 'analytics')    loadAnalytics();
  if (name === 'users')        loadUsers();
}

// ─── auth ──────────────────────────────────
async function doLogin() {
  $('li-err').style.display = 'none';
  $('li-spin').style.display = 'inline';
  try {
    const d = await api('/auth/login', {method:'POST', body: JSON.stringify({email: $('li-email').value.trim(), password: $('li-pw').value})});
    token = d.token; me = d.user;
    localStorage.setItem('ft_t', token);
    localStorage.setItem('ft_u', JSON.stringify(me));
    boot();
  } catch(e) {
    $('li-err').textContent = e.message;
    $('li-err').style.display = 'block';
  }
  $('li-spin').style.display = 'none';
}
$('li-pw').addEventListener('keydown', e => { if(e.key==='Enter') doLogin(); });

function doLogout() {
  token = null; me = null;
  localStorage.removeItem('ft_t'); localStorage.removeItem('ft_u');
  $('app').classList.remove('on'); $('app').style.display='none';
  $('login-page').style.display='flex';
}

function boot() {
  $('login-page').style.display = 'none';
  $('app').style.display = 'flex'; $('app').classList.add('on');

  $('tb-name').textContent = me.name;
  $('tb-chip').textContent = me.role;
  $('tb-chip').className = 'role-chip role-' + me.role;

  if (me.role === 'admin')   { $('admin-nav').style.display='block'; $('dash-add').style.display='inline-flex'; $('tx-add').style.display='inline-flex'; }
  if (me.role === 'analyst') { $('dash-add').style.display='inline-flex'; $('tx-add').style.display='inline-flex'; }

  // populate category filter
  const sel = $('f-cat');
  CATS.forEach(c => { const o = document.createElement('option'); o.value=c; o.textContent=c; sel.appendChild(o); });

  loadDash();
}

window.addEventListener('load', () => {
  const t = localStorage.getItem('ft_t'), u = localStorage.getItem('ft_u');
  if (t && u) { token=t; me=JSON.parse(u); boot(); }
});

// ─── dashboard ─────────────────────────────
async function loadDash() {
  try {
    const d = await api('/summary');
    const t = d.totals;
    $('s-income').textContent  = rupee(t.total_income);
    $('s-exp').textContent     = rupee(t.total_expenses);
    $('s-tot').textContent     = t.total_transactions;
    const bal = t.balance||0;
    $('s-bal').textContent     = rupee(bal);
    $('s-bal').className       = 'stat-box-val mono ' + (bal>=0?'pos':'neg');
    $('s-bal-bar').style.background = bal>=0 ? 'var(--green)' : 'var(--red)';
    $('s-income-ct').textContent = t.income_count  + ' records';
    $('s-exp-ct').textContent    = t.expense_count + ' records';

    // monthly chart
    const mo = d.monthly_totals;
    const moLabels = mo.map(m => { const [y,n]=m.month.split('-'); return new Date(y,n-1).toLocaleString('default',{month:'short'}); });
    if (chMonthly) chMonthly.destroy();
    chMonthly = new Chart($('ch-monthly'), {
      type: 'bar',
      data: { labels: moLabels, datasets: [
        { label:'Income',   data: mo.map(m=>m.income),   backgroundColor:'#b8e8c8', borderColor:'#2d6a4f', borderWidth:1, borderRadius:2 },
        { label:'Expenses', data: mo.map(m=>m.expenses), backgroundColor:'#f8d0d0', borderColor:'#9b2335', borderWidth:1, borderRadius:2 }
      ]},
      options: { responsive:true, maintainAspectRatio:false,
        plugins:{ legend:{ labels:{ color:'#4a4540', font:{size:11, family:"'Instrument Sans',sans-serif"} } } },
        scales:{
          x:{ ticks:{color:'#8a8278', font:{size:11}}, grid:{display:false} },
          y:{ ticks:{color:'#8a8278', font:{size:10, family:"'JetBrains Mono',monospace"}, callback:v=>'₹'+(v/1000).toFixed(0)+'k'}, grid:{color:'#ede8dc'} }
        }
      }
    });

    // donut
    const expCats = d.category_breakdown.filter(c=>c.type==='expense').slice(0,7);
    if (chDonut) chDonut.destroy();
    chDonut = new Chart($('ch-donut'), {
      type: 'doughnut',
      data: { labels: expCats.map(c=>c.category), datasets:[{ data: expCats.map(c=>c.total), backgroundColor: PAL, borderWidth:0, hoverOffset:6 }] },
      options: { responsive:true, maintainAspectRatio:false, cutout:'62%',
        plugins:{ legend:{ position:'right', labels:{ color:'#4a4540', font:{size:11}, boxWidth:8, padding:7 } } }
      }
    });

    // recent
    const rl = $('recent-list');
    rl.innerHTML = '';
    if (!d.recent_transactions.length) { rl.innerHTML = '<div class="empty">No transactions yet</div>'; }
    d.recent_transactions.forEach(tx => {
      rl.innerHTML += `<div class="recent-row">
        <div class="recent-dot ${tx.type==='income'?'inc':'exp'}"></div>
        <div class="recent-info">
          <div class="recent-cat">${tx.category}</div>
          <div class="recent-date">${tx.date}</div>
        </div>
        <div class="recent-amt ${tx.type==='income'?'inc':'exp'}">${tx.type==='income'?'+':'−'}${rupee(tx.amount)}</div>
      </div>`;
    });

    // top spending
    const cr = $('cat-rows');
    cr.innerHTML = '';
    const top = d.top_expense_categories;
    if (!top.length) { cr.innerHTML = '<div class="empty">No expense data</div>'; return; }
    const max = top[0].total || 1;
    top.forEach((c,i) => {
      const pct = Math.round((c.total/max)*100);
      cr.innerHTML += `<div class="cat-r">
        <div class="cat-nm">${c.category}</div>
        <div class="cat-track"><div class="cat-fill" style="width:${pct}%;background:${PAL[i]}"></div></div>
        <div class="cat-val">${rupee(c.total)}</div>
      </div>`;
    });

  } catch(e) { toast(e.message, 'err'); }
}

// ─── transactions ───────────────────────────
let debTimer;
function debounceLoad() { clearTimeout(debTimer); debTimer=setTimeout(()=>{txPage=1;loadTx();},380); }

function clearF() {
  ['f-q','f-type','f-cat','f-from','f-to'].forEach(id=>{const e=$( id);e.tagName==='SELECT'?e.value='':e.value='';});
  txPage=1; loadTx();
}

async function loadTx() {
  const p = new URLSearchParams({ page:txPage, per_page:15, search:$('f-q').value, type:$('f-type').value, category:$('f-cat').value, date_from:$('f-from').value, date_to:$('f-to').value });
  const body = $('tx-body');
  body.innerHTML = '<tr><td colspan="7"><div class="empty"><span class="spin"></span></div></td></tr>';
  try {
    const d = await api('/transactions?'+p);
    txTotal=d.pagination.total; txPages=d.pagination.pages;
    $('pager-info').textContent = `${d.data.length} of ${txTotal} records`;
    renderPager();
    if (!d.data.length) { body.innerHTML='<tr><td colspan="7"><div class="empty">Nothing matched your filters</div></td></tr>'; return; }
    const role = me.role;
    body.innerHTML = d.data.map(tx => `<tr>
      <td class="mono" style="color:var(--ink4);font-size:0.75rem">#${tx.id}</td>
      <td class="mono" style="font-size:0.8rem">${tx.date}</td>
      <td><span class="type-pill ${tx.type==='income'?'inc':'exp'}">${tx.type==='income'?'▲':'▼'}&nbsp;${tx.type}</span></td>
      <td><span class="cat-tag">${tx.category}</span></td>
      <td class="amt-cell ${tx.type==='income'?'inc':'exp'}">${tx.type==='income'?'+':'−'}${rupee(tx.amount)}</td>
      <td style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ink3);font-size:0.8rem">${tx.notes||'—'}</td>
      <td><div class="act-row">
        ${role!=='viewer'?`<button class="btn btn-ghost btn-sm" onclick="editTx(${tx.id})">Edit</button>`:''}
        ${role==='admin'?`<button class="btn btn-danger-soft" onclick="delTx(${tx.id})">Delete</button>`:''}
      </div></td>
    </tr>`).join('');
  } catch(e) { toast(e.message,'err'); }
}

function renderPager() {
  const c = $('pager-btns'); c.innerHTML='';
  const prev = document.createElement('button');
  prev.className='pg-btn'; prev.textContent='←'; prev.disabled=txPage<=1;
  prev.onclick=()=>{txPage--;loadTx();}; c.appendChild(prev);
  for(let i=Math.max(1,txPage-2);i<=Math.min(txPages,txPage+2);i++){
    const b=document.createElement('button');
    b.className='pg-btn'+(i===txPage?' cur':''); b.textContent=i;
    b.onclick=(p=>()=>{txPage=p;loadTx();})(i); c.appendChild(b);
  }
  const next=document.createElement('button');
  next.className='pg-btn'; next.textContent='→'; next.disabled=txPage>=txPages;
  next.onclick=()=>{txPage++;loadTx();}; c.appendChild(next);
}

// ─── tx modal ──────────────────────────────
function openTxModal(tx=null) {
  $('tx-modal-title').textContent = tx ? 'Edit transaction' : 'New transaction';
  $('tx-id').value    = tx ? tx.id : '';
  $('tx-amt').value   = tx ? tx.amount : '';
  $('tx-type').value  = tx ? tx.type : 'income';
  $('tx-cat').value   = tx ? tx.category : 'Salary';
  $('tx-date').value  = tx ? tx.date : new Date().toISOString().split('T')[0];
  $('tx-notes').value = tx ? tx.notes : '';
  $('tx-err').style.display = 'none';
  $('tx-modal').classList.add('open');
}
function closeTx() { $('tx-modal').classList.remove('open'); }
function closeTxOnBg(e) { if(e.target===$('tx-modal')) closeTx(); }

async function editTx(id) {
  try { openTxModal(await api('/transactions/'+id)); }
  catch(e) { toast(e.message,'err'); }
}

async function saveTx() {
  const id = $('tx-id').value;
  const body = { amount:parseFloat($('tx-amt').value), type:$('tx-type').value, category:$('tx-cat').value, date:$('tx-date').value, notes:$('tx-notes').value };
  $('tx-err').style.display='none';
  const btn=$('tx-save-btn'); btn.disabled=true; btn.textContent='Saving…';
  try {
    if (id) { await api('/transactions/'+id,{method:'PUT', body:JSON.stringify(body)}); toast('Entry updated'); }
    else     { await api('/transactions',   {method:'POST',body:JSON.stringify(body)}); toast('Entry saved'); }
    closeTx(); loadTx(); loadDash();
  } catch(e) { $('tx-err').textContent=e.message; $('tx-err').style.display='block'; }
  btn.disabled=false; btn.textContent='Save entry';
}

async function delTx(id) {
  if (!confirm('Delete this entry? This cannot be undone.')) return;
  try { await api('/transactions/'+id,{method:'DELETE'}); toast('Deleted'); loadTx(); loadDash(); }
  catch(e) { toast(e.message,'err'); }
}

// ─── analytics ─────────────────────────────
async function loadAnalytics() {
  const yr = $('ana-year').value;
  try {
    const [mo, sum] = await Promise.all([api('/analytics/monthly?year='+yr), api('/summary')]);
    const MO = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const inc=new Array(12).fill(0), exp=new Array(12).fill(0);
    mo.forEach(m=>{inc[+m.month-1]=m.income; exp[+m.month-1]=m.expenses;});

    if (chBarYr) chBarYr.destroy();
    chBarYr = new Chart($('ch-bar-yr'),{
      type:'bar',
      data:{labels:MO, datasets:[
        {label:'Income',   data:inc, backgroundColor:'#b8e8c8', borderColor:'#2d6a4f', borderWidth:1, borderRadius:2},
        {label:'Expenses', data:exp, backgroundColor:'#f8d0d0', borderColor:'#9b2335', borderWidth:1, borderRadius:2}
      ]},
      options:{responsive:true,maintainAspectRatio:false,
        plugins:{legend:{labels:{color:'#4a4540',font:{size:11}}}},
        scales:{x:{ticks:{color:'#8a8278',font:{size:11}},grid:{display:false}},y:{ticks:{color:'#8a8278',font:{size:10,family:"'JetBrains Mono',monospace"},callback:v=>'₹'+(v/1000).toFixed(0)+'k'},grid:{color:'#ede8dc'}}}}
    });

    const cats = sum.category_breakdown;
    const incC = cats.filter(c=>c.type==='income');
    const expC = cats.filter(c=>c.type==='expense');

    if (chIncPie) chIncPie.destroy();
    chIncPie = new Chart($('ch-inc-pie'),{type:'doughnut',data:{labels:incC.map(c=>c.category),datasets:[{data:incC.map(c=>c.total),backgroundColor:PAL,borderWidth:0,hoverOffset:6}]},options:{responsive:true,maintainAspectRatio:false,cutout:'58%',plugins:{legend:{labels:{color:'#4a4540',font:{size:11},boxWidth:8,padding:7}}}}});

    if (chExpPie) chExpPie.destroy();
    chExpPie = new Chart($('ch-exp-pie'),{type:'doughnut',data:{labels:expC.map(c=>c.category),datasets:[{data:expC.map(c=>c.total),backgroundColor:[...PAL].reverse(),borderWidth:0,hoverOffset:6}]},options:{responsive:true,maintainAspectRatio:false,cutout:'58%',plugins:{legend:{labels:{color:'#4a4540',font:{size:11},boxWidth:8,padding:7}}}}});

  } catch(e) { toast(e.message,'err'); }
}

// ─── users ─────────────────────────────────
async function loadUsers() {
  const g = $('user-grid');
  g.innerHTML='<div class="empty" style="grid-column:1/-1"><span class="spin"></span></div>';
  try {
    const users = await api('/users');
    if (!users.length) { g.innerHTML='<div class="empty" style="grid-column:1/-1">No users found</div>'; return; }
    g.innerHTML = users.map(u=>`
      <div class="user-card">
        <div class="user-card-top">
          <div class="avatar">${u.name.charAt(0).toUpperCase()}</div>
          <div>
            <div class="user-name">${u.name}</div>
            <div class="user-email">${u.email}</div>
          </div>
        </div>
        <div class="user-card-foot">
          <span class="role-chip role-${u.role}" style="font-size:0.66rem">${u.role}</span>
          ${u.id!==me.id?`<button class="btn btn-danger-soft" onclick="deleteUser(${u.id},'${u.name}')">Remove</button>`:'<span style="font-size:0.75rem;color:var(--ink4);font-style:italic">you</span>'}
        </div>
      </div>`).join('');
  } catch(e) { toast(e.message,'err'); }
}

function openUserModal() { $('u-modal').classList.add('open'); $('u-err').style.display='none'; }
function closeU() { $('u-modal').classList.remove('open'); }
function closeUOnBg(e) { if(e.target===$('u-modal')) closeU(); }

async function saveUser() {
  const b={name:$('u-name').value.trim(),email:$('u-email').value.trim(),password:$('u-pw').value,role:$('u-role').value};
  $('u-err').style.display='none';
  try { await api('/users',{method:'POST',body:JSON.stringify(b)}); toast('User created'); closeU(); loadUsers(); $('u-name').value=$('u-email').value=$('u-pw').value=''; }
  catch(e) { $('u-err').textContent=e.message; $('u-err').style.display='block'; }
}

async function deleteUser(id, name) {
  if (!confirm(`Remove "${name}"?`)) return;
  try { await api('/users/'+id,{method:'DELETE'}); toast('User removed'); loadUsers(); }
  catch(e) { toast(e.message,'err'); }
}

// ─── export ────────────────────────────────
function doExport() {
  const a=document.createElement('a'); a.href='/api/export/csv'; a.download='transactions.csv'; a.click();
  toast('CSV download started');
}
</script>
</body>
</html>
"""

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path.startswith("api/"):
        return jsonify({"error": "Not found"}), 404
    return FRONTEND_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}

# ─────────────────────────────────────────────
# Error handlers
# ─────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return FRONTEND_HTML, 200, {"Content-Type": "text/html; charset=utf-8"}

@app.errorhandler(405)
def method_not_allowed(e): return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def server_error(e): return jsonify({"error": "Internal server error"}), 500

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\n✅ FinTrack running at http://127.0.0.1:5000")
    print("   admin@fintrack.com   / admin123")
    print("   analyst@fintrack.com / analyst123")
    print("   viewer@fintrack.com  / viewer123\n")
    app.run(debug=True, port=5000)
