"""
FinTrack — Python Finance System Backend
========================================
Framework : Flask
Database  : SQLite (via built-in sqlite3)
Auth      : JWT (PyJWT)
Author    : Narendar Reddy Pathakuntla

Run:
    python app.py
Then open: http://127.0.0.1:5000
"""

import sqlite3
import hashlib
import os
import csv
import io
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, g, send_from_directory, Response
import jwt

# ──────────────────────────────────────────────────────────────
# App & Config
# ──────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static")

SECRET_KEY      = os.environ.get("SECRET_KEY", "fintrack_dev_secret_2024")
DB_PATH         = os.environ.get("DB_PATH", "fintrack.db")
TOKEN_EXP_HOURS = int(os.environ.get("TOKEN_EXP_HOURS", 24))


# ──────────────────────────────────────────────────────────────
# Database
# ──────────────────────────────────────────────────────────────
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
    if db:
        db.close()


def query(sql, params=(), one=False, commit=False):
    """Execute a query and return results or last row id."""
    db  = get_db()
    cur = db.execute(sql, params)
    if commit:
        db.commit()
        return cur.lastrowid
    rows = cur.fetchone() if one else cur.fetchall()
    if one:
        return dict(rows) if rows else None
    return [dict(r) for r in rows]


# ──────────────────────────────────────────────────────────────
# Database initialisation & seed data
# ──────────────────────────────────────────────────────────────
def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT    NOT NULL,
            email         TEXT    UNIQUE NOT NULL,
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'viewer'
                          CHECK(role IN ('admin','analyst','viewer')),
            created_at    TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER NOT NULL,
            amount     REAL    NOT NULL CHECK(amount > 0),
            type       TEXT    NOT NULL CHECK(type IN ('income','expense')),
            category   TEXT    NOT NULL,
            date       TEXT    NOT NULL,
            notes      TEXT    DEFAULT '',
            created_at TEXT    DEFAULT (datetime('now')),
            updated_at TEXT    DEFAULT (datetime('now')),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    db.commit()

    # Seed default users
    seed_users = [
        ("Admin User",   "admin@fintrack.com",   "admin123",   "admin"),
        ("Ana Analyst",  "analyst@fintrack.com", "analyst123", "analyst"),
        ("Viewer User",  "viewer@fintrack.com",  "viewer123",  "viewer"),
    ]
    for name, email, pw, role in seed_users:
        exists = db.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not exists:
            db.execute(
                "INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                (name, email, hash_pw(pw), role)
            )
    db.commit()

    # Seed sample transactions for admin (only if table is empty)
    admin = db.execute("SELECT id FROM users WHERE email='admin@fintrack.com'").fetchone()
    if admin and db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0] == 0:
        import random
        random.seed(42)
        uid = admin[0]
        income_cats  = ["Salary", "Freelance", "Investment", "Bonus", "Rental"]
        expense_cats = ["Food", "Rent", "Transport", "Shopping", "Utilities",
                        "Healthcare", "Entertainment", "Education"]
        rows = []
        for i in range(60):
            month = (i % 6) + 1
            day   = random.randint(1, 28)
            date  = f"2024-{month:02d}-{day:02d}"
            if random.random() > 0.4:
                rows.append((uid, round(random.uniform(500, 8000), 2),
                             "income", random.choice(income_cats), date, "Seed data"))
            else:
                rows.append((uid, round(random.uniform(50, 3000), 2),
                             "expense", random.choice(expense_cats), date, "Seed data"))
        db.executemany(
            "INSERT INTO transactions(user_id,amount,type,category,date,notes) VALUES(?,?,?,?,?,?)",
            rows
        )
        db.commit()

    db.close()


# ──────────────────────────────────────────────────────────────
# Auth utilities
# ──────────────────────────────────────────────────────────────
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


def make_token(user):
    payload = {
        "user_id": user["id"],
        "role":    user["role"],
        "name":    user["name"],
        "exp":     datetime.utcnow() + timedelta(hours=TOKEN_EXP_HOURS),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth  = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else None
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
                return jsonify({
                    "error": f"Access denied. Required: {', '.join(roles)}"
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ──────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────
VALID_CATEGORIES = [
    "Salary", "Freelance", "Investment", "Bonus", "Rental",
    "Food", "Rent", "Transport", "Shopping", "Utilities",
    "Healthcare", "Entertainment", "Education", "Other",
]


def validate_transaction(data, partial=False):
    errors = {}

    if not partial or "amount" in data:
        try:
            if float(data.get("amount", 0)) <= 0:
                errors["amount"] = "Must be a positive number"
        except (TypeError, ValueError):
            errors["amount"] = "Must be a valid number"

    if not partial or "type" in data:
        if data.get("type") not in ("income", "expense"):
            errors["type"] = "Must be 'income' or 'expense'"

    if not partial or "category" in data:
        if data.get("category") not in VALID_CATEGORIES:
            errors["category"] = f"Must be one of: {', '.join(VALID_CATEGORIES)}"

    if not partial or "date" in data:
        try:
            datetime.strptime(data.get("date", ""), "%Y-%m-%d")
        except ValueError:
            errors["date"] = "Must be in YYYY-MM-DD format"

    return errors


# ──────────────────────────────────────────────────────────────
# Routes — Auth
# ──────────────────────────────────────────────────────────────
@app.route("/api/auth/login", methods=["POST"])
def login():
    data     = request.get_json() or {}
    email    = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = query(
        "SELECT * FROM users WHERE email=? AND password_hash=?",
        (email, hash_pw(password)),
        one=True
    )
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({
        "token": make_token(user),
        "user":  {"id": user["id"], "name": user["name"],
                  "email": user["email"], "role": user["role"]},
    })


@app.route("/api/auth/me", methods=["GET"])
@token_required
def me():
    user = query(
        "SELECT id, name, email, role, created_at FROM users WHERE id=?",
        (g.current_user["user_id"],),
        one=True
    )
    return jsonify(user)


# ──────────────────────────────────────────────────────────────
# Routes — Transactions
# ──────────────────────────────────────────────────────────────
@app.route("/api/transactions", methods=["GET"])
@token_required
def list_transactions():
    role = g.current_user["role"]
    uid  = g.current_user["user_id"]

    filters, params = [], []
    if role != "admin":
        filters.append("t.user_id = ?")
        params.append(uid)

    # Optional filters from query string
    tx_type   = request.args.get("type")
    category  = request.args.get("category")
    date_from = request.args.get("date_from")
    date_to   = request.args.get("date_to")
    search    = request.args.get("search", "").strip()
    sort_by   = request.args.get("sort_by", "date")
    order     = "DESC" if request.args.get("order", "desc").lower() == "desc" else "ASC"
    page      = max(1, int(request.args.get("page", 1)))
    per_page  = min(100, max(1, int(request.args.get("per_page", 15))))

    if tx_type in ("income", "expense"):
        filters.append("t.type = ?"); params.append(tx_type)
    if category:
        filters.append("t.category = ?"); params.append(category)
    if date_from:
        filters.append("t.date >= ?"); params.append(date_from)
    if date_to:
        filters.append("t.date <= ?"); params.append(date_to)
    if search:
        filters.append("(t.notes LIKE ? OR t.category LIKE ?)")
        params += [f"%{search}%", f"%{search}%"]

    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    safe_sort = sort_by if sort_by in {"date","amount","category","type","created_at"} else "date"

    total  = query(f"SELECT COUNT(*) as c FROM transactions t {where}", params, one=True)["c"]
    offset = (page - 1) * per_page

    rows = query(
        f"""SELECT t.*, u.name as user_name
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            {where}
            ORDER BY t.{safe_sort} {order}
            LIMIT ? OFFSET ?""",
        params + [per_page, offset]
    )

    return jsonify({
        "data": rows,
        "pagination": {
            "total":    total,
            "page":     page,
            "per_page": per_page,
            "pages":    -(-total // per_page),
        },
    })


@app.route("/api/transactions/<int:tid>", methods=["GET"])
@token_required
def get_transaction(tid):
    role = g.current_user["role"]
    uid  = g.current_user["user_id"]

    row = query(
        "SELECT t.*, u.name as user_name FROM transactions t JOIN users u ON t.user_id=u.id WHERE t.id=?",
        (tid,), one=True
    )
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

    tid = query(
        "INSERT INTO transactions(user_id,amount,type,category,date,notes) VALUES(?,?,?,?,?,?)",
        (g.current_user["user_id"], float(data["amount"]),
         data["type"], data["category"], data["date"], data.get("notes", "")),
        commit=True
    )
    return jsonify(query("SELECT * FROM transactions WHERE id=?", (tid,), one=True)), 201


@app.route("/api/transactions/<int:tid>", methods=["PUT"])
@token_required
@role_required("admin", "analyst")
def update_transaction(tid):
    role = g.current_user["role"]
    uid  = g.current_user["user_id"]

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
    if not query("SELECT id FROM transactions WHERE id=?", (tid,), one=True):
        return jsonify({"error": "Transaction not found"}), 404
    query("DELETE FROM transactions WHERE id=?", (tid,), commit=True)
    return jsonify({"message": "Deleted successfully"})


# ──────────────────────────────────────────────────────────────
# Routes — Summary & Analytics
# ──────────────────────────────────────────────────────────────
@app.route("/api/summary", methods=["GET"])
@token_required
def summary():
    role = g.current_user["role"]
    uid  = g.current_user["user_id"]
    where = f"WHERE user_id = {uid}" if role != "admin" else ""
    and_  = "AND" if where else "WHERE"

    totals = query(f"""
        SELECT
            SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) AS total_income,
            SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS total_expenses,
            COUNT(*) AS total_transactions,
            COUNT(CASE WHEN type='income'  THEN 1 END) AS income_count,
            COUNT(CASE WHEN type='expense' THEN 1 END) AS expense_count
        FROM transactions {where}
    """, one=True)
    totals["balance"] = (totals["total_income"] or 0) - (totals["total_expenses"] or 0)

    category_breakdown = query(f"""
        SELECT category, type, SUM(amount) AS total, COUNT(*) AS count
        FROM transactions {where}
        GROUP BY category, type
        ORDER BY total DESC
    """)

    monthly_totals = query(f"""
        SELECT strftime('%Y-%m', date) AS month,
               SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) AS income,
               SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS expenses,
               COUNT(*) AS count
        FROM transactions
        {where} {and_} date >= date('now', '-6 months')
        GROUP BY month ORDER BY month ASC
    """)

    recent_transactions = query(f"""
        SELECT t.*, u.name AS user_name
        FROM transactions t JOIN users u ON t.user_id = u.id
        {where}
        ORDER BY t.date DESC, t.created_at DESC
        LIMIT 5
    """)

    top_expense_categories = query(f"""
        SELECT category, SUM(amount) AS total
        FROM transactions
        {where} {and_} type = 'expense'
        GROUP BY category ORDER BY total DESC LIMIT 5
    """)

    return jsonify({
        "totals":                 totals,
        "category_breakdown":     category_breakdown,
        "monthly_totals":         monthly_totals,
        "recent_transactions":    recent_transactions,
        "top_expense_categories": top_expense_categories,
    })


@app.route("/api/analytics/monthly", methods=["GET"])
@token_required
@role_required("admin", "analyst")
def analytics_monthly():
    role = g.current_user["role"]
    uid  = g.current_user["user_id"]
    year = request.args.get("year", str(datetime.now().year))
    where = f"WHERE user_id={uid}" if role != "admin" else ""
    and_  = "AND" if where else "WHERE"

    rows = query(f"""
        SELECT strftime('%m', date) AS month,
               SUM(CASE WHEN type='income'  THEN amount ELSE 0 END) AS income,
               SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) AS expenses
        FROM transactions {where} {and_} strftime('%Y', date)=?
        GROUP BY month ORDER BY month
    """, (year,))
    return jsonify(rows)


# ──────────────────────────────────────────────────────────────
# Routes — Users (Admin only)
# ──────────────────────────────────────────────────────────────
@app.route("/api/users", methods=["GET"])
@token_required
@role_required("admin")
def list_users():
    return jsonify(query("SELECT id, name, email, role, created_at FROM users ORDER BY id"))


@app.route("/api/users", methods=["POST"])
@token_required
@role_required("admin")
def create_user():
    data  = request.get_json() or {}
    name  = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    pw    = (data.get("password") or "").strip()
    role  = data.get("role", "viewer")

    if not name or not email or not pw:
        return jsonify({"error": "name, email, and password are required"}), 400
    if role not in ("admin", "analyst", "viewer"):
        return jsonify({"error": "Role must be admin, analyst, or viewer"}), 400
    if query("SELECT id FROM users WHERE email=?", (email,), one=True):
        return jsonify({"error": "Email already registered"}), 409

    uid = query(
        "INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
        (name, email, hash_pw(pw), role),
        commit=True
    )
    return jsonify({"id": uid, "name": name, "email": email, "role": role}), 201


@app.route("/api/users/<int:uid>", methods=["DELETE"])
@token_required
@role_required("admin")
def delete_user(uid):
    if uid == g.current_user["user_id"]:
        return jsonify({"error": "Cannot delete your own account"}), 400
    if not query("SELECT id FROM users WHERE id=?", (uid,), one=True):
        return jsonify({"error": "User not found"}), 404
    query("DELETE FROM users WHERE id=?", (uid,), commit=True)
    return jsonify({"message": "User deleted"})


# ──────────────────────────────────────────────────────────────
# Routes — Export
# ──────────────────────────────────────────────────────────────
@app.route("/api/export/csv", methods=["GET"])
@token_required
def export_csv():
    role  = g.current_user["role"]
    uid   = g.current_user["user_id"]
    where = "" if role == "admin" else f"WHERE t.user_id={uid}"

    rows = query(f"""
        SELECT t.id, u.name AS user, t.amount, t.type,
               t.category, t.date, t.notes, t.created_at
        FROM transactions t JOIN users u ON t.user_id = u.id
        {where} ORDER BY t.date DESC
    """)

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["id", "user", "amount", "type", "category", "date", "notes", "created_at"]
    )
    writer.writeheader()
    writer.writerows(rows)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=transactions.csv"}
    )


# ──────────────────────────────────────────────────────────────
# Serve frontend SPA
# ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:path>")
def serve_static(path):
    full = os.path.join(app.static_folder, path)
    if os.path.exists(full):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")


# ──────────────────────────────────────────────────────────────
# Error handlers
# ──────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(app.static_folder, "index.html")

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\n✅  FinTrack is running → http://127.0.0.1:5000")
    print("─" * 46)
    print("  admin@fintrack.com    / admin123    (Admin)")
    print("  analyst@fintrack.com  / analyst123  (Analyst)")
    print("  viewer@fintrack.com   / viewer123   (Viewer)")
    print("─" * 46 + "\n")
    app.run(debug=True, port=5000)
