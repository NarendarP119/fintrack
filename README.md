# FinTrack — Python Finance System

A complete finance tracking backend with a built-in dashboard UI.  
Built with **Flask**, **SQLite**, and vanilla **HTML/CSS/JS**.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.x-green)
![SQLite](https://img.shields.io/badge/Database-SQLite-lightgrey)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Screenshots

> Dashboard with income/expense charts, recent activity, and top spending categories.  
> Transactions page with full filtering, pagination, and inline edit/delete.  
> Role-based access: Admins see user management, Analysts can write, Viewers read-only.

---

## Project Structure

```
fintrack/
├── app.py                  # All backend logic — routes, auth, DB, validation
├── requirements.txt        # Python dependencies (Flask + PyJWT only)
├── .gitignore
├── README.md
└── static/
    └── index.html          # Complete SPA frontend (vanilla JS + Chart.js)
```

---

## Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/fintrack.git
cd fintrack
```

### 2. Create a virtual environment (recommended)
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
python app.py
```

### 5. Open in browser
```
http://127.0.0.1:5000
```

The SQLite database (`fintrack.db`) is created automatically on first run with seed data.

---

## Demo Accounts

| Email | Password | Role |
|---|---|---|
| admin@fintrack.com | admin123 | Admin |
| analyst@fintrack.com | analyst123 | Analyst |
| viewer@fintrack.com | viewer123 | Viewer |

---

## Role Permissions

| Feature | Viewer | Analyst | Admin |
|---|:---:|:---:|:---:|
| View transactions | ✅ | ✅ | ✅ |
| Filter & search | ✅ | ✅ | ✅ |
| View dashboard & charts | ✅ | ✅ | ✅ |
| Create transaction | ❌ | ✅ | ✅ |
| Edit transaction | ❌ | ✅ | ✅ |
| Delete transaction | ❌ | ❌ | ✅ |
| Access analytics page | ❌ | ✅ | ✅ |
| Manage users | ❌ | ❌ | ✅ |
| Export CSV | ✅ | ✅ | ✅ |

---

## API Reference

All API routes are prefixed with `/api`. Protected routes require a `Bearer` token in the `Authorization` header.

### Authentication

#### POST `/api/auth/login`
```json
// Request
{ "email": "admin@fintrack.com", "password": "admin123" }

// Response 200
{
  "token": "eyJ...",
  "user": { "id": 1, "name": "Admin User", "email": "...", "role": "admin" }
}
```

#### GET `/api/auth/me`
Returns the currently authenticated user's profile.

---

### Transactions

#### GET `/api/transactions`
List transactions with optional filters.

| Query Param | Type | Description |
|---|---|---|
| `type` | string | `income` or `expense` |
| `category` | string | Filter by category name |
| `date_from` | string | Start date `YYYY-MM-DD` |
| `date_to` | string | End date `YYYY-MM-DD` |
| `search` | string | Search in notes and category |
| `sort_by` | string | `date`, `amount`, `category` (default: `date`) |
| `order` | string | `asc` or `desc` (default: `desc`) |
| `page` | int | Page number (default: `1`) |
| `per_page` | int | Results per page, max 100 (default: `15`) |

```json
// Response 200
{
  "data": [ { "id": 1, "amount": 5000, "type": "income", ... } ],
  "pagination": { "total": 61, "page": 1, "per_page": 15, "pages": 5 }
}
```

#### GET `/api/transactions/:id`
Get a single transaction by ID.

#### POST `/api/transactions` *(Analyst, Admin)*
```json
// Request body
{
  "amount":   5000.00,
  "type":     "income",
  "category": "Salary",
  "date":     "2024-07-01",
  "notes":    "Monthly salary"
}
```

#### PUT `/api/transactions/:id` *(Analyst, Admin)*
Partial update — only include fields you want to change.

#### DELETE `/api/transactions/:id` *(Admin only)*

---

### Summary & Analytics

#### GET `/api/summary`
Returns a dashboard-ready payload:
- Total income, expenses, balance, and record counts
- Category breakdown (income + expense separately)
- Monthly totals for the last 6 months
- 5 most recent transactions
- Top 5 expense categories

#### GET `/api/analytics/monthly?year=2024` *(Analyst, Admin)*
Returns month-by-month income and expenses for the given year.

---

### Users *(Admin only)*

#### GET `/api/users`
List all users.

#### POST `/api/users`
```json
{ "name": "Jane Doe", "email": "jane@example.com", "password": "pass123", "role": "viewer" }
```

#### DELETE `/api/users/:id`

---

### Export

#### GET `/api/export/csv`
Downloads all transactions as a CSV file.

---

## Data Model

### `users`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER | Primary key |
| name | TEXT | Full name |
| email | TEXT | Unique, used for login |
| password_hash | TEXT | SHA-256 hash |
| role | TEXT | `admin` / `analyst` / `viewer` |
| created_at | TEXT | ISO datetime |

### `transactions`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER | Primary key |
| user_id | INTEGER | Foreign key → users |
| amount | REAL | Must be positive |
| type | TEXT | `income` or `expense` |
| category | TEXT | From predefined list |
| date | TEXT | `YYYY-MM-DD` |
| notes | TEXT | Optional |
| created_at | TEXT | ISO datetime |
| updated_at | TEXT | ISO datetime |

### Valid categories
**Income:** Salary, Freelance, Investment, Bonus, Rental  
**Expense:** Food, Rent, Transport, Shopping, Utilities, Healthcare, Entertainment, Education  
**Other:** Other

---

## Validation

Every write operation validates the request body before touching the database.  
On failure, a structured error is returned:

```json
// POST /api/transactions with bad data → 422
{
  "error": "Validation failed",
  "details": {
    "amount":   "Must be a positive number",
    "type":     "Must be 'income' or 'expense'",
    "category": "Must be one of: Salary, Freelance, ...",
    "date":     "Must be in YYYY-MM-DD format"
  }
}
```

---

## Technical Decisions

**Why Flask over FastAPI / Django?**  
Flask was chosen for its transparency — every route, decorator, and helper is explicit. There's no ORM magic or auto-generated schema, which makes the codebase easier to read and evaluate at a glance.

**Why raw sqlite3 instead of SQLAlchemy?**  
For a project of this size, raw SQL is cleaner and more readable than ORM abstractions. WAL mode is enabled for better concurrent reads. In production I'd use SQLAlchemy + PostgreSQL.

**Why no separate frontend build?**  
The entire UI is served as a single `static/index.html` file — no Node.js, no build step, no webpack. The project runs with one command. Chart.js is loaded via CDN.

**Password storage:**  
SHA-256 hashing — sufficient for an assessment. In production: bcrypt with salt rounds.

**JWT expiry:**  
24 hours by default, configurable via `TOKEN_EXP_HOURS` environment variable.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `fintrack_dev_secret_2024` | JWT signing secret |
| `DB_PATH` | `fintrack.db` | SQLite database file path |
| `TOKEN_EXP_HOURS` | `24` | JWT token lifetime in hours |

---

## Assumptions Made

1. Each user owns their own transactions. Admins can view and manage all records.
2. The category list is fixed to ensure data consistency in aggregations.
3. Partial PUT updates only validate the fields that are present in the request body.
4. Seed data uses deterministic random (seed 42) for reproducible demo data.
5. The frontend is intentionally kept as a single file to simplify setup.

---

## Built With

- [Flask](https://flask.palletsprojects.com/) — Web framework
- [PyJWT](https://pyjwt.readthedocs.io/) — JWT authentication
- [Chart.js](https://www.chartjs.org/) — Dashboard charts (CDN)
- [Libre Baskerville](https://fonts.google.com/specimen/Libre+Baskerville) + [JetBrains Mono](https://www.jetbrains.com/lp/mono/) — Typography

---

*Built by Narendar Reddy Pathakuntla — Zorvyn FinTech Python Developer Internship Assignment*
