"""
Expense Tracker - a small Flask + SQLite project.

HOW TO READ THIS FILE (learning Flask):
1. Flask(...)         -> creates the web application object.
2. @app.route(...)    -> a "decorator" that connects a URL to a Python function.
3. render_template()  -> fills an HTML file in templates/ with data and returns it.
4. request            -> holds data sent by the browser (form fields, URL params).
5. session            -> a small encrypted cookie that remembers who is logged in.
6. redirect/url_for   -> send the browser to another page.
7. flash()            -> show a one-time message (success / error) on the next page.
"""

import os
import sqlite3
from datetime import date
from functools import wraps

from flask import (
    Flask, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# 1. App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# The secret key signs the session cookie so users cannot tamper with it.
# In a real project, read this from an environment variable.
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")

# Database file lives next to app.py
DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "expense.db")

CATEGORIES = ["Food", "Travel", "Shopping", "Bills", "Health", "Entertainment", "Other"]


# ---------------------------------------------------------------------------
# 2. Database helpers
# ---------------------------------------------------------------------------
def get_db():
    """Open one database connection per request and reuse it.

    `g` is a special Flask object that lives only for the current request.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # lets us use row["title"] instead of row[1]
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """Runs automatically after every request: close the connection."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the tables if they do not exist yet."""
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS expenses (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   INTEGER NOT NULL,
            title     TEXT NOT NULL,
            amount    REAL NOT NULL,
            category  TEXT NOT NULL,
            date      TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# 3. Login protection
# ---------------------------------------------------------------------------
def login_required(view):
    """A decorator: pages wrapped with it are only for logged-in users."""

    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


# ---------------------------------------------------------------------------
# 4. Auth routes: register, login, logout
# ---------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    # GET  = the browser just wants to SEE the form.
    # POST = the user pressed the submit button and sent data.
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        error = None
        if not username or not password:
            error = "Username and password are required."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."

        if error is None:
            db = get_db()
            try:
                # The ? placeholders protect against SQL injection. Always use them.
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "That username is already taken."
            else:
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))

        flash(error, "danger")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # We never store plain passwords. We compare the typed password with the hash.
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# 5. Expense routes
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def index():
    """List the logged-in user's expenses, optionally filtered by category."""
    selected = request.args.get("category", "")  # reads ?category=Food from the URL

    query = "SELECT * FROM expenses WHERE user_id = ?"
    params = [session["user_id"]]
    if selected:
        query += " AND category = ?"
        params.append(selected)
    query += " ORDER BY date DESC, id DESC"

    db = get_db()
    expenses = db.execute(query, params).fetchall()
    total = sum(e["amount"] for e in expenses)

    return render_template(
        "index.html",
        expenses=expenses,
        total=total,
        categories=CATEGORIES,
        selected=selected,
    )


def validate_expense_form(form):
    """Check the form fields. Returns (cleaned_data, error_message)."""
    title = form.get("title", "").strip()
    category = form.get("category", "")
    expense_date = form.get("date", "")

    try:
        amount = float(form.get("amount", ""))
    except ValueError:
        return None, "Amount must be a number."

    if not title:
        return None, "Title is required."
    if amount <= 0:
        return None, "Amount must be greater than zero."
    if category not in CATEGORIES:
        return None, "Please choose a valid category."
    if not expense_date:
        return None, "Date is required."

    return {"title": title, "amount": amount, "category": category, "date": expense_date}, None


@app.route("/add", methods=["GET", "POST"])
@login_required
def add_expense():
    if request.method == "POST":
        data, error = validate_expense_form(request.form)
        if error:
            flash(error, "danger")
        else:
            db = get_db()
            db.execute(
                "INSERT INTO expenses (user_id, title, amount, category, date) "
                "VALUES (?, ?, ?, ?, ?)",
                (session["user_id"], data["title"], data["amount"],
                 data["category"], data["date"]),
            )
            db.commit()
            flash("Expense added.", "success")
            return redirect(url_for("index"))

    return render_template(
        "expense_form.html",
        expense=None,
        categories=CATEGORIES,
        today=date.today().isoformat(),
        heading="Add Expense",
    )


def get_expense_or_404(expense_id):
    """Fetch an expense, making sure it belongs to the logged-in user."""
    db = get_db()
    expense = db.execute(
        "SELECT * FROM expenses WHERE id = ? AND user_id = ?",
        (expense_id, session["user_id"]),
    ).fetchone()
    if expense is None:
        from flask import abort
        abort(404)
    return expense


# <int:expense_id> in the URL becomes the function argument expense_id.
@app.route("/edit/<int:expense_id>", methods=["GET", "POST"])
@login_required
def edit_expense(expense_id):
    expense = get_expense_or_404(expense_id)

    if request.method == "POST":
        data, error = validate_expense_form(request.form)
        if error:
            flash(error, "danger")
        else:
            db = get_db()
            db.execute(
                "UPDATE expenses SET title = ?, amount = ?, category = ?, date = ? "
                "WHERE id = ? AND user_id = ?",
                (data["title"], data["amount"], data["category"], data["date"],
                 expense_id, session["user_id"]),
            )
            db.commit()
            flash("Expense updated.", "success")
            return redirect(url_for("index"))

    return render_template(
        "expense_form.html",
        expense=expense,
        categories=CATEGORIES,
        today=date.today().isoformat(),
        heading="Edit Expense",
    )


# Deleting changes data, so we only allow POST (never GET).
@app.route("/delete/<int:expense_id>", methods=["POST"])
@login_required
def delete_expense(expense_id):
    get_expense_or_404(expense_id)
    db = get_db()
    db.execute(
        "DELETE FROM expenses WHERE id = ? AND user_id = ?",
        (expense_id, session["user_id"]),
    )
    db.commit()
    flash("Expense deleted.", "info")
    return redirect(url_for("index"))


@app.route("/summary")
@login_required
def summary():
    """Total spent per category (uses SQL GROUP BY)."""
    db = get_db()
    rows = db.execute(
        "SELECT category, SUM(amount) AS total, COUNT(*) AS count "
        "FROM expenses WHERE user_id = ? "
        "GROUP BY category ORDER BY total DESC",
        (session["user_id"],),
    ).fetchall()
    grand_total = sum(r["total"] for r in rows)
    return render_template("summary.html", rows=rows, grand_total=grand_total)


# ---------------------------------------------------------------------------
# 6. Run the app
# ---------------------------------------------------------------------------
init_db()  # make sure tables exist when the app starts

if __name__ == "__main__":
    # debug=True auto-reloads on code changes. Turn it off in production.
    app.run(debug=True)
