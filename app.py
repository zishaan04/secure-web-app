"""
Secure Web Application - main Flask app.

Run with: python app.py
Then visit http://127.0.0.1:5000
"""

import os
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, g, flash

import db
import auth

app = Flask(__name__)

# SECURITY NOTE: never hardcode a real secret key in source control.
# In production, set the SECRET_KEY environment variable.
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
JWT_SECRET = app.secret_key

db.init_db()


# ---------- Security headers on every response ----------
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    return response


# ---------- Auth helpers / decorators ----------
def get_current_user():
    token = request.cookies.get("access_token")
    if not token:
        return None
    payload = auth.verify_token(token, JWT_SECRET)
    if not payload:
        return None
    return payload  # {"sub": username, "role": ..., ...}


@app.before_request
def load_user():
    g.user = get_current_user()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please log in to continue.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please log in to continue.")
            return redirect(url_for("login"))
        if g.user.get("role") != "admin":
            return render_template("error.html", message="403 Forbidden - admin access required."), 403
        return view(*args, **kwargs)
    return wrapped


# ---------- Routes ----------
@app.route("/")
def index():
    return render_template("index.html", user=g.user)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        error = auth.register_user(username, email, password)
        if error:
            flash(error)
            return render_template("register.html")

        flash("Registration successful! Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user, error = auth.authenticate(username, password)
        if error:
            flash(error)
            return render_template("login.html")

        token = auth.issue_token(user, JWT_SECRET)
        response = redirect(url_for("dashboard"))
        # HttpOnly: JS can't read the cookie (mitigates XSS token theft)
        # SameSite=Lax: mitigates CSRF by not sending cookie on cross-site POSTs
        response.set_cookie(
            "access_token",
            token,
            httponly=True,
            samesite="Lax",
            secure=False,  # set True when served over HTTPS in production
            max_age=30 * 60,
        )
        return response

    return render_template("login.html")


@app.route("/logout")
def logout():
    response = redirect(url_for("index"))
    response.delete_cookie("access_token")
    return response


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=g.user)


@app.route("/admin")
@admin_required
def admin_panel():
    return f"<h1>Admin Panel</h1><p>Welcome, {g.user['sub']}. Only admins can see this.</p>"


if __name__ == "__main__":
    app.run(debug=False, port=5000)
