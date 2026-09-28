# Secure Web Application (Flask)

A small but security-conscious web application demonstrating authentication, authorization, and secure data storage — built to practice defending against common OWASP Top 10 vulnerabilities.

Built as part of a cybersecurity internship project requirement.

## 📌 Objective

Build a web app that implements real security controls rather than "happy path only" code:
- User registration & login with properly hashed passwords (no plaintext, no reversible encryption)
- Stateless authentication using JWT
- Role-based authorization (regular users vs. admin)
- SQL injection prevention via parameterized queries
- Input validation and output escaping (XSS prevention)
- Secure HTTP headers and cookie flags
- Rate-limiting login attempts to slow brute-force attacks

## 🧰 Tools Used

- Python 3 + Flask
- SQLite (via Python's built-in `sqlite3`, using **parameterized queries only**)
- `werkzeug.security` for password hashing (PBKDF2-SHA256 under the hood)
- `PyJWT` for JSON Web Tokens
- Jinja2 auto-escaping (Flask default) for XSS protection

## 📂 Project Structure

```
secure-web-app/
├── README.md
├── SECURITY_NOTES.md      # OWASP Top 10 mapping - what's covered & how
├── requirements.txt
├── app.py                 # Flask app, routes, security middleware
├── db.py                  # SQLite setup + parameterized query helpers
├── auth.py                # Registration, login, JWT issuing/verification, rate limiting
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   └── dashboard.html
└── static/
    └── style.css
```

## ⚙️ Setup

```bash
git clone <your-repo-url>
cd secure-web-app
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

On first run, `app.py` will automatically create `app.db` (SQLite) with the required tables.

> ⚠️ Before deploying anywhere beyond localhost, set a strong random `SECRET_KEY` via an environment variable (see `app.py`) - never commit real secrets to source control.

## 🔐 Security Features Implemented

| Feature | How it's implemented |
|---|---|
| Password storage | `werkzeug.security.generate_password_hash` (salted PBKDF2-SHA256) — never store plaintext or use fast/unsalted hashes |
| Authentication | JWT issued on login, signed with `HS256`, short expiry (30 min), verified on every protected route |
| Authorization | Role field (`user` / `admin`) checked server-side before granting access to admin-only routes |
| SQL injection prevention | 100% parameterized queries (`?` placeholders) — user input is **never** string-formatted into SQL |
| XSS prevention | Jinja2 auto-escaping left enabled everywhere; no `\| safe` filters on user-controlled data |
| Brute-force mitigation | Login attempts are rate-limited per username (in-memory counter + cooldown) |
| Session/cookie hardening | JWT delivered via `HttpOnly`, `SameSite=Lax` cookie so it isn't accessible to JavaScript |
| Input validation | Username/password length & character checks; email format validation on registration |
| Secure headers | `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy` set on every response |
| Generic error messages | Login failures return the same generic message whether the username or password was wrong (prevents user enumeration) |

See **SECURITY_NOTES.md** for the full OWASP Top 10 (2021) walkthrough.

## 🧪 Trying It Out

1. Register a new account at `/register`.
2. Log in at `/login` — you'll receive a JWT stored in an HttpOnly cookie.
3. Visit `/dashboard` — a protected route that requires a valid JWT.
4. Try visiting `/admin` as a normal user — you'll get a `403 Forbidden`.
5. Try an SQL-injection-style username on the login form, e.g. `' OR '1'='1` — it will safely fail as a normal (incorrect) login instead of bypassing authentication, because queries are parameterized.

## 🎓 Skills Learned

- Secure password storage (salting + key stretching, not encryption)
- Stateless authentication with JWTs, including expiry and signature verification
- Role-based access control (RBAC)
- Preventing SQL injection through parameterized queries (and why string-formatting SQL is dangerous)
- Preventing XSS through templating auto-escaping
- Why generic error messages matter for preventing user enumeration
- Basic rate-limiting as a brute-force defense
- Mapping real code to the OWASP Top 10 framework

## ⚠️ Disclaimer

This is an educational demo. For production use, add HTTPS/TLS termination, a production-grade rate limiter (e.g. Flask-Limiter backed by Redis), CSRF protection for form submissions, structured logging/monitoring, and a proper secrets manager for `SECRET_KEY`.
