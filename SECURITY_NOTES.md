# OWASP Top 10 (2021) — Mapping to This Project

A short walkthrough of how this app addresses (or intentionally does not fully address, for scope reasons) each OWASP Top 10 category.

### A01: Broken Access Control
- `/dashboard` requires a valid JWT (`@login_required` decorator in `app.py`).
- `/admin` additionally requires `role == "admin"` (`@admin_required` decorator).
- Authorization checks happen **server-side** on every request — never trust a client-side "isAdmin" flag alone.

### A02: Cryptographic Failures
- Passwords are never stored in plaintext or with reversible encryption — only salted PBKDF2-SHA256 hashes (`werkzeug.security`).
- JWTs are signed (HS256) with a server-side secret so they can't be forged, and carry an expiry (`exp` claim) so a leaked token doesn't work forever.

### A03: Injection
- All database access goes through parameterized queries in `db.py` (`cursor.execute("... WHERE username = ?", (username,))`).
- User input is **never** concatenated or f-string-formatted into a SQL statement.
- Demonstrated defense: attempting `' OR '1'='1` as a username at login is treated as a literal (non-matching) string, not SQL syntax.

### A04: Insecure Design
- Rate limiting on login attempts (basic in-memory version here; use Redis-backed limiter in production) to slow credential-stuffing/brute-force attacks.
- Generic "invalid username or password" message regardless of which field was wrong, to prevent username enumeration.

### A05: Security Misconfiguration
- `app.py` sets security headers on every response: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a basic `Content-Security-Policy`.
- Debug mode is off by default; `SECRET_KEY` is read from an environment variable, not hardcoded, so it isn't accidentally committed.

### A06: Vulnerable and Outdated Components
- `requirements.txt` pins minimum modern versions of Flask/PyJWT; run `pip list --outdated` periodically and use tools like `pip-audit` in CI for real projects.

### A07: Identification and Authentication Failures
- Passwords require a minimum length and are hashed with a slow, salted algorithm (PBKDF2).
- JWTs expire after 30 minutes, limiting the blast radius of a stolen token.
- Cookie storing the JWT is `HttpOnly` (not readable by JavaScript, mitigating token theft via XSS) and `SameSite=Lax` (mitigating CSRF token leakage via cross-site requests).

### A08: Software and Data Integrity Failures
- JWT signature verification (`jwt.decode(..., algorithms=["HS256"])`) ensures tokens can't be tampered with client-side — the `algorithms` allowlist also prevents the classic "alg: none" JWT bypass attack.

### A09: Security Logging and Monitoring Failures
- Basic print-based logging of failed login attempts is included for demonstration; a production system should send this to a real log/SIEM pipeline (e.g., the Splunk-based approach used in the Incident Response Playbook project) rather than stdout.

### A10: Server-Side Request Forgery (SSRF)
- Not directly applicable — this app makes no outbound requests based on user-supplied URLs. Noted here for completeness since a full OWASP review should always state when a category is out of scope and why.

---

**Takeaway:** most real-world web app breaches trace back to A01–A03 (broken access control, crypto failures, and injection). This project deliberately focuses the bulk of its implementation effort there.
