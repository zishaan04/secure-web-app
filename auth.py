"""
Authentication logic: registration, login, JWT issuing/verification,
input validation, and a simple in-memory rate limiter for login attempts.
"""

import re
import time
import jwt
from datetime import datetime, timedelta, timezone
from werkzeug.security import generate_password_hash, check_password_hash

import db

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 30

# --- Simple in-memory rate limiter for login attempts ---
# Production apps should use Redis or a dedicated library (e.g. Flask-Limiter)
# so limits survive restarts and work across multiple server instances.
_login_attempts = {}  # username -> list of timestamps
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300  # 5 minutes


def validate_registration(username: str, email: str, password: str) -> str | None:
    """Return an error message if invalid, else None."""
    if not USERNAME_RE.match(username or ""):
        return "Username must be 3-20 characters (letters, numbers, underscore only)."
    if not EMAIL_RE.match(email or ""):
        return "Please enter a valid email address."
    if not password or len(password) < 8:
        return "Password must be at least 8 characters long."
    return None


def register_user(username: str, email: str, password: str, role: str = "user") -> str | None:
    """Create a user. Returns an error message if it fails, else None."""
    error = validate_registration(username, email, password)
    if error:
        return error

    if db.username_or_email_exists(username, email):
        # Deliberately generic - don't reveal whether it was the username
        # or email that collided (minor enumeration hardening).
        return "That username or email is already registered."

    password_hash = generate_password_hash(password)  # salted PBKDF2-SHA256
    db.create_user(username, email, password_hash, role)
    return None


def is_rate_limited(username: str) -> bool:
    now = time.time()
    attempts = _login_attempts.get(username, [])
    # drop attempts outside the window
    attempts = [t for t in attempts if now - t < WINDOW_SECONDS]
    _login_attempts[username] = attempts
    return len(attempts) >= MAX_ATTEMPTS


def record_failed_attempt(username: str):
    _login_attempts.setdefault(username, []).append(time.time())


def clear_attempts(username: str):
    _login_attempts.pop(username, None)


def authenticate(username: str, password: str):
    """
    Returns (user_dict, error_message).
    On failure, user_dict is None and error_message is a GENERIC message
    (never reveals whether the username exists) to reduce enumeration risk.
    """
    generic_error = "Invalid username or password."

    if is_rate_limited(username):
        return None, "Too many failed attempts. Please wait a few minutes and try again."

    user = db.get_user_by_username(username)
    if not user or not check_password_hash(user["password_hash"], password):
        record_failed_attempt(username)
        return None, generic_error

    clear_attempts(username)
    return user, None


def issue_token(user: dict, secret_key: str) -> str:
    payload = {
        "sub": user["username"],
        "role": user["role"],
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, secret_key, algorithm=JWT_ALGORITHM)


def verify_token(token: str, secret_key: str):
    """Returns the decoded payload, or None if invalid/expired.
    The `algorithms` allowlist here is important: it prevents the classic
    'alg: none' JWT forgery attack by refusing to accept unsigned tokens."""
    try:
        return jwt.decode(token, secret_key, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None
