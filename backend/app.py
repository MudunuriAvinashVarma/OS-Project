# ═══════════════════════════════════════════════════════════════
# SecureAuth OS — backend/app.py
# Flask REST API: /register  /login  /verify-otp
#
# Architecture:
#   • Password hashing  : bcrypt (never stored plain-text)
#   • Credential check  : delegated to C++ binary (system/auth)
#   • OTP generation    : pyotp TOTP (6-digit, 120-second window)
#   • Session state     : in-memory dict (swap for Redis in prod)
#   • Transport         : CORS-restricted to localhost origins
# ═══════════════════════════════════════════════════════════════

import sqlite3
import os
import re
import subprocess
import secrets
import logging
import pyotp
import bcrypt

from contextlib import contextmanager
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Database setup
import os
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        """)
        conn.commit()

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

init_db()

# ── Logging setup ───────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("secureauth")

# ── Flask app ────────────────────────────────────────────────────
app = Flask(__name__)

# ── CORS: allow only localhost origins ──────────────────────────
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost",
            "http://127.0.0.1",
            "http://localhost:5500",   # Live Server (VS Code)
            "null",                    # file:// origin for direct open
        ]
    }
})

# ── Rate limiting (brute-force protection) ───────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "60 per hour"],
    storage_uri="memory://",
)

# ── In-memory stores (replace with a DB in production) ──────────
# user_store  : { username: { "hash": bytes } }
# otp_store   : { username: { "secret": str, "created_at": datetime } }
otp_store  = {}

# OTP validity window in seconds (must match countdown in JS)
OTP_VALID_SECONDS = 120

# Path to compiled C++ auth binary
CPP_BINARY = os.path.join(os.path.dirname(__file__), "..", "system", "auth")

# ── Input validation constants ───────────────────────────────────
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_\-]{3,64}$')
MAX_PASSWORD_LEN = 128
MIN_PASSWORD_LEN = 8


# ════════════════════════════════════════════════════════════════
# Helper utilities
# ════════════════════════════════════════════════════════════════

def ok(message: str, **extra) -> tuple:
    """Return a 200 success JSON response."""
    body = {"status": "success", "message": message}
    body.update(extra)
    return jsonify(body), 200


def fail(message: str, code: int = 400) -> tuple:
    """Return an error JSON response."""
    return jsonify({"status": "fail", "message": message}), code


def validate_username(username: str) -> str | None:
    """
    Validate username against the allowed pattern.
    Returns an error string or None if valid.
    """
    if not username or not username.strip():
        return "Username is required."
    if not USERNAME_RE.match(username.strip()):
        return "Username must be 3–64 chars: letters, digits, underscore, hyphen."
    return None


def validate_password(password: str) -> str | None:
    """
    Validate password length constraints.
    Returns an error string or None if valid.
    """
    if not password:
        return "Password is required."
    if len(password) < MIN_PASSWORD_LEN:
        return f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if len(password) > MAX_PASSWORD_LEN:
        return f"Password must be at most {MAX_PASSWORD_LEN} characters."
    return None


def hash_password(plain: str) -> bytes:
    """
    Hash a plain-text password with bcrypt (cost factor 12).
    Returns the hashed bytes.
    """
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(plain.encode("utf-8"), salt)


# ════════════════════════════════════════════════════════════════
# C++ Integration
# ════════════════════════════════════════════════════════════════

def verify_credentials_via_cpp(username: str, hashed_pw: bytes) -> bool:
    """
    Call the compiled C++ binary to perform credential validation.

    The C++ binary receives two arguments via stdin (newline-separated):
        Line 1: username
        Line 2: bcrypt hash (as UTF-8 string)

    It prints either "VALID" or "INVALID" to stdout and exits 0.
    Any non-zero exit or unexpected output is treated as failure.

    Security notes:
    - Inputs are passed via stdin, NOT as shell arguments, to prevent
      shell injection and argument-length attacks.
    - subprocess is called with shell=False (default).
    - stdout/stderr are captured and not echoed to the client.
    - A timeout prevents indefinite blocking.
    """
    if not os.path.isfile(CPP_BINARY):
        log.warning("C++ binary not found at %s — falling back to Python-only check.", CPP_BINARY)
        return False

    stdin_data = f"{username}\n{hashed_pw.decode('utf-8')}\n"

    try:
        result = subprocess.run(
            [CPP_BINARY],          # no shell=True → no injection risk
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=5,             # seconds; prevent hanging
        )
        output = result.stdout.strip()
        log.info("C++ auth result for '%s': %s (exit %d)", username, output, result.returncode)
        return result.returncode == 0 and output == "VALID"

    except subprocess.TimeoutExpired:
        log.error("C++ binary timed out for user '%s'.", username)
        return False
    except FileNotFoundError:
        log.error("C++ binary not executable: %s", CPP_BINARY)
        return False
    except Exception as exc:
        log.exception("Unexpected error calling C++ binary: %s", exc)
        return False


# ════════════════════════════════════════════════════════════════
# OTP utilities
# ════════════════════════════════════════════════════════════════

def generate_otp_for_user(username: str) -> str:
    """
    Generate a TOTP secret for the user, store it with a timestamp,
    and return the current 6-digit OTP token.
    Uses a 120-second interval so the same token is valid for 2 minutes.
    """
    secret = pyotp.random_base32()           # cryptographically random
    totp   = pyotp.TOTP(secret, interval=OTP_VALID_SECONDS)
    token  = totp.now()

    otp_store[username] = {
        "secret":     secret,
        "created_at": datetime.now(timezone.utc),
    }

    log.info("OTP generated for '%s': %s (valid %ds)", username, token, OTP_VALID_SECONDS)
    # In production: send token via SMS/email. Here we log it for demo.
    print(f"\n{'='*40}\n  OTP for '{username}': {token}\n{'='*40}\n")
    return token


def verify_otp_for_user(username: str, token: str) -> tuple[bool, str]:
    """
    Verify a submitted OTP token against the stored TOTP secret.
    Returns (is_valid: bool, reason: str).
    """
    entry = otp_store.get(username)
    if not entry:
        return False, "No OTP session found. Please log in again."

    # Check age of OTP session
    age = (datetime.now(timezone.utc) - entry["created_at"]).total_seconds()
    if age > OTP_VALID_SECONDS + 5:      # +5 s grace period for clock skew
        del otp_store[username]
        return False, "OTP has expired. Please log in again."

    totp  = pyotp.TOTP(entry["secret"], interval=OTP_VALID_SECONDS)
    valid = totp.verify(token, valid_window=1)

    if valid:
        del otp_store[username]           # one-time use — invalidate immediately
        return True, "OTP verified successfully."

    return False, "Invalid OTP. Please try again."


# ════════════════════════════════════════════════════════════════
# Routes
# ════════════════════════════════════════════════════════════════

@app.route("/register", methods=["POST"])
@limiter.limit("10 per minute")
def register():
    """
    POST /register
    Body: { "username": str, "password": str }

    1. Validate inputs
    2. Check username is not already taken
    3. Hash password with bcrypt
    4. Store { hash } in user_store
    """
    data = request.get_json(silent=True)
    if not data:
        return fail("Request body must be valid JSON.", 400)

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    # ── Validate ────────────────────────────────────────────────
    u_err = validate_username(username)
    if u_err:
        return fail(u_err, 400)

    p_err = validate_password(password)
    if p_err:
        return fail(p_err, 400)

    # ── Hash & store ─────────────────────────────────────────────
    hashed = hash_password(password)
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, hashed.decode("utf-8"))
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return fail("Username already exists", 409)

    log.info("User registered: '%s'", username)
    return ok("Account created successfully. You may now log in.")


@app.route("/login", methods=["POST"])
@limiter.limit("15 per minute")
def login():
    """
    POST /login
    Body: { "username": str, "password": str }

    1. Validate inputs
    2. Look up user
    3. Verify password with bcrypt (constant-time)
    4. Delegate to C++ for additional validation layer
    5. Generate OTP and return success (OTP printed to server console)
    """
    data = request.get_json(silent=True)
    if not data:
        return fail("Request body must be valid JSON.", 400)

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    # ── Validate inputs ─────────────────────────────────────────
    u_err = validate_username(username)
    if u_err:
        return fail(u_err, 400)

    if not password:
        return fail("Password is required.", 400)

    # ── Look up user ─────────────────────────────────────────────
    with get_db() as conn:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

    dummy_hash = bcrypt.hashpw(b"dummy", bcrypt.gensalt())

    stored_hash = row["password_hash"].encode("utf-8") if row else dummy_hash

    pw_correct = bcrypt.checkpw(password.encode("utf-8"), stored_hash)

    if not row or not pw_correct:
            log.warning("Failed login attempt for '%s'.", username)
            # Generic message — do not reveal whether user exists
            return fail("Invalid username or password.", 401)

    # ── C++ validation layer ─────────────────────────────────────
    cpp_valid = verify_credentials_via_cpp(username, stored_hash)
    if not cpp_valid:
        # C++ binary not present → log warning but continue
        # In strict mode you could: return fail("System validation failed.", 500)
        log.warning(
            "C++ validation skipped or failed for '%s'. "
            "Ensure system/auth is compiled. Proceeding with Python-only auth.",
            username,
        )

    # ── Generate OTP ─────────────────────────────────────────────
    generate_otp_for_user(username)

    log.info("Login step 1 success for '%s'. OTP dispatched.", username)
    return ok("Credentials verified. Check your OTP (printed to server console in demo mode).")


@app.route("/verify-otp", methods=["POST"])
@limiter.limit("10 per minute")
def verify_otp():
    """
    POST /verify-otp
    Body: { "username": str, "otp": str }

    1. Validate inputs
    2. Verify OTP via TOTP
    3. Return success/failure
    """
    data = request.get_json(silent=True)
    if not data:
        return fail("Request body must be valid JSON.", 400)

    username = str(data.get("username", "")).strip()
    otp      = str(data.get("otp", "")).strip()

    # ── Validate ─────────────────────────────────────────────────
    u_err = validate_username(username)
    if u_err:
        return fail(u_err, 400)

    if not otp or not re.match(r'^\d{6}$', otp):
        return fail("OTP must be exactly 6 digits.", 400)

    # ── Verify ───────────────────────────────────────────────────
    valid, message = verify_otp_for_user(username, otp)

    if valid:
        log.info("OTP verified for '%s'. Full authentication complete.", username)
        return ok(message)

    log.warning("OTP failure for '%s': %s", username, message)
    return fail(message, 401)


# ════════════════════════════════════════════════════════════════
# Error handlers
# ════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(_):
    return fail("Endpoint not found.", 404)


@app.errorhandler(405)
def method_not_allowed(_):
    return fail("Method not allowed.", 405)


@app.errorhandler(429)
def rate_limited(_):
    return fail("Too many requests. Please wait and try again.", 429)


@app.errorhandler(500)
def internal_error(exc):
    log.exception("Internal server error: %s", exc)
    return fail("Internal server error.", 500)


# ════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    log.info("Starting SecureAuth OS backend on http://localhost:5000")
    log.info("C++ binary path: %s", os.path.abspath(CPP_BINARY))
    log.info("OTP will be printed to this console (demo mode).")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,      # Never True in production
    )
