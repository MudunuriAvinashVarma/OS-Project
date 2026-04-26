# SecureAuth OS — 3-Tier Secure Authentication Module

```
 ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗ █████╗ ██╗   ██╗████████╗██╗  ██╗
 ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║
 ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ███████║██║   ██║   ██║   ███████║
 ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██╔══██║██║   ██║   ██║   ██╔══██║
 ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║
 ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
```

> **A production-grade, three-tier authentication system demonstrating secure OS-level
> credential management with bcrypt hashing, C++ kernel validation, and TOTP-based 2FA.**

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Project Structure](#project-structure)
3. [Authentication Flow](#authentication-flow)
4. [Security Features](#security-features)
5. [Quick Start](#quick-start)
6. [API Reference](#api-reference)
7. [C++ Layer Details](#c-layer-details)
8. [Frontend Details](#frontend-details)
9. [Configuration](#configuration)
10. [Production Hardening](#production-hardening)
11. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     TIER 1 — FRONTEND                       │
│           HTML5 + CSS3 + Vanilla JS (fetch API)             │
│   Register │ Login │ OTP Input │ Success Panel              │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTPS POST (JSON)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                     TIER 2 — BACKEND                        │
│             Python 3.10+ · Flask 3.0 · REST API             │
│                                                             │
│  /register  →  validate → bcrypt hash → store               │
│  /login     →  validate → bcrypt verify → call C++ → OTP   │
│  /verify-otp → validate → TOTP verify → grant access        │
│                                                             │
│  Security: Flask-Limiter · Flask-CORS · pyotp               │
└──────────────────────┬──────────────────────────────────────┘
                       │ stdin/stdout (subprocess)
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                  TIER 3 — SYSTEM LAYER                      │
│                C++17 · Compiled Binary (auth)               │
│                                                             │
│  • Independent input validation (regex + bounds)            │
│  • Constant-time string comparison                          │
│  • Buffer overflow protection (no gets/scanf)               │
│  • Stack canary (-fstack-protector-strong)                  │
│  • FORTIFY_SOURCE=2                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
/project
 ├── frontend/
 │    ├── index.html      ← UI shell: 4 panels (register/login/OTP/success)
 │    ├── styles.css      ← Industrial-terminal dark theme, animations
 │    └── script.js       ← Boot sequence, API calls, OTP input, validation
 │
 ├── backend/
 │    ├── app.py          ← Flask REST API (register / login / verify-otp)
 │    └── requirements.txt
 │
 ├── system/
 │    └── auth.cpp        ← C++ credential validator (compile to ./auth)
 │
 └── README.md
```

---

## Authentication Flow

```
User                  Frontend              Flask API             C++ Binary
 │                       │                      │                      │
 │──── Register ─────────▶                      │                      │
 │     username+password  │──── POST /register ─▶                      │
 │                        │                     │── bcrypt(pw,12) ─┐   │
 │                        │                     │◀─ hash ──────────┘   │
 │                        │                     │── store(user,hash)   │
 │                        │◀─── {success} ──────│                      │
 │                        │                     │                      │
 │──── Login ────────────▶                      │                      │
 │     username+password  │──── POST /login ────▶                      │
 │                        │                     │── bcrypt.verify() ─┐ │
 │                        │                     │◀─ pw_correct ──────┘ │
 │                        │                     │                      │
 │                        │                     │── subprocess ────────▶
 │                        │                     │   stdin: user+hash   │
 │                        │                     │                      │── validate()
 │                        │                     │◀── "VALID" ──────────│
 │                        │                     │                      │
 │                        │                     │── generate_otp() ──┐ │
 │                        │                     │◀─ token ───────────┘ │
 │                        │◀─── {success+msg} ──│  (printed to console)│
 │                        │                     │                      │
 │──── Enter OTP ────────▶                      │                      │
 │     6-digit code       │── POST /verify-otp ─▶                      │
 │                        │                     │── pyotp.verify() ──┐ │
 │                        │                     │◀─ valid ───────────┘ │
 │                        │◀─── {success} ──────│                      │
 │◀─── ACCESS GRANTED ────│                     │                      │
```

---

## Security Features

### Password Security
| Feature | Implementation |
|---|---|
| Hashing algorithm | bcrypt with cost factor 12 |
| Salt | Per-password random salt (bcrypt built-in) |
| Storage | Hash bytes only — plaintext never stored or logged |
| Verification | `bcrypt.checkpw()` — constant-time |
| Max length | 128 characters (prevents bcrypt DoS via 72-byte limit) |

### Anti-Attack Measures
| Attack | Mitigation |
|---|---|
| Brute force | Flask-Limiter: 10–15 req/min per endpoint per IP |
| Timing attack | Dummy hash computed even when username not found |
| User enumeration | Generic `"Invalid username or password"` on all failures |
| OTP replay | Token deleted from store immediately after first valid use |
| OTP expiry | 120-second TOTP window; session purged on expiry |
| Shell injection | C++ called via `subprocess` list (no `shell=True`); input via stdin |
| Buffer overflow | `std::string` + `safe_read_line()` with hard length ceilings in C++ |
| Null-byte injection | Explicit `find('\0')` check in C++ layer |
| Path traversal | Banned character list checked in C++ before any processing |

### Transport & API Security
| Feature | Detail |
|---|---|
| CORS | Restricted to `localhost` origins only |
| Input validation | Regex + length limits in both Python **and** C++ (defense-in-depth) |
| Error responses | No stack traces or internal details exposed to client |
| Content-Type | API enforces `application/json` only |

### C++ Compile-Time Hardening
```bash
-fstack-protector-strong   # Stack canaries on vulnerable functions
-D_FORTIFY_SOURCE=2        # Bounds-checked libc replacements
-O2                        # Enables additional static analysis
-pie -fPIE                 # Position-independent executable (ASLR)
-Wl,-z,relro,-z,now        # Full RELRO — read-only GOT
```

---

## Quick Start

### Prerequisites
- Python >= 3.10
- g++ with C++17 support (`g++ --version`)
- pip

### Step 1 — Compile the C++ binary

```bash
cd project/system

# Standard build
g++ -std=c++17 -Wall -Wextra \
    -fstack-protector-strong \
    -D_FORTIFY_SOURCE=2 \
    -O2 \
    -o auth auth.cpp

# Verify it compiled
echo -e "testuser\n\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj/o/9.G9" | ./auth
# Expected output: INVALID  (hash is a demo value)
```

### Step 2 — Install Python dependencies

```bash
cd project/backend
pip install -r requirements.txt
```

### Step 3 — Start the Flask backend

```bash
cd project/backend
python app.py
```

You should see:
```
Starting SecureAuth OS backend on http://localhost:5000
C++ binary path: /path/to/project/system/auth
OTP will be printed to this console (demo mode).
```

### Step 4 — Open the frontend

Open `project/frontend/index.html` in your browser directly, **or** serve it
with any static file server:

```bash
# Python built-in server (from project/frontend/)
cd project/frontend
python -m http.server 5500

# Then open: http://localhost:5500
```

> **Note:** The frontend makes requests to `http://localhost:5000`.
> CORS is configured to allow `localhost:5500`, `localhost`, and `null` (file://) origins.

### Step 5 — Test the full flow

1. Click **Register** → enter a username and password (min 8 chars) → submit
2. You are auto-redirected to **Login** → enter the same credentials
3. Check the **Flask terminal** — the OTP is printed there:
   ```
   ========================================
     OTP for 'alice': 482910
   ========================================
   ```
4. Enter the 6-digit OTP in the browser → click **VERIFY & ENTER**
5. **ACCESS GRANTED** panel appears

---

## API Reference

### `POST /register`

Register a new user account.

**Request**
```json
{
  "username": "alice",
  "password": "Secure@Pass99"
}
```

**Response — success (200)**
```json
{
  "status": "success",
  "message": "Account created successfully. You may now log in."
}
```

**Response — failure (400 / 409)**
```json
{
  "status": "fail",
  "message": "Username already exists. Please choose another."
}
```

---

### `POST /login`

Verify credentials and trigger OTP dispatch.

**Request**
```json
{
  "username": "alice",
  "password": "Secure@Pass99"
}
```

**Response — success (200)**
```json
{
  "status": "success",
  "message": "Credentials verified. Check your OTP (printed to server console in demo mode)."
}
```

**Response — failure (401)**
```json
{
  "status": "fail",
  "message": "Invalid username or password."
}
```

---

### `POST /verify-otp`

Verify the 6-digit TOTP and complete authentication.

**Request**
```json
{
  "username": "alice",
  "otp": "482910"
}
```

**Response — success (200)**
```json
{
  "status": "success",
  "message": "OTP verified successfully."
}
```

**Response — failure (401)**
```json
{
  "status": "fail",
  "message": "Invalid OTP. Please try again."
}
```

---

## C++ Layer Details

### How Python calls auth.cpp

```python
result = subprocess.run(
    ["/path/to/system/auth"],   # no shell=True
    input="alice\n$2b$12$...\n",
    capture_output=True,
    text=True,
    timeout=5,
)
# result.stdout == "VALID\n" or "INVALID\n"
```

### What auth.cpp validates independently

| Check | Detail |
|---|---|
| Username regex | `[a-zA-Z0-9_\-]{3,64}` |
| Username length | 3–64 characters |
| Banned characters | `/`, `.`, `\`, `;`, `'`, `"`, `<`, `>`, `|`, `&`, `` ` ``, `$` etc. |
| Hash prefix | Must match `$2[aby]$NN$` (bcrypt variants) |
| Hash length | Exactly 60 characters (bcrypt standard) |
| Hash characters | Printable ASCII only (0x20–0x7E) |
| Null bytes | Rejected in both fields |
| Line length | Hard ceiling of 512 bytes via `safe_read_line()` |

### Buffer overflow demonstration

```cpp
// ✗ UNSAFE — never use these:
char buf[64];
gets(buf);              // no bounds check
scanf("%s", buf);       // reads until whitespace, no limit
strcpy(dst, src);       // no length check

// ✓ SAFE — what auth.cpp uses:
std::string line;
std::getline(std::cin, line);          // heap-managed
if (line.size() > MAX_USERNAME_LEN) {  // explicit ceiling
    return false;
}
```

---

## Frontend Details

### Panel Flow
```
[Register] ──success──▶ [Login] ──success──▶ [OTP] ──success──▶ [Success]
     ▲                      │                                        │
     └──── go-register ─────┘                              btn-logout▼
                                                             [Login]
```

### OTP Input UX
- 6 individual digit boxes with auto-advance on input
- Backspace moves focus to previous box
- Full paste support (paste a 6-digit code into any box)
- Shake animation on wrong OTP submission
- 2-minute countdown; turns red at 30 seconds remaining
- Resend button enabled on expiry

### Password Strength Meter
| Level | Criteria |
|---|---|
| WEAK | Length ≥ 8 only |
| FAIR | + uppercase |
| GOOD | + digits |
| STRONG | + special chars + length ≥ 12 |

---

## Configuration

### Change the API base URL

Edit `frontend/script.js` line 7:
```js
const API_BASE = 'http://localhost:5000';
```

### Change the Flask port

Edit `backend/app.py` last line:
```python
app.run(host="127.0.0.1", port=5000, debug=False)
```

### Change bcrypt cost factor

Edit `backend/app.py`:
```python
salt = bcrypt.gensalt(rounds=12)   # increase for slower hashing = more secure
```

### Change OTP validity window

Must be changed in **both** files to stay in sync:

`backend/app.py`:
```python
OTP_VALID_SECONDS = 120
```

`frontend/script.js`:
```js
const OTP_DURATION_S = 120;
```

---

## Production Hardening

Before deploying beyond localhost, apply these changes:

```
1. HTTPS         → Put Flask behind nginx with a TLS certificate (Let's Encrypt)
2. CORS          → Replace "null" / localhost origins with your real domain
3. OTP delivery  → Integrate Twilio (SMS) or SendGrid (email) instead of console print
4. Secret key    → Add Flask SECRET_KEY from environment variable (os.environ)
5. Database      → Replace in-memory dicts with PostgreSQL + SQLAlchemy
6. Sessions      → Use Flask-Login + signed JWTs or server-side sessions (Redis)
7. Logging       → Ship logs to a SIEM (Splunk / ELK)
8. Rate limits   → Back Flask-Limiter with Redis instead of memory://
9. WSGI          → Run with gunicorn: gunicorn -w 4 -b 127.0.0.1:5000 app:app
10. C++ binary   → Sign binary, verify checksum before subprocess call
```

---

## Troubleshooting

**`C++ binary not found` warning in Flask logs**
```bash
# Make sure you compiled auth.cpp first:
cd project/system
g++ -std=c++17 -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -o auth auth.cpp
```

**CORS error in browser console**
```
# Serve the frontend from a web server, not file://
cd project/frontend && python -m http.server 5500
```

**`ModuleNotFoundError` when starting Flask**
```bash
pip install -r backend/requirements.txt
```

**OTP keeps failing**
- Check the **Flask terminal** — the OTP is printed there for demo mode
- Ensure you submit within 120 seconds of the Login response
- The OTP is one-time use; log in again if you already submitted it once

**Port 5000 already in use**
```bash
# macOS: AirPlay Receiver uses 5000 — disable in System Settings → Sharing
# Or change the port in backend/app.py and frontend/script.js
```

---

## Technology Stack

| Layer | Technology | Version |
|---|---|---|
| Frontend | HTML5 / CSS3 / Vanilla JS | — |
| Fonts | Syne + Fira Code | Google Fonts |
| Backend | Python / Flask | 3.10+ / 3.0.3 |
| Password hashing | bcrypt | 4.1.3 |
| 2FA / OTP | pyotp (TOTP RFC-6238) | 2.9.0 |
| Rate limiting | Flask-Limiter | 3.7.0 |
| CORS | Flask-Cors | 4.0.1 |
| System layer | C++17 | g++ / clang++ |
| WSGI (prod) | Gunicorn | 22.0.0 |

---

*SecureAuth OS — built for educational demonstration of multi-tier authentication security.*
This is my OS project.
This is Secure Authentication Module.