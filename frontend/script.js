/* ═══════════════════════════════════════════════════════════════
   SecureAuth OS — script.js
   Handles: boot animation, panel navigation, API calls,
            OTP input, password strength, status bar, clock
   API base: http://localhost:5000
═══════════════════════════════════════════════════════════════ */

'use strict';

/* ── 0. Configuration ─────────────────────────────────────── */
const API_BASE = 'http://localhost:5000';

/* ── 1. Boot Sequence ─────────────────────────────────────── */
const BOOT_MESSAGES = [
  { text: '[  0.000001] SecureAuth OS kernel initialising...', cls: '' },
  { text: '[  0.012340] Loading cryptographic subsystem (AES-256, bcrypt)', cls: '' },
  { text: '[  0.018700] Mounting auth.cpp native module... OK', cls: 'ok' },
  { text: '[  0.024510] Verifying bcrypt library integrity... OK', cls: 'ok' },
  { text: '[  0.031200] Starting Flask API gateway on :5000', cls: '' },
  { text: '[  0.041800] CORS policy enforced: localhost only', cls: 'ok' },
  { text: '[  0.055990] OTP subsystem (TOTP) standby... READY', cls: 'ok' },
  { text: '[  0.063400] Buffer-overflow guard (stack canaries): ACTIVE', cls: 'ok' },
  { text: '[  0.071100] Input sanitisation layer loaded', cls: '' },
  { text: '[  0.082300] Session store initialised (in-memory)', cls: '' },
  { text: '[  0.091200] WARNING: running in development mode', cls: 'warn' },
  { text: '[  0.099500] All subsystems nominal. Launching UI...', cls: 'ok' },
];

function runBootSequence() {
  const container = document.getElementById('boot-lines');
  const fill      = document.getElementById('boot-fill');
  const overlay   = document.getElementById('boot-overlay');
  const app       = document.getElementById('app');
  const total     = BOOT_MESSAGES.length;
  let   idx       = 0;

  function printNext() {
    if (idx >= total) {
      // finish bar, then fade overlay
      fill.style.width = '100%';
      setTimeout(() => {
        overlay.classList.add('fade-out');
        app.classList.remove('hidden');
        startClock();
      }, 500);
      return;
    }

    const msg  = BOOT_MESSAGES[idx];
    const line = document.createElement('div');
    line.className = `boot-line ${msg.cls}`;
    line.textContent = msg.text;
    line.style.animationDelay = '0s';
    container.appendChild(line);

    // progress bar
    fill.style.width = `${Math.round(((idx + 1) / total) * 100)}%`;

    idx++;
    setTimeout(printNext, 95 + Math.random() * 60);
  }

  printNext();
}

document.addEventListener('DOMContentLoaded', runBootSequence);

/* ── 2. Clock ─────────────────────────────────────────────── */
function startClock() {
  const el = document.getElementById('clock');
  function tick() {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-GB', { hour12: false });
  }
  tick();
  setInterval(tick, 1000);
}

/* ── 3. Status Bar helpers ────────────────────────────────── */
const statusDot  = document.getElementById('status-dot');
const statusText = document.getElementById('status-text');

/**
 * Update the top status indicator.
 * @param {'idle'|'loading'|'active'|'error'} state
 * @param {string} msg
 */
function setStatus(state, msg) {
  statusDot.className = 'status-dot';
  if (state === 'loading') statusDot.classList.add('loading');
  if (state === 'active')  statusDot.classList.add('active');
  if (state === 'error')   statusDot.classList.add('error');
  statusText.textContent = msg.toUpperCase();
}

/* ── 4. Panel navigation ──────────────────────────────────── */
const PANELS = ['register', 'login', 'otp', 'success'];
let   currentPanel = 'register';   // track current for cleanup

/**
 * Show one panel, hide all others.
 * @param {'register'|'login'|'otp'|'success'} name
 */
function showPanel(name) {
  PANELS.forEach(id => {
    const el = document.getElementById(`panel-${id}`);
    if (id === name) {
      el.classList.remove('hidden');
      // re-trigger entry animation
      el.style.animation = 'none';
      // force reflow
      void el.offsetHeight;
      el.style.animation = '';
    } else {
      el.classList.add('hidden');
    }
  });
  currentPanel = name;
  clearAllFeedback();
}

// Wire navigation links
document.getElementById('go-login').addEventListener('click', () => {
  showPanel('login');
  setStatus('idle', 'SYSTEM IDLE');
});

document.getElementById('go-register').addEventListener('click', () => {
  showPanel('register');
  setStatus('idle', 'SYSTEM IDLE');
});

/* ── 5. Feedback Box helpers ──────────────────────────────── */
/**
 * Show a feedback message.
 * @param {string} boxId   - element id of the feedback box
 * @param {'success'|'error'|'info'} type
 * @param {string} message
 */
function showFeedback(boxId, type, message) {
  const el = document.getElementById(boxId);
  el.className = `feedback-box ${type}`;
  el.textContent = message;
  el.classList.remove('hidden');
}

function hideFeedback(boxId) {
  const el = document.getElementById(boxId);
  el.classList.add('hidden');
  el.textContent = '';
}

function clearAllFeedback() {
  ['reg-feedback', 'login-feedback', 'otp-feedback'].forEach(hideFeedback);
}

/* ── 6. Button loading state ─────────────────────────────── */
/**
 * Toggle a button's loading state.
 * @param {HTMLButtonElement} btn
 * @param {boolean} loading
 */
function setBtnLoading(btn, loading) {
  const textEl   = btn.querySelector('.btn-text');
  const loaderEl = btn.querySelector('.btn-loader');
  btn.disabled = loading;
  if (loading) {
    textEl.classList.add('hidden');
    loaderEl.classList.remove('hidden');
  } else {
    textEl.classList.remove('hidden');
    loaderEl.classList.add('hidden');
  }
}

/* ── 7. Input validation helpers ─────────────────────────── */
const USERNAME_RE = /^[a-zA-Z0-9_\-]{3,64}$/;

/**
 * Mark a field as error or clear error state.
 * @param {HTMLInputElement} input
 * @param {boolean} isError
 */
function markFieldError(input, isError) {
  if (isError) input.classList.add('error');
  else         input.classList.remove('error');
}

function validateUsername(value) {
  if (!value || value.trim().length === 0) return 'Username is required.';
  if (!USERNAME_RE.test(value.trim()))     return 'Username: 3–64 chars, letters/digits/_/- only.';
  return null;
}

function validatePassword(value) {
  if (!value || value.length === 0)  return 'Password is required.';
  if (value.length < 8)              return 'Password must be at least 8 characters.';
  if (value.length > 128)            return 'Password too long (max 128 characters).';
  return null;
}

/* ── 8. Password Strength Meter ───────────────────────────── */
const regPasswordInput = document.getElementById('reg-password');
const strengthFill     = document.getElementById('strength-fill');
const strengthLabel    = document.getElementById('strength-label');

const STRENGTH_LABELS = ['—', 'WEAK', 'FAIR', 'GOOD', 'STRONG'];
const STRENGTH_COLORS = ['', 'var(--danger)', 'var(--warn)', '#7fff6b', 'var(--accent)'];

/**
 * Score a password 0-4.
 * Criteria: length≥8, uppercase, digits, special chars, length≥12
 */
function scorePassword(pw) {
  if (!pw || pw.length === 0) return 0;
  let score = 0;
  if (pw.length >= 8)               score++;
  if (/[A-Z]/.test(pw))             score++;
  if (/[0-9]/.test(pw))             score++;
  if (/[^a-zA-Z0-9]/.test(pw))      score++;
  if (pw.length >= 12 && score >= 3) score = 4;  // bonus for long+complex
  return Math.min(score, 4);
}

regPasswordInput.addEventListener('input', () => {
  const score = scorePassword(regPasswordInput.value);
  strengthFill.setAttribute('data-level', score > 0 ? score : '');
  strengthFill.style.width = score > 0 ? `${score * 25}%` : '0%';
  strengthFill.style.background = STRENGTH_COLORS[score];
  strengthLabel.textContent = STRENGTH_LABELS[score];
});

/* ── 9. Toggle password visibility ─────────────────────────── */
document.querySelectorAll('.toggle-pw').forEach(btn => {
  btn.addEventListener('click', () => {
    const targetId = btn.dataset.target;
    const input    = document.getElementById(targetId);
    if (!input) return;
    if (input.type === 'password') {
      input.type = 'text';
      btn.textContent = '●';
      btn.setAttribute('aria-label', 'Hide password');
    } else {
      input.type = 'password';
      btn.textContent = '◎';
      btn.setAttribute('aria-label', 'Show password');
    }
  });
});

/* ── 10. API helpers ─────────────────────────────────────────── */
/**
 * Generic JSON POST to the Flask backend.
 * @param {string} endpoint  - e.g. '/register'
 * @param {object} payload   - request body
 * @returns {Promise<{status:string, message:string}>}
 */
async function apiPost(endpoint, payload) {
  const resp = await fetch(`${API_BASE}${endpoint}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(payload),
  });

  if (!resp.ok) {
    // Try to parse error JSON; fall back to HTTP status text
    let errMsg = `HTTP ${resp.status}: ${resp.statusText}`;
    try {
      const errBody = await resp.json();
      if (errBody.message) errMsg = errBody.message;
    } catch (_) {}
    throw new Error(errMsg);
  }

  return resp.json();
}

/* ── 11. State: logged-in username (for OTP step) ─────────── */
let pendingUsername = '';   // set after successful login credential check

/* ── 12. Register Flow ───────────────────────────────────────── */
const btnRegister    = document.getElementById('btn-register');
const regUsernameIn  = document.getElementById('reg-username');
const regPasswordIn  = document.getElementById('reg-password');

btnRegister.addEventListener('click', async () => {
  hideFeedback('reg-feedback');

  const username = regUsernameIn.value.trim();
  const password = regPasswordIn.value;

  // Client-side validation
  const uErr = validateUsername(username);
  const pErr = validatePassword(password);

  markFieldError(regUsernameIn, !!uErr);
  markFieldError(regPasswordIn, !!pErr);

  if (uErr) { showFeedback('reg-feedback', 'error', uErr); return; }
  if (pErr) { showFeedback('reg-feedback', 'error', pErr); return; }

  setBtnLoading(btnRegister, true);
  setStatus('loading', 'REGISTERING USER');

  try {
    const data = await apiPost('/register', { username, password });

    if (data.status === 'success') {
      showFeedback('reg-feedback', 'success', `✔ ${data.message}`);
      setStatus('active', 'ACCOUNT CREATED');
      // Auto-switch to login after short delay
      setTimeout(() => {
        regUsernameIn.value = '';
        regPasswordIn.value = '';
        strengthFill.style.width = '0%';
        strengthLabel.textContent = '—';
        showPanel('login');
        setStatus('idle', 'SYSTEM IDLE');
      }, 1400);
    } else {
      showFeedback('reg-feedback', 'error', `✘ ${data.message}`);
      setStatus('error', 'REGISTRATION FAILED');
    }
  } catch (err) {
    showFeedback('reg-feedback', 'error', `✘ Network error: ${err.message}`);
    setStatus('error', 'CONNECTION FAILED');
  } finally {
    setBtnLoading(btnRegister, false);
  }
});

// Allow Enter key in register fields
[regUsernameIn, regPasswordIn].forEach(input => {
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') btnRegister.click();
  });
});

/* ── 13. Login Flow ──────────────────────────────────────────── */
const btnLogin       = document.getElementById('btn-login');
const loginUsernameIn = document.getElementById('login-username');
const loginPasswordIn = document.getElementById('login-password');

btnLogin.addEventListener('click', async () => {
  hideFeedback('login-feedback');

  const username = loginUsernameIn.value.trim();
  const password = loginPasswordIn.value;

  const uErr = validateUsername(username);
  const pErr = validatePassword(password);

  markFieldError(loginUsernameIn, !!uErr);
  markFieldError(loginPasswordIn, !!pErr);

  if (uErr) { showFeedback('login-feedback', 'error', uErr); return; }
  if (pErr) { showFeedback('login-feedback', 'error', pErr); return; }

  setBtnLoading(btnLogin, true);
  setStatus('loading', 'AUTHENTICATING');

  try {
    const data = await apiPost('/login', { username, password });

    if (data.status === 'success') {
      pendingUsername = username;
      showFeedback('login-feedback', 'success', `✔ ${data.message}`);
      setStatus('active', 'OTP DISPATCHED');

      // Transition to OTP panel
      setTimeout(() => {
        loginUsernameIn.value = '';
        loginPasswordIn.value = '';
        showPanel('otp');
        startOtpCountdown();
        // Focus first OTP box
        document.querySelector('.otp-box')?.focus();
      }, 800);
    } else {
      showFeedback('login-feedback', 'error', `✘ ${data.message}`);
      setStatus('error', 'AUTH FAILED');
    }
  } catch (err) {
    showFeedback('login-feedback', 'error', `✘ Network error: ${err.message}`);
    setStatus('error', 'CONNECTION FAILED');
  } finally {
    setBtnLoading(btnLogin, false);
  }
});

[loginUsernameIn, loginPasswordIn].forEach(input => {
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') btnLogin.click();
  });
});

/* ── 14. OTP Input Cluster ───────────────────────────────────── */
const otpBoxes = Array.from(document.querySelectorAll('.otp-box'));

otpBoxes.forEach((box, idx) => {
  // Only allow digits
  box.addEventListener('keydown', e => {
    // Allow: Backspace, Tab, ArrowLeft, ArrowRight
    const allowed = ['Backspace', 'Tab', 'ArrowLeft', 'ArrowRight', 'Delete'];
    if (allowed.includes(e.key)) return;
    if (e.key === 'Enter') { btnVerifyOtp.click(); return; }
    // Block non-digit
    if (!/^[0-9]$/.test(e.key)) { e.preventDefault(); return; }
  });

  box.addEventListener('input', e => {
    const val = box.value.replace(/[^0-9]/g, '');
    box.value = val.slice(-1);   // keep only last char

    if (box.value) {
      box.classList.add('filled');
      // Move to next box
      if (idx < otpBoxes.length - 1) otpBoxes[idx + 1].focus();
    } else {
      box.classList.remove('filled');
    }
  });

  box.addEventListener('keydown', e => {
    if (e.key === 'Backspace' && !box.value && idx > 0) {
      // move focus back
      otpBoxes[idx - 1].focus();
      otpBoxes[idx - 1].value = '';
      otpBoxes[idx - 1].classList.remove('filled');
    }
    if (e.key === 'ArrowLeft'  && idx > 0)                    otpBoxes[idx - 1].focus();
    if (e.key === 'ArrowRight' && idx < otpBoxes.length - 1)  otpBoxes[idx + 1].focus();
  });

  // Handle paste of full OTP code
  box.addEventListener('paste', e => {
    e.preventDefault();
    const pasted = (e.clipboardData || window.clipboardData)
      .getData('text').replace(/[^0-9]/g, '').slice(0, 6);
    pasted.split('').forEach((char, i) => {
      if (otpBoxes[i]) {
        otpBoxes[i].value = char;
        otpBoxes[i].classList.add('filled');
      }
    });
    // Focus last filled or next empty
    const focusIdx = Math.min(pasted.length, otpBoxes.length - 1);
    otpBoxes[focusIdx].focus();
  });
});

/** Collect all 6 digits from OTP boxes */
function getOtpValue() {
  return otpBoxes.map(b => b.value).join('');
}

/** Clear all OTP boxes */
function clearOtpBoxes() {
  otpBoxes.forEach(b => { b.value = ''; b.classList.remove('filled', 'error'); });
}

/** Mark OTP boxes as error */
function shakeOtpBoxes() {
  otpBoxes.forEach(b => {
    b.classList.add('error');
    b.addEventListener('animationend', () => b.classList.remove('error'), { once: true });
  });
}

/* ── 15. OTP Countdown Timer ──────────────────────────────── */
let otpTimerInterval = null;
const OTP_DURATION_S = 120;  // 2 minutes

function startOtpCountdown() {
  const countdownEl = document.getElementById('otp-countdown');
  const resendBtn   = document.getElementById('btn-resend-otp');
  let   remaining   = OTP_DURATION_S;

  resendBtn.disabled = true;
  countdownEl.classList.remove('expiring');

  if (otpTimerInterval) clearInterval(otpTimerInterval);

  function format(s) {
    const m = Math.floor(s / 60).toString().padStart(2, '0');
    const sec = (s % 60).toString().padStart(2, '0');
    return `${m}:${sec}`;
  }

  countdownEl.textContent = format(remaining);

  otpTimerInterval = setInterval(() => {
    remaining--;
    countdownEl.textContent = format(remaining);

    if (remaining <= 30) countdownEl.classList.add('expiring');

    if (remaining <= 0) {
      clearInterval(otpTimerInterval);
      countdownEl.textContent = '00:00';
      resendBtn.disabled = false;
      showFeedback('otp-feedback', 'info', '⚠ OTP expired. Request a new code.');
      setStatus('error', 'OTP EXPIRED');
    }
  }, 1000);
}

// Resend OTP (calls login again with cached username)
document.getElementById('btn-resend-otp').addEventListener('click', async () => {
  clearOtpBoxes();
  hideFeedback('otp-feedback');
  setStatus('loading', 'RESENDING OTP');
  // Re-trigger login on backend to generate a fresh OTP
  try {
    // We only resend; the backend /login endpoint regenerates OTP when credentials are already verified
    // In this flow we signal a resend via a dedicated attempt — we show info only
    showFeedback('otp-feedback', 'info', '↺ Please log in again to receive a new OTP.');
    setStatus('idle', 'SYSTEM IDLE');
    setTimeout(() => showPanel('login'), 1800);
  } catch (_) {}
});

/* ── 16. OTP Verify Flow ─────────────────────────────────── */
const btnVerifyOtp = document.getElementById('btn-verify-otp');

btnVerifyOtp.addEventListener('click', async () => {
  hideFeedback('otp-feedback');

  const otp = getOtpValue();

  // Validate: must be exactly 6 digits
  if (otp.length !== 6 || !/^\d{6}$/.test(otp)) {
    shakeOtpBoxes();
    showFeedback('otp-feedback', 'error', '✘ Enter all 6 digits of your OTP.');
    return;
  }

  if (!pendingUsername) {
    showFeedback('otp-feedback', 'error', '✘ Session expired. Please log in again.');
    setTimeout(() => showPanel('login'), 1500);
    return;
  }

  setBtnLoading(btnVerifyOtp, true);
  setStatus('loading', 'VERIFYING OTP');

  try {
    const data = await apiPost('/verify-otp', {
      username: pendingUsername,
      otp,
    });

    if (data.status === 'success') {
      clearInterval(otpTimerInterval);
      clearOtpBoxes();
      setStatus('active', 'ACCESS GRANTED');
      showPanel('success');
      renderSuccessTerminal(pendingUsername);
    } else {
      shakeOtpBoxes();
      showFeedback('otp-feedback', 'error', `✘ ${data.message}`);
      setStatus('error', 'OTP INVALID');
      clearOtpBoxes();
      document.querySelector('.otp-box')?.focus();
    }
  } catch (err) {
    showFeedback('otp-feedback', 'error', `✘ Network error: ${err.message}`);
    setStatus('error', 'CONNECTION FAILED');
  } finally {
    setBtnLoading(btnVerifyOtp, false);
  }
});

/* ── 17. Success Terminal animation ─────────────────────────── */
const SUCCESS_LINES = (username) => [
  `> Identity confirmed: ${username}`,
  '> bcrypt signature   : VALID',
  '> OTP sequence       : ACCEPTED',
  '> Session token      : generated',
  '> Privilege level    : USER',
  '> Access log entry   : written',
  '> Welcome to SecureAuth OS.',
];

function renderSuccessTerminal(username) {
  const terminal = document.getElementById('success-terminal');
  const userMsg  = document.getElementById('success-user-msg');
  terminal.innerHTML = '';
  userMsg.textContent = `Identity confirmed for: ${username}`;

  SUCCESS_LINES(username).forEach((line, i) => {
    const el = document.createElement('div');
    el.className = 't-line';
    el.textContent = line;
    el.style.animationDelay = `${i * 120}ms`;
    terminal.appendChild(el);
  });
}

/* ── 18. Logout / End Session ────────────────────────────────── */
document.getElementById('btn-logout').addEventListener('click', () => {
  pendingUsername = '';
  clearOtpBoxes();
  if (otpTimerInterval) clearInterval(otpTimerInterval);
  setStatus('idle', 'SESSION ENDED');
  showPanel('login');
});

/* ── 19. Initial state setup ─────────────────────────────────── */
// Show register panel first (boot overlay hides app until done)
showPanel('register');
setStatus('idle', 'SYSTEM IDLE');
