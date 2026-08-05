const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './data/leads.db';
const ADMIN_KEY = process.env.ADMIN_KEY || ''; // this is now your admin PASSWORD, entered on a login page

// Secret path segment — makes the whole admin area unguessable, not just password-protected.
// Set ADMIN_PATH in Railway to something long and random, e.g. "panel-7k2m9xq4vw".
// If not set, falls back to "admin" (guessable — fine for local testing, not for production).
const ADMIN_PATH = (process.env.ADMIN_PATH || 'admin').replace(/^\/+|\/+$/g, '') || 'admin';

// Resend — used to send the "new lead" notification email (free tier: 100/day, 3 domains)
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const ALERT_EMAIL = process.env.ALERT_EMAIL || '';           // where notifications land — any inbox you already own
const FROM_EMAIL = process.env.FROM_EMAIL || 'onboarding@resend.dev'; // e.g. "TreProof <leads@treproof.com>" once domain is verified

const SESSION_DAYS = 7;

// Make sure the folder for the DB file exists (matters if DB_PATH points into a mounted volume)
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

// Basic anti-spam: at most 5 submissions per 15 minutes per IP
const leadsLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'too_many_requests' }
});

// Slow down repeated password guesses at /admin/login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false
});

const db = new Database(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    name TEXT, contact TEXT, asset TEXT, amount TEXT,
    happened_when TEXT, description TEXT, lang TEXT,
    ip TEXT
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    expires_at TEXT NOT NULL
  );
`);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- tiny cookie helpers (no extra dependency needed) ---
function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  header.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}
function setCookie(req, res, name, value, maxAgeSeconds) {
  const isHttps = req.headers['x-forwarded-proto'] === 'https' || req.protocol === 'https';
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`
  ];
  if (isHttps) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function clearCookie(req, res, name) {
  const isHttps = req.headers['x-forwarded-proto'] === 'https' || req.protocol === 'https';
  const parts = [`${name}=`, 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=0'];
  if (isHttps) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

// --- session helpers ---
function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO sessions (token, expires_at) VALUES (?, ?)').run(token, expires);
  return token;
}
function isValidSession(token) {
  if (!token) return false;
  const row = db.prepare('SELECT expires_at FROM sessions WHERE token = ?').get(token);
  if (!row) return false;
  if (new Date(row.expires_at).getTime() < Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    return false;
  }
  return true;
}
function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}
function requireAdmin(req, res, next) {
  const cookies = parseCookies(req);
  if (ADMIN_KEY && isValidSession(cookies.sid)) return next();
  res.redirect(`/${ADMIN_PATH}/login`);
}

// --- receive a lead from the site form ---
app.post('/api/leads', leadsLimiter, (req, res) => {
  const { name, contact, asset, amount, when, desc, lang, website } = req.body || {};

  // Honeypot: real visitors never see or fill this field — bots that auto-fill every input do.
  if (website) {
    return res.json({ ok: true }); // pretend success, silently drop
  }

  if (!name || !contact || !desc) {
    return res.status(400).json({ ok: false, error: 'missing_required_fields' });
  }

  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();

  const stmt = db.prepare(`
    INSERT INTO leads (created_at, name, contact, asset, amount, happened_when, description, lang, ip)
    VALUES (@created_at, @name, @contact, @asset, @amount, @when, @desc, @lang, @ip)
  `);
  stmt.run({
    created_at: new Date().toISOString(),
    name: String(name).slice(0, 300),
    contact: String(contact).slice(0, 300),
    asset: String(asset || '').slice(0, 300),
    amount: String(amount || '').slice(0, 300),
    when: String(when || '').slice(0, 300),
    desc: String(desc).slice(0, 5000),
    lang: String(lang || '').slice(0, 10),
    ip: ip.slice(0, 100)
  });

  notifyByEmail({ name, contact, asset, amount, when, desc, lang }).catch(err => {
    console.error('email notify failed:', err.message);
  });

  res.json({ ok: true });
});

// --- email notification via Resend (skips silently if not configured) ---
async function notifyByEmail(lead) {
  if (!RESEND_API_KEY || !ALERT_EMAIL) return;

  const text = [
    `Новая заявка — TreProof`,
    `Имя: ${lead.name}`,
    `Контакт: ${lead.contact}`,
    `Актив/банк: ${lead.asset || '-'}`,
    `Сумма: ${lead.amount || '-'}`,
    `Когда: ${lead.when || '-'}`,
    `Язык: ${lead.lang || '-'}`,
    ``,
    `Описание:`,
    lead.desc
  ].join('\n');

  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: FROM_EMAIL,
      to: ALERT_EMAIL,
      subject: `Новая заявка — ${lead.name}`,
      text
    })
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Resend API ${resp.status}: ${body}`);
  }
}

// --- admin: login page ---
app.get(`/${ADMIN_PATH}/login`, (req, res) => {
  const adminBase = `/${ADMIN_PATH}`;
  const cookies = parseCookies(req);
  if (ADMIN_KEY && isValidSession(cookies.sid)) return res.redirect(`/${ADMIN_PATH}/leads`);

  const err = req.query.err ? '<p style="color:#b3261e;font-size:14px;margin:0 0 14px">Неверный пароль.</p>' : '';
  res.send(`
    <!DOCTYPE html><html><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Вход — TreProof</title>
    <style>
      body{font-family:system-ui,sans-serif;background:#faf6f0;color:#241f1a;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
      form{background:#fff;padding:32px;border-radius:16px;box-shadow:0 10px 30px -12px rgba(0,0,0,.15);width:280px}
      h1{font-size:18px;margin:0 0 18px}
      input{width:100%;box-sizing:border-box;padding:10px 12px;border:1px solid #e2d6c3;border-radius:8px;font-size:14px;margin-bottom:14px}
      button{width:100%;padding:11px;background:#241f1a;color:#fff;border:none;border-radius:8px;font-weight:700;cursor:pointer;font-size:14px}
    </style></head>
    <body>
      <form method="POST" action="${adminBase}/login">
        <h1>Вход в панель заявок</h1>
        ${err}
        <input type="password" name="password" placeholder="Пароль" autofocus required>
        <button type="submit">Войти</button>
      </form>
    </body></html>
  `);
});

app.post(`/${ADMIN_PATH}/login`, loginLimiter, express.urlencoded({ extended: false }), (req, res) => {
  const password = (req.body && req.body.password) || '';
  if (!ADMIN_KEY || !safeEqual(password, ADMIN_KEY)) {
    return res.redirect(`/${ADMIN_PATH}/login?err=1`);
  }
  const token = createSession();
  setCookie(req, res, 'sid', token, SESSION_DAYS * 24 * 60 * 60);
  res.redirect(`/${ADMIN_PATH}/leads`);
});

app.post(`/${ADMIN_PATH}/logout`, (req, res) => {
  const cookies = parseCookies(req);
  if (cookies.sid) db.prepare('DELETE FROM sessions WHERE token = ?').run(cookies.sid);
  clearCookie(req, res, 'sid');
  res.redirect(`/${ADMIN_PATH}/login`);
});

// --- admin: leads table (requires a valid login session) ---
app.get(`/${ADMIN_PATH}/leads`, requireAdmin, (req, res) => {
  const adminBase = `/${ADMIN_PATH}`;
  const rows = db.prepare('SELECT * FROM leads ORDER BY id DESC').all();

  const escape = s => String(s || '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));

  const tableRows = rows.map(r => `
    <tr>
      <td>${r.id}</td>
      <td>${escape(r.created_at)}</td>
      <td>${escape(r.name)}</td>
      <td>${escape(r.contact)}</td>
      <td>${escape(r.asset)}</td>
      <td>${escape(r.amount)}</td>
      <td>${escape(r.happened_when)}</td>
      <td style="max-width:360px;white-space:pre-wrap">${escape(r.description)}</td>
      <td>${escape(r.lang)}</td>
    </tr>
  `).join('');

  res.send(`
    <!DOCTYPE html><html><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Leads — TreProof</title>
    <style>
      body{font-family:system-ui,sans-serif;padding:24px;background:#faf6f0;color:#241f1a}
      .top{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
      table{border-collapse:collapse;width:100%;background:#fff}
      th,td{border:1px solid #e2d6c3;padding:8px 10px;font-size:13px;text-align:left;vertical-align:top}
      th{background:#f4ece0;position:sticky;top:0}
      h1{font-size:20px;margin:0}
      button{padding:8px 14px;border:1px solid #e2d6c3;background:#fff;border-radius:8px;cursor:pointer;font-size:13px}
    </style></head>
    <body>
      <div class="top">
        <h1>Leads (${rows.length})</h1>
        <form method="POST" action="${adminBase}/logout"><button type="submit">Выйти</button></form>
      </div>
      <table>
        <thead><tr>
          <th>#</th><th>Date</th><th>Name</th><th>Contact</th><th>Asset/bank</th>
          <th>Amount</th><th>When</th><th>Description</th><th>Lang</th>
        </tr></thead>
        <tbody>${tableRows}</tbody>
      </table>
    </body></html>
  `);
});

app.listen(PORT, () => {
  console.log(`TreProof server running on port ${PORT}`);
  console.log(`DB file: ${path.resolve(DB_PATH)}`);
});
