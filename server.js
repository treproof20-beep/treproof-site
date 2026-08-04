const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');
const fs = require('fs');

const PORT = process.env.PORT || 3000;
const DB_PATH = process.env.DB_PATH || './data/leads.db';
const ADMIN_KEY = process.env.ADMIN_KEY || '';
const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const ALERT_EMAIL = process.env.ALERT_EMAIL || '';
const FROM_EMAIL = process.env.FROM_EMAIL || 'onboarding@resend.dev';

// Make sure the folder for the DB file exists (matters if DB_PATH points into a mounted volume)
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

const db = new Database(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    name TEXT, contact TEXT, asset TEXT, amount TEXT,
    happened_when TEXT, description TEXT, lang TEXT,
    ip TEXT
  )
`);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- receive a lead from the site form ---
app.post('/api/leads', (req, res) => {
  const { name, contact, asset, amount, when, desc, lang } = req.body || {};

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

// --- optional email notification via Resend (skips silently if not configured) ---
async function notifyByEmail(lead) {
  if (!RESEND_API_KEY || !ALERT_EMAIL) return;

  const text = [
    `New lead from TreProof`,
    `Name: ${lead.name}`,
    `Contact: ${lead.contact}`,
    `Asset/bank: ${lead.asset || '-'}`,
    `Amount: ${lead.amount || '-'}`,
    `When: ${lead.when || '-'}`,
    `Language: ${lead.lang || '-'}`,
    ``,
    `Description:`,
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
      subject: `New lead — ${lead.name}`,
      text
    })
  });

  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Resend API ${resp.status}: ${body}`);
  }
}

// --- simple password-protected admin view of all leads ---
app.get('/admin/leads', (req, res) => {
  if (!ADMIN_KEY || req.query.key !== ADMIN_KEY) {
    return res.status(401).send('Unauthorized. Add ?key=YOUR_ADMIN_KEY to the URL.');
  }

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
    <title>Leads — TreProof</title>
    <style>
      body{font-family:system-ui,sans-serif;padding:24px;background:#faf6f0;color:#241f1a}
      table{border-collapse:collapse;width:100%;background:#fff}
      th,td{border:1px solid #e2d6c3;padding:8px 10px;font-size:13px;text-align:left;vertical-align:top}
      th{background:#f4ece0;position:sticky;top:0}
      h1{font-size:20px}
    </style></head>
    <body>
      <h1>Leads (${rows.length})</h1>
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
