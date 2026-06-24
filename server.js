'use strict';
const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const fs = require('fs');
const { initDb, getSetting, setSetting, getServiceByUrl, getService, createService } = require('./db');
const { startChecker, scheduleService } = require('./checker');

const PORT = process.env.PORT || 3000;
// SECURE_COOKIES=true nur setzen wenn hinter HTTPS (Reverse Proxy mit TLS)
const SECURE_COOKIES = process.env.SECURE_COOKIES === 'true';

// ---- Database & session secret ----
initDb();

let sessionSecret = getSetting('session_secret');
if (!sessionSecret) {
  sessionSecret = crypto.randomBytes(32).toString('hex');
  setSetting('session_secret', sessionSecret);
}

// ---- Express ----
const app = express();

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
  );
  next();
});

app.set('trust proxy', process.env.TRUST_PROXY === '1' ? 1 : false);

// Request logging
app.use((req, res, next) => {
  res.on('finish', () => {
    const color = res.statusCode < 300 ? '\x1b[32m' : res.statusCode < 400 ? '\x1b[33m' : '\x1b[31m';
    const reset = '\x1b[0m';
    console.log(`${color}${req.method} ${req.path} ${res.statusCode}${reset}`);
  });
  next();
});

app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// In-memory session store (fine for single-instance deployments).
// Sessions are lost on restart — users just log in again.
app.use(session({
  secret: sessionSecret,
  name: 'hc.sid',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: SECURE_COOKIES,
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
  },
}));

// ---- Routes ----
app.use('/api', require('./routes/api'));
app.use('/admin', require('./routes/admin'));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

app.use((err, req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ---- Admin password setup ----
// If ADMIN_PASSWORD env var is set, it always wins (useful for Docker/compose).
// On first run without env var, a random password is generated and printed.
async function ensureAdminPassword() {
  const envPassword = process.env.ADMIN_PASSWORD;
  const pad = s => String(s).padEnd(24);

  if (envPassword) {
    setSetting('admin_password_hash', await bcrypt.hash(envPassword, 12));
    console.log('\n╔══════════════════════════════════════════╗');
    console.log('║        HEALTH CHECKER — PASSWORT         ║');
    console.log('╠══════════════════════════════════════════╣');
    console.log(`║  Passwort aus ADMIN_PASSWORD gesetzt.    ║`);
    console.log(`║  URL: http://localhost:${pad(PORT)} ║`);
    console.log('╚══════════════════════════════════════════╝\n');
    return;
  }

  if (getSetting('admin_password_hash')) return;

  const password = crypto.randomBytes(12).toString('base64url');
  setSetting('admin_password_hash', await bcrypt.hash(password, 12));

  console.log('\n╔══════════════════════════════════════════╗');
  console.log('║       HEALTH CHECKER — FIRST RUN         ║');
  console.log('╠══════════════════════════════════════════╣');
  console.log(`║  Admin-Passwort: ${pad(password)} ║`);
  console.log(`║  URL: http://localhost:${pad(PORT)} ║`);
  console.log('╚══════════════════════════════════════════╝\n');
}

function autoImportServices() {
  const jsonPath = process.env.SERVICES_JSON;
  if (!jsonPath || !fs.existsSync(jsonPath)) return;

  let data;
  try { data = JSON.parse(fs.readFileSync(jsonPath, 'utf8')); }
  catch (err) { console.error('[IMPORT] Ungültiges JSON:', err.message); return; }

  const list = data.Services || data.services || [];
  let added = 0;

  for (const s of list) {
    const name = (s.Service_Name || s.name || '').trim();
    const url  = (s.url || '').trim();
    if (!name || !url) continue;
    if (getServiceByUrl(url)) continue; // bereits vorhanden

    const result = createService(name, url, parseInt(s.interval) || 60, 10, !!s.dual_stack);
    const service = getService(result.lastInsertRowid);
    scheduleService(service);
    console.log(`[IMPORT] ${name} (${url})`);
    added++;
  }

  if (added) console.log(`[IMPORT] ${added} neue(r) Dienst(e) aus ${jsonPath} importiert`);
}

ensureAdminPassword().then(() => {
  autoImportServices();
  startChecker();
  app.listen(PORT, () => console.log(`[SERVER] Health Checker läuft auf Port ${PORT}`));
}).catch(err => {
  console.error('[FATAL]', err);
  process.exit(1);
});
