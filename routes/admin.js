'use strict';
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const https = require('https');
const bcrypt = require('bcryptjs');

// --- Update-Check Cache ---
let _updateCache = null;
let _updateCacheAt = 0;
const UPDATE_REPO = 'sined0606/Website_online_log';
const { requireAdmin } = require('../middleware/auth');
const { loginRateLimit, recordFailedAttempt, clearAttempts, getClientIp } = require('../middleware/rateLimit');
const {
  getSetting, setSetting,
  getServices, getService, createService, updateService, deleteService,
  getTokens, getToken, createToken, updateTokenScope, deleteToken,
  getTokenPermissions, setTokenPermissions,
  getApiLogs, countApiLogs, getCheckHistory, getLatestCheckResult, getLatestResultPerFamily,
} = require('../db');
const { scheduleService, unscheduleService } = require('../checker');

// --- Session ---

router.post('/login', loginRateLimit, async (req, res) => {
  const { password } = req.body || {};
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password required' });
  }

  const hash = getSetting('admin_password_hash');
  if (!hash) return res.status(500).json({ error: 'Admin not initialised' });

  const valid = await bcrypt.compare(password, hash);
  if (!valid) {
    recordFailedAttempt(getClientIp(req));
    return res.status(401).json({ error: 'Invalid password' });
  }

  clearAttempts(getClientIp(req));
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Session error' });
    req.session.admin = true;
    res.json({ ok: true });
  });
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

router.get('/session', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ authenticated: !!(req.session && req.session.admin) });
});

// --- Services ---

router.get('/services', requireAdmin, (req, res) => {
  const services = getServices().map(s => {
    const isDual = !!s.dual_stack;

    if (isDual) {
      const results = getLatestResultPerFamily(s.id);
      const v4 = results.find(r => r.ip_family === 4) || null;
      const v6 = results.find(r => r.ip_family === 6) || null;
      const up4 = v4?.is_up, up6 = v6?.is_up;
      let status = 'unknown';
      if (v4 || v6) status = (up4 && up6) ? 'up' : (up4 || up6) ? 'partial' : 'down';
      return { ...s, enabled: !!s.enabled, dual_stack: true, status,
        last_check: null, last_check_v4: v4, last_check_v6: v6 };
    }

    const latest = getLatestCheckResult(s.id) || null;
    return { ...s, enabled: !!s.enabled, dual_stack: false,
      status: latest ? (latest.is_up ? 'up' : 'down') : 'unknown',
      last_check: latest, last_check_v4: null, last_check_v6: null };
  });
  res.json(services);
});

router.post('/services', requireAdmin, (req, res) => {
  const { name, url, check_interval, timeout, dual_stack } = req.body || {};
  const err = validateService(name, url, check_interval, timeout);
  if (err) return res.status(400).json({ error: err });

  const result = createService(
    name.trim(), url.trim(),
    parseInt(check_interval) || 60,
    parseInt(timeout) || 10,
    !!dual_stack
  );
  const service = getService(result.lastInsertRowid);
  scheduleService(service);
  res.status(201).json({ ...service, enabled: !!service.enabled, dual_stack: !!service.dual_stack });
});

router.put('/services/:id', requireAdmin, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID' });

  const { name, url, check_interval, timeout, enabled, dual_stack } = req.body || {};
  const err = validateService(name, url, check_interval, timeout);
  if (err) return res.status(400).json({ error: err });

  updateService(id, name.trim(), url.trim(),
    parseInt(check_interval) || 60,
    parseInt(timeout) || 10,
    enabled !== false,
    !!dual_stack
  );
  const service = getService(id);
  if (!service) return res.status(404).json({ error: 'Service not found' });

  if (service.enabled) {
    scheduleService(service);
  } else {
    unscheduleService(id);
  }
  res.json({ ...service, enabled: !!service.enabled, dual_stack: !!service.dual_stack });
});

router.delete('/services/:id', requireAdmin, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID' });

  unscheduleService(id);
  deleteService(id);
  res.json({ ok: true });
});

router.get('/services/:id/history', requireAdmin, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID' });

  const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), 1000);
  res.json(getCheckHistory(id, limit));
});

// Import from curl.json in project root
router.post('/services/import-local', requireAdmin, (req, res) => {
  const fs = require('fs');
  const filePath = require('path').join(__dirname, '..', 'curl.json');
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'curl.json not found in project root' });
  let data;
  try { data = JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch (_e) { return res.status(400).json({ error: 'curl.json is not valid JSON' }); }
  req.body = data;
  return importHandler(req, res);
});

router.post('/services/import', requireAdmin, (req, res) => importHandler(req, res));

function importHandler(req, res) {
  const { Services } = req.body || {};
  if (!Array.isArray(Services)) return res.status(400).json({ error: 'Invalid format. Expected { Services: [...] }' });

  const created = [];
  const errors = [];

  for (const s of Services) {
    const name = (s.Service_Name || s.name || '').trim();
    const url = (s.url || '').trim();
    const interval = parseInt(s.interval) || 60;

    if (!name || !url) { errors.push({ item: s, reason: 'Missing name or url' }); continue; }
    if (!isValidUrl(url)) { errors.push({ item: s, reason: 'Invalid URL' }); continue; }

    const result = createService(name, url, interval, 10);
    const service = getService(result.lastInsertRowid);
    scheduleService(service);
    created.push(service);
  }

  res.status(201).json({ created: created.length, errors });
}

// --- Tokens ---

router.get('/tokens', requireAdmin, (req, res) => {
  const tokens = getTokens().map(t => ({
    ...t,
    active: !!t.active,
    permissions: getTokenPermissions(t.id),
  }));
  res.json(tokens);
});

router.post('/tokens', requireAdmin, (req, res) => {
  const { name, scope } = req.body || {};
  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'Token name required' });
  }

  const validScope = scope === 'all' ? 'all' : 'restricted';
  const raw = crypto.randomBytes(32).toString('hex'); // 64-char hex token
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const prefix = raw.slice(0, 8);

  const result = createToken(name.trim(), hash, prefix, validScope);
  res.status(201).json({
    id: result.lastInsertRowid,
    name: name.trim(),
    token: raw, // Returned ONLY once — not stored in plain text
    token_prefix: prefix,
    scope: validScope,
    active: true,
    permissions: [],
  });
});

router.put('/tokens/:id/permissions', requireAdmin, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID' });

  const { service_ids, scope } = req.body || {};

  if (scope !== undefined) {
    const validScope = scope === 'all' ? 'all' : 'restricted';
    updateTokenScope(id, validScope);
  }

  if (Array.isArray(service_ids)) {
    const ids = service_ids.map(Number).filter(n => Number.isFinite(n) && n > 0);
    setTokenPermissions(id, ids);
  }

  const token = getToken(id);
  if (!token) return res.status(404).json({ error: 'Token not found' });

  res.json({ ...token, permissions: getTokenPermissions(id) });
});

router.delete('/tokens/:id', requireAdmin, (req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid ID' });

  deleteToken(id);
  res.json({ ok: true });
});

// --- Logs ---

router.get('/logs', requireAdmin, (req, res) => {
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 100, 1), 500);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  res.json({
    total: countApiLogs(),
    logs: getApiLogs(limit, offset),
  });
});

// --- Update Check ---

router.get('/update-check', requireAdmin, async (req, res) => {
  const CACHE_TTL = 6 * 60 * 60 * 1000;
  if (_updateCache && Date.now() - _updateCacheAt < CACHE_TTL) {
    return res.json(_updateCache);
  }

  const pkg = require('../package.json');

  try {
    const data = await new Promise((resolve, reject) => {
      const req2 = https.get({
        hostname: 'api.github.com',
        path: `/repos/${UPDATE_REPO}/releases/latest`,
        headers: { 'User-Agent': 'health-checker/1', 'Accept': 'application/vnd.github+json' },
      }, r => {
        let body = '';
        r.on('data', c => body += c);
        r.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
      });
      req2.on('error', reject);
      req2.setTimeout(8000, () => { req2.destroy(); reject(new Error('timeout')); });
    });

    if (data.message === 'Not Found') {
      _updateCache = { current: pkg.version, latest: null, update_available: false };
      _updateCacheAt = Date.now();
      return res.json(_updateCache);
    }

    const latest = (data.tag_name || '').replace(/^v/, '');
    _updateCache = {
      current: pkg.version,
      latest,
      update_available: !!latest && latest !== pkg.version,
      release_name: data.name || '',
      release_url: data.html_url || '',
      published_at: data.published_at || null,
      notes_url: `https://raw.githubusercontent.com/${UPDATE_REPO}/${data.tag_name || 'main'}/ReleaseNote.md`,
    };
    _updateCacheAt = Date.now();
    res.json(_updateCache);
  } catch (err) {
    res.json({ current: pkg.version, latest: null, update_available: false, error: err.message });
  }
});

// --- Settings ---

router.post('/change-password', requireAdmin, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'Both current_password and new_password required' });
  }
  if (new_password.length < 10) {
    return res.status(400).json({ error: 'New password must be at least 10 characters' });
  }

  const storedHash = getSetting('admin_password_hash');
  const valid = await bcrypt.compare(current_password, storedHash);
  if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });

  setSetting('admin_password_hash', await bcrypt.hash(new_password, 12));
  res.json({ ok: true });
});

// --- Helpers ---

function validateService(name, url, interval, timeout) {
  if (!name || typeof name !== 'string' || !name.trim()) return 'Service name required';
  if (!url || typeof url !== 'string' || !url.trim()) return 'URL required';
  if (!isValidUrl(url.trim())) return 'Invalid URL (must be http or https)';
  const iv = parseInt(interval);
  if (!Number.isFinite(iv) || iv < 10 || iv > 86400) return 'check_interval must be 10–86400 seconds';
  const to = parseInt(timeout);
  if (!Number.isFinite(to) || to < 1 || to > 120) return 'timeout must be 1–120 seconds';
  return null;
}

function isValidUrl(s) {
  try {
    const u = new URL(s);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}

function parseId(val) {
  const n = parseInt(val, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

module.exports = router;
