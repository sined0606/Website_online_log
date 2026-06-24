'use strict';
const express = require('express');
const router = express.Router();
const { tokenAuth } = require('../middleware/auth');
const { getClientIp } = require('../middleware/rateLimit');
const {
  getServicesForToken, getLatestCheckResult, getLatestResultPerFamily,
  getCheckHistory, logApiCall,
} = require('../db');

function withLog(handler) {
  return async (req, res, next) => {
    res.on('finish', () => {
      if (req.authToken) {
        logApiCall(req.authToken.id, req.authToken.token_prefix,
          req.path, req.method, getClientIp(req), res.statusCode);
      }
    });
    try { await handler(req, res, next); } catch (err) { next(err); }
  };
}

function formatResult(r) {
  if (!r) return null;
  return {
    status_code: r.status_code,
    is_up: !!r.is_up,
    response_time_ms: r.response_time_ms,
    resolved_ip: r.resolved_ip || null,
    ip_family: r.ip_family || null,
    error: r.error_message || null,
    checked_at: r.checked_at,
  };
}

function buildServiceEntry(s) {
  const isDual = !!s.dual_stack;

  if (isDual) {
    const results = getLatestResultPerFamily(s.id);
    const v4 = formatResult(results.find(r => r.ip_family === 4) || null);
    const v6 = formatResult(results.find(r => r.ip_family === 6) || null);

    let status = 'unknown';
    const up4 = v4?.is_up, up6 = v6?.is_up;
    if (up4 && up6) status = 'up';
    else if (up4 || up6) status = 'partial';
    else if (v4 !== null || v6 !== null) status = 'down';

    return {
      id: s.id, name: s.name, url: s.url,
      check_interval: s.check_interval, enabled: !!s.enabled,
      dual_stack: true, status,
      last_check_v4: v4,
      last_check_v6: v6,
    };
  }

  const latest = getLatestCheckResult(s.id);
  return {
    id: s.id, name: s.name, url: s.url,
    check_interval: s.check_interval, enabled: !!s.enabled,
    dual_stack: false,
    status: latest ? (latest.is_up ? 'up' : 'down') : 'unknown',
    last_check: formatResult(latest),
  };
}

// GET /api/all
router.get('/all', tokenAuth, withLog((req, res) => {
  const services = getServicesForToken(req.authToken.id, req.authToken.scope);
  res.json({ services: services.map(buildServiceEntry) });
}));

// GET /api/status/:id
router.get('/status/:id', tokenAuth, withLog((req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid service ID' });

  const services = getServicesForToken(req.authToken.id, req.authToken.scope);
  const service = services.find(s => s.id === id);
  if (!service) return res.status(404).json({ error: 'Service not found or access denied' });

  res.json(buildServiceEntry(service));
}));

// GET /api/history/:id?limit=100
router.get('/history/:id', tokenAuth, withLog((req, res) => {
  const id = parseId(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid service ID' });

  const services = getServicesForToken(req.authToken.id, req.authToken.scope);
  if (!services.find(s => s.id === id)) return res.status(404).json({ error: 'Service not found or access denied' });

  const limit = Math.min(Math.max(parseInt(req.query.limit) || 100, 1), 1000);
  const history = getCheckHistory(id, limit).map(r => ({ ...r, is_up: !!r.is_up }));
  res.json({ service_id: id, history });
}));

function parseId(val) {
  const n = parseInt(val, 10);
  return Number.isFinite(n) && n > 0 ? n : null;
}

module.exports = router;
