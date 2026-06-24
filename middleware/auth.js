'use strict';
const crypto = require('crypto');
const { getTokenByHash, updateTokenLastUsed, logApiCall } = require('../db');
const { getClientIp } = require('./rateLimit');

function tokenAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';

  if (!authHeader.startsWith('Bearer ')) {
    logApiCall(null, null, req.path, req.method, getClientIp(req), 401);
    return res.status(401).json({ error: 'Missing Authorization header. Use: Bearer <token>' });
  }

  const raw = authHeader.slice(7).trim();

  // Constant-time length check to avoid timing oracle
  if (raw.length < 32 || raw.length > 128) {
    logApiCall(null, null, req.path, req.method, getClientIp(req), 401);
    return res.status(401).json({ error: 'Invalid token format' });
  }

  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const token = getTokenByHash(hash);

  if (!token) {
    // Log with partial prefix for auditing (never log the full raw token)
    logApiCall(null, raw.slice(0, 8), req.path, req.method, getClientIp(req), 403);
    return res.status(403).json({ error: 'Invalid or revoked token' });
  }

  updateTokenLastUsed(token.id);
  req.authToken = token;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.admin) {
    return res.status(401).json({ error: 'Admin session required' });
  }
  next();
}

module.exports = { tokenAuth, requireAdmin };
