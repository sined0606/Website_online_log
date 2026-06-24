'use strict';

const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 10;

const attempts = new Map(); // ip -> { count, firstAttempt }

// Cleanup stale entries every 30 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of attempts) {
    if (now - rec.firstAttempt > WINDOW_MS) attempts.delete(ip);
  }
}, 30 * 60 * 1000).unref();

function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.ip || 'unknown';
}

function loginRateLimit(req, res, next) {
  const ip = getClientIp(req);
  const now = Date.now();
  const rec = attempts.get(ip);

  if (rec && now - rec.firstAttempt <= WINDOW_MS && rec.count >= MAX_ATTEMPTS) {
    const retryAfter = Math.ceil((WINDOW_MS - (now - rec.firstAttempt)) / 1000);
    res.setHeader('Retry-After', retryAfter);
    return res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
  }

  next();
}

function recordFailedAttempt(ip) {
  const now = Date.now();
  const rec = attempts.get(ip);
  if (!rec || now - rec.firstAttempt > WINDOW_MS) {
    attempts.set(ip, { count: 1, firstAttempt: now });
  } else {
    rec.count++;
  }
}

function clearAttempts(ip) {
  attempts.delete(ip);
}

module.exports = { loginRateLimit, recordFailedAttempt, clearAttempts, getClientIp };
