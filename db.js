'use strict';
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new DatabaseSync(path.join(dataDir, 'health-checker.db'));

db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS services (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      check_interval INTEGER DEFAULT 60,
      timeout INTEGER DEFAULT 10,
      enabled INTEGER DEFAULT 1,
      dual_stack INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS check_results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      service_id INTEGER NOT NULL,
      status_code INTEGER,
      is_up INTEGER NOT NULL,
      response_time_ms INTEGER,
      error_message TEXT,
      resolved_ip TEXT,
      ip_family INTEGER,
      checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      token_prefix TEXT NOT NULL,
      scope TEXT DEFAULT 'restricted',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_used DATETIME,
      active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS token_permissions (
      token_id INTEGER NOT NULL,
      service_id INTEGER NOT NULL,
      PRIMARY KEY (token_id, service_id),
      FOREIGN KEY (token_id) REFERENCES tokens(id) ON DELETE CASCADE,
      FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS api_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_id INTEGER,
      token_prefix TEXT,
      endpoint TEXT NOT NULL,
      method TEXT NOT NULL,
      ip TEXT,
      status_code INTEGER,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_check_results_service ON check_results(service_id, checked_at);
    CREATE INDEX IF NOT EXISTS idx_api_logs_ts ON api_logs(timestamp);
  `);

  // Migrations for existing databases
  for (const sql of [
    'ALTER TABLE services ADD COLUMN dual_stack INTEGER DEFAULT 0',
    'ALTER TABLE check_results ADD COLUMN resolved_ip TEXT',
    'ALTER TABLE check_results ADD COLUMN ip_family INTEGER',
  ]) {
    try { db.exec(sql); } catch (_e) { /* column already exists */ }
  }
}

// ---- Services ----

function getServices() {
  return db.prepare('SELECT * FROM services ORDER BY name').all();
}

function getEnabledServices() {
  return db.prepare('SELECT * FROM services WHERE enabled = 1').all();
}

function getService(id) {
  return db.prepare('SELECT * FROM services WHERE id = ?').get(id);
}

function createService(name, url, checkInterval, timeout, dualStack = false) {
  return db.prepare(
    'INSERT INTO services (name, url, check_interval, timeout, dual_stack) VALUES (?, ?, ?, ?, ?)'
  ).run(name, url, checkInterval, timeout, dualStack ? 1 : 0);
}

function updateService(id, name, url, checkInterval, timeout, enabled, dualStack = false) {
  return db.prepare(
    'UPDATE services SET name=?, url=?, check_interval=?, timeout=?, enabled=?, dual_stack=? WHERE id=?'
  ).run(name, url, checkInterval, timeout, enabled ? 1 : 0, dualStack ? 1 : 0, id);
}

function deleteService(id) {
  return db.prepare('DELETE FROM services WHERE id = ?').run(id);
}

// ---- Check results ----

function saveCheckResult(serviceId, statusCode, isUp, responseTimeMs, errorMessage, resolvedIp = null, ipFamily = null) {
  db.prepare(
    'INSERT INTO check_results (service_id, status_code, is_up, response_time_ms, error_message, resolved_ip, ip_family) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(serviceId, statusCode ?? null, isUp ? 1 : 0, responseTimeMs ?? null, errorMessage ?? null, resolvedIp ?? null, ipFamily ?? null);

  db.prepare(`
    DELETE FROM check_results WHERE service_id = ? AND id NOT IN (
      SELECT id FROM check_results WHERE service_id = ? ORDER BY checked_at DESC LIMIT 1000
    )
  `).run(serviceId, serviceId);
}

function getLatestCheckResult(serviceId) {
  return db.prepare(
    'SELECT * FROM check_results WHERE service_id = ? ORDER BY checked_at DESC LIMIT 1'
  ).get(serviceId);
}

// Returns the latest result per ip_family (1–2 rows for dual-stack, 1 for single)
function getLatestResultPerFamily(serviceId) {
  return db.prepare(`
    SELECT cr.* FROM check_results cr
    INNER JOIN (
      SELECT ip_family, MAX(id) AS max_id FROM check_results WHERE service_id = ? GROUP BY ip_family
    ) latest ON cr.id = latest.max_id
    ORDER BY cr.ip_family
  `).all(serviceId);
}

function getCheckHistory(serviceId, limit = 50) {
  return db.prepare(
    'SELECT * FROM check_results WHERE service_id = ? ORDER BY checked_at DESC LIMIT ?'
  ).all(serviceId, limit);
}

// ---- Tokens ----

function getTokens() {
  return db.prepare(
    'SELECT id, name, token_prefix, scope, created_at, last_used, active FROM tokens ORDER BY created_at DESC'
  ).all();
}

function getToken(id) {
  return db.prepare(
    'SELECT id, name, token_prefix, scope, created_at, last_used, active FROM tokens WHERE id = ?'
  ).get(id);
}

function createToken(name, tokenHash, tokenPrefix, scope) {
  return db.prepare(
    'INSERT INTO tokens (name, token_hash, token_prefix, scope) VALUES (?, ?, ?, ?)'
  ).run(name, tokenHash, tokenPrefix, scope);
}

function getTokenByHash(hash) {
  return db.prepare('SELECT * FROM tokens WHERE token_hash = ? AND active = 1').get(hash);
}

function updateTokenLastUsed(id) {
  db.prepare('UPDATE tokens SET last_used = CURRENT_TIMESTAMP WHERE id = ?').run(id);
}

function updateTokenScope(id, scope) {
  return db.prepare('UPDATE tokens SET scope = ? WHERE id = ?').run(scope, id);
}

function deleteToken(id) {
  return db.prepare('DELETE FROM tokens WHERE id = ?').run(id);
}

// ---- Token permissions ----

function getTokenPermissions(tokenId) {
  return db.prepare('SELECT service_id FROM token_permissions WHERE token_id = ?')
    .all(tokenId).map(r => r.service_id);
}

function setTokenPermissions(tokenId, serviceIds) {
  db.exec('BEGIN');
  try {
    db.prepare('DELETE FROM token_permissions WHERE token_id = ?').run(tokenId);
    const insert = db.prepare(
      'INSERT OR IGNORE INTO token_permissions (token_id, service_id) VALUES (?, ?)'
    );
    for (const sid of serviceIds) {
      insert.run(tokenId, sid);
    }
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
}

function getServicesForToken(tokenId, scope) {
  if (scope === 'all') {
    return db.prepare('SELECT * FROM services ORDER BY name').all();
  }
  return db.prepare(`
    SELECT s.* FROM services s
    INNER JOIN token_permissions tp ON s.id = tp.service_id
    WHERE tp.token_id = ?
    ORDER BY s.name
  `).all(tokenId);
}

// ---- API logs ----

function logApiCall(tokenId, tokenPrefix, endpoint, method, ip, statusCode) {
  db.prepare(
    'INSERT INTO api_logs (token_id, token_prefix, endpoint, method, ip, status_code) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(tokenId ?? null, tokenPrefix ?? null, endpoint, method, ip ?? null, statusCode);

  db.prepare(`
    DELETE FROM api_logs WHERE id NOT IN (
      SELECT id FROM api_logs ORDER BY timestamp DESC LIMIT 10000
    )
  `).run();
}

function getApiLogs(limit = 100, offset = 0) {
  return db.prepare('SELECT * FROM api_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?').all(limit, offset);
}

function countApiLogs() {
  return db.prepare('SELECT COUNT(*) as count FROM api_logs').get().count;
}

// ---- Settings ----

function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}

function setSetting(key, value) {
  db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').run(key, value);
}

function getServiceByUrl(url) {
  return db.prepare('SELECT id FROM services WHERE url = ?').get(url);
}

module.exports = {
  initDb,
  getServices, getEnabledServices, getService, getServiceByUrl,
  createService, updateService, deleteService,
  saveCheckResult, getLatestCheckResult, getLatestResultPerFamily, getCheckHistory,
  getTokens, getToken, createToken, getTokenByHash,
  updateTokenLastUsed, updateTokenScope, deleteToken,
  getTokenPermissions, setTokenPermissions, getServicesForToken,
  logApiCall, getApiLogs, countApiLogs,
  getSetting, setSetting,
};
