'use strict';
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const dns = require('dns').promises;
const { getEnabledServices, getService, saveCheckResult } = require('./db');

const timers = new Map(); // serviceId -> intervalId

async function doHttpCheck(service, resolvedIp, ipFamily) {
  const url = new URL(service.url);
  const isHttps = url.protocol === 'https:';
  const proto = isHttps ? https : http;
  const port = parseInt(url.port) || (isHttps ? 443 : 80);
  const path = (url.pathname || '/') + (url.search || '');
  const originalHost = url.hostname + (url.port ? `:${url.port}` : '');
  const start = Date.now();

  return new Promise((resolve) => {
    const options = {
      hostname: resolvedIp,
      port,
      path,
      method: 'GET',
      headers: { Host: originalHost, 'User-Agent': 'HealthChecker/1.0' },
      timeout: service.timeout * 1000,
    };

    if (isHttps) {
      // SNI + certificate validated against original hostname, not the resolved IP
      options.servername = url.hostname;
      options.checkServerIdentity = (_host, cert) => tls.checkServerIdentity(url.hostname, cert);
    }

    const req = proto.request(options, (res) => {
      res.resume();
      resolve({
        statusCode: res.statusCode,
        isUp: res.statusCode >= 200 && res.statusCode < 400,
        responseTimeMs: Date.now() - start,
        error: null, resolvedIp, ipFamily,
      });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ statusCode: null, isUp: false, responseTimeMs: Date.now() - start,
        error: `Timeout nach ${service.timeout}s`, resolvedIp, ipFamily });
    });

    req.on('error', (err) => {
      resolve({ statusCode: null, isUp: false, responseTimeMs: Date.now() - start,
        error: err.message, resolvedIp, ipFamily });
    });

    req.end();
  });
}

async function resolveAndCheck(service, family) {
  const url = new URL(service.url);
  const hostname = url.hostname;
  const existingFamily = net.isIP(hostname); // 0 = hostname, 4 = IPv4, 6 = IPv6

  if (existingFamily !== 0) {
    if (family && existingFamily !== family) {
      return { statusCode: null, isUp: false, responseTimeMs: 0,
        error: `Adresse ist IPv${existingFamily}, nicht IPv${family}`, resolvedIp: hostname, ipFamily: existingFamily };
    }
    return doHttpCheck(service, hostname, existingFamily);
  }

  try {
    const result = await dns.lookup(hostname, { family: family || 0, verbatim: true });
    return doHttpCheck(service, result.address, result.family);
  } catch (err) {
    return { statusCode: null, isUp: false, responseTimeMs: 0,
      error: `DNS-Fehler: ${err.message}`, resolvedIp: null, ipFamily: family || null };
  }
}

async function runCheck(serviceId) {
  const service = getService(serviceId);
  if (!service || !service.enabled) return;

  if (service.dual_stack) {
    const [r4, r6] = await Promise.all([
      resolveAndCheck(service, 4),
      resolveAndCheck(service, 6),
    ]);

    saveCheckResult(service.id, r4.statusCode, r4.isUp, r4.responseTimeMs, r4.error, r4.resolvedIp, 4);
    saveCheckResult(service.id, r6.statusCode, r6.isUp, r6.responseTimeMs, r6.error, r6.resolvedIp, 6);

    console.log(`[CHECK] ${service.name} IPv4(${r4.resolvedIp || '?'}) -> ${r4.isUp ? r4.statusCode : r4.error} (${r4.responseTimeMs}ms)`);
    console.log(`[CHECK] ${service.name} IPv6(${r6.resolvedIp || '?'}) -> ${r6.isUp ? r6.statusCode : r6.error} (${r6.responseTimeMs}ms)`);
  } else {
    const r = await resolveAndCheck(service, 0);
    saveCheckResult(service.id, r.statusCode, r.isUp, r.responseTimeMs, r.error, r.resolvedIp, r.ipFamily);
    console.log(`[CHECK] ${service.name}(${r.resolvedIp || '?'}) -> ${r.isUp ? r.statusCode : r.error} (${r.responseTimeMs}ms)`);
  }
}

function scheduleService(service) {
  if (timers.has(service.id)) {
    clearInterval(timers.get(service.id));
    timers.delete(service.id);
  }
  if (!service.enabled) return;

  runCheck(service.id);
  const timer = setInterval(() => runCheck(service.id), service.check_interval * 1000);
  timers.set(service.id, timer);
}

function unscheduleService(serviceId) {
  if (timers.has(serviceId)) {
    clearInterval(timers.get(serviceId));
    timers.delete(serviceId);
  }
}

function startChecker() {
  const services = getEnabledServices();
  for (const s of services) scheduleService(s);
  console.log(`[CHECKER] Started for ${services.length} service(s)`);
}

module.exports = { startChecker, scheduleService, unscheduleService };
