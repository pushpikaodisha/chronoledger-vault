/**
 * ChronoLedger REST API Router
 * Dispatches endpoints for notarization, verification, certificates,
 * block timeline, and cryptographic audit checks.
 */

import { NotaryController } from '../controllers/notaryController.js';
import { VerifyController } from '../controllers/verifyController.js';
import { AuditController } from '../controllers/auditController.js';

const notaryCtrl = new NotaryController();
const verifyCtrl = new VerifyController();
const auditCtrl = new AuditController();

/**
 * Helper to send JSON responses
 */
function sendJson(res, statusCode, data, extraHeaders = {}) {
  const payload = JSON.stringify(data, null, 2);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload, 'utf8'),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    ...extraHeaders
  });
  res.end(payload);
}

/**
 * Extract client IP address
 */
function getClientIp(req) {
  return req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
}

/**
 * Main API route dispatcher
 * @param {import('node:http').IncomingMessage} req 
 * @param {import('node:http').ServerResponse} res 
 * @param {string} pathname 
 * @param {URLSearchParams} query 
 * @param {object|null} body 
 */
export async function handleApiRoute(req, res, pathname, query, body) {
  const method = req.method.toUpperCase();
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';

  // Handle CORS Preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400'
    });
    res.end();
    return true;
  }

  // --- STATS & OVERVIEW ---
  if (method === 'GET' && pathname === '/api/stats') {
    const result = await auditCtrl.getOverview();
    sendJson(res, result.status, result.data);
    return true;
  }

  // --- NOTARIZATION ENDPOINTS ---
  if (method === 'POST' && pathname === '/api/notarize') {
    const result = await notaryCtrl.notarize(body);
    sendJson(res, result.status, result.data);
    return true;
  }

  if (method === 'GET' && pathname === '/api/documents') {
    const limit = query.get('limit') || 25;
    const result = await notaryCtrl.getRecentDocuments(limit);
    sendJson(res, result.status, result.data);
    return true;
  }

  // --- CERTIFICATE ENDPOINTS ---
  // Match /api/certificate/:id/download
  const downloadMatch = pathname.match(/^\/api\/certificate\/([^/]+)\/download$/);
  if (method === 'GET' && downloadMatch) {
    const certId = decodeURIComponent(downloadMatch[1]);
    const result = await notaryCtrl.getCertificate(certId);
    if (result.status === 200) {
      sendJson(res, 200, result.data, {
        'Content-Disposition': `attachment; filename="ChronoLedger_Cert_${certId}.json"`
      });
    } else {
      sendJson(res, result.status, result.data);
    }
    return true;
  }

  // Match /api/certificate/:id
  const certMatch = pathname.match(/^\/api\/certificate\/([^/]+)$/);
  if (method === 'GET' && certMatch) {
    const certId = decodeURIComponent(certMatch[1]);
    const result = await notaryCtrl.getCertificate(certId);
    sendJson(res, result.status, result.data);
    return true;
  }

  // --- VERIFICATION ENDPOINTS ---
  if (method === 'POST' && pathname === '/api/verify/hash') {
    const sha256 = body?.sha256;
    const result = await verifyCtrl.verifyHash({ sha256, ip, userAgent });
    sendJson(res, result.status, result.data);
    return true;
  }

  if (method === 'POST' && pathname === '/api/verify/certificate') {
    const certificateObj = body?.certificate || body;
    const result = await verifyCtrl.verifyCertificateFile(certificateObj, ip, userAgent);
    sendJson(res, result.status, result.data);
    return true;
  }

  if (method === 'GET' && pathname === '/api/verify/history') {
    const limit = query.get('limit') || 50;
    const result = await verifyCtrl.getHistory(limit);
    sendJson(res, result.status, result.data);
    return true;
  }

  // --- BLOCKCHAIN & MERKLE BLOCKS ---
  if (method === 'POST' && pathname === '/api/block/seal') {
    const result = await notaryCtrl.sealCurrentBlock();
    sendJson(res, result.status, result.data);
    return true;
  }

  if (method === 'GET' && pathname === '/api/blocks') {
    const result = await auditCtrl.getBlockTimeline();
    sendJson(res, result.status, result.data);
    return true;
  }

  // Match /api/block/:index
  const blockMatch = pathname.match(/^\/api\/block\/(\d+)$/);
  if (method === 'GET' && blockMatch) {
    const index = parseInt(blockMatch[1], 10);
    const result = await auditCtrl.getBlockDetails(index);
    sendJson(res, result.status, result.data);
    return true;
  }

  // --- CRYPTOGRAPHIC AUDIT & TAMPER LAB ---
  if (method === 'GET' && pathname === '/api/audit/verify') {
    const result = await auditCtrl.runDeepAudit();
    sendJson(res, result.status, result.data);
    return true;
  }

  if (method === 'POST' && pathname === '/api/audit/simulate-tamper') {
    const result = await auditCtrl.simulateTamper(body || {});
    sendJson(res, result.status, result.data);
    return true;
  }

  if (method === 'POST' && pathname === '/api/audit/restore') {
    const result = await auditCtrl.restoreLedger();
    sendJson(res, result.status, result.data);
    return true;
  }

  if (method === 'GET' && pathname === '/api/audit/overview') {
    const result = await auditCtrl.getOverview();
    sendJson(res, result.status, result.data);
    return true;
  }

  // If path starts with /api/ but didn't match
  if (pathname.startsWith('/api/')) {
    sendJson(res, 404, { error: `Endpoint '${method} ${pathname}' not found` });
    return true;
  }

  return false;
}

export default handleApiRoute;
