/**
 * End-to-End System Integration Test
 * Verifies HTTP server, API endpoints, static assets, notarization,
 * verification, block sealing, and audit tamper detection.
 */

import http from 'node:http';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

const TEST_PORT = 3456;

function request(url, options = {}, body = null) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const reqOptions = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: options.headers || {}
    };

    const req = http.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(data); } catch (e) {}
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data,
          json
        });
      });
    });

    req.on('error', reject);

    if (body) {
      if (typeof body === 'object') {
        req.setHeader('Content-Type', 'application/json');
        req.write(JSON.stringify(body));
      } else {
        req.write(body);
      }
    }
    req.end();
  });
}

async function runTests() {
  console.log('--- Launching ChronoLedger Vault Test Server on port', TEST_PORT, '---');

  const serverProc = spawn('node', ['server.js'], {
    cwd: projectRoot,
    env: { ...process.env, PORT: TEST_PORT.toString() },
    stdio: 'pipe'
  });

  serverProc.stdout.on('data', d => process.stdout.write('[SERVER]: ' + d.toString()));
  serverProc.stderr.on('data', d => process.stderr.write('[SERVER ERR]: ' + d.toString()));

  // Wait 1.5s for server to start
  await new Promise(r => setTimeout(r, 1500));

  try {
    const baseUrl = `http://127.0.0.1:${TEST_PORT}`;

    // 1. Test HTML routes
    console.log('\n[TEST 1] Fetching HTML views...');
    const indexRes = await request(`${baseUrl}/`);
    console.log('Index HTML status:', indexRes.statusCode, 'Contains ChronoLedger?', indexRes.body.includes('ChronoLedger'));
    if (indexRes.statusCode !== 200) throw new Error('Index view failed');

    const verifyRes = await request(`${baseUrl}/verify`);
    console.log('Verify HTML status:', verifyRes.statusCode);
    if (verifyRes.statusCode !== 200) throw new Error('Verify view failed');

    const auditRes = await request(`${baseUrl}/audit`);
    console.log('Audit HTML status:', auditRes.statusCode);
    if (auditRes.statusCode !== 200) throw new Error('Audit view failed');

    // 2. Test Static CSS & JS
    console.log('\n[TEST 2] Fetching Static Assets...');
    const cssRes = await request(`${baseUrl}/css/vault.css`);
    console.log('Vault CSS status:', cssRes.statusCode, 'MIME:', cssRes.headers['content-type']);
    if (cssRes.statusCode !== 200) throw new Error('CSS static serve failed');

    const jsRes = await request(`${baseUrl}/js/vault-app.js`);
    console.log('Vault App JS status:', jsRes.statusCode, 'MIME:', jsRes.headers['content-type']);
    if (jsRes.statusCode !== 200) throw new Error('JS static serve failed');

    // 3. Test Stats API
    console.log('\n[TEST 3] Testing /api/stats...');
    const statsRes = await request(`${baseUrl}/api/stats`);
    console.log('Stats status:', statsRes.statusCode, 'Height:', statsRes.json?.currentHeight);
    if (statsRes.statusCode !== 200) throw new Error('Stats API failed');

    // 4. Test Notarization Endpoint
    console.log('\n[TEST 4] Testing /api/notarize (Zero-Knowledge Mode)...');
    const testDocHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; // sha256 of empty string
    const notRes = await request(`${baseUrl}/api/notarize`, { method: 'POST' }, {
      sha256: testDocHash,
      fileName: 'Genesis_Test_Document.pdf',
      fileSize: 2048,
      mimeType: 'application/pdf',
      metadata: {
        title: 'Master Service Agreement 2026',
        author: 'Lead Architect',
        jurisdiction: 'Singapore'
      }
    });

    console.log('Notarize status:', notRes.statusCode, 'Cert ID:', notRes.json?.certificate?.certificateId);
    if (notRes.statusCode !== 201) throw new Error('Notarization failed: ' + notRes.body);
    const certId = notRes.json.certificate.certificateId;

    // 5. Test Verification Endpoint by Hash
    console.log('\n[TEST 5] Testing /api/verify/hash...');
    const verifyHashRes = await request(`${baseUrl}/api/verify/hash`, { method: 'POST' }, {
      sha256: testDocHash
    });
    console.log('Verify Hash Status:', verifyHashRes.statusCode, 'Verified?', verifyHashRes.json?.verified, 'Root:', verifyHashRes.json?.cryptographicProof?.rootHash);
    if (!verifyHashRes.json?.verified) throw new Error('Verification of notarized hash failed!');

    // 6. Test Verification with Unregistered/Tampered Hash
    console.log('\n[TEST 6] Testing verification of fake/tampered hash...');
    const fakeHash = '1111111111111111111111111111111111111111111111111111111111111111';
    const fakeRes = await request(`${baseUrl}/api/verify/hash`, { method: 'POST' }, {
      sha256: fakeHash
    });
    console.log('Fake hash verified?', fakeRes.json?.verified, 'Message:', fakeRes.json?.message);
    if (fakeRes.json?.verified === true) throw new Error('Fake hash was erroneously accepted!');

    // 7. Test Certificate Download
    console.log('\n[TEST 7] Testing Certificate Download /api/certificate/:id/download...');
    const downloadRes = await request(`${baseUrl}/api/certificate/${certId}/download`);
    console.log('Download status:', downloadRes.statusCode, 'Header:', downloadRes.headers['content-disposition']);
    if (downloadRes.statusCode !== 200 || !downloadRes.headers['content-disposition']) {
      throw new Error('Certificate download failed');
    }

    // 8. Test Deep Cryptographic Audit
    console.log('\n[TEST 8] Testing /api/audit/verify...');
    const auditRunRes = await request(`${baseUrl}/api/audit/verify`);
    console.log('Deep Audit status:', auditRunRes.statusCode, 'Intact?', auditRunRes.json?.intact, 'Audited Blocks:', auditRunRes.json?.totalBlocksAudited);
    if (!auditRunRes.json?.intact) throw new Error('Pristine deep audit failed!');

    // 9. Test Tamper Simulation & Alarm
    console.log('\n[TEST 9] Testing /api/audit/simulate-tamper...');
    const tamperRes = await request(`${baseUrl}/api/audit/simulate-tamper`, { method: 'POST' }, { field: 'sha256' });
    console.log('Simulate Tamper status:', tamperRes.statusCode, 'Message:', tamperRes.json?.message);

    const postTamperAudit = await request(`${baseUrl}/api/audit/verify`);
    console.log('Post-Tamper Audit Intact?', postTamperAudit.json?.intact, 'Detected Errors:', postTamperAudit.json?.errorsCount);
    if (postTamperAudit.json?.intact !== false) throw new Error('Tamper simulation failed to trigger alarm!');

    // 10. Restore Ledger
    console.log('\n[TEST 10] Testing /api/audit/restore...');
    const restoreRes = await request(`${baseUrl}/api/audit/restore`, { method: 'POST' });
    console.log('Restore status:', restoreRes.statusCode, 'Restored?', restoreRes.json?.restored);

    const postRestoreAudit = await request(`${baseUrl}/api/audit/verify`);
    console.log('Post-Restore Audit Intact?', postRestoreAudit.json?.intact);
    if (!postRestoreAudit.json?.intact) throw new Error('Restoration failed to return ledger to intact state!');

    console.log('\n======================================================');
    console.log(' >>> ALL 10 END-TO-END INTEGRATION TESTS PASSED! <<<');
    console.log('======================================================');
  } finally {
    serverProc.kill('SIGINT');
  }
}

runTests().catch(err => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});
