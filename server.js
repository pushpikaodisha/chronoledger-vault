/**
 * ChronoLedger Cryptographic Notary & Audit Vault
 * Native Node.js 22 HTTP Server
 * Zero external NPM dependencies required.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { handleApiRoute } from './src/routes/api.js';
import { hashDual } from './src/core/hasher.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';

const PUBLIC_DIR = path.resolve(__dirname, 'public');
const VIEWS_DIR = path.resolve(__dirname, 'views');

// MIME type map for static assets
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
  '.txt': 'text/plain; charset=utf-8'
};

/**
 * Robust request body parser (JSON, form-urlencoded, or multipart/raw)
 * @param {http.IncomingMessage} req 
 * @returns {Promise<object>}
 */
function parseRequestBody(req) {
  return new Promise((resolve, reject) => {
    const contentType = req.headers['content-type'] || '';
    const chunks = [];
    let totalBytes = 0;
    const MAX_SIZE = 50 * 1024 * 1024; // 50MB max body

    req.on('data', (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > MAX_SIZE) {
        reject(new Error('Payload Too Large (Exceeds 50MB limit)'));
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      const buffer = Buffer.concat(chunks);
      if (buffer.length === 0) {
        resolve({});
        return;
      }

      // 1. JSON parsing
      if (contentType.includes('application/json')) {
        try {
          const str = buffer.toString('utf8');
          resolve(JSON.parse(str));
        } catch (err) {
          reject(new Error(`Invalid JSON payload: ${err.message}`));
        }
        return;
      }

      // 2. Form URL-Encoded parsing
      if (contentType.includes('application/x-www-form-urlencoded')) {
        try {
          const str = buffer.toString('utf8');
          const params = new URLSearchParams(str);
          const result = {};
          for (const [key, val] of params.entries()) {
            result[key] = val;
          }
          resolve(result);
        } catch (err) {
          reject(err);
        }
        return;
      }

      // 3. Multipart form-data parser (native implementation)
      if (contentType.includes('multipart/form-data')) {
        try {
          const boundaryMatch = contentType.match(/boundary=([^;]+)/i);
          if (!boundaryMatch) {
            resolve({});
            return;
          }
          const boundary = boundaryMatch[1].trim();
          const parsed = parseMultipartBuffer(buffer, boundary);
          resolve(parsed);
        } catch (err) {
          reject(new Error(`Multipart parsing failed: ${err.message}`));
        }
        return;
      }

      // 4. Fallback raw buffer
      resolve({ rawBuffer: buffer });
    });

    req.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Lightweight native multipart parser to handle file drops without external packages
 * @param {Buffer} buffer 
 * @param {string} boundary 
 * @returns {object}
 */
function parseMultipartBuffer(buffer, boundary) {
  const result = { metadata: {} };
  const boundaryBuffer = Buffer.from(`--${boundary}`);
  let startIndex = 0;

  while (true) {
    const nextBoundary = buffer.indexOf(boundaryBuffer, startIndex);
    if (nextBoundary === -1) break;

    if (startIndex > 0) {
      const part = buffer.subarray(startIndex, nextBoundary);
      // Find header/body separator \r\n\r\n
      const headerEnd = part.indexOf(Buffer.from('\r\n\r\n'));
      if (headerEnd !== -1) {
        const headerStr = part.subarray(0, headerEnd).toString('utf8');
        let bodyBuffer = part.subarray(headerEnd + 4);
        // Strip trailing \r\n
        if (bodyBuffer.length >= 2 && bodyBuffer[bodyBuffer.length - 2] === 0x0d && bodyBuffer[bodyBuffer.length - 1] === 0x0a) {
          bodyBuffer = bodyBuffer.subarray(0, bodyBuffer.length - 2);
        }

        const nameMatch = headerStr.match(/name="([^"]+)"/);
        const filenameMatch = headerStr.match(/filename="([^"]+)"/);
        const contentTypeMatch = headerStr.match(/Content-Type:\s*([^\r\n]+)/i);

        if (filenameMatch) {
          const fileName = filenameMatch[1];
          const mimeType = contentTypeMatch ? contentTypeMatch[1] : 'application/octet-stream';
          const hashes = hashDual(bodyBuffer);
          result.fileName = fileName;
          result.fileSize = bodyBuffer.length;
          result.mimeType = mimeType;
          result.sha256 = hashes.sha256;
          result.sha512 = hashes.sha512;
          result.fileContentBase64 = bodyBuffer.toString('base64');
        } else if (nameMatch) {
          const fieldName = nameMatch[1];
          const fieldValue = bodyBuffer.toString('utf8');
          if (fieldName === 'sha256') result.sha256 = fieldValue;
          else if (fieldName === 'sha512') result.sha512 = fieldValue;
          else if (fieldName === 'fileName') result.fileName = fieldValue;
          else if (fieldName === 'title') result.metadata.title = fieldValue;
          else if (fieldName === 'author') result.metadata.author = fieldValue;
          else if (fieldName === 'notes') result.metadata.notes = fieldValue;
          else result[fieldName] = fieldValue;
        }
      }
    }

    startIndex = nextBoundary + boundaryBuffer.length;
  }

  return result;
}

/**
 * Serve static files from public directory
 * @param {string} filePath 
 * @param {http.ServerResponse} res 
 */
function serveStaticFile(filePath, res) {
  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': stats.size,
      'Cache-Control': 'public, max-age=3600',
      'X-Content-Type-Options': 'nosniff'
    });

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  });
}

/**
 * Primary HTTP Server
 */
const server = http.createServer(async (req, res) => {
  // Common security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  try {
    const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;
    const query = parsedUrl.searchParams;

    // 1. API Route Handler
    if (pathname.startsWith('/api/')) {
      let body = {};
      if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
        body = await parseRequestBody(req);
      }
      const handled = await handleApiRoute(req, res, pathname, query, body);
      if (handled) return;
    }

    // 2. HTML Views Routing
    if (pathname === '/' || pathname === '/index.html') {
      serveStaticFile(path.join(VIEWS_DIR, 'index.html'), res);
      return;
    }

    if (pathname === '/verify' || pathname === '/verify.html') {
      serveStaticFile(path.join(VIEWS_DIR, 'verify.html'), res);
      return;
    }

    if (pathname === '/audit' || pathname === '/audit.html') {
      serveStaticFile(path.join(VIEWS_DIR, 'audit.html'), res);
      return;
    }

    // 3. Static Assets in /public
    let relativeStaticPath = pathname;
    if (relativeStaticPath.startsWith('/public/')) {
      relativeStaticPath = relativeStaticPath.substring(7);
    }

    const safeFilePath = path.normalize(path.join(PUBLIC_DIR, relativeStaticPath));

    // Security check to prevent path traversal
    if (safeFilePath.startsWith(PUBLIC_DIR) && fs.existsSync(safeFilePath) && fs.statSync(safeFilePath).isFile()) {
      serveStaticFile(safeFilePath, res);
      return;
    }

    // 4. Not Found
    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>404 Not Found - ChronoLedger Vault</title>
        <link rel="stylesheet" href="/css/vault.css">
      </head>
      <body class="center-content">
        <div class="card error-card text-center" style="max-width: 500px; margin: 80px auto;">
          <h1 class="accent-danger" style="font-size: 3rem; margin-bottom: 0.5rem;">404</h1>
          <h2>Cryptographic Route Not Found</h2>
          <p style="color: var(--text-muted); margin: 1.5rem 0;">The requested path does not map to any active vault service or static resource.</p>
          <a href="/" class="btn btn-primary">&larr; Return to Notary Vault</a>
        </div>
      </body>
      </html>
    `);
  } catch (err) {
    console.error('Server Internal Error:', err);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Internal Server Error', message: err.message }));
  }
});

// Start Server
server.listen(PORT, HOST, () => {
  console.log(`
  ==============================================================
   CHRONOLEDGER CRYPTOGRAPHIC NOTARY & AUDIT VAULT (NODE 22)
  ==============================================================
   [✓] Native Cryptographic Engine Active (RFC 6962 / Ed25519)
   [✓] Merkle Tree Block Chaining Engine Ready
   [✓] Local HTTP Gateway: http://${HOST}:${PORT}
   [✓] Native Runtime: Node.js ${process.version} (Zero NPM deps)
  ==============================================================
  `);
});

// Graceful termination
process.on('SIGINT', () => {
  console.log('\nShutting down ChronoLedger Vault...');
  server.close(() => {
    console.log('ChronoLedger Vault terminated gracefully.');
    process.exit(0);
  });
});
