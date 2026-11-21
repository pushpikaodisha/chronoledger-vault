/**
 * ChronoLedger Core Cryptographic Hasher
 * Native Node.js 22 crypto module implementation
 * Provides streaming SHA-256 / SHA-512, RFC 6962 prefixing, and Canonical JSON hashing
 */

import crypto from 'node:crypto';
import { Readable } from 'node:stream';

/**
 * Hash a string or buffer with specified algorithm
 * @param {string|Buffer} input 
 * @param {string} algorithm 'sha256' | 'sha512'
 * @returns {string} Hex encoded hash
 */
export function hashData(input, algorithm = 'sha256') {
  return crypto.createHash(algorithm).update(input).digest('hex');
}

/**
 * Hash a UTF-8 string
 * @param {string} str 
 * @param {string} algorithm 
 * @returns {string} Hex hash
 */
export function hashString(str, algorithm = 'sha256') {
  return crypto.createHash(algorithm).update(String(str), 'utf8').digest('hex');
}

/**
 * Hash a Buffer
 * @param {Buffer} buffer 
 * @param {string} algorithm 
 * @returns {string} Hex hash
 */
export function hashBuffer(buffer, algorithm = 'sha256') {
  if (!Buffer.isBuffer(buffer)) {
    buffer = Buffer.from(buffer);
  }
  return crypto.createHash(algorithm).update(buffer).digest('hex');
}

/**
 * Streaming multi-hash calculation for files and Readable streams.
 * Computes both SHA-256 and SHA-512 simultaneously in a single stream pass.
 * @param {Readable|AsyncIterable<Buffer>} stream 
 * @returns {Promise<{ sha256: string, sha512: string, bytesRead: number }>}
 */
export async function hashStream(stream) {
  return new Promise((resolve, reject) => {
    const sha256Hasher = crypto.createHash('sha256');
    const sha512Hasher = crypto.createHash('sha512');
    let bytesRead = 0;

    stream.on('data', (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytesRead += buffer.length;
      sha256Hasher.update(buffer);
      sha512Hasher.update(buffer);
    });

    stream.on('end', () => {
      resolve({
        sha256: sha256Hasher.digest('hex'),
        sha512: sha512Hasher.digest('hex'),
        bytesRead
      });
    });

    stream.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Compute dual hashes (SHA-256 and SHA-512) for a Buffer or string
 * @param {Buffer|string} input 
 * @returns {{ sha256: string, sha512: string, bytes: number }}
 */
export function hashDual(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return {
    sha256: crypto.createHash('sha256').update(buffer).digest('hex'),
    sha512: crypto.createHash('sha512').update(buffer).digest('hex'),
    bytes: buffer.length
  };
}

/**
 * RFC 6962 Leaf Hash computation
 * Prepends a 0x00 single byte to the raw leaf data/hash to mitigate second-preimage attacks
 * @param {string|Buffer} dataHexOrBuffer 
 * @returns {string} Hex encoded leaf hash
 */
export function hashLeaf(dataHexOrBuffer) {
  const leafData = Buffer.isBuffer(dataHexOrBuffer)
    ? dataHexOrBuffer
    : Buffer.from(dataHexOrBuffer, /^[0-9a-fA-F]+$/.test(dataHexOrBuffer) ? 'hex' : 'utf8');

  const prefix = Buffer.from([0x00]);
  return crypto.createHash('sha256')
    .update(prefix)
    .update(leafData)
    .digest('hex');
}

/**
 * RFC 6962 Interior Node Hash computation
 * Prepends a 0x01 single byte before concatenating two child node hashes
 * @param {string} leftHex 64-char hex
 * @param {string} rightHex 64-char hex
 * @returns {string} Hex encoded parent hash
 */
export function hashInterior(leftHex, rightHex) {
  const prefix = Buffer.from([0x01]);
  const leftBuf = Buffer.from(leftHex, 'hex');
  const rightBuf = Buffer.from(rightHex, 'hex');

  return crypto.createHash('sha256')
    .update(prefix)
    .update(leftBuf)
    .update(rightBuf)
    .digest('hex');
}

/**
 * Deterministically stringifies any JavaScript object by sorting keys recursively (RFC 8785 principles)
 * Ensures digital signatures and block hashes are invariant regardless of property insertion order
 * @param {any} obj 
 * @returns {string} Canonical JSON string
 */
export function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalJsonStringify(item)).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  const pairs = sortedKeys.map(key => {
    return JSON.stringify(key) + ':' + canonicalJsonStringify(obj[key]);
  });
  return '{' + pairs.join(',') + '}';
}

/**
 * Compute SHA-256 hash of canonical JSON representation of an object
 * @param {object} obj 
 * @returns {string} Hex hash
 */
export function hashCanonicalJson(obj) {
  const canonical = canonicalJsonStringify(obj);
  return hashString(canonical, 'sha256');
}

/**
 * Constant-time comparison of two hex hashes to prevent timing attacks
 * @param {string} hexA 
 * @param {string} hexB 
 * @returns {boolean}
 */
export function timingSafeHashEqual(hexA, hexB) {
  if (typeof hexA !== 'string' || typeof hexB !== 'string') return false;
  if (hexA.length !== hexB.length) return false;
  const bufA = Buffer.from(hexA, 'hex');
  const bufB = Buffer.from(hexB, 'hex');
  return crypto.timingSafeEqual(bufA, bufB);
}

export default {
  hashData,
  hashString,
  hashBuffer,
  hashStream,
  hashDual,
  hashLeaf,
  hashInterior,
  canonicalJsonStringify,
  hashCanonicalJson,
  timingSafeHashEqual
};
