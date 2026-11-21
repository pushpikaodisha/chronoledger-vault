/**
 * ChronoLedger Notary Controller
 * Handles document notarization requests, cryptographic certificate issuing,
 * certificate retrieval, and manual block sealing.
 */

import { getLedgerDb } from '../db/ledgerDb.js';
import { hashDual, hashString } from '../core/hasher.js';

export class NotaryController {
  constructor() {
    this.db = getLedgerDb();
  }

  /**
   * Notarize a document
   * Accepts both pre-hashed payloads (Zero-Knowledge Privacy mode) and raw content/file uploads
   * @param {object} body Parsed request body
   * @returns {object} Response payload
   */
  async notarize(body) {
    if (!body) {
      return { status: 400, data: { error: 'Request payload is required' } };
    }

    let {
      sha256,
      sha512,
      fileName,
      fileSize,
      mimeType,
      fileContentBase64,
      rawText,
      metadata = {}
    } = body;

    // If raw text or base64 file content was provided and no hash, compute hashes server-side
    if (!sha256) {
      if (fileContentBase64) {
        const buffer = Buffer.from(fileContentBase64, 'base64');
        const hashes = hashDual(buffer);
        sha256 = hashes.sha256;
        sha512 = hashes.sha512;
        fileSize = buffer.length;
      } else if (rawText) {
        const hashes = hashDual(rawText);
        sha256 = hashes.sha256;
        sha512 = hashes.sha512;
        fileSize = Buffer.byteLength(rawText, 'utf8');
      } else {
        return {
          status: 400,
          data: { error: 'Missing SHA-256 hash or document content to notarize' }
        };
      }
    }

    // Validate SHA-256 format (64-char hex)
    sha256 = String(sha256).trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(sha256)) {
      return {
        status: 400,
        data: { error: 'Invalid SHA-256 format. Must be a 64-character hexadecimal string.' }
      };
    }

    // Sanitize metadata
    const cleanMetadata = {
      title: metadata.title || fileName || 'Untitled Record',
      author: metadata.author || 'Anonymous Signer',
      organization: metadata.organization || 'Independent',
      jurisdiction: metadata.jurisdiction || 'Global ChronoLedger Cryptographic Vault',
      notes: metadata.notes || '',
      tags: Array.isArray(metadata.tags) ? metadata.tags : (metadata.tags ? String(metadata.tags).split(',').map(s => s.trim()) : [])
    };

    const docRecord = {
      fileName: fileName || `notarized_doc_${sha256.slice(0, 8)}.bin`,
      fileSize: Number(fileSize) || 0,
      mimeType: mimeType || 'application/octet-stream',
      sha256,
      sha512: sha512 || null,
      metadata: cleanMetadata
    };

    try {
      const result = this.db.addDocument(docRecord);
      return {
        status: 201,
        data: {
          success: true,
          isDuplicate: result.isDuplicate,
          message: result.isDuplicate
            ? 'Document already anchored in ChronoLedger Vault. Returning existing immutable certificate.'
            : 'Document successfully notarized and anchored into Merkle block.',
          transaction: result.transaction,
          certificate: result.certificate
        }
      };
    } catch (err) {
      return {
        status: 500,
        data: { error: `Notarization failed: ${err.message}` }
      };
    }
  }

  /**
   * Get certificate by Certificate ID or Document Hash
   * @param {string} idOrHash 
   */
  async getCertificate(idOrHash) {
    if (!idOrHash) {
      return { status: 400, data: { error: 'Certificate ID or hash parameter is required' } };
    }

    // Search by Certificate ID first
    let cert = this.db.findCertificate(idOrHash);

    // If not found, search by Document SHA-256
    if (!cert) {
      const doc = this.db.findDocumentByHash(idOrHash);
      if (doc && doc.certificate) {
        cert = doc.certificate;
      }
    }

    if (!cert) {
      return {
        status: 404,
        data: { error: `No certificate found matching identifier '${idOrHash}'` }
      };
    }

    return {
      status: 200,
      data: cert
    };
  }

  /**
   * Get recent notarized documents list
   * @param {number} limit 
   */
  async getRecentDocuments(limit = 25) {
    const documents = this.db.getRecentDocuments(Number(limit) || 25);
    return {
      status: 200,
      data: {
        count: documents.length,
        documents
      }
    };
  }

  /**
   * Seal the current active block into the immutable chain
   */
  async sealCurrentBlock() {
    const sealed = this.db.sealCurrentBlock();
    if (!sealed) {
      return {
        status: 400,
        data: { error: 'Active block is empty. Nothing to seal.' }
      };
    }

    return {
      status: 200,
      data: {
        success: true,
        message: `Block #${sealed.index} successfully sealed with Merkle Root: ${sealed.merkleRoot}`,
        sealedBlock: sealed
      }
    };
  }
}

export default NotaryController;
