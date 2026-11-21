/**
 * ChronoLedger Verification Controller
 * Handles drag-and-drop instant proof validation, zero-knowledge hash verification,
 * and standalone certificate verification.
 */

import { getLedgerDb } from '../db/ledgerDb.js';
import { MerkleTree } from '../core/merkleTree.js';
import { CertSigner } from '../core/certSigner.js';

export class VerifyController {
  constructor() {
    this.db = getLedgerDb();
    this.signer = this.db.signer;
  }

  /**
   * Verify document by SHA-256 hash (Zero-Knowledge: file content not needed)
   * @param {object} params
   * @param {string} params.sha256 
   * @param {string} [params.ip]
   * @param {string} [params.userAgent]
   */
  async verifyHash({ sha256, ip = '127.0.0.1', userAgent = '' }) {
    const startTime = Date.now();

    if (!sha256) {
      return {
        status: 400,
        data: { verified: false, error: 'SHA-256 hash parameter is required' }
      };
    }

    const cleanHash = String(sha256).trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(cleanHash)) {
      return {
        status: 400,
        data: { verified: false, error: 'Invalid SHA-256 format. Must be 64 hexadecimal characters.' }
      };
    }

    // Lookup in ledger index
    const document = this.db.findDocumentByHash(cleanHash);

    if (!document) {
      const durationMs = Date.now() - startTime;
      this.db.logVerification({
        sha256: cleanHash,
        result: false,
        method: 'hash_lookup',
        ip,
        userAgent,
        durationMs,
        document: null
      });

      return {
        status: 200,
        data: {
          verified: false,
          sha256: cleanHash,
          timestamp: new Date().toISOString(),
          message: 'NOT FOUND: No cryptographic notary anchor matching this hash exists in ChronoLedger Vault.',
          recommendation: 'The document may be altered, modified by a single byte, or was never notarized.'
        }
      };
    }

    // Document found! Now perform real-time cryptographic validation of its Merkle Proof & Signature
    const cert = document.certificate;
    let merkleAudit = null;
    let signatureValid = false;
    let blockValid = false;
    let blockData = null;

    if (cert && cert.merkleProof) {
      merkleAudit = MerkleTree.verifyProofAudit(
        cleanHash,
        cert.merkleProof.proof,
        cert.merkleProof.rootHash
      );
    }

    if (cert) {
      const sigCheck = this.signer.verifyCertificate(cert);
      signatureValid = sigCheck.signatureValid;
    }

    // Verify block in chain
    const allBlocks = this.db.getAllBlocks();
    blockData = allBlocks.find(b => b.index === document.blockNumber);
    if (blockData) {
      blockValid = true;
    }

    const durationMs = Date.now() - startTime;
    const isFullyAuthentic = (merkleAudit ? merkleAudit.valid : false) && signatureValid;

    // Log the successful verification event
    this.db.logVerification({
      sha256: cleanHash,
      result: isFullyAuthentic,
      method: 'merkle_proof_verification',
      ip,
      userAgent,
      durationMs,
      document
    });

    return {
      status: 200,
      data: {
        verified: isFullyAuthentic,
        status: isFullyAuthentic ? 'VERIFIED_AUTHENTIC' : 'CRYPTOGRAPHIC_MISMATCH',
        verificationTimestamp: new Date().toISOString(),
        durationMs,
        document: {
          id: document.id,
          fileName: document.fileName,
          fileSize: document.fileSize,
          mimeType: document.mimeType,
          sha256: document.sha256,
          sha512: document.sha512,
          notarizedAt: document.timestamp,
          blockNumber: document.blockNumber,
          leafIndex: document.leafIndex,
          metadata: document.metadata
        },
        cryptographicProof: {
          merkleProofValid: merkleAudit ? merkleAudit.valid : false,
          rootHash: cert?.merkleProof?.rootHash,
          leafHash: merkleAudit?.initialLeafHash,
          proofStepsCount: cert?.merkleProof?.proof?.length || 0,
          signatureValid,
          notaryAuthority: cert?.authority?.name || 'ChronoLedger Vault',
          notaryKeyFingerprint: cert?.authority?.keyFingerprint,
          blockSealed: blockData?.sealed ?? false,
          blockHash: blockData?.blockHash,
          previousBlockHash: blockData?.previousHash,
          stepByStepTrajectory: merkleAudit ? merkleAudit.steps : []
        },
        certificate: cert
      }
    };
  }

  /**
   * Verify an uploaded .json certificate file
   * @param {object} certificateObj Parsed certificate object
   * @param {string} [ip]
   * @param {string} [userAgent]
   */
  async verifyCertificateFile(certificateObj, ip = '127.0.0.1', userAgent = '') {
    const startTime = Date.now();

    if (!certificateObj) {
      return {
        status: 400,
        data: { verified: false, error: 'Certificate JSON payload is required' }
      };
    }

    const validation = this.signer.verifyCertificate(certificateObj);
    const durationMs = Date.now() - startTime;

    // Cross-reference with ledger records if available
    let ledgerDoc = null;
    if (certificateObj.document && certificateObj.document.sha256) {
      ledgerDoc = this.db.findDocumentByHash(certificateObj.document.sha256);
    }

    this.db.logVerification({
      sha256: certificateObj?.document?.sha256 || 'UNKNOWN_CERT_HASH',
      result: validation.valid,
      method: 'certificate_file_audit',
      ip,
      userAgent,
      durationMs,
      document: ledgerDoc
    });

    return {
      status: 200,
      data: {
        verified: validation.valid,
        status: validation.valid ? 'CERTIFICATE_AUTHENTIC' : 'CERTIFICATE_TAMPERED',
        signatureValid: validation.signatureValid,
        merkleValid: validation.merkleValid,
        errors: validation.errors,
        certificateId: certificateObj.certificateId,
        issuedAt: certificateObj.issuedAt,
        documentSummary: certificateObj.document,
        anchoredInLedger: ledgerDoc !== null,
        durationMs
      }
    };
  }

  /**
   * Get recent verification activity logs
   * @param {number} limit 
   */
  async getHistory(limit = 50) {
    const logs = this.db.getVerificationLogs(Number(limit) || 50);
    return {
      status: 200,
      data: {
        count: logs.length,
        logs
      }
    };
  }
}

export default VerifyController;
