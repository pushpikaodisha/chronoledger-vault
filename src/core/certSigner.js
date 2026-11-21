/**
 * ChronoLedger Digital Notary Certificate Signer
 * Implements Ed25519 asymmetric cryptographic signing for notarized documents,
 * embedding Merkle proofs, canonical payload hashing, and tamper-evident signatures.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJsonStringify, hashCanonicalJson, hashString } from './hasher.js';
import { MerkleTree } from './merkleTree.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_KEYS_DIR = path.resolve(__dirname, '../../data/keys');

export class CertSigner {
  /**
   * Initialize signer with existing or auto-generated Ed25519 keys
   * @param {string} keysDir Path to store notary keypairs
   */
  constructor(keysDir = DEFAULT_KEYS_DIR) {
    this.keysDir = keysDir;
    this.privateKeyPem = null;
    this.publicKeyPem = null;
    this.keyFingerprint = null;
    this.initKeys();
  }

  /**
   * Load or generate Ed25519 keypair
   */
  initKeys() {
    if (!fs.existsSync(this.keysDir)) {
      fs.mkdirSync(this.keysDir, { recursive: true });
    }

    const privPath = path.join(this.keysDir, 'notary_ed25519.key');
    const pubPath = path.join(this.keysDir, 'notary_ed25519.pub');

    if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
      this.privateKeyPem = fs.readFileSync(privPath, 'utf8');
      this.publicKeyPem = fs.readFileSync(pubPath, 'utf8');
    } else {
      // Generate new Ed25519 keypair (High-speed, compact, modern standard)
      const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
      });

      this.privateKeyPem = privateKey;
      this.publicKeyPem = publicKey;

      fs.writeFileSync(privPath, privateKey, { mode: 0o600 });
      fs.writeFileSync(pubPath, publicKey, { mode: 0o644 });
    }

    // Compute public key fingerprint
    this.keyFingerprint = crypto.createHash('sha256')
      .update(this.publicKeyPem.trim())
      .digest('hex');
  }

  /**
   * Get public notary details
   */
  getNotaryInfo() {
    return {
      authority: 'ChronoLedger Cryptographic Notary Authority',
      algorithm: 'Ed25519',
      keyFingerprint: this.keyFingerprint,
      publicKeyPem: this.publicKeyPem
    };
  }

  /**
   * Issue a cryptographic certificate of notarization
   * @param {object} params
   * @param {object} params.document Document data (sha256, sha512, fileName, fileSize, mimeType, metadata)
   * @param {object} params.merkleProof Merkle proof data (leafIndex, leafHash, rootHash, proof)
   * @param {object} params.block Block data (blockNumber, blockHash, previousBlockHash, timestamp)
   * @returns {object} Full signed certificate object
   */
  issueCertificate({ document, merkleProof, block }) {
    const certificateId = `CLV-${new Date().getFullYear()}-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
    const issuedAt = new Date().toISOString();

    const unsignedPayload = {
      certificateId,
      version: '1.0.0',
      authority: {
        name: 'ChronoLedger Cryptographic Notary Authority',
        algorithm: 'Ed25519',
        keyFingerprint: this.keyFingerprint
      },
      issuedAt,
      document: {
        sha256: document.sha256,
        sha512: document.sha512 || null,
        fileName: document.fileName || 'unnamed_asset.bin',
        fileSize: document.fileSize || 0,
        mimeType: document.mimeType || 'application/octet-stream',
        metadata: document.metadata || {}
      },
      merkleProof: {
        leafIndex: merkleProof.leafIndex,
        leafHash: merkleProof.leafHash,
        rootHash: merkleProof.rootHash,
        proofLength: merkleProof.proof.length,
        proof: merkleProof.proof
      },
      block: {
        blockNumber: block.blockNumber,
        blockHash: block.blockHash,
        previousBlockHash: block.previousBlockHash,
        timestamp: block.timestamp
      }
    };

    // Sign the canonical JSON representation
    const canonicalPayloadString = canonicalJsonStringify(unsignedPayload);
    const signatureBuffer = crypto.sign(
      null, // Ed25519 does not require a pre-hash algorithm parameter in Node.js
      Buffer.from(canonicalPayloadString, 'utf8'),
      this.privateKeyPem
    );
    const signatureHex = signatureBuffer.toString('hex');

    return {
      ...unsignedPayload,
      signature: {
        algorithm: 'Ed25519',
        format: 'hex',
        value: signatureHex,
        payloadHash: hashString(canonicalPayloadString, 'sha256')
      }
    };
  }

  /**
   * Verifies an issued certificate
   * 1. Validates the Ed25519 digital signature
   * 2. Recalculates the Merkle inclusion proof against rootHash
   * 3. Checks document SHA-256 consistency
   * @param {object} certificate 
   * @returns {{ valid: boolean, signatureValid: boolean, merkleValid: boolean, errors: string[] }}
   */
  verifyCertificate(certificate) {
    const errors = [];
    let signatureValid = false;
    let merkleValid = false;

    try {
      if (!certificate || !certificate.signature || !certificate.document || !certificate.merkleProof) {
        return {
          valid: false,
          signatureValid: false,
          merkleValid: false,
          errors: ['Malformed certificate schema']
        };
      }

      // Reconstruct unsigned canonical payload
      const { signature, ...unsignedPayload } = certificate;
      const canonicalString = canonicalJsonStringify(unsignedPayload);

      // Verify signature with notary public key
      try {
        const sigBuffer = Buffer.from(signature.value, 'hex');
        signatureValid = crypto.verify(
          null,
          Buffer.from(canonicalString, 'utf8'),
          this.publicKeyPem,
          sigBuffer
        );
        if (!signatureValid) {
          errors.push('Digital signature mismatch: certificate data has been altered');
        }
      } catch (sigErr) {
        signatureValid = false;
        errors.push(`Signature verification error: ${sigErr.message}`);
      }

      // Verify Merkle proof
      merkleValid = MerkleTree.verifyProof(
        certificate.document.sha256,
        certificate.merkleProof.proof,
        certificate.merkleProof.rootHash
      );

      if (!merkleValid) {
        errors.push('Merkle inclusion proof invalid: leaf hash does not resolve to the stated block root');
      }

      return {
        valid: signatureValid && merkleValid,
        signatureValid,
        merkleValid,
        errors
      };
    } catch (err) {
      return {
        valid: false,
        signatureValid: false,
        merkleValid: false,
        errors: [`Certificate validation exception: ${err.message}`]
      };
    }
  }
}

export default CertSigner;
