/**
 * ChronoLedger Vault Storage Engine
 * High-performance, atomic, persistent cryptographic ledger with Merkle block chaining,
 * memory-indexed O(1) hash lookups, and deep integrity audit capabilities.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { MerkleTree } from '../core/merkleTree.js';
import { hashCanonicalJson, hashString, timingSafeHashEqual } from '../core/hasher.js';
import { CertSigner } from '../core/certSigner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = path.resolve(__dirname, '../../data');
const LEDGER_FILE = path.join(DATA_DIR, 'ledger.json');
const BACKUP_FILE = path.join(DATA_DIR, 'ledger.backup.json');
const AUDIT_LOGS_FILE = path.join(DATA_DIR, 'verification_logs.json');

export class LedgerDb {
  constructor(dataDir = DATA_DIR) {
    this.dataDir = dataDir;
    this.ledgerPath = path.join(dataDir, 'ledger.json');
    this.backupPath = path.join(dataDir, 'ledger.backup.json');
    this.auditLogsPath = path.join(dataDir, 'verification_logs.json');

    this.signer = new CertSigner(path.join(dataDir, 'keys'));

    this.blocks = [];
    this.activeBlock = null;
    this.verificationLogs = [];

    // O(1) in-memory indices
    this.docByHash = new Map();
    this.docById = new Map();
    this.certById = new Map();

    this.isTamperedSimulated = false;
    this.originalStateSnapshot = null;

    this.init();
  }

  /**
   * Initialize directory and ledger from disk or create genesis
   */
  init() {
    if (!fs.existsSync(this.dataDir)) {
      fs.mkdirSync(this.dataDir, { recursive: true });
    }

    if (fs.existsSync(this.ledgerPath)) {
      try {
        const raw = fs.readFileSync(this.ledgerPath, 'utf8');
        const data = JSON.parse(raw);
        this.blocks = data.blocks || [];
        this.activeBlock = data.activeBlock || null;
        this.rebuildIndices();
      } catch (err) {
        console.error('Warning: Error reading ledger file, attempting backup recovery...', err.message);
        this.recoverFromBackup();
      }
    }

    if (this.blocks.length === 0) {
      this.createGenesisBlock();
    }

    if (!this.activeBlock) {
      this.createNewActiveBlock();
    }

    this.loadAuditLogs();
    this.saveState();
  }

  /**
   * Rebuild fast in-memory indexes
   */
  rebuildIndices() {
    this.docByHash.clear();
    this.docById.clear();
    this.certById.clear();

    const allBlocks = [...this.blocks];
    if (this.activeBlock) {
      allBlocks.push(this.activeBlock);
    }

    for (const block of allBlocks) {
      for (const tx of block.transactions) {
        this.docByHash.set(tx.sha256.toLowerCase(), tx);
        this.docById.set(tx.id, tx);
        if (tx.certificate) {
          this.certById.set(tx.certificate.certificateId, tx.certificate);
        }
      }
    }
  }

  /**
   * Creates Genesis Block (#0)
   */
  createGenesisBlock() {
    const genesisTime = '2026-01-01T00:00:00.000Z';
    const genesisDocHash = hashString('CHRONOLEDGER_GENESIS_ROOT_INITIATION_PROTOCOL');

    const genesisTree = new MerkleTree([genesisDocHash]);
    const proof = genesisTree.getProof(0);

    const genesisBlockHeader = {
      index: 0,
      timestamp: genesisTime,
      previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
      merkleRoot: genesisTree.getRoot(),
      txCount: 1
    };

    const blockHash = hashCanonicalJson(genesisBlockHeader);

    const genesisTx = {
      id: 'tx_genesis_0',
      fileName: 'chrono_genesis_manifest.json',
      fileSize: 420,
      mimeType: 'application/json',
      sha256: genesisDocHash,
      sha512: hashString('CHRONOLEDGER_GENESIS_ROOT_INITIATION_PROTOCOL', 'sha512'),
      metadata: {
        title: 'ChronoLedger Vault Genesis Protocol',
        notary: 'ChronoLedger System Core',
        jurisdiction: 'Global Immutable Decentralized Time-Stamp Notary',
        notes: 'Genesis notary anchor initialized.'
      },
      blockNumber: 0,
      leafIndex: 0,
      timestamp: genesisTime,
      certificate: null
    };

    const cert = this.signer.issueCertificate({
      document: genesisTx,
      merkleProof: {
        leafIndex: 0,
        leafHash: proof.leafHash,
        rootHash: genesisTree.getRoot(),
        proof: proof.proof
      },
      block: {
        blockNumber: 0,
        blockHash,
        previousBlockHash: genesisBlockHeader.previousHash,
        timestamp: genesisTime
      }
    });

    genesisTx.certificate = cert;

    const genesisBlock = {
      index: 0,
      timestamp: genesisTime,
      previousHash: genesisBlockHeader.previousHash,
      merkleRoot: genesisTree.getRoot(),
      blockHash,
      sealed: true,
      transactions: [genesisTx]
    };

    this.blocks = [genesisBlock];
    this.createNewActiveBlock();
    this.rebuildIndices();
  }

  /**
   * Initializes a new pending active block
   */
  createNewActiveBlock() {
    const prevBlock = this.blocks[this.blocks.length - 1];
    const newIndex = prevBlock ? prevBlock.index + 1 : 1;
    const prevHash = prevBlock ? prevBlock.blockHash : '0000000000000000000000000000000000000000000000000000000000000000';

    this.activeBlock = {
      index: newIndex,
      timestamp: new Date().toISOString(),
      previousHash: prevHash,
      merkleRoot: null,
      blockHash: null,
      sealed: false,
      transactions: []
    };
  }

  /**
   * Add a new document to the ledger
   * @param {object} docData 
   * @returns {object} The notarized transaction with certificate
   */
  addDocument(docData) {
    if (!docData || !docData.sha256) {
      throw new Error('Document must include valid SHA-256 hash');
    }

    const sha256Clean = docData.sha256.trim().toLowerCase();

    // Check if already registered
    if (this.docByHash.has(sha256Clean)) {
      const existing = this.docByHash.get(sha256Clean);
      return {
        isDuplicate: true,
        transaction: existing,
        certificate: existing.certificate
      };
    }

    const txId = `tx_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const timestamp = new Date().toISOString();

    const transaction = {
      id: txId,
      fileName: docData.fileName || 'unnamed_document.bin',
      fileSize: Number(docData.fileSize) || 0,
      mimeType: docData.mimeType || 'application/octet-stream',
      sha256: sha256Clean,
      sha512: docData.sha512 || null,
      metadata: docData.metadata || {},
      blockNumber: this.activeBlock.index,
      leafIndex: this.activeBlock.transactions.length,
      timestamp,
      certificate: null
    };

    this.activeBlock.transactions.push(transaction);

    // Update active block Merkle root and certificates for all transactions in this block
    this.refreshActiveBlockMerkle();

    // Update indexes
    this.docByHash.set(sha256Clean, transaction);
    this.docById.set(txId, transaction);
    if (transaction.certificate) {
      this.certById.set(transaction.certificate.certificateId, transaction.certificate);
    }

    // Persist
    this.saveState();

    // Auto-seal block if it reaches threshold (e.g., 6 transactions)
    if (this.activeBlock.transactions.length >= 6) {
      this.sealCurrentBlock();
    }

    return {
      isDuplicate: false,
      transaction,
      certificate: transaction.certificate
    };
  }

  /**
   * Recompute dynamic Merkle tree and certificates for active block transactions
   */
  refreshActiveBlockMerkle() {
    if (!this.activeBlock || this.activeBlock.transactions.length === 0) {
      return;
    }

    const leaves = this.activeBlock.transactions.map(t => t.sha256);
    const tree = new MerkleTree(leaves);
    const root = tree.getRoot();
    this.activeBlock.merkleRoot = root;

    // Temporary estimated block hash for active pending state
    const pendingHeader = {
      index: this.activeBlock.index,
      timestamp: this.activeBlock.timestamp,
      previousHash: this.activeBlock.previousHash,
      merkleRoot: root,
      txCount: this.activeBlock.transactions.length
    };
    this.activeBlock.blockHash = hashCanonicalJson(pendingHeader);

    // Update each transaction's proof & certificate
    for (let i = 0; i < this.activeBlock.transactions.length; i++) {
      const tx = this.activeBlock.transactions[i];
      tx.leafIndex = i;
      const proofObj = tree.getProof(i);

      tx.certificate = this.signer.issueCertificate({
        document: tx,
        merkleProof: {
          leafIndex: i,
          leafHash: proofObj.leafHash,
          rootHash: root,
          proof: proofObj.proof
        },
        block: {
          blockNumber: this.activeBlock.index,
          blockHash: this.activeBlock.blockHash,
          previousBlockHash: this.activeBlock.previousHash,
          timestamp: this.activeBlock.timestamp
        }
      });

      this.certById.set(tx.certificate.certificateId, tx.certificate);
    }
  }

  /**
   * Explicitly seal the current active block, immutably anchoring it into the chain
   * @returns {object} The sealed block
   */
  sealCurrentBlock() {
    if (!this.activeBlock || this.activeBlock.transactions.length === 0) {
      // Nothing to seal
      return null;
    }

    // Freeze timestamp and finalize Merkle tree
    const sealTimestamp = new Date().toISOString();
    this.activeBlock.timestamp = sealTimestamp;

    const leaves = this.activeBlock.transactions.map(t => t.sha256);
    const tree = new MerkleTree(leaves);
    const root = tree.getRoot();
    this.activeBlock.merkleRoot = root;

    const finalHeader = {
      index: this.activeBlock.index,
      timestamp: sealTimestamp,
      previousHash: this.activeBlock.previousHash,
      merkleRoot: root,
      txCount: this.activeBlock.transactions.length
    };

    const finalBlockHash = hashCanonicalJson(finalHeader);
    this.activeBlock.blockHash = finalBlockHash;
    this.activeBlock.sealed = true;

    // Issue permanent certificates with sealed block hash
    for (let i = 0; i < this.activeBlock.transactions.length; i++) {
      const tx = this.activeBlock.transactions[i];
      const proofObj = tree.getProof(i);

      tx.certificate = this.signer.issueCertificate({
        document: tx,
        merkleProof: {
          leafIndex: i,
          leafHash: proofObj.leafHash,
          rootHash: root,
          proof: proofObj.proof
        },
        block: {
          blockNumber: this.activeBlock.index,
          blockHash: finalBlockHash,
          previousBlockHash: this.activeBlock.previousHash,
          timestamp: sealTimestamp
        }
      });

      this.certById.set(tx.certificate.certificateId, tx.certificate);
    }

    const sealed = this.activeBlock;
    this.blocks.push(sealed);

    // Open next active block
    this.createNewActiveBlock();
    this.saveState();

    return sealed;
  }

  /**
   * Find document by SHA-256
   * @param {string} sha256 
   * @returns {object|null}
   */
  findDocumentByHash(sha256) {
    if (!sha256) return null;
    return this.docByHash.get(sha256.trim().toLowerCase()) || null;
  }

  /**
   * Find certificate by certificate ID
   * @param {string} certId 
   * @returns {object|null}
   */
  findCertificate(certId) {
    if (!certId) return null;
    return this.certById.get(certId) || null;
  }

  /**
   * Get all sealed blocks plus active block
   * @returns {Array<object>}
   */
  getAllBlocks() {
    return [...this.blocks, ...(this.activeBlock ? [this.activeBlock] : [])];
  }

  /**
   * Get specific block by index with full Merkle visualization metadata
   * @param {number} index 
   * @returns {object|null}
   */
  getBlock(index) {
    const numIndex = Number(index);
    let target = this.blocks.find(b => b.index === numIndex);
    if (!target && this.activeBlock && this.activeBlock.index === numIndex) {
      target = this.activeBlock;
    }
    if (!target) return null;

    const leaves = target.transactions.map(t => t.sha256);
    const tree = new MerkleTree(leaves);
    const visual = tree.getVisualizationData();

    return {
      ...target,
      visualization: visual
    };
  }

  /**
   * Get recent notarized documents across the ledger
   * @param {number} limit 
   * @returns {Array<object>}
   */
  getRecentDocuments(limit = 25) {
    const allDocs = [];
    const all = [...this.blocks, ...(this.activeBlock ? [this.activeBlock] : [])];

    for (let i = all.length - 1; i >= 0; i--) {
      const block = all[i];
      for (let j = block.transactions.length - 1; j >= 0; j--) {
        allDocs.push(block.transactions[j]);
        if (allDocs.length >= limit) return allDocs;
      }
    }

    return allDocs;
  }

  /**
   * Verification Audit Logging
   * Records every verification attempt for compliance and forensic tracking
   */
  logVerification({ sha256, result, method = 'hash', ip = '127.0.0.1', userAgent = '', durationMs = 0, document = null }) {
    const entry = {
      id: `log_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`,
      timestamp: new Date().toISOString(),
      sha256,
      result: result ? 'VERIFIED' : 'UNVERIFIED',
      method,
      ip,
      userAgent: userAgent ? userAgent.slice(0, 100) : 'Internal/Client',
      durationMs,
      documentName: document ? document.fileName : null,
      blockNumber: document ? document.blockNumber : null
    };

    this.verificationLogs.unshift(entry);
    if (this.verificationLogs.length > 500) {
      this.verificationLogs.pop();
    }

    this.saveAuditLogs();
    return entry;
  }

  loadAuditLogs() {
    if (fs.existsSync(this.auditLogsPath)) {
      try {
        const raw = fs.readFileSync(this.auditLogsPath, 'utf8');
        this.verificationLogs = JSON.parse(raw) || [];
      } catch (err) {
        this.verificationLogs = [];
      }
    }
  }

  saveAuditLogs() {
    try {
      fs.writeFileSync(this.auditLogsPath, JSON.stringify(this.verificationLogs, null, 2), 'utf8');
    } catch (err) {
      console.error('Failed to save audit logs:', err.message);
    }
  }

  getVerificationLogs(limit = 50) {
    return this.verificationLogs.slice(0, limit);
  }

  /**
   * DEEP AUDIT & CRYPTOGRAPHIC TAMPER DETECTION ENGINE
   * Verifies the entire blockchain and all Merkle trees from Genesis to current tip:
   * 1. Validates previousHash chain continuity.
   * 2. Recalculates Merkle tree roots for every block and verifies against stored root.
   * 3. Recomputes canonical blockHash and compares with stored blockHash.
   * 4. Validates all transaction inclusion proofs and Ed25519 digital signatures.
   * @returns {object} Comprehensive forensic audit report
   */
  verifyLedgerIntegrity() {
    const startTime = Date.now();
    const errors = [];
    const blockAuditResults = [];
    let totalDocumentsChecked = 0;

    const allBlocks = [...this.blocks];
    if (this.activeBlock && this.activeBlock.transactions.length > 0) {
      allBlocks.push(this.activeBlock);
    }

    let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';

    for (let i = 0; i < allBlocks.length; i++) {
      const block = allBlocks[i];
      const blockErrors = [];

      // 1. Check previous hash pointer
      if (i > 0) {
        if (!timingSafeHashEqual(block.previousHash, expectedPrevHash)) {
          const errMsg = `Block #${block.index} previousHash link broken! Expected: ${expectedPrevHash.slice(0, 12)}..., Found: ${block.previousHash.slice(0, 12)}...`;
          blockErrors.push(errMsg);
          errors.push(errMsg);
        }
      }

      // 2. Recompute Merkle root from transactions
      const txHashes = block.transactions.map(t => t.sha256);
      const computedTree = new MerkleTree(txHashes);
      const computedRoot = computedTree.getRoot();

      if (block.merkleRoot && !timingSafeHashEqual(block.merkleRoot, computedRoot)) {
        const errMsg = `Block #${block.index} Merkle Root MISMATCH! Stored: ${block.merkleRoot.slice(0, 12)}..., Computed from TXs: ${computedRoot.slice(0, 12)}... (Data tampering detected)`;
        blockErrors.push(errMsg);
        errors.push(errMsg);
      }

      // 3. Recompute block header hash if sealed
      if (block.sealed) {
        const header = {
          index: block.index,
          timestamp: block.timestamp,
          previousHash: block.previousHash,
          merkleRoot: block.merkleRoot,
          txCount: block.transactions.length
        };
        const computedBlockHash = hashCanonicalJson(header);
        if (block.blockHash && !timingSafeHashEqual(block.blockHash, computedBlockHash)) {
          const errMsg = `Block #${block.index} BlockHash altered! Stored: ${block.blockHash.slice(0, 12)}..., Canonical computed: ${computedBlockHash.slice(0, 12)}...`;
          blockErrors.push(errMsg);
          errors.push(errMsg);
        }
      }

      // 4. Verify all transaction certificates and Merkle inclusion proofs in this block
      for (const tx of block.transactions) {
        totalDocumentsChecked++;

        if (tx.certificate) {
          const certValidation = this.signer.verifyCertificate(tx.certificate);
          if (!certValidation.valid) {
            const errMsg = `Transaction '${tx.fileName}' (${tx.id}) certificate invalid: ${certValidation.errors.join('; ')}`;
            blockErrors.push(errMsg);
            errors.push(errMsg);
          }
        }
      }

      blockAuditResults.push({
        blockIndex: block.index,
        sealed: block.sealed,
        txCount: block.transactions.length,
        merkleRoot: block.merkleRoot,
        blockHash: block.blockHash,
        status: blockErrors.length === 0 ? 'VALID' : 'CORRUPTED',
        errors: blockErrors
      });

      expectedPrevHash = block.blockHash || expectedPrevHash;
    }

    const durationMs = Date.now() - startTime;
    const intact = (errors.length === 0);

    return {
      intact,
      status: intact ? 'VERIFIED_SECURE' : 'COMPROMISED',
      auditedAt: new Date().toISOString(),
      durationMs,
      totalBlocksAudited: allBlocks.length,
      totalDocumentsAudited: totalDocumentsChecked,
      errorsCount: errors.length,
      errors,
      blocks: blockAuditResults
    };
  }

  /**
   * TAMPER SIMULATION LAB (For demonstration & forensic testing)
   * Intentionally mutates 1 byte in a document or block header to demonstrate
   * cryptographic alarm triggers.
   */
  simulateTamper({ blockIndex = 1, docIndex = 0, field = 'fileName', fakeValue = 'MALICIOUS_TAMPERED_CONTENT.pdf' }) {
    if (!this.originalStateSnapshot) {
      // Save pristine state for clean restoration
      this.originalStateSnapshot = JSON.stringify({
        blocks: this.blocks,
        activeBlock: this.activeBlock
      });
    }

    const all = [...this.blocks, ...(this.activeBlock ? [this.activeBlock] : [])];
    const targetBlock = all.find(b => b.index === Number(blockIndex)) || all[all.length - 1];

    if (!targetBlock || targetBlock.transactions.length === 0) {
      throw new Error('No documents available in targeted block to tamper');
    }

    const tx = targetBlock.transactions[docIndex] || targetBlock.transactions[0];
    const oldValue = tx[field];
    tx[field] = fakeValue;

    // If tampering sha256, it directly breaks Merkle root
    if (field === 'sha256') {
      tx.sha256 = hashString('ALTERED_TAMPERED_DATA_TEST');
    }

    this.isTamperedSimulated = true;
    this.rebuildIndices();

    return {
      tampered: true,
      blockIndex: targetBlock.index,
      docId: tx.id,
      field,
      oldValue,
      tamperedValue: tx[field],
      message: 'Cryptographic tamper simulated! Run Full Audit to view cryptographic alarms.'
    };
  }

  /**
   * Restore ledger back to pristine integrity
   */
  restorePristineState() {
    if (this.originalStateSnapshot) {
      const data = JSON.parse(this.originalStateSnapshot);
      this.blocks = data.blocks;
      this.activeBlock = data.activeBlock;
      this.isTamperedSimulated = false;
      this.originalStateSnapshot = null;
      this.rebuildIndices();
      this.saveState();
      return { restored: true, message: 'Ledger restored from pristine snapshot.' };
    }

    // Otherwise reload from disk backup
    return this.recoverFromBackup();
  }

  /**
   * Save state atomically to prevent corruption during writes
   */
  saveState() {
    try {
      const state = {
        version: '1.0.0',
        updatedAt: new Date().toISOString(),
        blocks: this.blocks,
        activeBlock: this.activeBlock
      };

      const payload = JSON.stringify(state, null, 2);
      const tempPath = `${this.ledgerPath}.${Date.now()}.tmp`;

      // Atomic write: write to temp file then rename
      fs.writeFileSync(tempPath, payload, 'utf8');
      fs.renameSync(tempPath, this.ledgerPath);

      // Save rolling backup
      if (!this.isTamperedSimulated) {
        fs.writeFileSync(this.backupPath, payload, 'utf8');
      }
    } catch (err) {
      console.error('Fatal Ledger Save Error:', err.message);
    }
  }

  /**
   * Recover from backup file
   */
  recoverFromBackup() {
    if (fs.existsSync(this.backupPath)) {
      try {
        const raw = fs.readFileSync(this.backupPath, 'utf8');
        const data = JSON.parse(raw);
        this.blocks = data.blocks || [];
        this.activeBlock = data.activeBlock || null;
        this.isTamperedSimulated = false;
        this.rebuildIndices();
        this.saveState();
        return { restored: true, message: 'Ledger recovered from backup.' };
      } catch (err) {
        console.error('Failed to restore from backup:', err.message);
      }
    }
    return { restored: false, message: 'No valid backup found.' };
  }

  /**
   * Summary stats for dashboard
   */
  getStats() {
    let totalDocs = 0;
    for (const b of this.blocks) {
      totalDocs += b.transactions.length;
    }
    const pendingDocs = this.activeBlock ? this.activeBlock.transactions.length : 0;
    const all = [...this.blocks, ...(this.activeBlock ? [this.activeBlock] : [])];
    const latestBlock = all[all.length - 1];

    return {
      totalBlocks: this.blocks.length,
      currentHeight: latestBlock ? latestBlock.index : 0,
      totalNotarizedDocuments: totalDocs + pendingDocs,
      sealedDocuments: totalDocs,
      pendingDocuments: pendingDocs,
      activeBlockIndex: this.activeBlock ? this.activeBlock.index : null,
      activeBlockMerkleRoot: this.activeBlock ? this.activeBlock.merkleRoot : null,
      lastBlockHash: latestBlock ? latestBlock.blockHash : null,
      notaryKeyFingerprint: this.signer.keyFingerprint,
      isTamperSimulated: this.isTamperedSimulated,
      totalVerificationsLogged: this.verificationLogs.length
    };
  }
}

// Export singleton instance or factory
let defaultInstance = null;
export function getLedgerDb() {
  if (!defaultInstance) {
    defaultInstance = new LedgerDb();
  }
  return defaultInstance;
}

export default LedgerDb;
