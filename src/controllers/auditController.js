/**
 * ChronoLedger Audit Controller
 * Handles blockchain timeline inspection, deep cryptographic integrity audits,
 * and the tamper simulation / forensic analysis laboratory.
 */

import { getLedgerDb } from '../db/ledgerDb.js';

export class AuditController {
  constructor() {
    this.db = getLedgerDb();
  }

  /**
   * Get high-level audit overview & system statistics
   */
  async getOverview() {
    const stats = this.db.getStats();
    const allBlocks = this.db.getAllBlocks();

    return {
      status: 200,
      data: {
        ...stats,
        blocksCount: allBlocks.length,
        systemStatus: stats.isTamperSimulated ? 'TAMPER_ALERT_ACTIVE' : 'CRYPTOGRAPHICALLY_SOUND',
        timestamp: new Date().toISOString()
      }
    };
  }

  /**
   * Execute deep cryptographic audit across the entire ledger
   */
  async runDeepAudit() {
    const auditReport = this.db.verifyLedgerIntegrity();
    return {
      status: 200,
      data: auditReport
    };
  }

  /**
   * Get complete block timeline
   */
  async getBlockTimeline() {
    const blocks = this.db.getAllBlocks();
    const formattedBlocks = blocks.map(b => ({
      index: b.index,
      timestamp: b.timestamp,
      sealed: b.sealed,
      txCount: b.transactions.length,
      merkleRoot: b.merkleRoot,
      blockHash: b.blockHash,
      previousHash: b.previousHash,
      transactions: b.transactions.map(t => ({
        id: t.id,
        fileName: t.fileName,
        fileSize: t.fileSize,
        sha256: t.sha256,
        timestamp: t.timestamp,
        certificateId: t.certificate?.certificateId
      }))
    }));

    return {
      status: 200,
      data: {
        totalBlocks: formattedBlocks.length,
        blocks: formattedBlocks
      }
    };
  }

  /**
   * Get single block with full Merkle visualization graph
   * @param {number} blockIndex 
   */
  async getBlockDetails(blockIndex) {
    const block = this.db.getBlock(blockIndex);
    if (!block) {
      return {
        status: 404,
        data: { error: `Block #${blockIndex} not found in ledger` }
      };
    }

    return {
      status: 200,
      data: block
    };
  }

  /**
   * Trigger tamper simulation lab
   * @param {object} params 
   */
  async simulateTamper(params = {}) {
    try {
      const result = this.db.simulateTamper(params);
      return {
        status: 200,
        data: result
      };
    } catch (err) {
      return {
        status: 400,
        data: { error: err.message }
      };
    }
  }

  /**
   * Restore ledger back to pristine integrity
   */
  async restoreLedger() {
    const result = this.db.restorePristineState();
    return {
      status: 200,
      data: result
    };
  }
}

export default AuditController;
