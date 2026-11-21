import { LedgerDb } from '../src/db/ledgerDb.js';
import { hashString } from '../src/core/hasher.js';

console.log('--- Testing LedgerDb Storage & Integrity Engine ---');

const db = new LedgerDb();
console.log('Initial stats:', db.getStats());

// Add 3 documents
const doc1 = db.addDocument({
  fileName: 'NDA_Acme_Corp.pdf',
  fileSize: 45012,
  mimeType: 'application/pdf',
  sha256: hashString('NDA_Acme_Corp_Content_V1'),
  metadata: { signer: 'Alice Smith', department: 'Legal' }
});

const doc2 = db.addDocument({
  fileName: 'Financial_Q3_Report.xlsx',
  fileSize: 128900,
  mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  sha256: hashString('Financial_Q3_Report_Data'),
  metadata: { signer: 'Bob CFO', department: 'Finance' }
});

console.log('Added doc 1:', doc1.transaction.fileName, 'Block:', doc1.transaction.blockNumber, 'Cert:', doc1.certificate.certificateId);

// Verify lookup
const found = db.findDocumentByHash(hashString('NDA_Acme_Corp_Content_V1'));
console.log('Lookup by hash found doc?', found !== null, 'Filename:', found?.fileName);
if (!found) throw new Error('Lookup failed!');

// Run integrity check
const auditPristine = db.verifyLedgerIntegrity();
console.log('Pristine Ledger Integrity:', auditPristine.status, 'Errors:', auditPristine.errors);
if (!auditPristine.intact) throw new Error('Pristine ledger was not intact!');

// Test tamper simulation
console.log('Simulating tamper on active block...');
db.simulateTamper({ blockIndex: db.activeBlock.index, docIndex: 0, field: 'sha256' });

const auditTampered = db.verifyLedgerIntegrity();
console.log('Tampered Ledger Status:', auditTampered.status, 'Detected Errors:', auditTampered.errors.length);
if (auditTampered.intact) throw new Error('Tampered ledger failed to trigger alarm!');

// Restore
db.restorePristineState();
const auditRestored = db.verifyLedgerIntegrity();
console.log('Restored Ledger Status:', auditRestored.status, 'Errors:', auditRestored.errors.length);
if (!auditRestored.intact) throw new Error('Restoration failed!');

console.log('LEDGER DB TESTS PASSED SUCCESSFULLY!');
