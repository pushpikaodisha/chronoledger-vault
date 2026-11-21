import { CertSigner } from '../src/core/certSigner.js';
import { MerkleTree } from '../src/core/merkleTree.js';
import { hashString } from '../src/core/hasher.js';

console.log('--- Testing Certificate Signer & Verifier ---');

const signer = new CertSigner();
console.log('Notary Key Fingerprint:', signer.keyFingerprint);

const docHash = hashString('Confidential Board Resolution 2026');
const tree = new MerkleTree([docHash, hashString('doc2'), hashString('doc3')]);
const proof = tree.getProof(0);

const block = {
  blockNumber: 1,
  blockHash: hashString('block_1_header'),
  previousBlockHash: hashString('genesis_block_0'),
  timestamp: new Date().toISOString()
};

const cert = signer.issueCertificate({
  document: {
    sha256: docHash,
    fileName: 'board_resolution.pdf',
    fileSize: 10240,
    mimeType: 'application/pdf',
    metadata: { author: 'Board Secretary', classification: 'Strictly Confidential' }
  },
  merkleProof: {
    leafIndex: proof.leafIndex,
    leafHash: proof.leafHash,
    rootHash: tree.getRoot(),
    proof: proof.proof
  },
  block
});

console.log('Issued Certificate ID:', cert.certificateId);
console.log('Signature preview:', cert.signature.value.slice(0, 32) + '...');

// Verification test 1: Valid cert
const verifyResult = signer.verifyCertificate(cert);
console.log('Certificate Valid?', verifyResult.valid, 'Sig:', verifyResult.signatureValid, 'Merkle:', verifyResult.merkleValid);
if (!verifyResult.valid) throw new Error('Valid certificate failed verification!');

// Verification test 2: Tampered doc hash
const tamperedCert = JSON.parse(JSON.stringify(cert));
tamperedCert.document.fileName = 'malicious_alteration.exe';
const tamperedVerify = signer.verifyCertificate(tamperedCert);
console.log('Tampered Cert rejected?', !tamperedVerify.valid, 'Errors:', tamperedVerify.errors);
if (tamperedVerify.valid) throw new Error('Tampered certificate was accepted!');

console.log('CERTIFICATE SIGNER TESTS PASSED SUCCESSFULLY!');
