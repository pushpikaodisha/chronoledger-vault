import { MerkleTree } from '../src/core/merkleTree.js';
import { hashString, hashLeaf, hashInterior } from '../src/core/hasher.js';

console.log('--- Testing Merkle Tree Implementation ---');

// Test 1: Empty tree
const emptyTree = new MerkleTree([]);
console.log('Empty Root:', emptyTree.getRoot());

// Test 2: Single leaf
const leaf1 = hashString('document 1');
const singleTree = new MerkleTree([leaf1]);
console.log('Single Leaf Root:', singleTree.getRoot());
const singleProof = singleTree.getProof(0);
console.log('Single Leaf Proof valid?', MerkleTree.verifyProof(leaf1, singleProof.proof, singleTree.getRoot()));

// Test 3: Multiple leaves (4 leaves)
const docs = ['Contract A', 'Identity Proof B', 'Audit Record C', 'Medical Data D'].map(d => hashString(d));
const tree4 = new MerkleTree(docs);
console.log('4-leaf Tree Root:', tree4.getRoot());

for (let i = 0; i < docs.length; i++) {
  const p = tree4.getProof(i);
  const isValid = MerkleTree.verifyProof(docs[i], p.proof, tree4.getRoot());
  console.log(`Proof for leaf ${i} ('${docs[i].slice(0, 8)}...'):`, isValid ? 'VALID' : 'FAILED');
  if (!isValid) throw new Error(`Proof validation failed for leaf ${i}`);
}

// Test 4: Odd number of leaves (3 leaves)
const tree3 = new MerkleTree(docs.slice(0, 3));
console.log('3-leaf Tree Root:', tree3.getRoot());
for (let i = 0; i < 3; i++) {
  const p = tree3.getProof(i);
  const isValid = MerkleTree.verifyProof(docs[i], p.proof, tree3.getRoot());
  console.log(`3-leaf Proof for leaf ${i}:`, isValid ? 'VALID' : 'FAILED');
  if (!isValid) throw new Error(`Proof validation failed for 3-leaf index ${i}`);
}

// Test 5: Tamper resistance (corrupt proof or corrupt leaf)
const badLeaf = hashString('Tampered document');
const p0 = tree4.getProof(0);
const tamperLeafResult = MerkleTree.verifyProof(badLeaf, p0.proof, tree4.getRoot());
console.log('Tampered leaf rejected?', !tamperLeafResult ? 'PASSED (Rejected)' : 'FAILED (Accepted bad leaf)');
if (tamperLeafResult) throw new Error('Tampered leaf was incorrectly accepted!');

// Test 6: Audit step-by-step
const auditResult = MerkleTree.verifyProofAudit(docs[0], p0.proof, tree4.getRoot());
console.log('Step-by-step audit steps count:', auditResult.steps.length, 'Root matches:', auditResult.valid);

console.log('ALL MERKLE CRYPTOGRAPHIC TESTS PASSED SUCCESSFULLY!');
