/**
 * ChronoLedger Cryptographic Merkle Tree
 * Implements RFC 6962 Merkle Tree generation, directional inclusion proofs,
 * and deterministic root calculation.
 */

import { hashLeaf, hashInterior, timingSafeHashEqual, hashString } from './hasher.js';

export class MerkleTree {
  /**
   * Constructs a Merkle Tree from an array of leaf items (hex hashes or string data)
   * @param {Array<string>} leaves Array of hex hashes or data strings
   */
  constructor(leaves = []) {
    this.rawLeaves = [...leaves];
    this.leafHashes = [];
    this.layers = [];
    this.root = null;

    this.buildTree();
  }

  /**
   * Build the complete Merkle Tree layer by layer
   */
  buildTree() {
    if (this.rawLeaves.length === 0) {
      // Empty tree has deterministic zero root
      this.root = hashString('CHRONOLEDGER_EMPTY_ROOT_GENESIS');
      this.leafHashes = [];
      this.layers = [[this.root]];
      return;
    }

    // Step 1: Compute RFC 6962 leaf hashes
    this.leafHashes = this.rawLeaves.map(leaf => hashLeaf(leaf));
    this.layers = [this.leafHashes];

    let currentLayer = this.leafHashes;

    // Step 2: Compute interior layers until single root hash
    while (currentLayer.length > 1) {
      const nextLayer = [];

      for (let i = 0; i < currentLayer.length; i += 2) {
        const left = currentLayer[i];
        // If odd number of nodes at this layer, duplicate the last node
        const right = (i + 1 < currentLayer.length) ? currentLayer[i + 1] : left;
        const parent = hashInterior(left, right);
        nextLayer.push(parent);
      }

      this.layers.push(nextLayer);
      currentLayer = nextLayer;
    }

    this.root = this.layers[this.layers.length - 1][0];
  }

  /**
   * Get the Merkle Root hash (64-char hex)
   * @returns {string}
   */
  getRoot() {
    return this.root;
  }

  /**
   * Get number of leaves
   * @returns {number}
   */
  getLeafCount() {
    return this.rawLeaves.length;
  }

  /**
   * Get depth of the tree
   * @returns {number}
   */
  getDepth() {
    return this.layers.length;
  }

  /**
   * Generate an inclusion proof for a given leaf index or raw leaf data
   * @param {number|string} indexOrData Leaf index (0-based) or raw leaf value
   * @returns {{ leafIndex: number, rawLeaf: string, leafHash: string, root: string, proof: Array<{ position: 'left'|'right', hash: string, layerIndex: number }> }}
   */
  getProof(indexOrData) {
    let leafIndex = -1;

    if (typeof indexOrData === 'number') {
      leafIndex = indexOrData;
    } else {
      leafIndex = this.rawLeaves.indexOf(indexOrData);
    }

    if (leafIndex < 0 || leafIndex >= this.rawLeaves.length) {
      throw new Error(`Leaf index ${leafIndex} out of bounds (leaves count: ${this.rawLeaves.length})`);
    }

    const proof = [];
    let currentIndex = leafIndex;

    // Traverse from layer 0 up to layer (N-1) (just below root)
    for (let layerIndex = 0; layerIndex < this.layers.length - 1; layerIndex++) {
      const layer = this.layers[layerIndex];
      const isEven = (currentIndex % 2 === 0);
      let siblingIndex;
      let position;

      if (isEven) {
        // Current is left node, sibling is right
        siblingIndex = currentIndex + 1;
        position = 'right';
        // If sibling is out of bounds, it was duplicated from current
        const siblingHash = (siblingIndex < layer.length) ? layer[siblingIndex] : layer[currentIndex];
        proof.push({
          layerIndex,
          position,
          hash: siblingHash
        });
      } else {
        // Current is right node, sibling is left
        siblingIndex = currentIndex - 1;
        position = 'left';
        proof.push({
          layerIndex,
          position,
          hash: layer[siblingIndex]
        });
      }

      currentIndex = Math.floor(currentIndex / 2);
    }

    return {
      leafIndex,
      rawLeaf: this.rawLeaves[leafIndex],
      leafHash: this.leafHashes[leafIndex],
      root: this.root,
      proof
    };
  }

  /**
   * Verifies an inclusion proof statically against a known root hash
   * @param {string} rawLeaf Original document SHA-256
   * @param {Array<{ position: 'left'|'right', hash: string }>} proof Array of sibling hashes and positions
   * @param {string} expectedRoot The expected Merkle root
   * @returns {boolean} True if proof is cryptographically sound
   */
  static verifyProof(rawLeaf, proof, expectedRoot) {
    if (!rawLeaf || !Array.isArray(proof) || !expectedRoot) {
      return false;
    }

    // Hash the raw document to get the RFC 6962 leaf hash
    let currentHash = hashLeaf(rawLeaf);

    for (const step of proof) {
      if (step.position === 'right') {
        currentHash = hashInterior(currentHash, step.hash);
      } else if (step.position === 'left') {
        currentHash = hashInterior(step.hash, currentHash);
      } else {
        return false;
      }
    }

    return timingSafeHashEqual(currentHash, expectedRoot);
  }

  /**
   * Verifies proof step-by-step and returns complete audit trajectory with intermediate hashes
   * Ideal for visual inspection and audit verification in UI
   * @param {string} rawLeaf 
   * @param {Array<{ position: 'left'|'right', hash: string }>} proof 
   * @param {string} expectedRoot 
   * @returns {{ valid: boolean, calculatedRoot: string, steps: Array<{ stepIndex: number, position: string, siblingHash: string, inputA: string, inputB: string, outputHash: string }> }}
   */
  static verifyProofAudit(rawLeaf, proof, expectedRoot) {
    const steps = [];
    let currentHash = hashLeaf(rawLeaf);
    const initialLeafHash = currentHash;

    for (let i = 0; i < proof.length; i++) {
      const step = proof[i];
      let leftInput, rightInput;

      if (step.position === 'right') {
        leftInput = currentHash;
        rightInput = step.hash;
        currentHash = hashInterior(leftInput, rightInput);
      } else {
        leftInput = step.hash;
        rightInput = currentHash;
        currentHash = hashInterior(leftInput, rightInput);
      }

      steps.push({
        stepIndex: i + 1,
        position: step.position,
        siblingHash: step.hash,
        leftInput,
        rightInput,
        outputHash: currentHash
      });
    }

    const valid = timingSafeHashEqual(currentHash, expectedRoot);

    return {
      valid,
      rawLeaf,
      initialLeafHash,
      calculatedRoot: currentHash,
      expectedRoot,
      steps
    };
  }

  /**
   * Generates graph data structure suitable for 2D Canvas or SVG rendering
   * @returns {{ nodes: Array<object>, edges: Array<object>, levels: number, leafCount: number }}
   */
  getVisualizationData() {
    const nodes = [];
    const edges = [];

    // Traverse layers
    for (let layerIndex = 0; layerIndex < this.layers.length; layerIndex++) {
      const layer = this.layers[layerIndex];
      const isLeafLayer = (layerIndex === 0);
      const isRootLayer = (layerIndex === this.layers.length - 1);

      for (let nodeIndex = 0; nodeIndex < layer.length; nodeIndex++) {
        const hash = layer[nodeIndex];
        const id = `L${layerIndex}_N${nodeIndex}`;

        const node = {
          id,
          layerIndex,
          nodeIndex,
          hash,
          shortHash: `${hash.slice(0, 6)}...${hash.slice(-4)}`,
          isLeaf: isLeafLayer,
          isRoot: isRootLayer,
          rawLeaf: isLeafLayer ? (this.rawLeaves[nodeIndex] || null) : null
        };

        nodes.push(node);

        // Connect to parent in next layer
        if (!isRootLayer) {
          const parentIndex = Math.floor(nodeIndex / 2);
          const parentId = `L${layerIndex + 1}_N${parentIndex}`;
          edges.push({
            id: `${id}->${parentId}`,
            source: id,
            target: parentId,
            position: (nodeIndex % 2 === 0) ? 'left' : 'right'
          });
        }
      }
    }

    return {
      root: this.root,
      levels: this.layers.length,
      leafCount: this.rawLeaves.length,
      nodes,
      edges
    };
  }
}

export default MerkleTree;
