/**
 * ChronoLedger Merkle Tree Canvas Renderer
 * Interactive HTML5 Canvas visualization for cryptographic Merkle trees
 * Supports multi-layer rendering, parent-child links, proof path highlighting,
 * and high-DPI crisp rendering.
 */

export class MerkleTreeCanvas {
  /**
   * @param {HTMLCanvasElement} canvas 
   * @param {object} [options]
   */
  constructor(canvas, options = {}) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.options = {
      nodeRadius: 22,
      levelSpacing: 90,
      activeColor: '#ffbe0b',
      rootColor: '#ffc233',
      interiorColor: '#00f0ff',
      leafColor: '#00ffaa',
      lineColor: 'rgba(56, 189, 248, 0.25)',
      activeLineColor: '#ffbe0b',
      ...options
    };

    this.treeData = null;
    this.nodePositions = new Map(); // id -> { x, y, node }
    this.hoveredNode = null;
    this.selectedNodeId = null;
    this.highlightedPath = new Set(); // set of node IDs on active proof path

    this.scale = 1;
    this.panX = 0;
    this.panY = 0;
    this.isDragging = false;
    this.startX = 0;
    this.startY = 0;

    this.init();
  }

  init() {
    this.setupDpr();
    this.attachEvents();
  }

  /**
   * Configure canvas for High-DPI displays
   */
  setupDpr() {
    const rect = this.canvas.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.width = rect.width || 800;
    this.height = rect.height || 420;

    this.canvas.width = this.width * dpr;
    this.canvas.height = this.height * dpr;
    this.ctx.scale(dpr, dpr);
  }

  attachEvents() {
    window.addEventListener('resize', () => {
      this.setupDpr();
      this.render();
    });

    this.canvas.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = (e.clientX - rect.left - this.panX) / this.scale;
      const mouseY = (e.clientY - rect.top - this.panY) / this.scale;

      let found = null;
      for (const [id, pos] of this.nodePositions.entries()) {
        const dx = mouseX - pos.x;
        const dy = mouseY - pos.y;
        if (Math.sqrt(dx * dx + dy * dy) <= this.options.nodeRadius + 4) {
          found = pos.node;
          break;
        }
      }

      if (found !== this.hoveredNode) {
        this.hoveredNode = found;
        this.canvas.style.cursor = found ? 'pointer' : (this.isDragging ? 'grabbing' : 'default');
        this.render();
      }

      if (this.isDragging) {
        this.panX = e.clientX - this.startX;
        this.panY = e.clientY - this.startY;
        this.render();
      }
    });

    this.canvas.addEventListener('mousedown', (e) => {
      if (this.hoveredNode) {
        this.selectNode(this.hoveredNode.id);
      } else {
        this.isDragging = true;
        this.startX = e.clientX - this.panX;
        this.startY = e.clientY - this.panY;
        this.canvas.style.cursor = 'grabbing';
      }
    });

    window.addEventListener('mouseup', () => {
      this.isDragging = false;
      this.canvas.style.cursor = this.hoveredNode ? 'pointer' : 'default';
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      this.scale = Math.min(Math.max(0.4, this.scale * zoomFactor), 2.5);
      this.render();
    }, { passive: false });
  }

  /**
   * Set tree data from API / MerkleTree class
   * @param {object} treeData 
   */
  setData(treeData) {
    this.treeData = treeData;
    this.highlightedPath.clear();
    this.selectedNodeId = null;
    this.calculateLayout();
    this.fitToView();
    this.render();
  }

  /**
   * Calculate (x, y) coordinates for all tree nodes
   */
  calculateLayout() {
    this.nodePositions.clear();
    if (!this.treeData || !this.treeData.nodes || this.treeData.nodes.length === 0) return;

    // Group nodes by layerIndex
    const layers = [];
    for (const node of this.treeData.nodes) {
      if (!layers[node.layerIndex]) {
        layers[node.layerIndex] = [];
      }
      layers[node.layerIndex].push(node);
    }

    const totalLayers = layers.length;
    const startY = 60;
    const availableHeight = Math.max(this.height - 120, totalLayers * this.options.levelSpacing);
    const layerStepY = totalLayers > 1 ? availableHeight / (totalLayers - 1) : 0;

    // Root at top layer (highest layerIndex), leaves at bottom layer (0)
    for (let l = 0; l < totalLayers; l++) {
      const layerNodes = layers[l];
      // Invert vertical index so Root (highest layerIndex) is top (y = startY)
      const visualLayer = totalLayers - 1 - l;
      const y = startY + visualLayer * layerStepY;

      const layerCount = layerNodes.length;
      const spacingX = this.width / (layerCount + 1);

      for (let i = 0; i < layerCount; i++) {
        const node = layerNodes[i];
        const x = spacingX * (i + 1);
        this.nodePositions.set(node.id, { x, y, node });
      }
    }
  }

  /**
   * Automatically center and fit the tree within canvas view
   */
  fitToView() {
    this.scale = 1;
    this.panX = 0;
    this.panY = 0;
  }

  zoomIn() {
    this.scale = Math.min(2.5, this.scale * 1.2);
    this.render();
  }

  zoomOut() {
    this.scale = Math.max(0.4, this.scale * 0.8);
    this.render();
  }

  resetView() {
    this.fitToView();
    this.render();
  }

  /**
   * Highlight the inclusion path for a given leaf index
   * @param {number} leafIndex 
   */
  highlightProofPath(leafIndex) {
    this.highlightedPath.clear();
    if (!this.treeData || !this.treeData.nodes) return;

    let currentIndex = leafIndex;
    const totalLayers = this.treeData.levels || 1;

    for (let layerIndex = 0; layerIndex < totalLayers; layerIndex++) {
      const nodeId = `L${layerIndex}_N${currentIndex}`;
      this.highlightedPath.add(nodeId);

      // Sibling in proof
      if (layerIndex < totalLayers - 1) {
        const isEven = (currentIndex % 2 === 0);
        const siblingIndex = isEven ? currentIndex + 1 : currentIndex - 1;
        const siblingId = `L${layerIndex}_N${siblingIndex}`;
        this.highlightedPath.add(siblingId);
      }

      currentIndex = Math.floor(currentIndex / 2);
    }

    this.render();
  }

  selectNode(nodeId) {
    this.selectedNodeId = nodeId;
    const pos = this.nodePositions.get(nodeId);
    if (pos && pos.node.isLeaf) {
      this.highlightProofPath(pos.node.nodeIndex);
    }
    this.render();

    // Trigger custom event if listener exists
    if (typeof this.options.onNodeSelect === 'function' && pos) {
      this.options.onNodeSelect(pos.node);
    }
  }

  /**
   * Primary Render Loop
   */
  render() {
    const ctx = this.ctx;
    ctx.save();

    // Clear background
    ctx.clearRect(0, 0, this.width, this.height);

    // Apply pan & zoom
    ctx.translate(this.panX, this.panY);
    ctx.scale(this.scale, this.scale);

    if (!this.treeData || this.nodePositions.size === 0) {
      this.renderEmptyState();
      ctx.restore();
      return;
    }

    // 1. Draw connecting circuit edges
    this.renderEdges();

    // 2. Draw nodes
    this.renderNodes();

    // 3. Draw tooltip for hovered node
    if (this.hoveredNode) {
      this.renderTooltip(this.hoveredNode);
    }

    ctx.restore();
  }

  renderEmptyState() {
    const ctx = this.ctx;
    ctx.fillStyle = '#64748b';
    ctx.font = '14px "Inter", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('Awaiting Merkle Tree Initialization...', this.width / 2, this.height / 2);
  }

  renderEdges() {
    const ctx = this.ctx;
    if (!this.treeData.edges) return;

    for (const edge of this.treeData.edges) {
      const sourcePos = this.nodePositions.get(edge.source);
      const targetPos = this.nodePositions.get(edge.target);
      if (!sourcePos || !targetPos) continue;

      const isPathActive = this.highlightedPath.has(edge.source) && this.highlightedPath.has(edge.target);

      ctx.beginPath();
      ctx.moveTo(sourcePos.x, sourcePos.y);

      // Cyber curve
      const midY = (sourcePos.y + targetPos.y) / 2;
      ctx.bezierCurveTo(sourcePos.x, midY, targetPos.x, midY, targetPos.x, targetPos.y);

      if (isPathActive) {
        ctx.strokeStyle = this.options.activeLineColor;
        ctx.lineWidth = 3;
        ctx.shadowColor = this.options.activeLineColor;
        ctx.shadowBlur = 10;
      } else {
        ctx.strokeStyle = this.options.lineColor;
        ctx.lineWidth = 1.5;
        ctx.shadowBlur = 0;
      }

      ctx.stroke();
      ctx.shadowBlur = 0; // reset
    }
  }

  renderNodes() {
    const ctx = this.ctx;
    const r = this.options.nodeRadius;

    for (const [id, pos] of this.nodePositions.entries()) {
      const node = pos.node;
      const isHovered = (this.hoveredNode && this.hoveredNode.id === id);
      const isSelected = (this.selectedNodeId === id);
      const isPathActive = this.highlightedPath.has(id);

      // Determine colors
      let nodeColor = this.options.interiorColor;
      let label = `L${node.layerIndex}`;

      if (node.isRoot) {
        nodeColor = this.options.rootColor;
        label = 'ROOT';
      } else if (node.isLeaf) {
        nodeColor = this.options.leafColor;
        label = `Leaf ${node.nodeIndex}`;
      }

      if (isPathActive) {
        nodeColor = this.options.activeColor;
      }

      // Outer glow circle
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, r + (isHovered ? 4 : 0), 0, Math.PI * 2);
      ctx.fillStyle = '#0a0f1d';
      ctx.fill();

      ctx.lineWidth = isPathActive ? 3.5 : (isHovered || isSelected ? 2.5 : 1.5);
      ctx.strokeStyle = nodeColor;

      if (isPathActive || isHovered) {
        ctx.shadowColor = nodeColor;
        ctx.shadowBlur = 14;
      } else {
        ctx.shadowBlur = 0;
      }
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Inner accent dot
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, 4, 0, Math.PI * 2);
      ctx.fillStyle = nodeColor;
      ctx.fill();

      // Node label
      ctx.font = '10px "JetBrains Mono", monospace';
      ctx.fillStyle = '#94a3b8';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(label, pos.x, pos.y - r - 8);

      // Short hash text under node
      ctx.font = '9px "JetBrains Mono", monospace';
      ctx.fillStyle = isPathActive ? '#ffffff' : '#64748b';
      ctx.fillText(node.shortHash, pos.x, pos.y + r + 12);
    }
  }

  renderTooltip(node) {
    const pos = this.nodePositions.get(node.id);
    if (!pos) return;

    const ctx = this.ctx;
    const padding = 10;
    const text1 = `${node.isRoot ? 'MERKLE ROOT' : (node.isLeaf ? `LEAF NODE #${node.nodeIndex}` : `INTERIOR NODE L${node.layerIndex}`)}`;
    const text2 = node.hash;

    ctx.font = 'bold 11px "Inter", sans-serif';
    const w1 = ctx.measureText(text1).width;
    ctx.font = '10px "JetBrains Mono", monospace';
    const w2 = ctx.measureText(text2).width;

    const boxWidth = Math.max(w1, w2) + padding * 2;
    const boxHeight = 44;
    const boxX = Math.min(Math.max(pos.x - boxWidth / 2, 10), this.width - boxWidth - 10);
    const boxY = Math.max(pos.y - this.options.nodeRadius - boxHeight - 16, 10);

    // Box background
    ctx.fillStyle = 'rgba(8, 12, 22, 0.95)';
    ctx.strokeStyle = '#00f0ff';
    ctx.lineWidth = 1;
    ctx.shadowColor = 'rgba(0, 240, 255, 0.3)';
    ctx.shadowBlur = 12;

    ctx.beginPath();
    ctx.roundRect ? ctx.roundRect(boxX, boxY, boxWidth, boxHeight, 6) : ctx.rect(boxX, boxY, boxWidth, boxHeight);
    ctx.fill();
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Header text
    ctx.font = 'bold 10px "Inter", sans-serif';
    ctx.fillStyle = '#00f0ff';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    ctx.fillText(text1, boxX + padding, boxY + 8);

    // Hash text
    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.fillStyle = '#f1f5f9';
    ctx.fillText(text2, boxX + padding, boxY + 24);
  }
}

export default MerkleTreeCanvas;
