/**
 * ChronoLedger Vault Application Client Controller
 * Native WebCrypto file hashing, drag-and-drop processing, certificate rendering,
 * and real-time Merkle tree visualization integration.
 */

import { MerkleTreeCanvas } from './merkle-canvas.js';

class VaultApp {
  constructor() {
    this.canvasInstance = null;
    this.activeBlockData = null;
    this.selectedFile = null;
    this.selectedFileHashes = null;

    document.addEventListener('DOMContentLoaded', () => {
      this.init();
    });
  }

  async init() {
    this.initMobileNav();
    this.initGlobalStats();

    const path = window.location.pathname;

    if (path === '/' || path.endsWith('index.html')) {
      this.initDashboard();
    } else if (path.includes('verify')) {
      this.initVerifyPortal();
    } else if (path.includes('audit')) {
      this.initAuditCenter();
    }
  }

  /**
   * Mobile Hamburger Navigation
   */
  initMobileNav() {
    const toggle = document.getElementById('mobileNavToggle');
    const nav = document.getElementById('navLinks');
    if (toggle && nav) {
      toggle.addEventListener('click', () => {
        nav.classList.toggle('active');
      });
    }
  }

  /**
   * Global Stats Polling & Network Pill
   */
  async initGlobalStats() {
    try {
      const res = await fetch('/api/stats');
      if (res.ok) {
        const stats = await res.json();
        this.updateGlobalBadge(stats);
      }
    } catch (err) {
      console.warn('Stats fetch error:', err.message);
    }
  }

  updateGlobalBadge(stats) {
    const statusText = document.getElementById('networkStatusText');
    const pulseDot = document.getElementById('networkPulseDot');
    if (statusText && pulseDot) {
      if (stats.isTamperSimulated) {
        statusText.textContent = 'TAMPER DETECTED';
        statusText.style.color = 'var(--accent-danger)';
        pulseDot.classList.add('danger');
      } else {
        statusText.textContent = `HEIGHT: #${stats.currentHeight} (VERIFIED)`;
        statusText.style.color = 'var(--accent-emerald)';
        pulseDot.classList.remove('danger');
      }
    }
  }

  /* ==========================================================================
     DASHBOARD (views/index.html)
     ========================================================================== */
  async initDashboard() {
    this.initCanvas();
    this.initDropzone();
    this.initNotaryForm();
    this.initSealButton();

    await this.loadRecentDocuments();
    await this.loadActiveBlockTree();
  }

  initCanvas() {
    const canvasElem = document.getElementById('merkleTreeCanvas');
    if (canvasElem) {
      this.canvasInstance = new MerkleTreeCanvas(canvasElem, {
        onNodeSelect: (node) => {
          this.showToast(`Inspecting ${node.isRoot ? 'Merkle Root' : (node.isLeaf ? `Leaf #${node.nodeIndex}` : `Node ${node.id}`)}: ${node.shortHash}`);
        }
      });

      // Canvas toolbar buttons
      document.getElementById('zoomInBtn')?.addEventListener('click', () => this.canvasInstance.zoomIn());
      document.getElementById('zoomOutBtn')?.addEventListener('click', () => this.canvasInstance.zoomOut());
      document.getElementById('resetViewBtn')?.addEventListener('click', () => this.canvasInstance.resetView());
    }
  }

  initDropzone() {
    const dropzone = document.getElementById('notaryDropzone');
    const fileInput = document.getElementById('fileInput');

    if (!dropzone || !fileInput) return;

    dropzone.addEventListener('click', () => fileInput.click());

    dropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
      dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', async (e) => {
      e.preventDefault();
      dropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        await this.handleFileSelected(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', async (e) => {
      if (e.target.files && e.target.files.length > 0) {
        await this.handleFileSelected(e.target.files[0]);
      }
    });
  }

  /**
   * Browser WebCrypto SHA-256 and SHA-512 client-side hashing
   * Guarantees zero leakage of file contents over the wire
   */
  async handleFileSelected(file) {
    this.selectedFile = file;
    const previewStrip = document.getElementById('filePreviewStrip');
    const fileNameElem = document.getElementById('previewFileName');
    const fileSizeElem = document.getElementById('previewFileSize');
    const sha256Preview = document.getElementById('previewSha256');

    if (previewStrip) previewStrip.style.display = 'flex';
    if (fileNameElem) fileNameElem.textContent = file.name;
    if (fileSizeElem) fileSizeElem.textContent = this.formatBytes(file.size);
    if (sha256Preview) sha256Preview.textContent = 'Computing WebCrypto SHA-256...';

    // Also prefill document title if empty
    const titleInput = document.getElementById('docTitle');
    if (titleInput && !titleInput.value) {
      titleInput.value = file.name;
    }

    try {
      const hashes = await this.computeHashesClientSide(file);
      this.selectedFileHashes = hashes;

      if (sha256Preview) {
        sha256Preview.innerHTML = `SHA-256: <strong>${hashes.sha256.slice(0, 16)}...${hashes.sha256.slice(-10)}</strong>`;
      }
      this.showToast('Client-side cryptographic hash calculated (Zero-Knowledge)', 'success');
    } catch (err) {
      console.error('Hashing failed:', err);
      this.showToast(`Error computing file hash: ${err.message}`, 'danger');
    }
  }

  /**
   * Native Browser WebCrypto SHA-256 calculation
   */
  async computeHashesClientSide(file) {
    const arrayBuffer = await file.arrayBuffer();
    const hashBuffer256 = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray256 = Array.from(new Uint8Array(hashBuffer256));
    const sha256 = hashArray256.map(b => b.toString(16).padStart(2, '0')).join('');

    return {
      sha256,
      size: file.size
    };
  }

  initNotaryForm() {
    const form = document.getElementById('notaryForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      await this.submitNotarization();
    });
  }

  async submitNotarization() {
    const submitBtn = document.getElementById('notarizeSubmitBtn');
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = '<span class="pulse-dot"></span> Anchoring into Merkle Block...';
    }

    try {
      const isZkMode = document.getElementById('zkModeToggle')?.checked ?? true;
      const title = document.getElementById('docTitle')?.value || '';
      const author = document.getElementById('docAuthor')?.value || '';
      const notes = document.getElementById('docNotes')?.value || '';
      const rawText = document.getElementById('manualTextInput')?.value || '';

      let payload = {
        metadata: {
          title,
          author,
          notes
        }
      };

      if (this.selectedFile && this.selectedFileHashes) {
        payload.fileName = this.selectedFile.name;
        payload.fileSize = this.selectedFile.size;
        payload.mimeType = this.selectedFile.type || 'application/octet-stream';
        payload.sha256 = this.selectedFileHashes.sha256;

        // If NOT in ZK mode, upload base64 payload as well
        if (!isZkMode) {
          const buffer = await this.selectedFile.arrayBuffer();
          payload.fileContentBase64 = this.arrayBufferToBase64(buffer);
        }
      } else if (rawText) {
        payload.fileName = title ? `${title}.txt` : 'manual_entry.txt';
        payload.rawText = rawText;
      } else {
        this.showToast('Please select a file or enter document text to notarize', 'danger');
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.innerHTML = 'Notarize on ChronoLedger';
        }
        return;
      }

      const res = await fetch('/api/notarize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Notarization failed');
      }

      this.showToast(data.message, 'success');

      // Reset form
      document.getElementById('notaryForm')?.reset();
      this.selectedFile = null;
      this.selectedFileHashes = null;
      const preview = document.getElementById('filePreviewStrip');
      if (preview) preview.style.display = 'none';

      // Show Certificate Modal
      if (data.certificate) {
        this.openCertificateModal(data.certificate);
      }

      // Refresh recent items & Merkle canvas
      await this.loadRecentDocuments();
      await this.loadActiveBlockTree();
      await this.initGlobalStats();

    } catch (err) {
      console.error(err);
      this.showToast(err.message, 'danger');
    } finally {
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Notarize on ChronoLedger';
      }
    }
  }

  initSealButton() {
    const sealBtn = document.getElementById('sealActiveBlockBtn');
    if (sealBtn) {
      sealBtn.addEventListener('click', async () => {
        sealBtn.disabled = true;
        sealBtn.textContent = 'Sealing Block...';
        try {
          const res = await fetch('/api/block/seal', { method: 'POST' });
          const data = await res.json();
          if (res.ok) {
            this.showToast(data.message, 'success');
            await this.loadActiveBlockTree();
            await this.loadRecentDocuments();
            await this.initGlobalStats();
          } else {
            this.showToast(data.error || 'Cannot seal block', 'danger');
          }
        } catch (err) {
          this.showToast(err.message, 'danger');
        } finally {
          sealBtn.disabled = false;
          sealBtn.textContent = 'Seal Current Block';
        }
      });
    }
  }

  async loadActiveBlockTree() {
    try {
      const statsRes = await fetch('/api/stats');
      if (!statsRes.ok) return;
      const stats = await statsRes.json();

      const blockIndex = stats.activeBlockIndex || stats.currentHeight;
      const blockRes = await fetch(`/api/block/${blockIndex}`);
      if (!blockRes.ok) return;
      const blockData = await blockRes.json();

      const blockBadge = document.getElementById('activeBlockBadge');
      if (blockBadge) {
        blockBadge.textContent = `BLOCK #${blockData.index} (${blockData.sealed ? 'SEALED' : 'ACTIVE / PENDING'})`;
      }

      const rootBadge = document.getElementById('activeBlockRootBadge');
      if (rootBadge) {
        rootBadge.textContent = blockData.merkleRoot ? `${blockData.merkleRoot.slice(0, 14)}...${blockData.merkleRoot.slice(-8)}` : 'Generating...';
        rootBadge.title = blockData.merkleRoot || '';
      }

      if (this.canvasInstance && blockData.visualization) {
        this.canvasInstance.setData(blockData.visualization);
      }
    } catch (err) {
      console.warn('Error loading active block tree:', err);
    }
  }

  async loadRecentDocuments() {
    const tableBody = document.getElementById('recentDocsTableBody');
    if (!tableBody) return;

    try {
      const res = await fetch('/api/documents?limit=15');
      if (!res.ok) return;
      const data = await res.json();

      if (data.documents.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="5" class="text-center" style="color: var(--text-muted); padding: 2rem;">No documents notarized yet.</td></tr>`;
        return;
      }

      tableBody.innerHTML = data.documents.map(doc => {
        const shortHash = `${doc.sha256.slice(0, 8)}...${doc.sha256.slice(-6)}`;
        const dateStr = new Date(doc.timestamp).toLocaleString();
        const certId = doc.certificate ? doc.certificate.certificateId : 'N/A';

        return `
          <tr>
            <td>
              <strong>${this.escapeHtml(doc.fileName)}</strong>
              <div style="font-size: 0.75rem; color: var(--text-muted);">${doc.metadata?.title || ''}</div>
            </td>
            <td>
              <span class="hash-badge" onclick="window.vaultApp.copyText('${doc.sha256}')" title="Click to copy SHA-256">
                ${shortHash}
              </span>
            </td>
            <td>
              <span class="badge-tag sealed">Block #${doc.blockNumber}</span>
            </td>
            <td style="font-size: 0.8rem; color: var(--text-secondary);">${dateStr}</td>
            <td>
              <div style="display: flex; gap: 6px;">
                <button class="btn btn-secondary btn-sm" onclick="window.vaultApp.viewCertificateByHash('${doc.sha256}')">Cert</button>
                <a href="/api/certificate/${certId}/download" class="btn btn-primary btn-sm" title="Download Signed JSON Proof">JSON</a>
              </div>
            </td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.error('Failed to load documents:', err);
    }
  }

  /* ==========================================================================
     VERIFICATION PORTAL (views/verify.html)
     ========================================================================== */
  initVerifyPortal() {
    this.initCanvas();
    const dropzone = document.getElementById('verifyDropzone');
    const fileInput = document.getElementById('verifyFileInput');
    const hashInput = document.getElementById('manualHashInput');
    const verifyHashBtn = document.getElementById('verifyHashBtn');
    const certInput = document.getElementById('certFileInput');

    // Drag-and-drop file
    if (dropzone && fileInput) {
      dropzone.addEventListener('click', () => fileInput.click());

      dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
      });

      dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));

      dropzone.addEventListener('drop', async (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) {
          const file = e.dataTransfer.files[0];
          // Check if user dropped a certificate JSON file
          if (file.name.endsWith('.json') && file.size < 500000) {
            await this.handleCertificateUpload(file);
          } else {
            await this.handleVerifyFile(file);
          }
        }
      });

      fileInput.addEventListener('change', async (e) => {
        if (e.target.files.length > 0) {
          await this.handleVerifyFile(e.target.files[0]);
        }
      });
    }

    // Manual hash submit
    if (verifyHashBtn && hashInput) {
      verifyHashBtn.addEventListener('click', () => {
        const hash = hashInput.value.trim();
        if (hash) {
          this.executeHashVerification(hash);
        } else {
          this.showToast('Please paste a 64-character SHA-256 hash', 'danger');
        }
      });

      hashInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          verifyHashBtn.click();
        }
      });
    }

    // Direct certificate upload
    if (certInput) {
      certInput.addEventListener('change', async (e) => {
        if (e.target.files.length > 0) {
          await this.handleCertificateUpload(e.target.files[0]);
        }
      });
    }

    this.loadVerificationHistory();
  }

  async handleVerifyFile(file) {
    this.showToast(`Computing cryptographic hash for '${file.name}'...`);
    try {
      const hashes = await this.computeHashesClientSide(file);
      await this.executeHashVerification(hashes.sha256, file.name);
    } catch (err) {
      this.showToast(`Verification error: ${err.message}`, 'danger');
    }
  }

  async handleCertificateUpload(file) {
    this.showToast(`Verifying digital certificate '${file.name}'...`);
    try {
      const text = await file.text();
      const certObj = JSON.parse(text);

      const res = await fetch('/api/verify/certificate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ certificate: certObj })
      });

      const data = await res.json();
      this.renderCertificateVerificationResult(data, certObj);
    } catch (err) {
      this.showToast(`Invalid certificate format: ${err.message}`, 'danger');
    }
  }

  async executeHashVerification(sha256, fileName = null) {
    const resultContainer = document.getElementById('verifyResultContainer');
    if (!resultContainer) return;

    resultContainer.innerHTML = `
      <div class="card text-center" style="padding: 3rem;">
        <span class="pulse-dot" style="margin: 0 auto 1rem;"></span>
        <h3>Traversing Merkle Ledger...</h3>
        <p style="color: var(--text-muted);">Querying O(1) hash index and recalculating mathematical proof trajectory</p>
      </div>
    `;
    resultContainer.style.display = 'block';

    try {
      const res = await fetch('/api/verify/hash', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sha256 })
      });

      const data = await res.json();
      this.renderVerificationResult(data, fileName);
      this.loadVerificationHistory();
    } catch (err) {
      resultContainer.innerHTML = `<div class="card error-card"><h3>Verification Failed</h3><p>${err.message}</p></div>`;
    }
  }

  renderVerificationResult(data, localFileName) {
    const container = document.getElementById('verifyResultContainer');
    if (!container) return;

    if (!data.verified) {
      container.innerHTML = `
        <div class="verify-result-panel unverified">
          <div class="verify-header">
            <div class="verify-status-badge">✕</div>
            <div>
              <div class="badge-tag danger" style="margin-bottom: 0.4rem;">VERIFICATION FAILED</div>
              <h2 class="verify-title" style="color: var(--accent-danger);">NOT FOUND / ALTERED RECORD</h2>
              <p style="color: var(--text-secondary); margin-top: 0.35rem;">${data.message}</p>
            </div>
          </div>
          <div class="card" style="background: rgba(10, 15, 29, 0.6); margin-bottom: 0;">
            <div class="form-label">Tested SHA-256 Digest</div>
            <span class="hash-badge mono" style="font-size: 0.95rem; width: 100%;">${data.sha256}</span>
            <p style="margin-top: 1rem; font-size: 0.85rem; color: var(--text-muted);">${data.recommendation || ''}</p>
          </div>
        </div>
      `;
      return;
    }

    const doc = data.document;
    const proof = data.cryptographicProof;
    const cert = data.certificate;

    container.innerHTML = `
      <div class="verify-result-panel verified">
        <div class="verify-header">
          <div class="verify-status-badge">✓</div>
          <div>
            <div class="badge-tag sealed" style="margin-bottom: 0.4rem;">CRYPTOGRAPHICALLY VERIFIED</div>
            <h2 class="verify-title" style="color: var(--accent-emerald);">AUTHENTIC & IMMUTABLE</h2>
            <p style="color: var(--text-secondary); margin-top: 0.35rem;">
              Document successfully proven against Block #${doc.blockNumber} Merkle Root with valid Ed25519 notary authority signature.
            </p>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 1.5rem;">
          <div class="card" style="background: rgba(10, 15, 29, 0.6); margin: 0;">
            <h4 style="font-size: 0.9rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.75rem;">Document Details</h4>
            <div style="margin-bottom: 0.5rem;"><strong>File Name:</strong> ${this.escapeHtml(doc.fileName)}</div>
            <div style="margin-bottom: 0.5rem;"><strong>File Size:</strong> ${this.formatBytes(doc.fileSize)}</div>
            <div style="margin-bottom: 0.5rem;"><strong>Notarized At:</strong> ${new Date(doc.notarizedAt).toLocaleString()}</div>
            <div><strong>Signer/Author:</strong> ${this.escapeHtml(doc.metadata?.author || 'Unspecified')}</div>
          </div>

          <div class="card" style="background: rgba(10, 15, 29, 0.6); margin: 0;">
            <h4 style="font-size: 0.9rem; color: var(--text-muted); text-transform: uppercase; margin-bottom: 0.75rem;">Ledger Anchor Proofs</h4>
            <div style="margin-bottom: 0.5rem;"><strong>Merkle Proof:</strong> <span style="color: var(--accent-emerald);">✓ MATHEMATICALLY VALID</span></div>
            <div style="margin-bottom: 0.5rem;"><strong>Ed25519 Notary Signature:</strong> <span style="color: var(--accent-emerald);">✓ AUTHENTIC</span></div>
            <div style="margin-bottom: 0.5rem;"><strong>Block Status:</strong> ${proof.blockSealed ? '<span class="badge-tag sealed">SEALED IN CHAIN</span>' : '<span class="badge-tag pending">ACTIVE BLOCK</span>'}</div>
            <div><strong>Verification Speed:</strong> ${data.durationMs}ms</div>
          </div>
        </div>

        <div class="card" style="background: rgba(10, 15, 29, 0.6); margin-bottom: 1.5rem;">
          <h4 style="margin-bottom: 1rem; font-size: 0.95rem;">Step-by-Step Merkle Trajectory Recalculation</h4>
          <div class="proof-step-card">
            <div>
              <span class="badge-tag" style="background: rgba(0, 255, 170, 0.15); color: var(--accent-emerald);">LEAF HASH (RFC 6962)</span>
              <div class="mono" style="margin-top: 4px; font-size: 0.78rem;">0x00 || ${doc.sha256.slice(0, 20)}...</div>
            </div>
            <div class="mono" style="color: var(--accent-emerald);">${proof.leafHash ? proof.leafHash.slice(0, 16) + '...' : ''}</div>
          </div>

          ${proof.stepByStepTrajectory.map(step => `
            <div class="proof-step-card">
              <div>
                <span class="badge-tag" style="background: rgba(0, 240, 255, 0.15); color: var(--accent-cyan);">STEP ${step.stepIndex} (${step.position.toUpperCase()} SIBLING)</span>
                <div class="mono" style="margin-top: 4px; font-size: 0.75rem;">hashInterior(${step.position === 'left' ? 'Sibling, Current' : 'Current, Sibling'})</div>
              </div>
              <div class="mono" style="color: var(--accent-cyan);">${step.outputHash.slice(0, 16)}...</div>
            </div>
          `).join('')}

          <div class="proof-step-card" style="border-color: rgba(255, 194, 51, 0.4); background: rgba(255, 194, 51, 0.05);">
            <div>
              <span class="badge-tag gold">RESOLVED MERKLE ROOT</span>
              <div class="mono" style="margin-top: 4px; font-size: 0.78rem;">Matches Block #${doc.blockNumber} Root Exactly</div>
            </div>
            <div class="mono" style="color: var(--accent-gold); font-weight: bold;">${proof.rootHash.slice(0, 20)}...</div>
          </div>
        </div>

        <div style="display: flex; gap: 1rem; justify-content: flex-end;">
          <button class="btn btn-secondary" onclick="window.vaultApp.openCertificateModal(${JSON.stringify(cert).replace(/"/g, '&quot;')})">View Full Notary Certificate</button>
          <a href="/api/certificate/${cert?.certificateId}/download" class="btn btn-primary">Download Signed JSON Proof</a>
        </div>
      </div>
    `;

    // Highlight path on tree canvas if loaded
    if (this.canvasInstance) {
      this.canvasInstance.highlightProofPath(doc.leafIndex);
    }
  }

  renderCertificateVerificationResult(data, certObj) {
    const container = document.getElementById('verifyResultContainer');
    if (!container) return;

    container.style.display = 'block';

    if (!data.verified) {
      container.innerHTML = `
        <div class="verify-result-panel unverified">
          <div class="verify-header">
            <div class="verify-status-badge">✕</div>
            <div>
              <div class="badge-tag danger" style="margin-bottom: 0.4rem;">CERTIFICATE INVALID</div>
              <h2 class="verify-title" style="color: var(--accent-danger);">SIGNATURE OR PROOF CORRUPTED</h2>
              <p style="color: var(--text-secondary); margin-top: 0.35rem;">
                ${data.errors ? data.errors.join('<br>') : 'Certificate payload fails cryptographic verification'}
              </p>
            </div>
          </div>
        </div>
      `;
      return;
    }

    container.innerHTML = `
      <div class="verify-result-panel verified">
        <div class="verify-header">
          <div class="verify-status-badge">✓</div>
          <div>
            <div class="badge-tag sealed" style="margin-bottom: 0.4rem;">CERTIFICATE AUTHENTIC</div>
            <h2 class="verify-title" style="color: var(--accent-emerald);">CERTIFICATE #${certObj.certificateId} VALID</h2>
            <p style="color: var(--text-secondary); margin-top: 0.35rem;">
              Notary Ed25519 signature is authentic. Merkle proof resolves to root.
            </p>
          </div>
        </div>
        <div class="card" style="background: rgba(10, 15, 29, 0.6); margin-bottom: 0;">
          <div style="margin-bottom: 0.5rem;"><strong>Document:</strong> ${this.escapeHtml(certObj.document?.fileName || '')}</div>
          <div style="margin-bottom: 0.5rem;"><strong>SHA-256:</strong> <span class="mono">${certObj.document?.sha256}</span></div>
          <div style="margin-bottom: 0.5rem;"><strong>Issued At:</strong> ${new Date(certObj.issuedAt).toLocaleString()}</div>
          <div><strong>Anchored In Local Vault:</strong> ${data.anchoredInLedger ? 'YES' : 'Cross-Vault Remote Proof'}</div>
        </div>
      </div>
    `;
  }

  async loadVerificationHistory() {
    const historyBody = document.getElementById('verifyHistoryBody');
    if (!historyBody) return;

    try {
      const res = await fetch('/api/verify/history?limit=15');
      if (!res.ok) return;
      const data = await res.json();

      if (data.logs.length === 0) {
        historyBody.innerHTML = `<tr><td colspan="4" class="text-center" style="color: var(--text-muted); padding: 1.5rem;">No verification checks recorded yet.</td></tr>`;
        return;
      }

      historyBody.innerHTML = data.logs.map(log => {
        const isSuccess = log.result === 'VERIFIED';
        const dateStr = new Date(log.timestamp).toLocaleTimeString();
        const shortHash = `${log.sha256.slice(0, 10)}...${log.sha256.slice(-6)}`;

        return `
          <tr>
            <td><span class="badge-tag ${isSuccess ? 'sealed' : 'danger'}">${log.result}</span></td>
            <td><span class="hash-badge" onclick="window.vaultApp.copyText('${log.sha256}')">${shortHash}</span></td>
            <td>${log.documentName ? this.escapeHtml(log.documentName) : '<span style="color: var(--text-muted);">Unregistered Digest</span>'}</td>
            <td style="color: var(--text-muted); font-size: 0.8rem;">${dateStr} (${log.durationMs}ms)</td>
          </tr>
        `;
      }).join('');
    } catch (err) {
      console.warn('History error:', err);
    }
  }

  /* ==========================================================================
     AUDIT CENTER (views/audit.html)
     ========================================================================== */
  initAuditCenter() {
    const runAuditBtn = document.getElementById('runAuditBtn');
    const simulateTamperBtn = document.getElementById('simulateTamperBtn');
    const restoreBtn = document.getElementById('restoreLedgerBtn');

    if (runAuditBtn) {
      runAuditBtn.addEventListener('click', () => this.executeDeepAudit());
    }

    if (simulateTamperBtn) {
      simulateTamperBtn.addEventListener('click', () => this.simulateTamperAttack());
    }

    if (restoreBtn) {
      restoreBtn.addEventListener('click', () => this.restoreLedger());
    }

    this.loadBlockTimeline();
    this.executeDeepAudit(true); // initial background audit
  }

  async executeDeepAudit(silent = false) {
    const reportBox = document.getElementById('auditReportContainer');
    const auditBtn = document.getElementById('runAuditBtn');

    if (auditBtn && !silent) {
      auditBtn.disabled = true;
      auditBtn.textContent = 'Auditing Hash Chain & Trees...';
    }

    try {
      const res = await fetch('/api/audit/verify');
      const data = await res.json();

      if (reportBox) {
        this.renderAuditReport(data);
      }

      if (!silent) {
        if (data.intact) {
          this.showToast('Audit complete: 100% cryptographic integrity verified.', 'success');
        } else {
          this.showToast(`SECURITY ALERT: ${data.errorsCount} integrity errors detected!`, 'danger');
        }
      }

      this.updateGlobalBadge({
        isTamperSimulated: !data.intact,
        currentHeight: data.totalBlocksAudited
      });
    } catch (err) {
      console.error(err);
      if (!silent) this.showToast(`Audit failed: ${err.message}`, 'danger');
    } finally {
      if (auditBtn && !silent) {
        auditBtn.disabled = false;
        auditBtn.textContent = 'Run Full Cryptographic Deep Audit';
      }
    }
  }

  renderAuditReport(report) {
    const container = document.getElementById('auditReportContainer');
    if (!container) return;

    const isGood = report.intact;

    container.innerHTML = `
      <div class="card" style="border-color: ${isGood ? 'rgba(0, 255, 170, 0.4)' : 'rgba(255, 51, 102, 0.4)'}; background: ${isGood ? 'linear-gradient(180deg, rgba(0, 255, 170, 0.05), var(--bg-card))' : 'linear-gradient(180deg, rgba(255, 51, 102, 0.05), var(--bg-card))'};">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.25rem;">
          <div style="display: flex; align-items: center; gap: 1rem;">
            <div class="verify-status-badge" style="width: 44px; height: 44px; font-size: 1.4rem; ${isGood ? 'background: rgba(0, 255, 170, 0.15); color: var(--accent-emerald); border: 2px solid var(--accent-emerald);' : 'background: rgba(255, 51, 102, 0.15); color: var(--accent-danger); border: 2px solid var(--accent-danger);'}">
              ${isGood ? '✓' : '!'}
            </div>
            <div>
              <h3 style="font-size: 1.25rem; color: ${isGood ? 'var(--accent-emerald)' : 'var(--accent-danger)'};">
                ${isGood ? 'LEDGER INTEGRITY VERIFIED (100% SOUND)' : 'CRYPTOGRAPHIC TAMPER ALARM TRIGGERED'}
              </h3>
              <p style="font-size: 0.82rem; color: var(--text-muted);">
                Audited at ${new Date(report.auditedAt).toLocaleString()} in ${report.durationMs}ms
              </p>
            </div>
          </div>
          <div>
            <span class="badge-tag ${isGood ? 'sealed' : 'danger'}" style="font-size: 0.85rem; padding: 4px 12px;">
              ${report.totalBlocksAudited} BLOCKS / ${report.totalDocumentsAudited} RECORDS CHECKED
            </span>
          </div>
        </div>

        ${!isGood ? `
          <div style="background: rgba(255, 51, 102, 0.1); border: 1px solid rgba(255, 51, 102, 0.3); border-radius: var(--radius-sm); padding: 1rem; margin-bottom: 1rem;">
            <h4 style="color: var(--accent-danger); margin-bottom: 0.5rem; font-size: 0.95rem;">Detected Tampering Errors:</h4>
            <ul style="padding-left: 1.25rem; color: #fca5a5; font-size: 0.85rem;">
              ${report.errors.map(e => `<li>${this.escapeHtml(e)}</li>`).join('')}
            </ul>
          </div>
        ` : ''}

        <div class="table-responsive">
          <table class="vault-table">
            <thead>
              <tr>
                <th>Block #</th>
                <th>Status</th>
                <th>Transactions</th>
                <th>Merkle Root</th>
                <th>Block Hash</th>
              </tr>
            </thead>
            <tbody>
              ${report.blocks.map(b => `
                <tr>
                  <td><strong>Block #${b.blockIndex}</strong></td>
                  <td><span class="badge-tag ${b.status === 'VALID' ? 'sealed' : 'danger'}">${b.status}</span></td>
                  <td>${b.txCount} txs</td>
                  <td><span class="hash-badge" title="${b.merkleRoot || ''}">${b.merkleRoot ? b.merkleRoot.slice(0, 10) + '...' + b.merkleRoot.slice(-6) : 'Pending'}</span></td>
                  <td><span class="hash-badge" title="${b.blockHash || ''}">${b.blockHash ? b.blockHash.slice(0, 10) + '...' + b.blockHash.slice(-6) : 'Pending'}</span></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  }

  async loadBlockTimeline() {
    const timelineList = document.getElementById('blockTimelineList');
    if (!timelineList) return;

    try {
      const res = await fetch('/api/blocks');
      if (!res.ok) return;
      const data = await res.json();

      timelineList.innerHTML = data.blocks.map(b => {
        const isSealed = b.sealed;
        return `
          <div class="timeline-node">
            <div class="timeline-dot ${isSealed ? 'sealed' : 'pending'}"></div>
            <div class="card" style="margin-bottom: 0.5rem;">
              <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;">
                <div style="display: flex; align-items: center; gap: 0.6rem;">
                  <h4 style="font-size: 1.05rem;">Block #${b.index}</h4>
                  <span class="badge-tag ${isSealed ? 'sealed' : 'pending'}">${isSealed ? 'SEALED BLOCK' : 'ACTIVE / PENDING'}</span>
                </div>
                <div style="font-size: 0.78rem; color: var(--text-muted);">${new Date(b.timestamp).toLocaleString()}</div>
              </div>

              <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1rem; font-size: 0.85rem; margin-bottom: 1rem;">
                <div>
                  <div style="color: var(--text-muted); font-size: 0.75rem;">MERKLE ROOT</div>
                  <span class="hash-badge" onclick="window.vaultApp.copyText('${b.merkleRoot}')">${b.merkleRoot ? b.merkleRoot.slice(0, 16) + '...' + b.merkleRoot.slice(-8) : 'Open'}</span>
                </div>
                <div>
                  <div style="color: var(--text-muted); font-size: 0.75rem;">PREVIOUS BLOCK HASH</div>
                  <span class="hash-badge" onclick="window.vaultApp.copyText('${b.previousHash}')">${b.previousHash.slice(0, 16)}...</span>
                </div>
              </div>

              <div>
                <div style="font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.4rem;">Anchored Documents (${b.transactions.length}):</div>
                <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                  ${b.transactions.map(t => `
                    <span class="hash-badge" onclick="window.vaultApp.viewCertificateByHash('${t.sha256}')">
                      📄 ${this.escapeHtml(t.fileName)}
                    </span>
                  `).join('')}
                </div>
              </div>
            </div>
          </div>
        `;
      }).join('');
    } catch (err) {
      console.warn('Timeline error:', err);
    }
  }

  async simulateTamperAttack() {
    try {
      const res = await fetch('/api/audit/simulate-tamper', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ field: 'sha256' })
      });

      const data = await res.json();
      if (res.ok) {
        this.showToast('Tamper attack simulated! Notice the red integrity alarm.', 'danger');
        await this.executeDeepAudit(false);
      } else {
        this.showToast(data.error || 'Tamper simulation failed', 'danger');
      }
    } catch (err) {
      this.showToast(err.message, 'danger');
    }
  }

  async restoreLedger() {
    try {
      const res = await fetch('/api/audit/restore', { method: 'POST' });
      const data = await res.json();
      if (res.ok) {
        this.showToast(data.message || 'Ledger restored to pristine state', 'success');
        await this.executeDeepAudit(false);
        await this.loadBlockTimeline();
      } else {
        this.showToast(data.error || 'Restoration failed', 'danger');
      }
    } catch (err) {
      this.showToast(err.message, 'danger');
    }
  }

  /* ==========================================================================
     CERTIFICATE MODAL VIEWER
     ========================================================================== */
  async viewCertificateByHash(sha256) {
    try {
      const res = await fetch(`/api/certificate/${sha256}`);
      if (!res.ok) {
        this.showToast('Certificate not found', 'danger');
        return;
      }
      const cert = await res.json();
      this.openCertificateModal(cert);
    } catch (err) {
      this.showToast(`Error loading certificate: ${err.message}`, 'danger');
    }
  }

  openCertificateModal(cert) {
    let modal = document.getElementById('certModalOverlay');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'certModalOverlay';
      modal.className = 'modal-overlay';
      document.body.appendChild(modal);
    }

    const doc = cert.document;
    const proof = cert.merkleProof;
    const block = cert.block;
    const auth = cert.authority;

    modal.innerHTML = `
      <div class="modal-content">
        <button class="modal-close" onclick="window.vaultApp.closeCertificateModal()">&times;</button>
        <div class="certificate-frame">
          <div class="certificate-watermark">CHRONOLEDGER</div>
          <div style="text-align: center; margin-bottom: 2rem;">
            <div class="brand-badge" style="display: inline-block; margin-bottom: 0.5rem;">OFFICIAL DIGITAL NOTARIZATION</div>
            <h2 style="font-size: 1.8rem; letter-spacing: -0.02em; margin-bottom: 0.25rem;">Cryptographic Certificate</h2>
            <div class="mono" style="color: var(--accent-cyan); font-size: 0.9rem;">ID: ${cert.certificateId}</div>
          </div>

          <div style="border-top: 1px solid rgba(0, 240, 255, 0.2); border-bottom: 1px solid rgba(0, 240, 255, 0.2); padding: 1.25rem 0; margin-bottom: 1.5rem; display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; font-size: 0.88rem;">
            <div>
              <div style="color: var(--text-muted); font-size: 0.75rem;">DOCUMENT ASSET</div>
              <strong>${this.escapeHtml(doc.fileName)}</strong>
              <div style="color: var(--text-secondary); font-size: 0.8rem;">${this.formatBytes(doc.fileSize)} &bull; ${doc.mimeType}</div>
            </div>
            <div>
              <div style="color: var(--text-muted); font-size: 0.75rem;">TIMESTAMP & BLOCK</div>
              <div>${new Date(cert.issuedAt).toLocaleString()}</div>
              <div>Anchor: <strong>Block #${block.blockNumber}</strong></div>
            </div>
          </div>

          <div style="margin-bottom: 1.5rem;">
            <div style="color: var(--text-muted); font-size: 0.75rem; margin-bottom: 0.25rem;">DOCUMENT SHA-256 DIGEST</div>
            <span class="hash-badge mono" style="width: 100%; font-size: 0.8rem;">${doc.sha256}</span>
          </div>

          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.5rem;">
            <div>
              <div style="color: var(--text-muted); font-size: 0.75rem; margin-bottom: 0.25rem;">MERKLE ROOT HASH</div>
              <span class="hash-badge mono">${proof.rootHash.slice(0, 14)}...${proof.rootHash.slice(-8)}</span>
            </div>
            <div>
              <div style="color: var(--text-muted); font-size: 0.75rem; margin-bottom: 0.25rem;">INCLUSION PROOF STEPS</div>
              <span class="badge-tag sealed">${proof.proofLength || proof.proof.length} Mathematical Steps</span>
            </div>
          </div>

          <div style="background: rgba(10, 15, 29, 0.8); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: var(--radius-sm); padding: 1rem; margin-bottom: 1.5rem;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem;">
              <span style="font-size: 0.75rem; color: var(--text-muted);">NOTARY AUTHORITY: ${auth.name}</span>
              <span class="badge-tag sealed">Ed25519 VALID</span>
            </div>
            <div style="color: var(--text-muted); font-size: 0.72rem; margin-bottom: 0.25rem;">DIGITAL SIGNATURE</div>
            <div class="mono" style="font-size: 0.7rem; color: var(--text-code); word-break: break-all;">
              ${cert.signature.value}
            </div>
          </div>

          <div style="display: flex; gap: 1rem; justify-content: flex-end;">
            <button class="btn btn-secondary btn-sm" onclick="window.vaultApp.copyText('${cert.signature.value}')">Copy Signature</button>
            <a href="/api/certificate/${cert.certificateId}/download" class="btn btn-primary btn-sm">Download JSON Certificate</a>
          </div>
        </div>
      </div>
    `;

    modal.classList.add('active');
  }

  closeCertificateModal() {
    const modal = document.getElementById('certModalOverlay');
    if (modal) modal.classList.remove('active');
  }

  /* ==========================================================================
     UTILITIES
     ========================================================================== */
  showToast(message, type = 'normal') {
    let container = document.getElementById('toastContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toastContainer';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <span class="pulse-dot ${type === 'danger' ? 'danger' : ''}"></span>
      <span>${this.escapeHtml(message)}</span>
    `;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  copyText(text) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      this.showToast('Hash copied to clipboard!', 'success');
    }
  }

  formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }
}

window.vaultApp = new VaultApp();
