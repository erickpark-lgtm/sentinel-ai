/**
 * SentinelAI Web Engine (app.js)
 * Real-Time SOC 2 Readiness Scanning Simulation & Interactive Checkout
 */

document.addEventListener('DOMContentLoaded', () => {
  const repoInput = document.getElementById('repo-input');
  const btnScan = document.getElementById('btn-scan');
  const scanTerminal = document.getElementById('scan-terminal');
  const scanResults = document.getElementById('scan-results');
  const terminalLogs = document.getElementById('terminal-logs');
  const scoreNum = document.getElementById('score-num');
  const scoreBadge = document.getElementById('score-badge');
  const checklistContainer = document.getElementById('checklist-container');
  const presetChips = document.querySelectorAll('.preset-chip');
  
  // Checkout Modal elements
  const modalOverlay = document.getElementById('modal-overlay');
  const modalClose = document.getElementById('modal-close');
  const modalPlanName = document.getElementById('modal-plan-name');
  const modalPlanPrice = document.getElementById('modal-plan-price');
  const btnCheckout = document.getElementById('btn-checkout-confirm');

  // Realistic Simulation Scenarios
  const scenarios = {
    'connex-system/core-backend': {
      score: 94,
      status: 'SOC 2 Type 2 Audit Ready',
      statusClass: 'tag-pass',
      checks: [
        { code: 'CC6.1', name: 'Identity & Access Management (MFA)', desc: 'Hardware MFA enforced via Google Workspace & GCP IAM', status: 'PASS' },
        { code: 'CC6.6', name: 'Network Encryption In-Transit', desc: 'TLS 1.3 enforced on all ALB ingress endpoints; zero TLS 1.0/1.1 traffic', status: 'PASS' },
        { code: 'CC7.1', name: 'Vulnerability Management', desc: 'Dependabot & Trivy scanners running in CI/CD pipeline; 0 Critical CVEs', status: 'PASS' },
        { code: 'CC8.1', name: 'Branch Protection & Peer Reviews', desc: 'Main branch requires 1+ peer review approval & signed commits', status: 'PASS' },
        { code: 'CC9.2', name: 'Third-Party Vendor Risk & CUEC Mapping', desc: 'Google Cloud & GitHub SOC 2 Type 2 reports collected & CUEC verified', status: 'PASS' }
      ]
    },
    'fintech-pilot/api-server': {
      score: 68,
      status: 'High Audit Risk (Action Required)',
      statusClass: 'tag-fail',
      checks: [
        { code: 'CC6.1', name: 'Identity & Access Management (MFA)', desc: '2 active AWS IAM admin accounts found without hardware MFA', status: 'FAIL' },
        { code: 'CC6.6', name: 'Network Encryption In-Transit', desc: 'Legacy TLS 1.1 cipher suites allowed on legacy public endpoint', status: 'WARN' },
        { code: 'CC7.1', name: 'Vulnerability Management', desc: '4 High severity npm package CVEs detected in package-lock.json', status: 'FAIL' },
        { code: 'CC8.1', name: 'Branch Protection & Peer Reviews', desc: 'Enforced branch protection active; 2 PRs merged without review approval', status: 'WARN' },
        { code: 'CC9.2', name: 'Third-Party Vendor Risk & CUEC Mapping', desc: 'Vendor risk assessment register missing Q3 annual baseline review', status: 'FAIL' }
      ]
    },
    'default': {
      score: 76,
      status: 'Moderate Audit Gap Detected',
      statusClass: 'tag-warn',
      checks: [
        { code: 'CC6.1', name: 'Identity & Access Management (MFA)', desc: 'Cloud IAM SSO active; Service Account keys older than 90 days detected', status: 'WARN' },
        { code: 'CC6.6', name: 'Network Encryption In-Transit', desc: 'TLS 1.3 encrypted on load balancer', status: 'PASS' },
        { code: 'CC7.1', name: 'Vulnerability Management', desc: 'Automated CI/CD security scanning active; minor vulnerabilities only', status: 'PASS' },
        { code: 'CC8.1', name: 'Branch Protection & Peer Reviews', desc: 'Main branch protected; PR review dismissal rules missing', status: 'WARN' },
        { code: 'CC9.2', name: 'Third-Party Vendor Risk & CUEC Mapping', desc: 'Missing vendor CUEC mapping documentation for cloud providers', status: 'FAIL' }
      ]
    }
  };

  // Preset click handling
  presetChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const repo = chip.getAttribute('data-repo');
      repoInput.value = repo;
      triggerScan(repo);
    });
  });

  // Scan Button Click
  btnScan.addEventListener('click', () => {
    const repo = repoInput.value.trim() || 'default-repo/app';
    triggerScan(repo);
  });

  function triggerScan(repoKey) {
    scanResults.style.display = 'none';
    scanTerminal.style.display = 'block';
    terminalLogs.innerHTML = '';
    
    btnScan.disabled = true;
    btnScan.textContent = 'Scanning...';

    const logSteps = [
      `Initiating read-only API connection to [${repoKey}]...`,
      `[CC6.1] Querying IAM identity center & MFA enforcement state...`,
      `[CC6.6] Auditing TLS cipher suites & SSL/TLS certificate chain...`,
      `[CC7.1] Inspecting package-lock dependencies & CVE vulnerability alerts...`,
      `[CC8.1] Validating GitHub branch protection rules & PR approval hooks...`,
      `[CC9.2] Extracting Third-Party Vendor Risk Register & CUEC obligations...`,
      `Synthesizing AICPA Trust Services Criteria assessment score...`
    ];

    let stepIdx = 0;
    const interval = setInterval(() => {
      if (stepIdx < logSteps.length) {
        const line = document.createElement('div');
        line.className = 'terminal-line';
        line.innerHTML = `<span class="terminal-spinner">⟳</span> <span>${logSteps[stepIdx]}</span>`;
        terminalLogs.appendChild(line);
        stepIdx++;
      } else {
        clearInterval(interval);
        setTimeout(() => {
          renderResults(repoKey);
          btnScan.disabled = false;
          btnScan.textContent = 'Scan Repository';
        }, 500);
      }
    }, 400);
  }

  function renderResults(repoKey) {
    scanTerminal.style.display = 'none';
    scanResults.style.display = 'grid';

    const data = scenarios[repoKey] || scenarios['default'];
    scoreNum.textContent = data.score;
    scoreBadge.textContent = data.status;
    scoreBadge.className = `score-status-badge ${data.statusClass}`;

    checklistContainer.innerHTML = '';
    data.checks.forEach(item => {
      const tagClass = item.status === 'PASS' ? 'tag-pass' : (item.status === 'FAIL' ? 'tag-fail' : 'tag-warn');
      const div = document.createElement('div');
      div.className = 'check-item';
      div.innerHTML = `
        <div class="check-meta">
          <span class="check-code">${item.code}</span>
          <div>
            <div class="check-name">${item.name}</div>
            <div class="check-desc">${item.desc}</div>
          </div>
        </div>
        <span class="status-tag ${tagClass}">${item.status}</span>
      `;
      checklistContainer.appendChild(div);
    });
  }

  // Pricing Modal Logic
  document.querySelectorAll('.btn-plan').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const plan = e.target.getAttribute('data-plan') || 'Starter';
      const price = e.target.getAttribute('data-price') || '$499';
      modalPlanName.textContent = `${plan} Plan`;
      modalPlanPrice.textContent = `${price} / month`;
      modalOverlay.style.display = 'flex';
    });
  });

  // Checkout Modal Events
  modalClose.addEventListener('click', () => {
    modalOverlay.style.display = 'none';
  });

  modalOverlay.addEventListener('click', (e) => {
    if (e.target === modalOverlay) modalOverlay.style.display = 'none';
  });

  btnCheckout.addEventListener('click', () => {
    btnCheckout.textContent = 'Processing Stripe Payment...';
    btnCheckout.disabled = true;
    setTimeout(() => {
      alert('🎉 SentinelAI Instant Activation Successful!\n\nYour 24/7 Autonomous vCISO agent is now connected and monitoring your repositories.');
      modalOverlay.style.display = 'none';
      btnCheckout.textContent = 'Complete Instant Activation';
      btnCheckout.disabled = false;
    }, 1200);
  });

  // Dossier Modal Elements
  const dossierModalOverlay = document.getElementById('dossier-modal-overlay');
  const dossierModalClose = document.getElementById('dossier-modal-close');
  const btnCloseDossier = document.getElementById('btn-close-dossier');
  const heroBtnEvidence = document.getElementById('hero-btn-evidence');
  const btnExportPreview = document.getElementById('btn-export-preview');
  const btnDownloadDossierSample = document.getElementById('btn-download-dossier-sample');

  function openDossierModal() {
    if (dossierModalOverlay) dossierModalOverlay.style.display = 'flex';
  }

  function closeDossierModal() {
    if (dossierModalOverlay) dossierModalOverlay.style.display = 'none';
  }

  if (heroBtnEvidence) heroBtnEvidence.addEventListener('click', openDossierModal);
  if (btnExportPreview) btnExportPreview.addEventListener('click', (e) => {
    e.preventDefault();
    openDossierModal();
  });
  if (dossierModalClose) dossierModalClose.addEventListener('click', closeDossierModal);
  if (btnCloseDossier) btnCloseDossier.addEventListener('click', closeDossierModal);

  if (dossierModalOverlay) {
    dossierModalOverlay.addEventListener('click', (e) => {
      if (e.target === dossierModalOverlay) closeDossierModal();
    });
  }

  if (btnDownloadDossierSample) {
    btnDownloadDossierSample.addEventListener('click', () => {
      btnDownloadDossierSample.innerHTML = '<span>⏳ Generating Signed PDF...</span>';
      btnDownloadDossierSample.disabled = true;
      setTimeout(() => {
        alert('📜 AICPA SOC 2 Type 2 Dossier Generated!\n\nPackage ID: SOC2-TYPE2-DOSSIER-2026Q3.pdf\nCryptographic SHA-256 Hash verified. Ready for Big-4 CPA audit submission.');
        btnDownloadDossierSample.innerHTML = '<span>📥 Download Full Signed PDF Package</span>';
        btnDownloadDossierSample.disabled = false;
        closeDossierModal();
      }, 1000);
    });
  }

  // FAQ Accordion Toggle Logic
  const faqTriggers = document.querySelectorAll('.faq-trigger');
  faqTriggers.forEach(trigger => {
    trigger.addEventListener('click', () => {
      const item = trigger.closest('.faq-item');
      const isActive = item.classList.contains('active');
      
      // Close other open items
      document.querySelectorAll('.faq-item').forEach(el => {
        el.classList.remove('active');
        const btn = el.querySelector('.faq-trigger');
        if (btn) btn.setAttribute('aria-expanded', 'false');
      });

      // Toggle current item
      if (!isActive) {
        item.classList.add('active');
        trigger.setAttribute('aria-expanded', 'true');
      }
    });
  });
});
