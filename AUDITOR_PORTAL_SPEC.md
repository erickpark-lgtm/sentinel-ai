# SentinelAI — AICPA Independent Service Auditor Portal
## UI/UX Architectural Specification & Zero-Touch Verification Engine
**Document Classification:** Enterprise Architecture / Compliance Specification (AICPA AT-C 205 & Trust Services Criteria)  
**Target Audience:** AICPA Peer Reviewers, Big-4 Lead Engagement Partners, and Independent CPAs  
**Version:** 2.4.0 (Production Release)

---

## 1. Executive Summary & Design Rationale

### 1.1 The Solopreneur Zero-Touch Imperative
In traditional compliance SaaS, audit engagements require dozens of synchronous meetings between founders, compliance consultants, and CPA audit teams to explain evidence formats, sample populations, and manual screenshots. 

SentinelAI eliminates **100% of these meetings** by implementing a **Self-Explaining, Self-Verifying, Product-Led Auditor Portal (`auditor-portal.html`)**. When a CPA auditor accesses the platform via a client-generated magic link:
1. The portal autonomously recognizes the client's repository scope without login credentials.
2. The cryptographic integrity of the observation window is verified mathematically in under 1 second.
3. The AICPA AI Auditor Copilot answers all technical and control-mapping questions 24/7 without founder intervention.
4. Pre-cleared working paper packages are exported directly into CPA-ready formats (Excel, JSONL, Signed PDF).

---

## 2. Information Architecture & User Journey

```
                        [SaaS Client Dashboard (index.html)]
                                       │
                      [✉️ Invite CPA Auditor Button]
                                       │
                      (Cryptographic Magic Link Generated)
               auditor-portal.html?client=org/repo&token=AUD-XXXX
                                       │
                                       ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       AICPA AUDITOR PORTAL (auditor-portal.html)             │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Dynamic Reverse Onboarding Client Banner                                 │
│    └─ "Auditing Client: [org/repo] • Scope: AT-C 205 • Continuity: 100%"    │
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. Cryptographic Ledger Verification Console                                 │
│    ├─ Input: Root Hash / Dossier ID / Merkle Commitment                     │
│    ├─ Live API Status: VALIDATED (0 Tampered Blocks, 100.00% Continuity)    │
│    └─ One-Click Exports: [Export CPA Workpapers .zip] [Download Register]   │
├─────────────────────────────────────────────────────────────────────────────┤
│ 3. Append-Only Heartbeat Ledger Block Explorer                              │
│    └─ Visual inspection of Block #N, #N-1, Genesis Hash, Timestamp & Prev   │
├─────────────────────────────────────────────────────────────────────────────┤
│ 4. AICPA Trust Services Criteria (TSC) Control Matrix                       │
│    └─ CC5.1, CC6.1/6.6, CC7.1/7.2, CC8.1, CC9.2 Automated Telemetry Sources│
├─────────────────────────────────────────────────────────────────────────────┤
│ 5. Regulatory Safe Harbor & Independent Attestation Notice                  │
│    └─ Full AT-C Section 205 professional independence compliance statement │
├─────────────────────────────────────────────────────────────────────────────┤
│ 6. Self-Serve CPA Fast-Track Alliance Modal                                 │
│    └─ Direct firm enrollment with zero sales calls or manual onboarding     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 7. AICPA AI Auditor Copilot (Floating Interactive 24/7 Telemetry Desk)      │
│    └─ Instant autonomous answers on Rego policies, Git API, & CUEC mapping  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed UI/UX Component Specifications

### 3.1 Reverse Onboarding Client Context Banner
- **Trigger**: Activated automatically via URL query parameter (`?client=owner/repo&token=AUD-XXXXX`).
- **Visual Presentation**: High-contrast ambient cyan glass banner (`linear-gradient(90deg, rgba(6,182,212,0.15), rgba(56,189,248,0.1))`).
- **Data Displayed**:
  - Client Entity Identifier: Monospaced code badge (`enterprise-org/core-backend`)
  - Verification Token: One-time attestation token (`AUD-98214`)
  - Telemetry Status: `100.00% Continuity Index Verified`
- **Auditor Benefit**: Instantly assures the auditor that they are examining the isolated, authorized scope of their specific client without browsing or searching.

### 3.2 Cryptographic Evidence Verification Console
- **Component ID**: `#auditor-verify-result`
- **Verification Engine**: Interacts with backend API `POST /api/auditor/verify` on `localhost:8090` (with full in-browser cryptographic fallback if offline).
- **Core Metrics Grid**:
  1. **Hash Chaining Integrity**: Verifies SHA-256 Merkle links between sequential observation intervals. Displays `✔ Chained SHA-256 (0 Tampered)`.
  2. **Observation Continuity Index**: Calculates percentage of expected hourly watchdog heartbeats successfully recorded. Displays `100.00% Continuity Index`.
  3. **CPA Fast-Track Alliance**: Displays pre-cleared eligibility for accredited audit partners (Johanson Group, Prescient Assurance).
  4. **CC5.1 Dual-Approval Gate**: Quantifies pull request peer review approvals (`100% PR Peer Approval, 0 Direct Production Commits`).

### 3.3 Append-Only Cryptographic Block Explorer
- **Component ID**: `.ledger-block`
- **Structure**: Each block displays:
  - Block Index (e.g., `Block #1042`)
  - Timestamp in ISO-8601 UTC
  - Execution Daemon ID (`sentinel-vciso-worker-01`)
  - Current SHA-256 Hash (`7f9a8b1c...`)
  - Previous Block SHA-256 Hash (`4e2d3f6a...`)
- **Interactive State**: Hover triggers cyan neon accent glow and reveals raw cryptographic payload serialization string for auditor verification.

### 3.4 AICPA Trust Services Criteria (TSC) Matrix
- **Standard**: AICPA AT-C Section 205 (SOC 2 Type 2 Examination Standards).
- **Controls Mapped**:
  | Criterion | Control Name | Automated Telemetry Source | Working Paper File |
  | :--- | :--- | :--- | :--- |
  | **CC5.1** | Dual-Person Change Approval Gates | GitHub Branch Protection API | `WP-CC5.1-PR-GATES.json` |
  | **CC6.1 / CC6.6** | Logical Access & Mandatory Hardware MFA | Identity Provider / Org Roster | `WP-CC6.6-MFA-ROSTER.json` |
  | **CC7.1 / CC7.2** | Continuous Vulnerability Identification | Dependabot / CodeQL API | `WP-CC7.2-VULN-LOG.json` |
  | **CC8.1** | Configuration & Branch Drift Prevention | 24/7 Drift Sentinel Daemon | `WP-CC8.1-DRIFT-LOG.json` |
  | **CC9.2** | Tamper-Evident Audit Logging | Append-Only Cryptographic Ledger | `WP-CC9.2-LEDGER-CHAIN.jsonl` |

### 3.5 AICPA AI Auditor Copilot (Floating Chatbot Widget)
- **Component ID**: `#auditor-chat-widget`
- **Location**: Fixed bottom-right overlay with glowing emerald status pulse.
- **Engine Logic**:
  - Custom conversational intelligence trained on AICPA Common Criteria, SSAE 18, and AT-C Section 205 definitions.
  - Suggestion Chips: One-click inquiry buttons for quick evaluation (`CC8.1 Branch Protection`, `SHA-256 Chaining`, `CUEC Roster`, `CPA Alliance`).
  - Response SLA: Immediate client-side synthesis (< 400ms) with zero latency.
  - Objective: Resolves 100% of engagement team procedural and technical questions without founder emails or calls.

### 3.6 CPA Fast-Track Alliance Self-Enrollment Modal
- **Component ID**: `#modal-alliance`
- **Workflow**:
  - Independent CPAs click `[🤝 CPA Alliance Self-Enroll]`.
  - Enter Firm Name, Engagement Partner Name, and Work Email.
  - System immediately generates a unique Partner ID (`CPA-ALLIANCE-XXXX`) and direct API streaming credentials.
  - Automatically triggers delivery of the complete 2026 Audit Working Paper Toolkit.

---

## 4. Security & Compliance Defensibility

1. **Zero-Trace Architecture**: All evidence is collected via read-only APIs with no write permissions to customer production codebases.
2. **Mathematical Tamper Proofing**: Modifying any historical JSONL log entry alters its SHA-256 digest, which breaks the `prev_hash` pointer of all subsequent entries, immediately alerting engagement teams.
3. **Legal Safe Harbor**: SentinelAI explicitly positions itself as an autonomous telemetry orchestration engine, preserving the statutory independence of the licensed CPA firm to render the official attestation opinion.
