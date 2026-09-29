# 2-Minute Demonstration Video Script
### SIH 2026 — Problem Statement 26156 (NTRO)
**Universal Log Pre-processing Framework (ULPF)**

> **Target Duration**: Exactly 120 seconds (2:00)  
> **Resolution**: 1080p (1920x1080)  
> **Tools needed**: OBS Studio / Loom / Windows Game Bar (Win + G)

---

### Timeline & Screen Action Breakdown

#### [0:00 – 0:20] Hook & Problem Statement
* **Screen Display**: Show the Presentation Title Slide (`ULPF_SIH2026_Presentation.pptx` Slide 1 or Architecture Diagram).
* **Voiceover**:
  > *"Hello evaluators. In defense and enterprise networks, perimeter devices generate millions of heterogeneous logs in incompatible syntaxes—CEF, Syslog, JSON, XML—with non-standard field names. Today, we present the Universal Log Pre-processing Framework (ULPF)—an air-gapped, zero-data-loss normalization and cryptographic integrity engine built from scratch in Python for SIH 2026, Problem Statement 26156 for NTRO."*

---

#### [0:20 – 0:50] Universal Ingestion & Normalization
* **Screen Display**: Switch to the browser at `http://localhost:8000` (ULPF Dashboard).
* **Screen Action**:
  1. Click **"Choose File"** in the Ingest section.
  2. Select `01_firewall_and_exploit_alerts.cef` from `demo_logs_for_upload/`.
  3. Click **"Process Log File"**.
* **Voiceover**:
  > *"Here is our live dashboard. We upload multi-vendor logs containing Palo Alto, Fortinet, and Check Point exploit events. Notice the sub-millisecond throughput: ULPF automatically detects the format, maps vendor-specific keys to our Universal Schema, standardizes timestamps to ISO 8601 UTC, normalizes actions and severities, and preserves 100% of the raw data and unmapped extensions with zero data loss."*

---

#### [0:50 – 1:20] Cryptographic Blockchain Integrity & Merkle Proofs
* **Screen Display**: Scroll down to the **Blockchain Ledger** and **Live Events Stream**.
* **Screen Action**:
  1. Click **"Inspect Merkle Proof"** on an event to show the popup with $O(\log N)$ cryptographic steps.
  2. Click **"Simulate Tamper Attack"** -> Show Block #1 turning red with `TAMPERED`.
  3. Click **"Audit Blockchain Ledger"** -> Show instant tamper alert.
  4. Click **"Self-Heal / Repair Ledger"** -> Show ledger returning to `100% UNTAMPERED`.
* **Voiceover**:
  > *"For non-repudiation and forensic compliance, every event is hashed using SHA-256 and sealed in an immutable Merkle-Tree Blockchain. Analysts can generate logarithmic zero-knowledge Merkle proofs for any log. When an insider attempts database tampering, our audit engine immediately pinpoints the exact corrupted block. Clicking Self-Heal demonstrates automated consensus recovery."*

---

#### [1:20 – 1:45] Seamless SIEM & Data Lake SOC Integration
* **Screen Display**: Click the **"Wazuh SIEM SOC"** badge or switch to tab at `http://localhost:8443`.
* **Screen Action**: Navigate to **Threat Hunting / Security Operations Events**. Show live alerts and MITRE ATT&CK techniques.
* **Voiceover**:
  > *"ULPF seamlessly streams normalized telemetry directly into our downstream SIEM and OpenSearch Security Data Lake. In our Wazuh SOC console, high-severity exploit events immediately trigger custom ULPF detection rules, tagged with MITRE ATT&CK techniques like T1059 and T1210 without requiring manual SIEM parser development."*

---

#### [1:45 – 2:00] Air-Gapped Readiness & Conclusion
* **Screen Display**: Show the terminal with `pytest` passing all 63 tests and Docker containers running.
* **Voiceover**:
  > *"ULPF is 100% air-gapped ready, fully containerized, requires zero cloud dependencies, and passes 63 out of 63 automated tests with an average latency of 0.24 milliseconds per event. ULPF provides unified visibility, forensic proof, and AI-ready telemetry for the next generation of national cyber defense. Thank you!"*
