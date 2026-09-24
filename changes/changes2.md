# Walkthrough: Offline GeoIP, Local Threat Intel & MITRE ATT&CK Tagging

We have successfully implemented **100% offline GeoIP geolocation resolution**, **local threat intelligence indicator matching**, and **MITRE ATT&CK technique auto-tagging** for **ULPF**, complete with UI badges and documentation in `changes/change2.md`.

---

## 🛠️ Changes Implemented

### 1. Offline GeoIP Geolocation Engine
- **[geoip_enricher.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/enrichment/geoip_enricher.py)**: Resolves IPv4/IPv6 addresses against local subnet databases. Private RFC1918 IPs (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`) are auto-tagged with `🏠 Local` badges.
- **[geoip_db.json](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/configs/geoip_db.json)**: Offline database mapping public IP subnets to geolocation details (`🇺🇸 US`, `🇮🇳 IN`, `🇷🇺 RU`, `🇩🇪 DE`).

### 2. Local Threat Intelligence Feed Matching
- **[threat_intel.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/enrichment/threat_intel.py)**: Matches endpoints against local threat indicator database. Auto-escalates severity to `CRITICAL` and enriches events with Threat Actor metadata (`APT29 / CozyBear`, `Lazarus Group`).
- **[threat_intel_feed.json](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/configs/threat_intel_feed.json)**: Pre-populated offline threat indicators (known scanners, C2 servers, Tor exit nodes).

### 3. MITRE ATT&CK Auto-Tagging Engine
- **[mitre_tagger.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/enrichment/mitre_tagger.py)**: Pattern-matching engine linking raw logs and signatures to official MITRE ATT&CK IDs:
  - **`T1110.001`**: Password Guessing (Brute Force)
  - **`T1046`**: Network Service Discovery (Port Scan)
  - **`T1078`**: Valid Accounts (Privilege Escalation)
  - **`T1071.001`**: Web Protocols (Command & Control)
  - **`T1190`**: Exploit Public-Facing Application (Log4j, SQLi, CVEs)
  - **`T1059.001`**: PowerShell Command Execution

### 4. Master Pipeline & UI Integration
- **[asset_enricher.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/enrichment/asset_enricher.py)**: Unified asset inventory, GeoIP, threat intel, and MITRE tagging into the core pipeline.
- **[routes.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/api/routes.py)**: Added `GET /api/v1/enrichment/status` endpoint.
- **[dashboard.html](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/app/templates/dashboard.html)**: Displays GeoIP country flags (`🇷🇺`, `🇺🇸`, `🇮🇳`), MITRE ATT&CK badges (`🛡️ T1110.001`), and Threat Intel IoC alerts (`⚠️ IOC ALERT`) directly on the UI event table.

### 5. Change Documentation & Automated Tests
- **[change2.md](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/changes/change2.md)**: Created document summarizing the architecture, files, and UI features.
- **[test_geoip_threat_mitre.py](file:///c:/Users/Maitra%20Prajapati/Desktop/sih/app/tests/enrichment/test_geoip_threat_mitre.py)**: Automated unit tests for GeoIP, threat intel, and MITRE tagging.

---

## 🧪 Verification

- Verified `configs/geoip_db.json` and `configs/threat_intel_feed.json` load cleanly.
- Verified events normalized by `pipeline.process_raw_event()` receive GeoIP flags, Threat Intel alerts, and MITRE ATT&CK badges.
