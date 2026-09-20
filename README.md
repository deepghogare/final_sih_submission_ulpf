# Universal Log Pre-processing Framework (ULPF)

[![SIH 2026](https://img.shields.io/badge/SIH%202026-Problem%2026156-blue.svg)](https://sih.gov.in)
[![Organization](https://img.shields.io/badge/Organization-NTRO-orange.svg)](https://ntro.gov.in)
[![Python Version](https://img.shields.io/badge/Python-3.12%2B-brightgreen.svg)](https://python.org)
[![Tests Status](https://img.shields.io/badge/Tests-63%2F63%20PASSED-success.svg)](#automated-verification--test-results)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Smart India Hackathon (SIH) 2026 — Problem Statement 26156**  
> **Organization**: National Technical Research Organisation (NTRO)  
> **Category**: Software | **Theme**: Cybersecurity & Blockchain  

---

## Executive Summary

The **Universal Log Pre-processing Framework (ULPF)** is an enterprise-grade, offline-capable, and modular log ingestion and standardization framework built completely from scratch in Python 3.12+.

Modern cybersecurity defense environments ingest telemetry from dozens of disparate vendors—firewalls, routers, IDS/IPS appliances, proxies, servers, and endpoint security software. These devices generate logs in heterogeneous syntaxes (JSON, CSV, Syslog, CEF, LEEF, XML, Key-Value) with inconsistent, proprietary field naming (`src_ip` vs `sourceAddress` vs `client_ip`).

> **CRITICAL ARCHITECTURAL ROLE**:  
> **ULPF IS NOT A SIEM.**  
> ULPF serves as the high-throughput preprocessing and standardization layer **before** a SIEM (e.g., Wazuh, OpenSearch, Splunk) or data lake. It ingests raw logs, verifies cryptographic integrity, losslessly preserves original raw events, normalizes semantics into a uniform **Universal Event Schema**, and routes them to downstream security platforms.

---

## Key Framework Features

1. **Multi-Format Syntactic Parsers**:
   - Native parsers for **JSON**, **NDJSON**, **CSV** (sniffer-driven), **Syslog** (RFC 3164 BSD & RFC 5424), **ArcSight CEF**, **IBM QRadar LEEF 1.0/2.0**, **XML** (XXE protected), and **Key-Value Text**.
2. **Dynamic Priority Mapping Engine**:
   - 6-tier fallback resolution mapping proprietary field names to standard schema attributes via configuration-driven YAML schemas (`configs/mappings/`).
3. **Semantic Normalization**:
   - Converts all timestamps to ISO 8601 UTC, validates IP addresses & port boundaries, standardizes network actions (`allow`, `deny`, `alert`), and unifies severities (`info`, `low`, `medium`, `high`, `critical`).
4. **Cryptographic SHA-256 & Immutable Blockchain Ledger**:
   - Computes deterministic SHA-256 hashes per raw log event.
   - Maintains an offline, append-only Merkle-tree Blockchain ledger for forensic chain-of-custody and tamper detection.
5. **Lossless Raw Event Preservation**:
   - Exact raw log byte-strings are preserved in `raw.data`. Unknown or vendor-specific attributes are saved in `extensions`. Zero data loss.
6. **Dead-Letter Fault Tolerance**:
   - Corrupted log lines do not halt pipeline execution. Failed records divert to `failed_events/failed_events.jsonl` with full diagnostic metadata.
7. **Downstream SIEM Forwarding**:
   - Dedicated output adapters for **Wazuh**, **OpenSearch/Elasticsearch Bulk**, **Kafka**, **Syslog Forwarder (RFC 5424)**, and **JSONL**.
8. **Dynamic Plug-and-Play Architecture**:
   - Add new vendor parsers drop-in via `plugins/` without modifying core framework code.
9. **REST API & Interactive Web Dashboard**:
   - Built with **FastAPI** providing OpenAPI/Swagger UI endpoints and live browser dashboard for event inspection and blockchain audit.
10. **100% Air-Gapped & Offline Ready**:
    - Zero external network dependencies, cloud APIs, or runtime downloads required.

---

## Framework Architecture

```
RAW LOGS (File / Directory / API Stream)
               │
               ▼
   FORMAT DETECTION (Heuristics & Signatures)
               │
               ▼
   MODULAR PARSER (JSON, CSV, Syslog, CEF, LEEF, XML, Text)
               │
               ▼
   SHA-256 INTEGRITY & UNIQUE EVENT ID GENERATION
               │
               ▼
   DYNAMIC MAPPING ENGINE (6-Stage Fallback Resolution)
               │
               ▼
   SEMANTIC NORMALIZER (Timestamp UTC, IP/Port, Action, Severity)
               │
               ▼
   CRYPTOGRAPHIC BLOCKCHAIN LEDGER (Merkle Root & Block Sealing)
               │
               ▼
   PYDANTIC V2 SCHEMA VALIDATION
               │
               ▼
   SIEM ADAPTERS (Wazuh, OpenSearch, Kafka, JSONL, Syslog)
```

---

## Universal Event Schema (v1.0)

Every event normalized by ULPF adheres to this standardized JSON schema:

```json
{
  "event_id": "ULPF-8a92f1b4c3e2",
  "schema_version": "1.0",
  "event": {
    "timestamp": "2026-09-02T17:30:15Z",
    "type": "network",
    "category": "firewall",
    "action": "deny",
    "severity": "medium"
  },
  "source": {
    "ip": "192.168.1.20",
    "port": 54321,
    "hostname": "client-01"
  },
  "destination": {
    "ip": "10.0.0.5",
    "port": 443,
    "hostname": "server-01"
  },
  "network": {
    "protocol": "TCP",
    "direction": "inbound",
    "bytes": 1024,
    "packets": 10
  },
  "device": {
    "vendor": "VendorA",
    "product": "FirewallA",
    "hostname": "FW-01"
  },
  "metadata": {
    "ingestion_timestamp": "2026-09-02T17:30:16Z",
    "parser": "json",
    "raw_event_hash": "c5f118835f8d68e...64chars",
    "source_file": "test_data/comparison/vendor_a.json",
    "processing_time_ms": 0.182
  },
  "raw": {
    "data": "{\"src_ip\":\"192.168.1.20\",\"dst_ip\":\"10.0.0.5\",\"action\":\"DENY\"}",
    "format": "json"
  },
  "extensions": {}
}
```

---

## Project Structure

```
ulpf-python/
├── app/
│   ├── main.py                     # CLI Entry Point
│   ├── api/                        # FastAPI REST Routes & Dashboard
│   ├── core/                       # Ingestion Pipeline, Detectors & Forwarders
│   ├── enrichment/                 # Offline Local Asset Enricher
│   ├── integrity/                  # SHA-256 Engine & Blockchain Ledger
│   ├── mapping/                    # Dynamic Priority Mapping Engine
│   ├── models/                     # Universal Event & Error Pydantic Schemas
│   ├── metrics/                    # Throughput & Latency Metrics Engine
│   ├── normalization/              # Semantic Normalizers (Time, Network, Action)
│   ├── parsers/                    # Syntactic Parsers (JSON, CSV, Syslog, CEF, LEEF, XML)
│   ├── plugins/                    # Dynamic Plug-and-Play Plugin System
│   └── storage/                    # Output Storage & SIEM Adapters (Wazuh, OpenSearch)
├── configs/                        # Application Config & YAML Field Mappings
├── docs/                           # Technical Docs (Architecture, Schema, Deployment)
├── plugins/                        # Custom Vendor Plugin Drop-in Folder
├── scripts/                        # Benchmarks & SIH Presentation Generators
├── test_data/                      # Multi-Format Realistic Sample Logs
├── tests/                          # Automated Pytest Suite (63 Tests)
├── wazuh/                          # Custom Wazuh Decoders & Alert Rules
├── wazuh-docker/                   # Wazuh SIEM Docker Compose Infrastructure
├── Dockerfile                      # Container Build File
├── docker-compose.yml              # Container Orchestration
├── requirements.txt                # Python Dependencies
└── README.md                       # Project Documentation
```

---

## Quickstart Guide

### 1. Installation

Clone the repository and install dependencies:

```powershell
git clone https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPO_NAME.git
cd YOUR_REPO_NAME
pip install -r requirements.txt
```

---

### 2. Usage Examples

#### **Ingest & Normalize Log Files**:
```powershell
# Process an entire directory of mixed format logs:
python -m app.main process test_data/ --output output/universal_events.jsonl

# Ingest single file with offline asset enrichment:
python -m app.main process test_data/syslog/system_auth.log --enrich
```

#### **Detect Log Format**:
```powershell
python -m app.main detect test_data/
```

#### **Inspect Loaded Dynamic Plugins**:
```powershell
python -m app.main plugins
```

#### **Audit Cryptographic SHA-256 Integrity**:
```powershell
python -m app.main verify-hash output/universal_events.jsonl
```

#### **Audit Immutable Blockchain Ledger**:
```powershell
python -m app.main audit-chain
```

#### **Run Performance Benchmark**:
```powershell
python -m app.main benchmark --count 2000 --format all
```

---

### 3. Launch Web API & Browser Dashboard

Start the REST API web service:

```powershell
python -m app.main serve --host 127.0.0.1 --port 8000
```

- **Swagger API Docs**: [`http://127.0.0.1:8000/docs`](http://127.0.0.1:8000/docs)
- **Web Dashboard**: [`http://127.0.0.1:8000/dashboard`](http://127.0.0.1:8000/dashboard)

---

## Wazuh SIEM Integration

ULPF includes native support for forwarding pre-processed events into **Wazuh SIEM**:

1. **Wazuh Adapter**: Formats events according to Wazuh's expected JSON alert schema ([app/storage/siem_adapters.py](app/storage/siem_adapters.py)).
2. **Custom Decoders**: Copy [wazuh/decoders/ulpf_decoders.xml](wazuh/decoders/ulpf_decoders.xml) into `/var/ossec/etc/decoders/`.
3. **Custom Detection Rules**: Copy [wazuh/rules/ulpf_rules.xml](wazuh/rules/ulpf_rules.xml) into `/var/ossec/etc/rules/`.
4. **Wazuh Docker Setup**: Pre-configured Docker Compose scripts available in [wazuh-docker/](wazuh-docker/).

---

## Automated Verification & Test Results

Run the full automated pytest suite:

```powershell
pytest -v tests
```

**Test Execution Output**:
```
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-8.4.2, pluggy-1.6.0
collected 63 items

tests/api/test_blockchain_api.py PASSED                                [  7%]
tests/api/test_dashboard_api.py PASSED                                 [ 14%]
tests/integration/test_edge_cases.py PASSED                            [ 41%]
tests/integration/test_parallel_processing.py PASSED                  [ 42%]
tests/integration/test_pipeline_e2e.py PASSED                         [ 44%]
tests/integration/test_siem_forwarder.py PASSED                        [ 49%]
tests/integrity/test_blockchain.py PASSED                             [ 55%]
tests/integrity/test_hashing.py PASSED                                [ 61%]
tests/mapping/test_mapping_engine.py PASSED                           [ 66%]
tests/normalization/test_normalization.py PASSED                       [ 76%]
tests/parsers/test_all_parsers.py PASSED                              [ 92%]
tests/plugins/test_plugins.py PASSED                                  [ 93%]
tests/validation/test_validation.py PASSED                            [100%]

======================== 63 passed, 1 warning in 4.86s ========================
```

---

## License

This project is open-source software licensed under the **MIT License**.
