# Universal Log Pre-processing Framework (ULPF) — Architecture Document

## 1. System Mission & Context

### Problem Statement: 26156 (NTRO) — SIH 2026
**Theme**: Blockchain & Cybersecurity  
**Organization**: National Technical Research Organisation (NTRO)  
**Role**: Preprocessing, standardization, integrity verification, and enrichment layer for heterogeneous log telemetry.

> **CRITICAL ARCHITECTURAL BOUNDARY**:  
> **ULPF IS NOT A SIEM.**  
> ULPF does not implement alert rule correlation, SIEM storage indexing, or incident dashboards.  
> ULPF is the upstream **data engineering and integrity layer** that transforms raw, messy, incompatible multi-vendor logs into validated Universal Events before forwarding them to downstream SIEMs (e.g. Wazuh, Splunk, Elastic/OpenSearch).

---

## 2. The "Universal" Philosophy

Instead of attempting "one magical parser that understands every vendor", ULPF enforces a decoupled, modular pipeline:

```
[ Generic Format Parser ]  +  [ Vendor Field Mapping ]  +  [ Semantic Normalization ]
                            ↓
             [ Universal Schema JSON Output ]
```

- **A new vendor using JSON does NOT require a new JSON parser.** The existing generic JSON parser extracts the raw keys; a lightweight YAML mapping or dynamic plugin translates vendor-specific keys to canonical fields.
- **A new log format (e.g. Protocol Buffers, Avro) only requires a new format parser.** The downstream vendor mappings and normalization engines remain unchanged.

---

## 3. High-Level Data Flow Diagram

```mermaid
flowchart TD
    subgraph S1["1. Ingestion Layer"]
        A["Input Logs\n(Files / Directory / Streams / API)"] --> B["Multi-Event Streamer\n(1 File -> N Events)"]
    end

    subgraph S2["2. Detection & Syntactic Parsing"]
        B --> C{"Format Detector\n(Content Heuristics)"}
        C -->|JSON| D1["JsonParser"]
        C -->|NDJSON| D2["NdjsonParser"]
        C -->|CSV| D3["CsvParser"]
        C -->|Syslog| D4["SyslogParser (RFC 3164/5424)"]
        C -->|CEF| D5["CefParser"]
        C -->|LEEF| D6["LeefParser"]
        C -->|XML| D7["XmlParser (XXE Safe)"]
        C -->|Text| D8["TextParser (Key-Value)"]
    end

    subgraph S3["3. Provenance & Cryptographic Integrity"]
        D1 & D2 & D3 & D4 & D5 & D6 & D7 & D8 --> E["Unique Event ID Generator\n(ULPF-UUID, Deduplication Tracker)"]
        E --> F["SHA-256 Engine\n(Strict UTF-8 Raw Checksum)"]
    end

    subgraph S4["4. Vendor Identification & Mapping"]
        F --> G["Vendor Detector\n(Header keywords, Signatures, Field pairs)"]
        G --> H{"Hybrid Mapping Engine\n(Priority 1 to 6)"}
        H -->|Priority 1| I1["Explicit Vendor YAML / Plugin"]
        H -->|Priority 2| I2["Semantic Synonym Aliases"]
        H -->|Priority 3| I3["Data Type & Pattern Detection"]
        H -->|Priority 4| I4["Value Dictionaries"]
        H -->|Priority 5| I5["Context Heuristics"]
        H -->|Priority 6| I6["Confidence Scoring"]
    end

    subgraph S5["5. Normalization & Validation"]
        I1 & I2 & I3 & I4 & I5 & I6 --> J["Normalizer\n(ISO8601 UTC, IP/Port, Actions, Severities)"]
        J --> K["Extensions Bag\n(100% Lossless Unmapped Retention)"]
        K --> L{"Optional Offline Asset Enrichment"}
        L --> M{"Validator (Pydantic Schema)"}
    end

    subgraph S6["6. Storage & SIEM Forwarding"]
        M -->|Valid Event| N["Universal Event JSONL / SQLite"]
        M -->|Invalid / Corrupt| O["Dead-Letter Storage\n(failed_events.jsonl)"]
        N --> P["SIEM Adapters\n(JSONL / Syslog RFC 5424 / OpenSearch / Wazuh / Kafka)"]
    end
```

---

## 4. Traceability & Provenance Model

Traceability is preserved across every layer:

```
[ Input File: firewall.log ]
         │
         ├── Event 1 (Line 1) ──> [ Event ID: ULPF-8a92f1 ] ──> SHA-256: e3b0c44298... ──> Universal Event 1
         ├── Event 2 (Line 2) ──> [ Event ID: ULPF-9b03e2 ] ──> SHA-256: d41d8cd98f... ──> Universal Event 2
         └── Event 3 (Line 3) ──> [ Event ID: ULPF-7c12a4 ] ──> SHA-256: 7d8f99a12c... ──> Universal Event 3
```

Every `UniversalEvent` includes:
- `event_id`: Unique identifier per event.
- `metadata.source_file`: Origin file path.
- `metadata.source_line`: Line index in source file.
- `metadata.parser`: Format parser that extracted the syntax.
- `metadata.raw_event_hash`: Cryptographic SHA-256 digest of `raw.data`.
- `raw.data`: Exact unmodified original raw event string.
- `raw.format`: Detected format identifier.

---

## 5. Security & Isolation Controls

1. **Path Traversal Protection**: Inputs are verified and sanitized before filesystem access.
2. **XML Entity Resolution Disabled**: `XmlParser` disables DTD entity expansion, preventing Billion Laughs and external entity (XXE) attacks.
3. **Buffer & Memory DOS Prevention**:
   - Max file size ceiling: `100 MB` (configurable).
   - Max single line ceiling: `64 KB`.
4. **No Unsafe Execution (`eval` / `exec`)**: Log text is strictly treated as data; dynamic Python code execution is completely prohibited on event content.
5. **Sandboxed Plugin Discovery**: Plugins must explicitly inherit from `PluginInterface` and undergo type inspection before registration into the active pipeline.
