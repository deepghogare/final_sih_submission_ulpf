# Universal Event Schema Specification (ULPF v1.0)

## Overview
The Universal Log Pre-processing Framework (ULPF) standardizes heterogeneous security logs from any hardware or software vendor into a uniform, semantically rich **Universal Event** representation. 

Downstream consumers (such as SIEM platforms, Data Lakes, or analytical engines) consume this uniform schema instead of implementing hundreds of fragile vendor-specific log collectors.

---

## Schema Principles

1. **Lossless Raw Event Preservation**: The exact raw text of the incoming event is retained in `raw.data` without stripping, mutation, or re-encoding.
2. **Extensions Bag for Zero Data Loss**: Any vendor-specific or unmapped field is retained under the `extensions` dictionary. No field is ever discarded.
3. **Cryptographic Integrity**: Every event computes and stores a 64-character hexadecimal SHA-256 hash in `metadata.raw_event_hash` calculated over `raw.data`.
4. **Unique Traceable Event ID**: Each event in every file receives its own distinct `event_id` (e.g. `ULPF-8a92f1b4c3e2`), maintaining an audit link: `raw event <-> event_id <-> universal event`.
5. **Non-Mandatory Fields**: Fields default to `null` (None) when not present in the original log. Only provenance fields (`event_id`, `schema_version`, `metadata`, `raw`) are strictly mandatory.

---

## JSON Structure Definition

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
    "hostname": "client-01",
    "mac": "AA:BB:CC:DD:EE:FF"
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
    "hostname": "FW-01",
    "ip": "10.10.10.1",
    "device_type": "firewall"
  },

  "user": {
    "id": null,
    "name": "john_doe"
  },

  "process": {
    "id": null,
    "name": null
  },

  "threat": {
    "name": "SQL Injection Pattern Detected",
    "id": "CVE-2023-1234",
    "confidence": "high"
  },

  "metadata": {
    "ingestion_timestamp": "2026-09-02T17:30:16Z",
    "parser": "json",
    "parser_version": "1.0",
    "mapping_version": "1.0",
    "raw_event_hash": "c5f118835f8d68e...64chars",
    "source_file": "test_data/comparison/vendor_a.json",
    "source_line": 1,
    "processing_time_ms": 0.182
  },

  "raw": {
    "data": "{\"src_ip\":\"192.168.1.20\",\"dst_ip\":\"10.0.0.5\",\"action\":\"DENY\"}",
    "format": "json"
  },

  "extensions": {
    "custom_vendor_flag": "FLAG_X99",
    "rule_uuid": "77a8b3-11"
  }
}
```

---

## Field Specifications

### 1. `event` (EventDetails)
| Field | Type | Description | Allowed / Normalized Values |
|---|---|---|---|
| `timestamp` | string (ISO 8601) | Normalized event generation timestamp | `YYYY-MM-DDTHH:MM:SSZ` |
| `type` | string | Broad telemetry classification | `network`, `auth`, `file`, `process`, `system` |
| `category` | string | Security subsystem category | `firewall`, `ids`, `vpn`, `endpoint`, `audit` |
| `action` | string | Standardized operational decision | `allow`, `deny`, `alert`, `login`, `logout` |
| `severity` | string | Standardized severity level | `info`, `low`, `medium`, `high`, `critical` |

### 2. `source` (EndpointDetails)
| Field | Type | Description | Validation |
|---|---|---|---|
| `ip` | string | Source IP address | Valid IPv4 or IPv6 address |
| `port` | integer | Source transport port | `1` to `65535` |
| `hostname` | string | Source hostname or workstation | Free text / FQDN |
| `mac` | string | Source MAC hardware address | IEEE 802 MAC format |

### 3. `destination` (DestinationDetails)
| Field | Type | Description | Validation |
|---|---|---|---|
| `ip` | string | Destination / Target IP | Valid IPv4 or IPv6 address |
| `port` | integer | Destination transport port | `1` to `65535` |
| `hostname` | string | Destination hostname / FQDN | Free text / FQDN |

### 4. `network` (NetworkDetails)
| Field | Type | Description | Normalized Values |
|---|---|---|---|
| `protocol` | string | Transport layer protocol | `TCP`, `UDP`, `ICMP`, `GRE`, `ESP`, etc. |
| `direction` | string | Traffic flow relative to network | `inbound`, `outbound`, `internal`, `unknown` |
| `bytes` | integer | Volume transferred | Non-negative integer |
| `packets` | integer | Packets transmitted | Non-negative integer |

### 5. `device` (DeviceDetails)
| Field | Type | Description | Examples |
|---|---|---|---|
| `vendor` | string | Hardware / Software vendor | `Cisco`, `Palo Alto Networks`, `VendorA` |
| `product` | string | Product model / system | `ASA`, `PAN-OS`, `FirewallA` |
| `hostname` | string | Device reporting the event | `fw01.corp.internal` |
| `ip` | string | Device management IP | Valid IPv4 or IPv6 |
| `device_type` | string | Device class | `firewall`, `ids`, `router`, `switch` |

### 6. `metadata` (MetadataDetails)
| Field | Type | Description |
|---|---|---|
| `ingestion_timestamp` | string (ISO 8601) | Exact timestamp when ULPF ingested the record |
| `parser` | string | Parser used (`json`, `syslog`, `cef`, `leef`, `csv`, `xml`, `text`) |
| `parser_version` | string | Active version of the parser component |
| `mapping_version` | string | Active version of the vendor mapping config |
| `raw_event_hash` | string (hex, 64) | SHA-256 hash computed directly from `raw.data` |
| `source_file` | string | Original filename or log stream origin |
| `source_line` | integer | Line number in origin file (1-indexed) |
| `processing_time_ms` | float | Wall-clock time spent processing this event in milliseconds |

### 7. `raw` (RawDetails)
| Field | Type | Description |
|---|---|---|
| `data` | string | Exact, unmodified original event text |
| `format` | string | Content format: `json`, `ndjson`, `csv`, `syslog`, `cef`, `leef`, `xml`, `text` |

### 8. `extensions` (Dict[str, Any])
Arbitrary dictionary containing any vendor-specific, unmapped, or supplementary enrichment fields. Ensures 100% lossless transformation.
