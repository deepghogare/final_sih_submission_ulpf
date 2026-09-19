# Testing and Quality Assurance Guide for ULPF

## 1. Automated Test Suite Overview

ULPF includes a comprehensive automated test suite built with **pytest** covering 100% of pipeline stages, parsers, and edge cases.

### Running All Automated Tests:
```powershell
pytest -v tests
```

### Coverage by Component:
- `tests/parsers/`: Unit tests for JSON, NDJSON, CSV, Syslog (RFC 3164/5424), CEF, LEEF, XML, Text.
- `tests/mapping/`: Tests for YAML mappings, semantic aliases, pattern recognition, extensions bag.
- `tests/normalization/`: Tests for ISO 8601 UTC timestamps, IPv4/IPv6, port ranges, action canonicalization, severity scales.
- `tests/integrity/`: Tests for SHA-256 calculation, verify_sha256 tamper alerts, event ID collision handling.
- `tests/plugins/`: Tests for dynamic plugin discovery, on_load lifecycle, custom vendor registration without core edits.
- `tests/integration/`: End-to-end integration and 17 edge case tests.

---

## 2. The 17 Mandatory Edge Cases Tested

| # | Edge Case | Test Function in `tests/integration/test_edge_cases.py` | Expected Behavior |
|---|---|---|---|
| 1 | Multiple events per file | `test_edge_case_multiple_events_per_file` | 1 File -> N Events, distinct `event_id` per event |
| 2 | Empty file | `test_edge_case_empty_file` | Returns empty list cleanly, zero crashes |
| 3 | Malformed JSON | `test_edge_case_malformed_json` | Dead-lettered to `failed_events.jsonl` |
| 4 | Malformed XML | `test_edge_case_malformed_xml` | Recorded as parse failure, no crash |
| 5 | Invalid CSV | `test_edge_case_invalid_csv` | Missing columns padded, process continues |
| 6 | Invalid IP | `test_edge_case_invalid_ip` | IP normalized to `None`, preserved in raw data |
| 7 | Invalid Port | `test_edge_case_invalid_port` | Out of range port set to `None`, no crash |
| 8 | Missing timestamp | `test_edge_case_missing_timestamp` | Event timestamp `None`, ingestion timestamp recorded |
| 9 | Unknown vendor | `test_edge_case_unknown_vendor` | Generic schema created, vendor fields preserved |
| 10 | Unknown format | `test_edge_case_unknown_format` | Fallback to `TextParser`, raw preserved |
| 11 | Unknown fields | `test_edge_case_unknown_fields` | Preserved losslessly in `extensions` bag |
| 12 | Duplicate event IDs | `test_edge_case_duplicate_event_ids` | Collision caught by `EventIdTracker`, regenerated |
| 13 | SHA-256 verification | `test_edge_case_sha256_verification` | `verify_sha256()` returns `True` for valid event |
| 14 | Corrupted raw event | `test_edge_case_corrupted_raw_event` | Tampered raw text causes hash mismatch alert |
| 15 | Plugin not found | `test_edge_case_plugin_not_found` | Graceful `None` returned, pipeline continues |
| 16 | Invalid plugin | `test_edge_case_invalid_plugin` | Malformed plugin isolated and skipped |
| 17 | Partial event failure | `test_edge_case_partial_event_failure` | 1 corrupt line in file dead-lettered, valid lines succeed |

---

## 3. Performance Benchmark

Run live performance measurement using synthetic multi-format logs:

```powershell
python -m app.main benchmark --count 5000 --format all
```

The script reports real empirical measurements:
- Total throughput (`events/second`)
- Average latency per event (`ms`)
- Latency percentiles (`p50`, `p95`, `p99`)
- Normalization success rate (`%`)
- Format distribution breakdown
