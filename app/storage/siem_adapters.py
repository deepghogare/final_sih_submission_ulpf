"""
Downstream SIEM & Data Lake Adapters for ULPF.
Formats standardized Universal Events for ingestion by:
  - JSON / JSONL streams
  - Syslog Forwarding (RFC 5424)
  - OpenSearch / Elasticsearch Bulk NDJSON
  - Kafka Producers (Payload wrapper)
  - Wazuh HIDS / SIEM JSON format
"""

import json
from abc import ABC, abstractmethod
from typing import Dict, Any
from app.models.universal_event import UniversalEvent


class BaseSiemAdapter(ABC):
    """Abstract interface for formatting events for downstream security consumers."""
    @abstractmethod
    def format_event(self, event: UniversalEvent) -> str:
        pass


class JsonlSiemAdapter(BaseSiemAdapter):
    """Standard JSON Lines adapter for SIEM consumers like Splunk HEC or Cribl."""
    def format_event(self, event: UniversalEvent) -> str:
        return event.model_dump_json()


class OpenSearchBulkAdapter(BaseSiemAdapter):
    """
    Formats event into OpenSearch / Elasticsearch bulk index action NDJSON pair:
    {"index": {"_index": "ulpf-events-YYYY.MM", "_id": "ULPF-..."}}
    {...event payload...}
    """
    def __init__(self, index_prefix: str = "ulpf-events"):
        self.index_prefix = index_prefix

    def format_event(self, event: UniversalEvent) -> str:
        ts = event.event.timestamp or "2026-01-01"
        year_month = ts[:7].replace("-", ".")
        index_name = f"{self.index_prefix}-{year_month}"
        action = json.dumps({"index": {"_index": index_name, "_id": event.event_id}})
        payload = event.model_dump_json()
        return f"{action}\n{payload}"


class SyslogForwardAdapter(BaseSiemAdapter):
    """Formats Universal Event into an RFC 5424 structured syslog message."""
    def format_event(self, event: UniversalEvent) -> str:
        pri = 134  # Facility: local0 (16*8=128) + Severity: info (6)
        ts = event.event.timestamp or "-"
        host = event.device.hostname or "ulpf-gateway"
        app = "ULPF"
        procid = "-"
        msgid = event.event_id
        sd = f'[ulpf@26156 vendor="{event.device.vendor or "unknown"}" action="{event.event.action or "unknown"}"]'
        msg = event.model_dump_json()
        return f"<{pri}>1 {ts} {host} {app} {procid} {msgid} {sd} {msg}"


class WazuhAdapter(BaseSiemAdapter):
    """
    Formats Universal Event for Wazuh Manager analysis.
    Maps to Wazuh's expected JSON alert taxonomy.
    """
    def format_event(self, event: UniversalEvent) -> str:
        wazuh_dict = {
            "timestamp": event.event.timestamp,
            "rule": {
                "id": event.threat.id or "100001",
                "level": 3 if event.event.severity == "info" else (7 if event.event.severity == "medium" else 12),
                "description": f"ULPF {event.event.category or 'network'} event from {event.device.vendor or 'device'}"
            },
            "agent": {
                "id": "000",
                "name": event.device.hostname or "ulpf-forwarder",
                "ip": event.device.ip or "127.0.0.1"
            },
            "data": {
                "srcip": event.source.ip,
                "srcport": event.source.port,
                "dstip": event.destination.ip,
                "dstport": event.destination.port,
                "protocol": event.network.protocol,
                "action": event.event.action,
                "raw_hash": event.metadata.raw_event_hash,
                "ulpf_event_id": event.event_id
            },
            "location": event.metadata.source_file or "ulpf"
        }
        return json.dumps(wazuh_dict)


class KafkaPayloadAdapter(BaseSiemAdapter):
    """Wraps Universal Event with Kafka routing headers and partition key."""
    def format_event(self, event: UniversalEvent) -> str:
        kafka_envelope = {
            "key": event.source.ip or event.event_id,
            "topic": f"ulpf.events.{event.event.category or 'general'}",
            "value": event.model_dump(),
            "headers": {
                "event_id": event.event_id,
                "raw_hash": event.metadata.raw_event_hash,
                "schema_version": event.schema_version
            }
        }
        return json.dumps(kafka_envelope)
