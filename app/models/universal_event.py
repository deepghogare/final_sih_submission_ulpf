"""
Universal Event Schema Definition for ULPF.
Implements the standardized JSON data model consumed by downstream cybersecurity systems (SIEM/Data Lake).
Uses Pydantic for validation and serialization.
"""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, ConfigDict


class EventDetails(BaseModel):
    timestamp: Optional[str] = Field(
        default=None,
        description="Standardized ISO 8601 UTC timestamp of the original event"
    )
    type: Optional[str] = Field(
        default=None,
        description="High-level event type (e.g. network, auth, file, system)"
    )
    category: Optional[str] = Field(
        default=None,
        description="Sub-category (e.g. firewall, ids, vpn, audit)"
    )
    action: Optional[str] = Field(
        default=None,
        description="Normalized action (e.g. allow, deny, drop, alert, login, logout)"
    )
    severity: Optional[str] = Field(
        default=None,
        description="Normalized severity level: info, low, medium, high, critical"
    )


class EndpointDetails(BaseModel):
    ip: Optional[str] = Field(default=None, description="Source IP address (IPv4 or IPv6)")
    port: Optional[int] = Field(default=None, description="Source transport port number (1-65535)")
    hostname: Optional[str] = Field(default=None, description="Source host or workstation name")
    mac: Optional[str] = Field(default=None, description="Source MAC address")


class DestinationDetails(BaseModel):
    ip: Optional[str] = Field(default=None, description="Destination IP address (IPv4 or IPv6)")
    port: Optional[int] = Field(default=None, description="Destination transport port number (1-65535)")
    hostname: Optional[str] = Field(default=None, description="Destination hostname or FQDN")


class NetworkDetails(BaseModel):
    protocol: Optional[str] = Field(default=None, description="Normalized protocol (e.g. TCP, UDP, ICMP)")
    direction: Optional[str] = Field(default=None, description="Direction: inbound, outbound, internal, unknown")
    bytes: Optional[int] = Field(default=None, description="Bytes transferred")
    packets: Optional[int] = Field(default=None, description="Packets transferred")


class DeviceDetails(BaseModel):
    vendor: Optional[str] = Field(default=None, description="Hardware/Software vendor name")
    product: Optional[str] = Field(default=None, description="Product or model name")
    hostname: Optional[str] = Field(default=None, description="Reporting device hostname")
    ip: Optional[str] = Field(default=None, description="Reporting device management IP")
    device_type: Optional[str] = Field(default=None, description="Device classification (e.g. firewall, router)")


class UserDetails(BaseModel):
    id: Optional[str] = Field(default=None, description="User identifier or SID")
    name: Optional[str] = Field(default=None, description="Username or account name")


class ProcessDetails(BaseModel):
    id: Optional[str] = Field(default=None, description="Process ID (PID)")
    name: Optional[str] = Field(default=None, description="Process or binary executable name")


class ThreatDetails(BaseModel):
    name: Optional[str] = Field(default=None, description="Threat, signature, or rule name")
    id: Optional[str] = Field(default=None, description="CVE, rule ID, or signature ID")
    confidence: Optional[str] = Field(default=None, description="Threat detection confidence level")


class MetadataDetails(BaseModel):
    ingestion_timestamp: str = Field(description="ISO 8601 UTC timestamp of ULPF ingestion")
    parser: str = Field(description="Parser used (e.g. json, syslog, cef)")
    parser_version: str = Field(default="1.0", description="Version of parser component")
    mapping_version: str = Field(default="1.0", description="Version of mapping rules applied")
    raw_event_hash: str = Field(description="SHA-256 integrity hash calculated from lossless raw data")
    source_file: Optional[str] = Field(default=None, description="Origin file name or path")
    source_line: Optional[int] = Field(default=None, description="Line number within origin file (1-indexed)")
    processing_time_ms: Optional[float] = Field(default=None, description="Time taken to process event in ms")


class RawDetails(BaseModel):
    data: str = Field(description="Lossless, exact original raw event text")
    format: str = Field(description="Detected format: json, ndjson, csv, syslog, cef, leef, xml, text")


class UniversalEvent(BaseModel):
    """
    Standardized Universal Event Schema (ULPF v1.0).
    Losslessly preserves raw event, computes SHA-256 integrity hash,
    normalizes key semantics, and retains any unmapped vendor fields in extensions.
    """
    event_id: str = Field(description="Globally unique identifier for this event (e.g. ULPF-8a92f1)")
    schema_version: str = Field(default="1.0", description="Universal Event Schema version")

    event: EventDetails = Field(default_factory=EventDetails)
    source: EndpointDetails = Field(default_factory=EndpointDetails)
    destination: DestinationDetails = Field(default_factory=DestinationDetails)
    network: NetworkDetails = Field(default_factory=NetworkDetails)
    device: DeviceDetails = Field(default_factory=DeviceDetails)
    user: UserDetails = Field(default_factory=UserDetails)
    process: ProcessDetails = Field(default_factory=ProcessDetails)
    threat: ThreatDetails = Field(default_factory=ThreatDetails)
    metadata: MetadataDetails
    raw: RawDetails
    extensions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Preserved vendor-specific and unmapped fields ensuring zero data loss"
    )

    model_config = ConfigDict(populate_by_name=True, extra="allow")
