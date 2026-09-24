"""
MITRE ATT&CK Enrichment Plugin for ULPF.
Dynamically tags normalized security events with MITRE technique IDs
and tactic classifications without modifying core framework code.
"""

from typing import Dict, Any
from app.plugins.interface import PluginInterface, PluginMetadata


class MitreEnricherPlugin(PluginInterface):
    """MITRE ATT&CK dynamic tagger and enricher plugin."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="mitre_attack_enricher",
            version="1.2.0",
            author="ULPF Threat Research Team",
            description="Enriches normalized events with offline MITRE ATT&CK Tactics & Technique IDs.",
            supported_vendors=["All"],
            supported_formats=["All"]
        )

    def custom_normalize(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        raw_text = event_dict.get("raw", {}).get("data", "").lower()
        extensions = event_dict.setdefault("extensions", {})

        # T1110: Brute Force
        if "failed password" in raw_text or "4625" in raw_text or "auth failure" in raw_text:
            extensions["mitre_technique_id"] = "T1110"
            extensions["mitre_tactic"] = "Credential Access"
            extensions["threat_category"] = "Authentication Brute-Force"

        # T1046: Network Service Discovery / Port Scan
        elif "port scan" in raw_text or "teardown tcp" in raw_text or "recon" in raw_text:
            extensions["mitre_technique_id"] = "T1046"
            extensions["mitre_tactic"] = "Discovery"
            extensions["threat_category"] = "Network Port Scan"

        # T1071: Standard Application Layer Protocol Violation
        elif "policy violation" in raw_text or "dns sinkhole" in raw_text:
            extensions["mitre_technique_id"] = "T1071"
            extensions["mitre_tactic"] = "Command and Control"
            extensions["threat_category"] = "Exfiltration / C2 Channel"

        return event_dict

