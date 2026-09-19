"""
Example Vendor Plugin for ULPF.
Demonstrates dynamic plug-and-play capability for a hypothetical vendor: 'AcmeCyberSecurity' (AcmeGuard).
Can be dynamically discovered and loaded into ULPF without touching a single line of core pipeline code.
"""

from typing import Dict, Any, List
from app.plugins.interface import PluginInterface, PluginMetadata


class AcmeGuardPlugin(PluginInterface):
    """
    Plugin for AcmeGuard Next-Gen Firewall logs.
    Supplies custom vendor field mappings and custom normalization hooks.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="acme_guard_plugin",
            version="1.0.0",
            author="Acme Security Technologies",
            description="Dynamic plugin providing native support for AcmeGuard UTM and Firewall events.",
            supported_vendors=["AcmeSecurity", "AcmeGuard"],
            supported_formats=["json", "syslog"]
        )

    def on_load(self) -> None:
        # Initialization logic (e.g. warming up caches, reading vendor license, etc.)
        pass

    def register_mappings(self) -> Dict[str, Dict[str, Any]]:
        """
        Maps Acme-specific field names to Universal Event Schema:
          acme_source_ip -> source.ip
          acme_dest_ip   -> destination.ip
          acme_disposition -> event.action
          acme_threat_level -> event.severity
        """
        return {
            "acmesecurity": {
                "vendor": "AcmeSecurity",
                "product": "AcmeGuard UTM",
                "device_type": "utm_firewall",
                "fields": {
                    "acme_src": "source.ip",
                    "acme_dst": "destination.ip",
                    "acme_sport": "source.port",
                    "acme_dport": "destination.port",
                    "acme_disposition": "event.action",
                    "acme_threat_level": "event.severity",
                    "acme_proto": "network.protocol",
                    "acme_timestamp": "event.timestamp",
                    "acme_user": "user.name"
                }
            },
            "acmeguard": {
                "vendor": "AcmeSecurity",
                "product": "AcmeGuard UTM",
                "device_type": "utm_firewall",
                "fields": {
                    "acme_src": "source.ip",
                    "acme_dst": "destination.ip",
                    "acme_sport": "source.port",
                    "acme_dport": "destination.port",
                    "acme_disposition": "event.action",
                    "acme_threat_level": "event.severity",
                    "acme_proto": "network.protocol",
                    "acme_timestamp": "event.timestamp",
                    "acme_user": "user.name"
                }
            }
        }

    def custom_normalize(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Custom hook to tag Acme events with security vendor metadata."""
        ext = event_dict.setdefault("extensions", {})
        if event_dict.get("device", {}).get("vendor") == "AcmeSecurity":
            ext["acme_verified_by_plugin"] = True
        return event_dict

    def on_unload(self) -> None:
        pass
