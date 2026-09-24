"""
Acme Guard Security Plugin for ULPF.
Demonstrates dynamic plug-and-play architecture by registering:
  - Custom Vendor Field Mappings for AcmeSecurity devices
  - Custom semantic normalization hooks
"""

from typing import Dict, Any, List
from app.plugins.interface import PluginInterface, PluginMetadata


class AcmeGuardPlugin(PluginInterface):
    """Acme Guard Security Appliance dynamic plugin."""

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="acme_guard_plugin",
            version="1.0.0",
            author="Acme Cybersecurity Labs",
            description="Dynamic parser and priority mapping extension for AcmeGuard Next-Gen Firewall.",
            supported_vendors=["AcmeSecurity", "AcmeGuard"],
            supported_formats=["json", "text", "key-value"]
        )

    def on_load(self) -> None:
        pass

    def register_mappings(self) -> Dict[str, Dict[str, Any]]:
        return {
            "acmesecurity": {
                "vendor": "AcmeSecurity",
                "product": "AcmeGuard-NGFW",
                "fields": {
                    "acme_src": "source.ip",
                    "acme_dst": "destination.ip",
                    "acme_sport": "source.port",
                    "acme_dport": "destination.port",
                    "acme_proto": "network.protocol",
                    "acme_disposition": "event.action",
                    "acme_threat_level": "event.severity"
                }
            }
        }

    def custom_normalize(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        # Custom vendor hook: Normalize Acme disposition to ULPF standard
        action = event_dict.get("event", {}).get("action", "")
        if action and action.upper() == "BLOCK":
            event_dict["event"]["action"] = "deny"
        return event_dict

