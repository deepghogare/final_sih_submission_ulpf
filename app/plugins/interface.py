"""
Plugin Interface and Base Class for ULPF.
Third-party vendors and external contributors subclass PluginInterface
to register custom parsers, vendor mappings, and custom normalization logic
without touching core framework code.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class PluginMetadata:
    name: str
    version: str
    author: str
    description: str
    supported_vendors: List[str] = field(default_factory=list)
    supported_formats: List[str] = field(default_factory=list)


class PluginInterface(ABC):
    """
    Abstract Base Class for all ULPF dynamic plugins.
    """
    @property
    @abstractmethod
    def metadata(self) -> PluginMetadata:
        """Returns plugin identity and capabilities."""
        pass

    def on_load(self) -> None:
        """Called immediately upon discovery and loading."""
        pass

    def register_parsers(self) -> List[Any]:
        """Returns a list of custom BaseParser instances to register with ULPF core."""
        return []

    def register_mappings(self) -> Dict[str, Dict[str, Any]]:
        """
        Returns a dict mapping vendor_name -> mapping_dict:
        {
            "myvendor": {
                "vendor": "MyVendor",
                "product": "MyProduct",
                "fields": {
                    "raw_field_1": "source.ip",
                    "raw_field_2": "destination.ip"
                }
            }
        }
        """
        return {}

    def custom_normalize(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Optional hook to run vendor-specific enrichment/normalization logic."""
        return event_dict

    def on_unload(self) -> None:
        """Cleanup hook."""
        pass
