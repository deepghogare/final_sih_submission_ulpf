"""
Central Service and Component Registry for ULPF.
Manages registered parsers, format detectors, vendor mapping configurations,
and dynamic plug-and-play components.
"""

from typing import Dict, Optional, Type, List
import logging
from app.parsers.base import BaseParser
from app.parsers.json_parser import JsonParser
from app.parsers.ndjson_parser import NdjsonParser
from app.parsers.csv_parser import CsvParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.cef_parser import CefParser
from app.parsers.leef_parser import LeefParser
from app.parsers.xml_parser import XmlParser
from app.parsers.text_parser import TextParser
from app.core.detector import FormatDetector, default_format_detector

logger = logging.getLogger("ULPF.Registry")


class ComponentRegistry:
    """
    Registry for runtime discovery and lookup of parsers, formats, and plugins.
    Allows new formats and vendors to be plugged in dynamically without core edits.
    """
    def __init__(self):
        self._parsers: Dict[str, BaseParser] = {}
        self._format_detector: FormatDetector = default_format_detector
        self._register_default_parsers()

    def register_parser(self, parser: BaseParser) -> None:
        """Register a format parser."""
        self._parsers[parser.name.lower()] = parser
        logger.info(f"Registered parser '{parser.name}' v{parser.version}")

    def get_parser(self, format_name: str) -> Optional[BaseParser]:
        """Retrieve parser by format name."""
        return self._parsers.get(format_name.lower())

    def list_parsers(self) -> List[str]:
        """List all available parser names."""
        return list(self._parsers.keys())

    @property
    def format_detector(self) -> FormatDetector:
        return self._format_detector

    def _register_default_parsers(self) -> None:
        self.register_parser(JsonParser())
        self.register_parser(NdjsonParser())
        self.register_parser(CsvParser())
        self.register_parser(SyslogParser())
        self.register_parser(CefParser())
        self.register_parser(LeefParser())
        self.register_parser(XmlParser())
        self.register_parser(TextParser())


# Global singleton registry
default_registry = ComponentRegistry()
