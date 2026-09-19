"""
CEF (Common Event Format) Parser for ULPF.
Supports ArcSight CEF syntax:
CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
"""

import re
from typing import Optional, Dict, Any
from app.parsers.base import BaseParser
from app.models.parsed_event import ParsedEvent
from app.models.errors import ParserError


class CefParser(BaseParser):
    name: str = "cef"
    version: str = "1.0"
    supported_extensions: tuple[str, ...] = (".cef", ".log")

    # Splits unescaped pipes
    PIPE_SPLIT_REGEX = re.compile(r'(?<!\\)\|')
    # Extracts key=value where value can contain spaces unless followed by another key=
    KV_REGEX = re.compile(r'(\w+)=(.*?)(?=(?:\s+\w+=)|$)')

    def can_parse(self, sample: str) -> bool:
        lines = [l.strip() for l in sample.splitlines() if l.strip()]
        if not lines:
            return False
        first = lines[0]
        # Syslog header might precede CEF
        return "CEF:" in first

    def parse_event(self, raw_event: str, source_file: Optional[str] = None, source_line: Optional[int] = None) -> ParsedEvent:
        clean = raw_event.strip()
        if not clean:
            raise ParserError("Empty CEF event")

        cef_pos = clean.find("CEF:")
        if cef_pos == -1:
            raise ParserError("Not a valid CEF event: missing 'CEF:' token")

        cef_data = clean[cef_pos:]
        parts = self.PIPE_SPLIT_REGEX.split(cef_data)

        if len(parts) < 8:
            raise ParserError(f"Malformed CEF event: expected 8 pipe-delimited fields, got {len(parts)}")

        # Unescape escaped pipes and backslashes in header fields
        version_part = parts[0].replace("CEF:", "").strip()
        device_vendor = parts[1].replace(r"\|", "|").strip()
        device_product = parts[2].replace(r"\|", "|").strip()
        device_version = parts[3].replace(r"\|", "|").strip()
        device_event_class_id = parts[4].replace(r"\|", "|").strip()
        name = parts[5].replace(r"\|", "|").strip()
        severity = parts[6].replace(r"\|", "|").strip()
        # Extension is the rest of parts joined back by | if there were pipes in extension
        extension_part = "|".join(parts[7:])

        fields: Dict[str, Any] = {
            "cef_version": version_part,
            "device_vendor": device_vendor,
            "device_product": device_product,
            "device_version": device_version,
            "device_event_class_id": device_event_class_id,
            "name": name,
            "severity": severity,
        }

        # Parse key=value extension pairs
        if extension_part:
            matches = self.KV_REGEX.findall(extension_part)
            for k, v in matches:
                clean_k = k.strip()
                clean_v = v.strip().replace(r"\=", "=").replace(r"\|", "|").replace(r"\n", "\n")
                fields[clean_k] = clean_v

        return ParsedEvent(
            raw_data=clean,
            format="cef",
            fields=fields,
            source_file=source_file,
            source_line=source_line,
            detected_vendor=device_vendor,
            parser_name=self.name,
            parser_version=self.version
        )
