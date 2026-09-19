"""
XML Parser for ULPF.
Supports hierarchical XML security events (Windows Event Log exports, firewall XML).
Disables entity resolution to protect against XXE attacks.
Supports multi-event XML files (e.g. <Events><Event>...</Event></Events>).
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterator, Union, Optional, Dict, Any
from app.parsers.base import BaseParser
from app.models.parsed_event import ParsedEvent
from app.models.errors import ParserError


def _xml_to_dict(element: ET.Element) -> Dict[str, Any]:
    """Recursively converts an XML element and its children into a dictionary."""
    result: Dict[str, Any] = {}

    # Include attributes prefixed with @
    for k, v in element.attrib.items():
        # Strip XML namespaces from attributes if present
        clean_k = k.split("}")[-1] if "}" in k else k
        result[f"@{clean_k}"] = v

    # If element has direct text and no children
    children = list(element)
    if not children:
        text = (element.text or "").strip()
        if result:
            if text:
                result["#text"] = text
            return result
        return text

    # Element has children
    child_dict: Dict[str, Any] = {}
    for child in children:
        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
        child_val = _xml_to_dict(child)
        if tag in child_dict:
            existing = child_dict[tag]
            if isinstance(existing, list):
                existing.append(child_val)
            else:
                child_dict[tag] = [existing, child_val]
        else:
            child_dict[tag] = child_val

    result.update(child_dict)
    return result


class XmlParser(BaseParser):
    name: str = "xml"
    version: str = "1.0"
    supported_extensions: tuple[str, ...] = (".xml",)

    def can_parse(self, sample: str) -> bool:
        trimmed = sample.strip()
        if not (trimmed.startswith("<") and trimmed.endswith(">")):
            return False
        # Disallow HTML or syslog PRI starting with <123>
        if trimmed.startswith("<") and not trimmed.startswith("<?xml") and not (">" in trimmed and "</" in trimmed):
            return False
        try:
            ET.fromstring(trimmed)
            return True
        except Exception:
            return False

    def parse_event(self, raw_event: str, source_file: Optional[str] = None, source_line: Optional[int] = None) -> ParsedEvent:
        clean = raw_event.strip()
        if not clean:
            raise ParserError("Empty XML event")
        try:
            # Defend against entity expansion
            parser = ET.XMLParser()
            root = ET.fromstring(clean, parser=parser)
            fields = _xml_to_dict(root)
            if not isinstance(fields, dict):
                fields = {"content": fields}
            return ParsedEvent(
                raw_data=clean,
                format="xml",
                fields=fields,
                source_file=source_file,
                source_line=source_line,
                parser_name=self.name,
                parser_version=self.version
            )
        except ET.ParseError as e:
            raise ParserError(f"Malformed XML event: {str(e)}") from e

    def parse_file(self, file_path: Union[str, Path], error_handler: Optional[Any] = None) -> Iterator[ParsedEvent]:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"XML file not found: {file_path}")

        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError as e:
            if error_handler:
                error_handler("<malformed_xml>", f"Malformed XML in {path.name}: {str(e)}", 1)
                return
            raise ParserError(f"Malformed XML in {path.name}: {str(e)}") from e

        # Check if root is a container of events, e.g. <Events><Event>...</Event></Events>
        children = list(root)
        event_tags = {"event", "entry", "log", "record", "item"}
        is_container = False

        if children:
            tag_names = {c.tag.split("}")[-1].lower() for c in children}
            if any(t in event_tags for t in tag_names) or len(children) > 1:
                is_container = True

        if is_container:
            for idx, child in enumerate(children, start=1):
                raw_str = ET.tostring(child, encoding="unicode").strip()
                fields = _xml_to_dict(child)
                if not isinstance(fields, dict):
                    fields = {"content": fields}
                yield ParsedEvent(
                    raw_data=raw_str,
                    format="xml",
                    fields=fields,
                    source_file=str(path),
                    source_line=idx,
                    parser_name=self.name,
                    parser_version=self.version
                )
        else:
            # Single root event
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
            fields = _xml_to_dict(root)
            if not isinstance(fields, dict):
                fields = {"content": fields}
            yield ParsedEvent(
                raw_data=content,
                format="xml",
                fields=fields,
                source_file=str(path),
                source_line=1,
                parser_name=self.name,
                parser_version=self.version
            )
