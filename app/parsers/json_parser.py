"""
JSON Parser for ULPF.
Supports single JSON objects and arrays of JSON objects.
Yields 1 event per JSON object, preserving exact raw representation.
"""

import json
from pathlib import Path
from typing import Iterator, Union, Optional, Any
from app.parsers.base import BaseParser
from app.models.parsed_event import ParsedEvent
from app.models.errors import ParserError


class JsonParser(BaseParser):
    name: str = "json"
    version: str = "1.0"
    supported_extensions: tuple[str, ...] = (".json",)

    def can_parse(self, sample: str) -> bool:
        trimmed = sample.strip()
        if not (trimmed.startswith("{") or trimmed.startswith("[")):
            return False
        try:
            json.loads(sample)
            return True
        except Exception:
            # If multi-line file sample was cut off, check prefix heuristic
            if (trimmed.startswith("{") and trimmed.endswith("}")) or (trimmed.startswith("[") and trimmed.endswith("]")):
                try:
                    json.loads(trimmed)
                    return True
                except Exception:
                    pass
            return False

    def parse_event(self, raw_event: str, source_file: Optional[str] = None, source_line: Optional[int] = None) -> ParsedEvent:
        try:
            data = json.loads(raw_event)
            if not isinstance(data, dict):
                raise ParserError("JSON event must decode to an object/dictionary")
            return ParsedEvent(
                raw_data=raw_event,
                format="json",
                fields=data,
                source_file=source_file,
                source_line=source_line,
                parser_name=self.name,
                parser_version=self.version
            )
        except json.JSONDecodeError as e:
            raise ParserError(f"Malformed JSON: {e.msg} at line {e.lineno} col {e.colno}") from e

    def parse_file(self, file_path: Union[str, Path], error_handler: Optional[Any] = None) -> Iterator[ParsedEvent]:
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"JSON file not found: {file_path}")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()

        if not content:
            return

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            if error_handler:
                error_handler(content[:500], f"Malformed JSON in file {path.name}: {e.msg}", 1)
                return
            raise ParserError(f"Malformed JSON in file {path.name}: {e.msg}") from e

        if isinstance(data, list):
            # 1 File -> N Events (JSON Array)
            for idx, item in enumerate(data, start=1):
                if isinstance(item, dict):
                    raw_str = json.dumps(item, separators=(",", ":"))
                    yield ParsedEvent(
                        raw_data=raw_str,
                        format="json",
                        fields=item,
                        source_file=str(path),
                        source_line=idx,
                        parser_name=self.name,
                        parser_version=self.version
                    )
                else:
                    if error_handler:
                        error_handler(str(item), f"Element {idx} in JSON array is not a JSON object", idx)
                    else:
                        raise ParserError(f"Element {idx} in JSON array is not a JSON object")
        elif isinstance(data, dict):
            # Single JSON object
            yield ParsedEvent(
                raw_data=content,
                format="json",
                fields=data,
                source_file=str(path),
                source_line=1,
                parser_name=self.name,
                parser_version=self.version
            )
        else:
            if error_handler:
                error_handler(content[:500], f"Root of JSON file {path.name} is neither object nor array", 1)
            else:
                raise ParserError(f"Root of JSON file {path.name} is neither object nor array")
