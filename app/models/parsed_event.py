"""
Intermediate representation between format parsing and semantic mapping.
"""

from typing import Any, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class ParsedEvent:
    """
    Holds syntactically extracted key-value pairs along with provenance metadata
    before semantic mapping and normalization take place.
    """
    raw_data: str
    format: str
    fields: Dict[str, Any] = field(default_factory=dict)
    source_file: Optional[str] = None
    source_line: Optional[int] = None
    source_offset: Optional[int] = None
    detected_vendor: Optional[str] = None
    parser_name: str = "generic"
    parser_version: str = "1.0"
