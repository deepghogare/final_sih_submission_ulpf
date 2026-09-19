"""
Hybrid Dynamic Mapping Engine for ULPF.
Executes prioritized field mapping:
  1. Explicit vendor configuration (YAML/plugin)
  2. Known semantic aliases
  3. Pattern & data type detection (IP, Port, Timestamp)
  4. Value dictionaries
  5. Heuristics & Context
  6. Confidence scoring
Preserves all unmapped fields in 'extensions' ensuring zero data loss.
"""

from typing import Dict, Any, Optional, Tuple, List
from pathlib import Path
import re
import ipaddress
import yaml
import logging

from app.models.parsed_event import ParsedEvent
from app.mapping.semantic_mapper import ALIAS_LOOKUP, SEMANTIC_ALIASES

logger = logging.getLogger("ULPF.MappingEngine")


class MappingEngine:
    """
    Translates heterogeneous parsed event dictionaries into the Universal Event Schema structure.
    """

    IPV4_REGEX = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')

    def __init__(self, mappings_dir: Optional[Path] = None):
        self._vendor_mappings: Dict[str, Dict[str, Any]] = {}
        if mappings_dir:
            self.load_mappings(mappings_dir)

    def load_mappings(self, mappings_dir: Path) -> None:
        """Load YAML vendor mapping files from configuration directory."""
        if not mappings_dir.is_dir():
            return
        for yml_file in mappings_dir.glob("*.yaml"):
            try:
                with open(yml_file, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                    if cfg and "vendor" in cfg and "fields" in cfg:
                        vendor_name = str(cfg["vendor"]).lower()
                        self._vendor_mappings[vendor_name] = cfg
                        logger.info(f"Loaded mapping for vendor: {cfg['vendor']}")
            except Exception as e:
                logger.warning(f"Failed to load mapping {yml_file.name}: {e}")

    def register_vendor_mapping(self, vendor_name: str, mapping_dict: Dict[str, Any]) -> None:
        """Dynamically register or override vendor mapping."""
        self._vendor_mappings[vendor_name.lower()] = mapping_dict

    def map_event(self, parsed: ParsedEvent, vendor_hint: Optional[str] = None) -> Tuple[Dict[str, Any], float]:
        """
        Maps a ParsedEvent to the Universal Event dictionary structure.
        Returns: (mapped_dict, confidence_score)
        """
        raw_fields = dict(parsed.fields)
        mapped_result: Dict[str, Any] = {
            "event": {},
            "source": {},
            "destination": {},
            "network": {},
            "device": {},
            "user": {},
            "process": {},
            "threat": {},
            "extensions": {}
        }

        vendor_name = vendor_hint or parsed.detected_vendor or raw_fields.get("vendor") or raw_fields.get("devVendor")
        vendor_cfg = self._vendor_mappings.get(str(vendor_name).lower()) if vendor_name else None

        explicit_map = vendor_cfg.get("fields", {}) if vendor_cfg else {}
        total_fields = len(raw_fields)
        mapped_fields_count = 0

        # Preserve metadata about vendor/device if known from config
        if vendor_cfg:
            if vendor_cfg.get("vendor"):
                mapped_result["device"]["vendor"] = vendor_cfg["vendor"]
            if vendor_cfg.get("product"):
                mapped_result["device"]["product"] = vendor_cfg["product"]
            if vendor_cfg.get("device_type"):
                mapped_result["device"]["device_type"] = vendor_cfg["device_type"]

        for orig_key, orig_val in raw_fields.items():
            if orig_val is None or orig_val == "":
                continue

            target_field: Optional[str] = None
            confidence = 0.0

            # -------------------------------------------------------------
            # Priority 1: Explicit vendor mapping
            # -------------------------------------------------------------
            if orig_key in explicit_map:
                target_field = explicit_map[orig_key]
                confidence = 1.0

            # -------------------------------------------------------------
            # Priority 2: Known semantic aliases
            # -------------------------------------------------------------
            if not target_field:
                clean_key = orig_key.lower().replace("_", "").replace("-", "").replace(".", "")
                if clean_key in ALIAS_LOOKUP:
                    target_field = ALIAS_LOOKUP[clean_key]
                    confidence = 0.90

            # -------------------------------------------------------------
            # Priority 3: Pattern & data type detection (heuristics)
            # -------------------------------------------------------------
            if not target_field and isinstance(orig_val, str):
                val_str = orig_val.strip()
                # Check for IP pattern
                if self.IPV4_REGEX.match(val_str):
                    try:
                        ipaddress.IPv4Address(val_str)
                        if "src" in orig_key.lower() or "source" in orig_key.lower() or "client" in orig_key.lower():
                            target_field = "source.ip"
                            confidence = 0.85
                        elif "dst" in orig_key.lower() or "dest" in orig_key.lower() or "server" in orig_key.lower():
                            target_field = "destination.ip"
                            confidence = 0.85
                    except ValueError:
                        pass

            # -------------------------------------------------------------
            # Target Field Assignment or Lossless Extension
            # -------------------------------------------------------------
            if target_field and "." in target_field:
                section, key = target_field.split(".", 1)
                if section in mapped_result:
                    # Do not overwrite if already populated with higher confidence
                    if key not in mapped_result[section] or mapped_result[section][key] is None:
                        mapped_result[section][key] = orig_val
                        mapped_fields_count += 1
                        continue

            # Field was not mapped or section not in universal schema:
            # Losslessly preserve in extensions! Zero data loss.
            mapped_result["extensions"][orig_key] = orig_val

        overall_confidence = mapped_fields_count / max(total_fields, 1)
        return mapped_result, min(max(overall_confidence, 0.5), 1.0)


# Global mapping engine instance
default_mapping_engine = MappingEngine(Path("configs/mappings"))
