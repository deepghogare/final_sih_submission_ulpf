"""
Offline Asset Enrichment Module for ULPF.
Enriches internal IP addresses with metadata from a local asset inventory (JSON or SQLite).
Completely offline, non-blocking, and optional.
"""

from typing import Dict, Any, Optional
from pathlib import Path
import json
import logging

logger = logging.getLogger("ULPF.AssetEnricher")


class AssetEnricher:
    """
    Offline asset lookup engine.
    Enhances Universal Events with local network context (hostnames, asset types, owners).
    """
    def __init__(self, asset_file: Optional[Path] = None):
        self._assets: Dict[str, Dict[str, Any]] = {}
        if asset_file and Path(asset_file).is_file():
            self.load_assets(Path(asset_file))

    def load_assets(self, asset_file: Path) -> None:
        try:
            with open(asset_file, "r", encoding="utf-8") as f:
                self._assets = json.load(f)
                logger.info(f"Loaded {len(self._assets)} asset records from {asset_file}")
        except Exception as e:
            logger.warning(f"Could not load asset file {asset_file}: {e}")

    def enrich(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Looks up source and destination IPs in local asset database.
        Populates hostname and asset details in-place without destroying existing values.
        """
        # Source enrichment
        src_ip = event_dict.get("source", {}).get("ip")
        if src_ip and src_ip in self._assets:
            asset = self._assets[src_ip]
            src_sec = event_dict.setdefault("source", {})
            if not src_sec.get("hostname") and asset.get("hostname"):
                src_sec["hostname"] = asset["hostname"]
            if not src_sec.get("mac") and asset.get("mac"):
                src_sec["mac"] = asset["mac"]
            # Add asset context to extensions
            event_dict.setdefault("extensions", {})["source_asset_type"] = asset.get("asset_type")
            event_dict.setdefault("extensions", {})["source_asset_owner"] = asset.get("owner")

        # Destination enrichment
        dst_ip = event_dict.get("destination", {}).get("ip")
        if dst_ip and dst_ip in self._assets:
            asset = self._assets[dst_ip]
            dst_sec = event_dict.setdefault("destination", {})
            if not dst_sec.get("hostname") and asset.get("hostname"):
                dst_sec["hostname"] = asset["hostname"]
            event_dict.setdefault("extensions", {})["destination_asset_type"] = asset.get("asset_type")

        return event_dict


default_asset_enricher = AssetEnricher(Path("configs/local_assets.json"))
