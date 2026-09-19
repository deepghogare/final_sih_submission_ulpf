"""
Application Configuration Loader for ULPF.
Reads settings from configs/application.yaml or environment variables with safe defaults.
"""

from pathlib import Path
from typing import Dict, Any, Optional
import os
import yaml


class AppSettings:
    """Strongly-typed application settings."""
    def __init__(self, config_dict: Optional[Dict[str, Any]] = None):
        cfg = config_dict or {}
        app_sec = cfg.get("app", {})
        pipe_sec = cfg.get("pipeline", {})
        paths_sec = cfg.get("paths", {})
        integ_sec = cfg.get("integrity", {})

        self.app_name: str = app_sec.get("name", "ULPF - Universal Log Pre-processing Framework")
        self.app_version: str = app_sec.get("version", "1.0.0")
        self.log_level: str = os.getenv("ULPF_LOG_LEVEL", app_sec.get("log_level", "INFO"))

        self.max_file_size_mb: int = int(os.getenv("ULPF_MAX_FILE_SIZE_MB", pipe_sec.get("max_file_size_mb", 100)))
        self.max_line_length_kb: int = int(os.getenv("ULPF_MAX_LINE_LENGTH_KB", pipe_sec.get("max_line_length_kb", 64)))
        self.default_output_format: str = os.getenv("ULPF_OUTPUT_FORMAT", pipe_sec.get("default_output_format", "jsonl"))
        self.dedup_cache_size: int = int(pipe_sec.get("dedup_cache_size", 500000))
        self.stop_on_error: bool = pipe_sec.get("stop_on_error", False)
        self.enable_enrichment: bool = pipe_sec.get("enable_enrichment", False)

        self.output_dir: Path = Path(os.getenv("ULPF_OUTPUT_DIR", paths_sec.get("output_dir", "output")))
        self.failed_events_dir: Path = Path(os.getenv("ULPF_FAILED_DIR", paths_sec.get("failed_events_dir", "failed_events")))
        self.plugins_dir: Path = Path(os.getenv("ULPF_PLUGINS_DIR", paths_sec.get("plugins_dir", "plugins")))
        self.mappings_dir: Path = Path(os.getenv("ULPF_MAPPINGS_DIR", paths_sec.get("mappings_dir", "configs/mappings")))
        self.asset_db_path: Path = Path(os.getenv("ULPF_ASSET_DB", paths_sec.get("asset_db_path", "configs/local_assets.json")))

        self.hash_algorithm: str = integ_sec.get("hash_algorithm", "sha256")
        self.verify_on_ingest: bool = integ_sec.get("verify_on_ingest", True)


def load_config(config_path: Optional[str] = None) -> AppSettings:
    """Loads configuration from YAML file or returns defaults."""
    candidate_paths = [
        Path(config_path) if config_path else None,
        Path("configs/application.yaml"),
        Path(__file__).parent.parent.parent / "configs" / "application.yaml",
    ]

    for p in candidate_paths:
        if p and p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                    return AppSettings(data)
            except Exception:
                pass

    return AppSettings({})


default_settings = load_config()
