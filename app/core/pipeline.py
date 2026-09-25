"""
Universal Log Pre-processing Framework (ULPF) Master Pipeline.
Coordinates end-to-end ingestion, format detection, parsing, integrity hashing,
vendor identification, semantic mapping, normalization, enrichment, validation, and storage.
"""

from typing import List, Iterator, Optional, Dict, Any, Union
from pathlib import Path
from datetime import datetime, timezone
import time
import logging

from app.core.config import AppSettings, default_settings
from app.core.registry import ComponentRegistry, default_registry
from app.core.vendor_detector import VendorDetector, default_vendor_detector
from app.mapping.mapping_engine import MappingEngine, default_mapping_engine
from app.normalization.normalizer import Normalizer, default_normalizer
from app.validation.validator import Validator, default_validator
from app.integrity.hashing import calculate_sha256, generate_event_id, EventIdTracker
from app.enrichment.asset_enricher import AssetEnricher, default_asset_enricher
from app.plugins.registry import PluginRegistry, default_plugin_registry
from app.storage.json_writer import JsonWriter
from app.storage.error_storage import ErrorStorage, default_error_storage
from app.storage.sqlite_storage import SqliteStorage, default_sqlite_storage
from app.integrity.blockchain import BlockchainLedger, default_blockchain_ledger
from app.core.siem_forwarder import SiemForwarder, default_siem_forwarder
from app.core.anomaly_detector import LogAnomalyDetector, default_anomaly_detector
from app.metrics.metrics import MetricsTracker, default_metrics_tracker
from app.models.universal_event import UniversalEvent, MetadataDetails, RawDetails
from app.models.parsed_event import ParsedEvent
from app.models.errors import ParserError, ValidationError, ULPFError

logger = logging.getLogger("ULPF.Pipeline")


class Pipeline:
    """
    Core ULPF Pipeline orchestrating the multi-stage transformation
    from heterogeneous raw logs to standardized Universal Events.
    """
    def __init__(
        self,
        settings: AppSettings = default_settings,
        registry: ComponentRegistry = default_registry,
        vendor_detector: VendorDetector = default_vendor_detector,
        mapping_engine: MappingEngine = default_mapping_engine,
        normalizer: Normalizer = default_normalizer,
        validator: Validator = default_validator,
        asset_enricher: AssetEnricher = default_asset_enricher,
        plugin_registry: PluginRegistry = default_plugin_registry,
        error_storage: ErrorStorage = default_error_storage,
        sqlite_storage: SqliteStorage = default_sqlite_storage,
        blockchain: BlockchainLedger = default_blockchain_ledger,
        siem_forwarder: SiemForwarder = default_siem_forwarder,
        metrics_tracker: MetricsTracker = default_metrics_tracker,
        anomaly_detector: LogAnomalyDetector = default_anomaly_detector,
    ):
        self.settings = settings
        self.registry = registry
        self.vendor_detector = vendor_detector
        self.mapping_engine = mapping_engine
        self.normalizer = normalizer
        self.validator = validator
        self.asset_enricher = asset_enricher
        self.plugin_registry = plugin_registry
        self.error_storage = error_storage
        self.sqlite_storage = sqlite_storage
        self.blockchain = blockchain
        self.siem_forwarder = siem_forwarder
        self.metrics = metrics_tracker
        self.anomaly_detector = anomaly_detector
        self.id_tracker = EventIdTracker(max_capacity=settings.dedup_cache_size)

    def process_file(
        self,
        file_path: Union[str, Path],
        output_writer: Optional[JsonWriter] = None,
        force_format: Optional[str] = None,
        force_vendor: Optional[str] = None,
        enable_enrichment: Optional[bool] = None,
    ) -> List[UniversalEvent]:
        """
        Process a single log file containing 1 to N events.
        Maintains file-level provenance and error isolation.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        # Security check: Max file size
        file_size_mb = path.stat().st_size / (1024 * 1024)
        if file_size_mb > self.settings.max_file_size_mb:
            raise ValueError(f"File size ({file_size_mb:.1f} MB) exceeds maximum allowed ({self.settings.max_file_size_mb} MB)")

        # 1. Format Detection
        fmt = force_format or self.registry.format_detector.detect_format(str(path))
        parser = self.registry.get_parser(fmt)
        if not parser:
            # Fallback to text parser
            parser = self.registry.get_parser("text")
            fmt = "text"

        results: List[UniversalEvent] = []
        should_enrich = self.settings.enable_enrichment if enable_enrichment is None else enable_enrichment

        # 2. Iterate parsed events from file (1 File -> N Events)
        def on_parser_error(raw_line: str, err_msg: str, line_no: int):
            self.metrics.record_received(1)
            self.metrics.record_failure("parsing", fmt)
            self.error_storage.record_failure(
                raw_event=raw_line,
                error_msg=err_msg,
                stage="parsing",
                parser=fmt,
                source_file=str(path),
                source_line=line_no
            )

        try:
            parsed_stream = parser.parse_file(path, error_handler=on_parser_error)
        except Exception as e:
            # Whole-file parsing failure (e.g. invalid top-level JSON/XML)
            self.metrics.record_received(1)
            self.metrics.record_failure("parsing", fmt)
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                raw_sample = f.read(1024)
            self.error_storage.record_failure(
                raw_event=raw_sample,
                error_msg=f"File-level parser failure: {str(e)}",
                stage="parsing",
                parser=fmt,
                source_file=str(path),
                source_line=1
            )
            return []

        try:
            for parsed_event in parsed_stream:
                self.metrics.record_received(1)
                event_obj = self._process_single_parsed_event(
                    parsed_event=parsed_event,
                    force_vendor=force_vendor,
                    enable_enrichment=should_enrich,
                    output_writer=output_writer
                )
                if event_obj:
                    results.append(event_obj)
        except Exception as e:
            self.metrics.record_failure("parsing", fmt)
            self.error_storage.record_failure(
                raw_event=f"Stream error in {path.name}",
                error_msg=str(e),
                stage="parsing",
                parser=fmt,
                source_file=str(path),
                source_line=1
            )

        if results:
            try:
                self.blockchain.seal_block()
            except Exception as e:
                logger.debug(f"Blockchain sealing skipped: {e}")

        return results

    def process_raw_event(
        self,
        raw_text: str,
        force_format: Optional[str] = None,
        force_vendor: Optional[str] = None,
        enable_enrichment: Optional[bool] = None,
        source_name: Optional[str] = "api",
        line_no: Optional[int] = 1,
    ) -> Optional[UniversalEvent]:
        """
        Process a single raw event string.
        """
        self.metrics.record_received(1)
        fmt = force_format or self.registry.format_detector.detect_format(raw_text)
        parser = self.registry.get_parser(fmt) or self.registry.get_parser("text")

        try:
            parsed_event = parser.parse_event(raw_text, source_file=source_name, source_line=line_no)
        except Exception as e:
            self.metrics.record_failure("parsing", fmt)
            self.error_storage.record_failure(
                raw_event=raw_text,
                error_msg=f"Parse failure: {str(e)}",
                stage="parsing",
                parser=fmt,
                source_file=source_name,
                source_line=line_no
            )
            if getattr(self.settings, "enable_anomaly_detection", True):
                try:
                    err_event = UniversalEvent(
                        event_id=generate_event_id(prefix="ULPF-ERR"),
                        schema_version="1.0",
                        metadata=MetadataDetails(
                            ingestion_timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                            parser=fmt,
                            raw_event_hash=calculate_sha256(raw_text)
                        ),
                        raw=RawDetails(data=raw_text, format=fmt)
                    )
                    self.anomaly_detector.analyze(err_event)
                except Exception:
                    pass
            return None

        should_enrich = self.settings.enable_enrichment if enable_enrichment is None else enable_enrichment
        ev = self._process_single_parsed_event(
            parsed_event=parsed_event,
            force_vendor=force_vendor,
            enable_enrichment=should_enrich
        )
        if ev:
            try:
                self.blockchain.seal_block()
            except Exception as e:
                logger.debug(f"Blockchain sealing skipped: {e}")
        return ev

    def _process_single_parsed_event(
        self,
        parsed_event: ParsedEvent,
        force_vendor: Optional[str] = None,
        enable_enrichment: bool = False,
        output_writer: Optional[JsonWriter] = None,
    ) -> Optional[UniversalEvent]:
        """Internal processing pipeline for a single parsed event."""
        start_time = time.perf_counter()
        raw_data = parsed_event.raw_data

        # 1. Event ID and Collision Detection
        event_id = generate_event_id()
        is_unique = self.id_tracker.register(event_id)
        if not is_unique:
            logger.warning(f"Event ID collision detected: {event_id}. Regenerating...")
            event_id = generate_event_id(prefix="ULPF-DUP")
            self.id_tracker.register(event_id)

        # 2. Lossless SHA-256 Integrity Hash Calculation
        raw_hash = calculate_sha256(raw_data)

        # 3. Vendor / Source Detection
        detected_info = self.vendor_detector.detect_vendor(parsed_event.fields, raw_data)
        vendor = force_vendor or detected_info.get("vendor") or parsed_event.detected_vendor

        # 4. Dynamic Semantic Field Mapping (Priority 1 to 6)
        try:
            mapped_dict, mapping_conf = self.mapping_engine.map_event(parsed_event, vendor_hint=vendor)
        except Exception as e:
            self.metrics.record_failure("mapping", parsed_event.format)
            self.error_storage.record_failure(
                raw_event=raw_data,
                error_msg=f"Mapping failure: {str(e)}",
                stage="mapping",
                event_id=event_id,
                parser=parsed_event.parser_name,
                source_file=parsed_event.source_file,
                source_line=parsed_event.source_line
            )
            return None

        # Supplement device fields if detected
        if detected_info.get("vendor") and not mapped_dict["device"].get("vendor"):
            mapped_dict["device"]["vendor"] = detected_info["vendor"]
        if detected_info.get("product") and not mapped_dict["device"].get("product"):
            mapped_dict["device"]["product"] = detected_info["product"]
        if detected_info.get("device_type") and not mapped_dict["device"].get("device_type"):
            mapped_dict["device"]["device_type"] = detected_info["device_type"]

        # 5. Semantic Normalization
        try:
            normalized_dict = self.normalizer.normalize(mapped_dict)
        except Exception as e:
            logger.warning(f"Normalization warning on event {event_id}: {e}")
            normalized_dict = mapped_dict

        # 6. Optional Dynamic Plugin Custom Normalization Hooks
        normalized_dict = self.plugin_registry.execute_custom_normalizations(normalized_dict)

        # 7. Optional Offline Asset Enrichment
        if enable_enrichment:
            normalized_dict = self.asset_enricher.enrich(normalized_dict)

        # 8. Assemble Full Universal Event Structure
        elapsed_ms = round((time.perf_counter() - start_time) * 1000.0, 3)
        ingestion_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        normalized_dict["event_id"] = event_id
        normalized_dict["schema_version"] = "1.0"
        normalized_dict["metadata"] = {
            "ingestion_timestamp": ingestion_ts,
            "parser": parsed_event.parser_name,
            "parser_version": parsed_event.parser_version,
            "mapping_version": "1.0",
            "raw_event_hash": raw_hash,
            "source_file": parsed_event.source_file,
            "source_line": parsed_event.source_line,
            "processing_time_ms": elapsed_ms
        }
        normalized_dict["raw"] = {
            "data": raw_data,
            "format": parsed_event.format
        }

        # 8.5 Construct candidate event & run Anomaly Detection
        candidate_obj = None
        try:
            candidate_obj = UniversalEvent.model_validate(normalized_dict)
        except Exception as e:
            logger.debug(f"Candidate event creation error: {e}")

        if candidate_obj and getattr(self.settings, "enable_anomaly_detection", True):
            try:
                self.anomaly_detector.analyze(candidate_obj)
            except Exception as e:
                logger.debug(f"Anomaly detection step skipped: {e}")

        # 9. Schema & Constraint Validation
        is_valid, event_obj, error_msg = self.validator.validate(normalized_dict, verify_hash=True)
        if not is_valid or event_obj is None:
            self.metrics.record_failure("validation", parsed_event.format)
            self.error_storage.record_failure(
                raw_event=raw_data,
                error_msg=f"Validation failure: {error_msg}",
                stage="validation",
                event_id=event_id,
                parser=parsed_event.parser_name,
                source_file=parsed_event.source_file,
                source_line=parsed_event.source_line
            )
            return None

        # Copy attached anomalies to validated event object
        if candidate_obj and "anomalies" in candidate_obj.extensions:
            event_obj.extensions["anomalies"] = candidate_obj.extensions["anomalies"]

        # 10. Persistence and Recording
        if output_writer:
            output_writer.write_event(event_obj)

        try:
            self.sqlite_storage.save_event(event_obj)
        except Exception as e:
            logger.debug(f"SQLite indexing skipped: {e}")

        try:
            self.blockchain.add_event(event_id, event_obj.metadata.raw_event_hash)
        except Exception as e:
            logger.debug(f"Blockchain buffering skipped: {e}")

        try:
            self.siem_forwarder.forward(event_obj.model_dump())
        except Exception as e:
            logger.debug(f"SIEM forwarding skipped: {e}")

        # Record Metrics
        self.metrics.record_success(
            fmt=parsed_event.format,
            vendor=event_obj.device.vendor or "unknown",
            latency_ms=elapsed_ms
        )

        return event_obj


default_pipeline = Pipeline()
