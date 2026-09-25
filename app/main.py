"""
Command Line Interface (CLI) Entry Point for ULPF.
Supports:
  - process: Batch log processor for files or directories
  - detect: Content-based format identification
  - plugins: Plugin inspector and dynamic discovery
  - validate: Schema and constraint validation
  - verify-hash: Lossless SHA-256 integrity check
  - benchmark: Throughput and latency benchmarking
  - serve: Start FastAPI server
"""

import sys
import os
import time
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import logging

from app.core.config import default_settings
from app.core.pipeline import default_pipeline
from app.core.detector import default_format_detector
from app.plugins.loader import default_plugin_loader
from app.storage.json_writer import JsonWriter
from app.integrity.hashing import verify_sha256, calculate_sha256, calculate_file_sha256

logging.basicConfig(
    level=getattr(logging, default_settings.log_level.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("ULPF.CLI")


def cmd_process(args):
    """Process a single file or directory of logs."""
    input_path = Path(args.path)
    output_path = Path(args.output or "output/universal_events.jsonl")
    writer = JsonWriter(output_path, format_mode=args.output_format)

    # Load dynamic plugins from plugins dir
    plugins_loaded = default_plugin_loader.discover_and_load(default_settings.plugins_dir)
    print(f"[*] ULPF Ingestion Engine Initialized | Plugins active: {plugins_loaded}")

    files_to_process = []
    if input_path.is_file():
        files_to_process.append(input_path)
    elif input_path.is_dir():
        for p in sorted(input_path.rglob("*")):
            if p.is_file() and not p.name.startswith((".", "__")) and p.suffix != ".py":
                files_to_process.append(p)
    else:
        print(f"[!] Error: Input path '{input_path}' not found.")
        sys.exit(1)

    total_files = len(files_to_process)
    print(f"[*] Found {total_files:,} log file(s) to process.")

    total_events = 0
    start_time = time.time()

    if total_files == 1:
        file_p = files_to_process[0]
        print(f"--> Ingesting: {file_p.name}")
        events = default_pipeline.process_file(
            file_path=file_p,
            output_writer=writer,
            force_format=args.format,
            force_vendor=args.vendor,
            enable_enrichment=args.enrich
        )
        print(f"    [+] Processed {len(events):,} event(s)")
        total_events = len(events)
    elif total_files > 1:
        num_workers = args.workers or min(32, (os.cpu_count() or 1) + 4)
        print(f"[*] Parallel Multi-Worker Pipeline active ({num_workers} worker threads)")

        def process_worker(fp):
            try:
                evs = default_pipeline.process_file(
                    file_path=fp,
                    output_writer=writer,
                    force_format=args.format,
                    force_vendor=args.vendor,
                    enable_enrichment=args.enrich
                )
                return len(evs), None
            except Exception as e:
                return 0, str(e)

        completed_files = 0
        last_report_time = start_time
        report_interval = max(1, total_files // 20)

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            future_to_file = {executor.submit(process_worker, fp): fp for fp in files_to_process}
            for future in as_completed(future_to_file):
                count, err = future.result()
                total_events += count
                completed_files += 1

                curr_time = time.time()
                if completed_files == total_files or completed_files % report_interval == 0 or (curr_time - last_report_time) >= 1.5:
                    elapsed = max(0.001, curr_time - start_time)
                    pct = (completed_files / total_files) * 100
                    eps = total_events / elapsed
                    end_char = "\n" if completed_files == total_files else "\r"
                    print(f"  [*] Progress: {completed_files:,}/{total_files:,} files ({pct:.1f}%) | {total_events:,} events | {eps:,.1f} EPS", end=end_char, flush=True)
                    last_report_time = curr_time

    snapshot = default_pipeline.metrics.get_snapshot()
    print("\n" + "=" * 60)
    print(f" PROCESSING SUMMARY")
    print("=" * 60)
    print(f" Total Events Received   : {snapshot['events_received']}")
    print(f" Successfully Processed  : {snapshot['events_processed']}")
    print(f" Failed / Dead-Lettered  : {snapshot['events_failed']}")
    print(f" Throughput              : {snapshot['events_per_second']} events/sec")
    print(f" Average Latency         : {snapshot['average_latency_ms']} ms")
    print(f" Output Location         : {output_path}")
    if snapshot['events_failed'] > 0:
        print(f" Dead-Letter Queue       : failed_events/failed_events.jsonl")
    print("=" * 60)


def cmd_detect(args):
    """Detect the format of a file or directory using content heuristics."""
    input_path = Path(args.path)
    if input_path.is_file():
        fmt = default_format_detector.detect_format(str(input_path))
        print(f"File: {input_path.name} --> Detected Format: {fmt.upper()}")
    elif input_path.is_dir():
        print(f"Scanning directory: {input_path}")
        for p in sorted(input_path.rglob("*")):
            if p.is_file() and not p.name.startswith((".", "__")) and p.suffix != ".py":
                fmt = default_format_detector.detect_format(str(p))
                print(f"  [{fmt.upper():<7}] {p.relative_to(input_path)}")
    else:
        print(f"[!] Target not found: {input_path}")


def cmd_plugins(args):
    """List loaded plugins and discover new plugins from the plugins/ directory."""
    plugins_dir = Path(args.dir or default_settings.plugins_dir)
    print(f"[*] Scanning plugins directory: {plugins_dir}")
    loaded = default_plugin_loader.discover_and_load(plugins_dir)
    plugins = default_pipeline.plugin_registry.list_plugins()

    print(f"[*] Active Plugins ({len(plugins)}):")
    for idx, p in enumerate(plugins, start=1):
        print(f"  {idx}. {p.name} v{p.version} (Author: {p.author})")
        print(f"     Description : {p.description}")
        print(f"     Vendors     : {', '.join(p.supported_vendors) or 'Generic'}")
        print(f"     Formats     : {', '.join(p.supported_formats) or 'All'}")


def cmd_validate(args):
    """Validate a JSON or JSONL file containing Universal Events."""
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    valid_count = 0
    invalid_count = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            clean = line.strip()
            if not clean:
                continue
            try:
                data = json.loads(clean)
                is_valid, obj, err = default_pipeline.validator.validate(data)
                if is_valid:
                    valid_count += 1
                else:
                    invalid_count += 1
                    print(f"  [X] Line {idx} failed: {err}")
            except Exception as e:
                invalid_count += 1
                print(f"  [X] Line {idx} JSON parse error: {e}")

    print(f"\n[*] Validation Results for {file_path.name}:")
    print(f"    Valid Events   : {valid_count}")
    print(f"    Invalid Events : {invalid_count}")


def cmd_verify_hash(args):
    """Verify cryptographic SHA-256 integrity of events in an output JSONL file."""
    file_path = Path(args.file)
    if not file_path.is_file():
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    verified = 0
    tampered = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for idx, line in enumerate(f, start=1):
            clean = line.strip()
            if not clean:
                continue
            try:
                data = json.loads(clean)
                raw_data = data.get("raw", {}).get("data", "")
                expected_hash = data.get("metadata", {}).get("raw_event_hash", "")
                event_id = data.get("event_id", f"line_{idx}")

                if verify_sha256(raw_data, expected_hash):
                    verified += 1
                else:
                    tampered += 1
                    print(f"  [TAMPER ALERT] Event {event_id} hash mismatch!")
                    print(f"    Expected : {expected_hash}")
                    print(f"    Calculated: {calculate_sha256(raw_data)}")
            except Exception as e:
                tampered += 1
                print(f"  [!] Error parsing event at line {idx}: {e}")

    print(f"\n[*] Integrity Audit for {file_path.name}:")
    print(f"    Verified Untampered : {verified}")
    print(f"    Tampered / Corrupted: {tampered}")


def cmd_benchmark(args):
    """Execute live performance benchmark."""
    from scripts.benchmark import run_benchmark
    run_benchmark(count=args.count, format_choice=args.format)


def cmd_audit_chain(args):
    """Perform mathematical chain-of-custody audit on the cryptographic block ledger."""
    print("[*] Auditing Cryptographic Blockchain Ledger...")
    res = default_pipeline.blockchain.verify_chain()
    print("=" * 60)
    print(" BLOCKCHAIN CHAIN-OF-CUSTODY AUDIT SUMMARY")
    print("=" * 60)
    print(f" Status            : {'[+] 100% UNTAMPERED' if res['is_valid'] else '[!] CRITICAL: TAMPER DETECTED'}")
    print(f" Total Blocks      : {res['total_blocks']:,}")
    print(f" Total Log Events  : {res.get('total_events', 0):,}")
    if not res["is_valid"]:
        print(f" Broken at Block   : #{res['broken_at_block']}")
        print(f" Failure Reason    : {res['reason']}")
    else:
        print(f" Verification Note : {res['reason']}")
    print("=" * 60)
    if not res["is_valid"]:
        sys.exit(1)


def cmd_serve(args):
    """Run the FastAPI web service with Uvicorn."""
    import uvicorn
    print(f"[*] Starting ULPF API server on {args.host}:{args.port}")
    try:
        uvicorn.run("app.api:app", host=args.host, port=args.port, reload=args.reload, log_level="info")
    except (KeyboardInterrupt, SystemExit):
        print("\n[*] ULPF API server stopped.")


def cmd_listen(args):
    """Launch real-time streaming ingestion listeners (UDP/TCP/Kafka)."""
    import asyncio
    import signal
    from app.core.stream_listener import default_stream_listener

    output_path = Path(args.output or "output/live_stream_events.jsonl")
    writer = JsonWriter(output_path)
    default_stream_listener.output_writer = writer
    default_stream_listener.enable_enrichment = args.enrich
    default_stream_listener.use_high_throughput = not getattr(args, "no_high_throughput", False)
    if default_stream_listener.use_high_throughput and not default_stream_listener.async_processor:
        from app.core.high_throughput import AsyncBatchProcessor
        default_stream_listener.async_processor = AsyncBatchProcessor(batch_size=2500, flush_interval=0.05)

    print("=" * 60)
    print(" ULPF REAL-TIME STREAMING INGESTION ENGINE ACTIVE")
    print("=" * 60)
    print(f" Output Location  : {output_path}")
    print(f" UDP Syslog Port  : {args.udp_port}")
    print(f" TCP Syslog Port  : {args.tcp_port}")
    print(f" High-Throughput  : {'ACTIVE (50,000+ EPS Async ProcessPool)' if default_stream_listener.use_high_throughput else 'DISABLED (Single-Thread)'}")
    if args.kafka_topic:
        print(f" Kafka Broker     : {args.kafka_bootstrap} (Topic: {args.kafka_topic})")
    print(" Press Ctrl+C to stop listening.")
    print("=" * 60)

    stop_event = asyncio.Event()

    async def run_listeners():
        await default_stream_listener.start_udp_listener(host=args.host, port=args.udp_port)
        await default_stream_listener.start_tcp_listener(host=args.host, port=args.tcp_port)
        if args.kafka_topic:
            default_stream_listener.start_kafka_consumer(
                bootstrap_servers=args.kafka_bootstrap,
                topic=args.kafka_topic
            )

        try:
            while not stop_event.is_set():
                await asyncio.sleep(0.2)
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        finally:
            print("\n[*] Stopping listeners...")
            await default_stream_listener.stop_udp_listener()
            await default_stream_listener.stop_tcp_listener()
            if args.kafka_topic:
                default_stream_listener.stop_kafka_consumer()
            print("[+] Listeners cleanly shutdown.")

    try:
        asyncio.run(run_listeners())
    except (KeyboardInterrupt, SystemExit):
        pass


def main():
    parser = argparse.ArgumentParser(
        prog="ulpf",
        description="Universal Log Pre-processing Framework (ULPF) - SIH 2026 (Problem 26156, NTRO)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

    # process
    p_proc = subparsers.add_parser("process", help="Process log files or directories")
    p_proc.add_argument("path", help="Path to log file or directory")
    p_proc.add_argument("-o", "--output", help="Output file path (default: output/universal_events.jsonl)")
    p_proc.add_argument("--output-format", choices=["jsonl", "json"], default="jsonl")
    p_proc.add_argument("--format", help="Force parser format (json, csv, syslog, cef, leef, xml, text)")
    p_proc.add_argument("--vendor", help="Force vendor mapping profile")
    p_proc.add_argument("--enrich", action="store_true", help="Enable offline asset database enrichment")
    p_proc.add_argument("-w", "--workers", type=int, default=None, help="Number of parallel worker threads (default: CPU cores)")
    p_proc.set_defaults(func=cmd_process)

    # detect
    p_det = subparsers.add_parser("detect", help="Detect log format using content heuristics")
    p_det.add_argument("path", help="Path to file or directory")
    p_det.set_defaults(func=cmd_detect)

    # plugins
    p_plg = subparsers.add_parser("plugins", help="List and inspect dynamic plugins")
    p_plg.add_argument("--dir", help="Plugins directory to scan")
    p_plg.set_defaults(func=cmd_plugins)

    # validate
    p_val = subparsers.add_parser("validate", help="Validate universal event JSON/JSONL file")
    p_val.add_argument("file", help="Path to Universal Event JSONL file")
    p_val.set_defaults(func=cmd_validate)

    # verify-hash
    p_hash = subparsers.add_parser("verify-hash", help="Audit SHA-256 integrity of events")
    p_hash.add_argument("file", help="Path to Universal Event JSONL file")
    p_hash.set_defaults(func=cmd_verify_hash)

    # benchmark
    p_bm = subparsers.add_parser("benchmark", help="Run throughput benchmark")
    p_bm.add_argument("-n", "--count", type=int, default=2000, help="Number of synthetic events (default: 2000)")
    p_bm.add_argument("-f", "--format", default="all", choices=["all", "json", "syslog", "cef", "csv"], help="Format to benchmark")
    p_bm.set_defaults(func=cmd_benchmark)

    # audit-chain
    p_chain = subparsers.add_parser("audit-chain", help="Audit cryptographic blockchain ledger integrity")
    p_chain.set_defaults(func=cmd_audit_chain)

    # serve
    p_srv = subparsers.add_parser("serve", help="Launch FastAPI REST service")
    p_srv.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    p_srv.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    p_srv.add_argument("--reload", action="store_true", help="Enable hot reload")
    p_srv.set_defaults(func=cmd_serve)

    # listen
    p_lst = subparsers.add_parser("listen", help="Launch real-time UDP/TCP/Kafka log streaming listeners")
    p_lst.add_argument("--host", default="0.0.0.0", help="Bind host IP")
    p_lst.add_argument("--udp-port", type=int, default=5140, help="UDP Syslog Port (default: 5140)")
    p_lst.add_argument("--tcp-port", type=int, default=5141, help="TCP Syslog Port (default: 5141)")
    p_lst.add_argument("--kafka-bootstrap", default="localhost:9092", help="Kafka broker bootstrap servers")
    p_lst.add_argument("--kafka-topic", default=None, help="Kafka topic to consume from (optional)")
    p_lst.add_argument("-o", "--output", help="Output JSONL path for streamed events")
    p_lst.add_argument("--enrich", action="store_true", help="Enable offline asset database enrichment")
    p_lst.add_argument("--no-high-throughput", action="store_true", help="Disable high-throughput async process pool batching")
    p_lst.set_defaults(func=cmd_listen)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    try:
        args.func(args)
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)


if __name__ == "__main__":
    main()
