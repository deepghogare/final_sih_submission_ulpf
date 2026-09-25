"""
ULPF Performance Benchmarking Suite.
Generates realistic synthetic log streams and empirically measures
throughput (events/sec), latency percentiles (p50, p95, p99), and stage metrics.
"""

import sys
import time
import random
from pathlib import Path
from typing import List

# Add parent directory to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.pipeline import Pipeline
from app.core.config import AppSettings
from app.storage.json_writer import JsonWriter
from app.metrics.metrics import MetricsTracker


def generate_synthetic_events(count: int, format_choice: str = "all") -> List[str]:
    """Generates synthetic log records across specified formats."""
    ips = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.1.100", "8.8.8.8", "1.1.1.1"]
    ports = [80, 443, 22, 53, 8080, 3389, 5432]
    actions = ["ALLOW", "DENY", "DROP", "BLOCK", "PERMIT", "ACCEPT"]
    severities = ["low", "medium", "high", "critical", "info"]

    events = []
    for i in range(count):
        src_ip = random.choice(ips)
        dst_ip = random.choice(ips)
        src_port = random.choice(ports)
        dst_port = random.choice(ports)
        act = random.choice(actions)
        sev = random.choice(severities)

        fmt = format_choice
        if format_choice == "all":
            fmt = random.choice(["json", "syslog", "cef", "csv"])

        if fmt == "json":
            # Vendor A or Vendor B style JSON
            if i % 2 == 0:
                ev = f'{{"timestamp":"2026-09-02T17:30:15Z","src_ip":"{src_ip}","dst_ip":"{dst_ip}","src_port":{src_port},"dst_port":{dst_port},"action":"{act}","severity":"{sev}","proto":"TCP","vendor":"VendorA"}}'
            else:
                ev = f'{{"eventTime":"2026-09-02T17:30:15Z","sourceAddress":"{src_ip}","destinationAddress":"{dst_ip}","sourcePort":{src_port},"destinationPort":{dst_port},"decision":"{act}","priority":"{sev}","transportProtocol":"TCP","devVendor":"VendorB"}}'
        elif fmt == "syslog":
            ev = f"<134>1 2026-09-02T17:30:15Z fw-perimeter.corp ULPF - - - action={act} src={src_ip} dst={dst_ip} sport={src_port} dport={dst_port} proto=TCP severity={sev}"
        elif fmt == "cef":
            ev = f"CEF:0|CyberVendor|NextGenFW|1.0|100|Connection {act}|{sev}|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto=TCP act={act}"
        elif fmt == "csv":
            ev = f"timestamp=2026-09-02T17:30:15Z src_ip={src_ip} dst_ip={dst_ip} src_port={src_port} dst_port={dst_port} proto=TCP action={act} severity={sev} vendor=GenericFW"
        else:
            ev = f"src_ip={src_ip} dst_ip={dst_ip} action={act} proto=TCP severity={sev}"

        events.append(ev)

    return events


def run_benchmark(count: int = 2000, format_choice: str = "all"):
    """Runs empirical benchmark and prints detailed performance report."""
    print("=" * 65)
    print(f" ULPF EMPIRICAL PERFORMANCE BENCHMARK")
    print(f" Target Event Count: {count:,} | Format: {format_choice.upper()}")
    print("=" * 65)

    print(f"[*] Generating {count:,} realistic synthetic log records...")
    raw_events = generate_synthetic_events(count, format_choice)

    settings = AppSettings({"pipeline": {"stop_on_error": False, "enable_enrichment": False}})
    metrics = MetricsTracker()
    pipeline = Pipeline(settings=settings, metrics_tracker=metrics)

    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    bench_output = output_dir / "benchmark_run.jsonl"
    if bench_output.exists():
        bench_output.unlink()
    writer = JsonWriter(bench_output)

    print("[*] Streaming records through ULPF 13-stage pipeline...")
    start_time = time.perf_counter()

    for idx, raw in enumerate(raw_events, start=1):
        pipeline.process_raw_event(raw_text=raw, source_name="benchmark_stream", line_no=idx)

    total_time = time.perf_counter() - start_time
    snapshot = metrics.get_snapshot()

    print("\n" + "=" * 65)
    print(" BENCHMARK RESULTS (EMPIRICAL MEASUREMENTS)")
    print("=" * 65)
    print(f" Total Events Ingested       : {snapshot['events_received']:,}")
    print(f" Successfully Processed      : {snapshot['events_processed']:,}")
    print(f" Failed Events               : {snapshot['events_failed']}")
    print(f" Total Elapsed Time          : {total_time:.4f} seconds")
    print(f" Throughput (Events/Second)  : {snapshot['events_per_second']:,} eps")
    print(f" Average Latency per Event   : {snapshot['average_latency_ms']:.3f} ms")
    print(f" Median Latency (p50)        : {snapshot['latency_p50_ms']:.3f} ms")
    print(f" 95th Percentile (p95)       : {snapshot['latency_p95_ms']:.3f} ms")
    print(f" 99th Percentile (p99)       : {snapshot['latency_p99_ms']:.3f} ms")
    print(f" Normalization Success Rate  : {snapshot['normalization_success_rate_pct']:.2f}%")
    print(f" Raw Events Preserved (100%) : {snapshot['raw_events_preserved']:,}")
    print("\n Format Breakdown:")
    for fmt, c in snapshot["format_distribution"].items():
        print(f"   - {fmt.upper():<10}: {c:,} events")
    print("=" * 65)


if __name__ == "__main__":
    count_arg = 2000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        count_arg = int(sys.argv[1])
    run_benchmark(count=count_arg)
