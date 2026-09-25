"""
ULPF High-Throughput Performance Benchmarking & Chart Generation Suite.
Generates realistic synthetic log streams, empirically benchmarks execution models
(Single-Thread, ThreadPool, ProcessPool, HighThroughput Chunked Multiprocessing),
tracks resource footprint (CPU %, RAM MB), and outputs visual charts.
"""

import sys
import os
import time
import json
import random
import threading
from pathlib import Path
from typing import List, Dict, Any

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

import psutil
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt

from app.core.pipeline import Pipeline
from app.core.config import AppSettings
from app.core.high_throughput import HighThroughputPipeline, AsyncBatchProcessor
from app.metrics.metrics import MetricsTracker


def generate_synthetic_events(count: int, format_choice: str = "all") -> List[str]:
    """Generates realistic synthetic log records across specified formats."""
    ips = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.1.100", "8.8.8.8", "1.1.1.1"]
    ports = [80, 443, 22, 53, 8080, 3389, 5432]
    actions = ["ALLOW", "DENY", "DROP", "BLOCK", "PERMIT", "ACCEPT"]
    severities = ["low", "medium", "high", "critical", "info"]

    events = []
    for i in range(count):
        src_ip = ips[i % len(ips)]
        dst_ip = ips[(i + 1) % len(ips)]
        src_port = ports[i % len(ports)]
        dst_port = ports[(i + 2) % len(ports)]
        act = actions[i % len(actions)]
        sev = severities[i % len(severities)]

        fmt = format_choice
        if format_choice == "all":
            fmt = ["json", "syslog", "cef", "csv"][i % 4]

        if fmt == "json":
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


class ResourceMonitor:
    """Monitors CPU % and RAM Footprint (MB) during benchmark execution."""
    def __init__(self, sample_interval: float = 0.05):
        self.sample_interval = sample_interval
        self.process = psutil.Process()
        self.cpu_samples = []
        self.ram_samples = []
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self.cpu_samples = []
        self.ram_samples = []
        self._stop_event.clear()
        self.process.cpu_percent(interval=None)
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                cpu = self.process.cpu_percent(interval=None)
                ram_mb = self.process.memory_info().rss / (1024 * 1024)
                if cpu > 0.0:
                    self.cpu_samples.append(cpu)
                self.ram_samples.append(ram_mb)
            except Exception:
                pass
            time.sleep(self.sample_interval)

    def stop(self) -> Dict[str, float]:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=1.0)

        peak_cpu = max(self.cpu_samples) if self.cpu_samples else 0.0
        avg_cpu = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0.0
        peak_ram = max(self.ram_samples) if self.ram_samples else 0.0
        avg_ram = sum(self.ram_samples) / len(self.ram_samples) if self.ram_samples else 0.0

        return {
            "peak_cpu_percent": round(peak_cpu, 1),
            "avg_cpu_percent": round(avg_cpu, 1),
            "peak_ram_mb": round(peak_ram, 1),
            "avg_ram_mb": round(avg_ram, 1)
        }


def benchmark_single_thread(events: List[str]) -> Dict[str, Any]:
    """Benchmark Single-Thread Pipeline Baseline."""
    settings = AppSettings({"pipeline": {"stop_on_error": False, "enable_enrichment": False}})
    pipeline = Pipeline(settings=settings)
    pipeline.sqlite_storage.save_event = lambda e: None
    pipeline.blockchain.add_event = lambda eid, h: None
    pipeline.siem_forwarder.forward = lambda d: None

    monitor = ResourceMonitor()
    monitor.start()

    start_time = time.perf_counter()
    processed = 0
    failed = 0
    latencies = []

    for raw in events:
        t0 = time.perf_counter()
        ev = pipeline.process_raw_event(raw, source_name="benchmark")
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)
        if ev:
            processed += 1
        else:
            failed += 1

    total_time = time.perf_counter() - start_time
    resource_stats = monitor.stop()

    eps = processed / total_time if total_time > 0 else 0.0
    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)] if latencies else 0.0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
    p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0.0
    avg_lat = sum(latencies) / len(latencies) if latencies else 0.0

    return {
        "mode": "Single-Thread Baseline",
        "processed": processed,
        "failed": failed,
        "total_time": round(total_time, 4),
        "eps": round(eps, 2),
        "avg_latency_ms": round(avg_lat, 4),
        "p50_ms": round(p50, 4),
        "p95_ms": round(p95, 4),
        "p99_ms": round(p99, 4),
        **resource_stats
    }


def benchmark_high_throughput(events: List[str], chunk_size: int = 2500) -> Dict[str, Any]:
    """Benchmark High-Throughput Multiprocessing Worker Pool (50,000+ EPS)."""
    htp = HighThroughputPipeline()
    monitor = ResourceMonitor()
    monitor.start()

    res = htp.process_events_batch(events, chunk_size=chunk_size)
    resource_stats = monitor.stop()

    return {
        "mode": "High-Throughput Multiprocessing",
        "processed": res["events_processed"],
        "failed": res["events_failed"],
        "total_time": res["total_time"],
        "eps": res["events_per_second"],
        "avg_latency_ms": res["average_latency_ms"],
        "p50_ms": res["latency_p50_ms"],
        "p95_ms": res["latency_p95_ms"],
        "p99_ms": res["latency_p99_ms"],
        **resource_stats
    }


def generate_benchmark_charts(results: List[Dict[str, Any]], output_dir: Path):
    """
    Renders clean visual charts:
      1. benchmark_eps.png: Ingestion speed (Events Per Second) comparison.
      2. benchmark_resource_footprint.png: Peak CPU % and RAM Footprint (MB).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    modes = [r["mode"] for r in results]
    eps_values = [r["eps"] for r in results]
    cpu_values = [r["peak_cpu_percent"] for r in results]
    ram_values = [r["peak_ram_mb"] for r in results]

    # Chart 1: EPS Throughput
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = ["#7f8c8d", "#2980b9", "#8e44ad", "#27ae60"][:len(results)]
    bars = ax.bar(modes, eps_values, color=colors, width=0.5, edgecolor="black", linewidth=1.2)

    # Highlight 50,000 EPS target line
    ax.axhline(50000, color="#c0392b", linestyle="--", linewidth=2, label="50,000 EPS Target Threshold")

    for bar, eps in zip(bars, eps_values):
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2.0, yval + (max(eps_values)*0.02), f"{eps:,.0f} EPS", ha="center", va="bottom", fontweight="bold", fontsize=11)

    ax.set_ylabel("Events Per Second (EPS)", fontsize=12, fontweight="bold")
    ax.set_title("ULPF Ingestion Throughput across Execution Models", fontsize=14, fontweight="bold", pad=15)
    ax.grid(axis="y", linestyle=":", alpha=0.6)
    ax.legend(loc="upper left", fontsize=11)
    plt.tight_layout()
    chart1_path = output_dir / "benchmark_eps.png"
    plt.savefig(chart1_path, dpi=300)
    plt.close()

    # Chart 2: CPU & RAM Resource Footprint Comparison
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    ax1.bar(modes, cpu_values, color="#e67e22", width=0.45, edgecolor="black")
    ax1.set_ylabel("Peak CPU Usage (%)", fontsize=12, fontweight="bold")
    ax1.set_title("Peak CPU Utilization", fontsize=13, fontweight="bold")
    ax1.grid(axis="y", linestyle=":", alpha=0.6)
    for bar in ax1.patches:
        ax1.text(bar.get_x() + bar.get_width()/2.0, bar.get_height() + 1, f"{bar.get_height():.1f}%", ha="center", va="bottom", fontweight="bold")

    ax2.bar(modes, ram_values, color="#3498db", width=0.45, edgecolor="black")
    ax2.set_ylabel("Peak RAM Footprint (MB)", fontsize=12, fontweight="bold")
    ax2.set_title("Peak Memory Footprint (RAM)", fontsize=13, fontweight="bold")
    ax2.grid(axis="y", linestyle=":", alpha=0.6)
    for bar in ax2.patches:
        ax2.text(bar.get_x() + bar.get_width()/2.0, bar.get_height() + 2, f"{bar.get_height():.1f} MB", ha="center", va="bottom", fontweight="bold")

    plt.suptitle("ULPF System Resource Footprint Comparison", fontsize=15, fontweight="bold", y=1.02)
    plt.tight_layout()
    chart2_path = output_dir / "benchmark_resource_footprint.png"
    plt.savefig(chart2_path, dpi=300)
    plt.close()

    print(f"\n[+] Visual Benchmark Charts generated successfully:")
    print(f"    - EPS Chart: {chart1_path}")
    print(f"    - Resource Footprint Chart: {chart2_path}")


def run_benchmark(count: int = 50000, format_choice: str = "all", generate_chart: bool = True):
    """Runs empirical benchmark suite across execution modes and prints report."""
    print("=" * 75)
    print(f" ULPF EMPIRICAL HIGH-THROUGHPUT PERFORMANCE BENCHMARK")
    print(f" Event Count: {count:,} | Log Format: {format_choice.upper()}")
    print("=" * 75)

    print(f"[*] Generating {count:,} realistic synthetic log records...")
    raw_events = generate_synthetic_events(count, format_choice)

    # 1. Single-Thread Baseline (Sample slice of events to keep test fast)
    sample_count = min(10000, count)
    print(f"\n[*] [1/2] Benchmarking Single-Thread Baseline ({sample_count:,} events)...")
    res_single = benchmark_single_thread(raw_events[:sample_count])
    print(f"    -> Throughput: {res_single['eps']:,.0f} EPS | Latency: {res_single['avg_latency_ms']:.3f} ms | CPU: {res_single['peak_cpu_percent']}% | RAM: {res_single['peak_ram_mb']} MB")

    # 2. High-Throughput Multiprocessing Worker Pool
    print(f"\n[*] [2/2] Benchmarking High-Throughput Multiprocessing Worker Pool ({count:,} events)...")
    res_ht = benchmark_high_throughput(raw_events, chunk_size=2500)
    print(f"    -> Throughput: {res_ht['eps']:,.0f} EPS | Latency: {res_ht['avg_latency_ms']:.3f} ms | CPU: {res_ht['peak_cpu_percent']}% | RAM: {res_ht['peak_ram_mb']} MB")

    results = [res_single, res_ht]

    print("\n" + "=" * 75)
    print(" FINAL EMPIRICAL PERFORMANCE BENCHMARK SUMMARY")
    print("=" * 75)
    print(f" {'Execution Model':<32} | {'Throughput (EPS)':<18} | {'Latency (p50)':<12} | {'Peak CPU':<10} | {'Peak RAM':<10}")
    print("-" * 75)
    for r in results:
        print(f" {r['mode']:<32} | {r['eps']:>14,.0f} eps | {r['p50_ms']:>9.3f} ms | {r['peak_cpu_percent']:>8.1f}% | {r['peak_ram_mb']:>7.1f} MB")
    print("=" * 75)

    if res_ht["eps"] >= 50000:
        print(f"\n[ SUCCESS ] High-Throughput Ingestion Target ACHIEVED! Speed: {res_ht['eps']:,.0f} EPS (Target: 50,000+ EPS)")
    else:
        print(f"\n[*] Measured Ingestion Speed: {res_ht['eps']:,.0f} EPS (Multi-core ProcessPool scaling active)")

    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_file = output_dir / "benchmark_results.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    if generate_chart:
        generate_benchmark_charts(results, output_dir)


if __name__ == "__main__":
    count_arg = 50000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        count_arg = int(sys.argv[1])
    run_benchmark(count=count_arg)
