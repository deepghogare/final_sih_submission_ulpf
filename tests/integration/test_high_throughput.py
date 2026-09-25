"""
Integration test suite for High-Throughput Multiprocessing, Async Batching,
and Visual Benchmark Chart Generation in ULPF.
"""

import pytest
import asyncio
from pathlib import Path

from app.core.high_throughput import HighThroughputPipeline, AsyncBatchProcessor
from scripts.benchmark import generate_synthetic_events, generate_benchmark_charts, benchmark_high_throughput


def test_high_throughput_pipeline_batch_50k():
    """Verify HighThroughputPipeline processes 50,000 events using ProcessPoolExecutor."""
    events = generate_synthetic_events(50000, format_choice="all")
    htp = HighThroughputPipeline()
    res = htp.process_events_batch(events, chunk_size=2500)

    assert res["events_received"] == 50000
    assert res["events_processed"] == 50000
    assert res["events_failed"] == 0
    assert res["events_per_second"] > 0
    assert res["average_latency_ms"] > 0
    assert "latency_p50_ms" in res
    assert "latency_p95_ms" in res
    assert "latency_p99_ms" in res
    print(f"\n[+] Processed 50,000 events at {res['events_per_second']:,.0f} EPS!")


def test_async_batch_processor():
    """Verify AsyncBatchProcessor queues and flushes batches asynchronously."""
    async def _run():
        processor = AsyncBatchProcessor(batch_size=1000, flush_interval=0.02)
        await processor.start()

        events = generate_synthetic_events(5000, format_choice="syslog")
        await processor.push_events_batch(events)

        # Give worker loop time to process queue
        await asyncio.sleep(0.5)
        await processor.stop()

        assert processor.total_processed == 5000
        assert processor.total_failed == 0
        print("\n[+] AsyncBatchProcessor processed all 5,000 queued events cleanly!")

    asyncio.run(_run())


def test_benchmark_chart_generation(tmp_path):
    """Verify matplotlib renders EPS and Resource Footprint charts to PNG."""
    mock_results = [
        {
            "mode": "Single-Thread Baseline",
            "processed": 10000,
            "failed": 0,
            "total_time": 2.5,
            "eps": 4000.0,
            "avg_latency_ms": 0.25,
            "p50_ms": 0.23,
            "p95_ms": 0.35,
            "p99_ms": 0.50,
            "peak_cpu_percent": 100.0,
            "avg_cpu_percent": 95.0,
            "peak_ram_mb": 85.0,
            "avg_ram_mb": 80.0
        },
        {
            "mode": "High-Throughput Multiprocessing",
            "processed": 50000,
            "failed": 0,
            "total_time": 0.9,
            "eps": 55555.5,
            "avg_latency_ms": 0.11,
            "p50_ms": 0.09,
            "p95_ms": 0.18,
            "p99_ms": 0.25,
            "peak_cpu_percent": 85.0,
            "avg_cpu_percent": 70.0,
            "peak_ram_mb": 95.0,
            "avg_ram_mb": 90.0
        }
    ]

    generate_benchmark_charts(mock_results, tmp_path)

    eps_chart = tmp_path / "benchmark_eps.png"
    resource_chart = tmp_path / "benchmark_resource_footprint.png"

    assert eps_chart.is_file()
    assert eps_chart.stat().st_size > 0
    assert resource_chart.is_file()
    assert resource_chart.stat().st_size > 0
    print("\n[+] Visual PNG chart outputs verified on disk!")
