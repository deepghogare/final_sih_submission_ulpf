"""
Integration test for high-volume parallel multi-worker log processing.
Generates 100+ log files across multiple subdirectories and processes
them concurrently with multiple worker threads.
"""

from pathlib import Path
from app.core.pipeline import Pipeline
from app.core.config import AppSettings
from app.storage.json_writer import JsonWriter
from app.storage.sqlite_storage import SqliteStorage
from app.main import cmd_process
import argparse


def test_parallel_batch_processing_100_files(tmp_path):
    """Generate 100 heterogeneous log files and process them concurrently with 4 workers."""
    batch_dir = tmp_path / "batch_logs"
    batch_dir.mkdir()

    total_expected_events = 0

    # Create 10 subdirectories with 10 files each = 100 files
    for sub_idx in range(10):
        sub_dir = batch_dir / f"sub_{sub_idx}"
        sub_dir.mkdir()

        for f_idx in range(10):
            fmt_choice = f_idx % 4
            file_num = sub_idx * 10 + f_idx

            if fmt_choice == 0:
                # JSON log
                log_file = sub_dir / f"log_{file_num}.json"
                log_file.write_text(
                    f'{{"src_ip": "10.0.{sub_idx}.{f_idx}", "dst_ip": "192.168.1.1", "action": "deny", "severity": "high", "vendor": "VendorA"}}\n',
                    encoding="utf-8"
                )
                total_expected_events += 1
            elif fmt_choice == 1:
                # Syslog
                log_file = sub_dir / f"log_{file_num}.log"
                log_file.write_text(
                    f"<134>1 2026-09-02T18:00:00Z fw.corp ULPF - - - action=allow src=172.16.{sub_idx}.{f_idx} dst=8.8.8.8 sport=52000 dport=443 proto=TCP\n",
                    encoding="utf-8"
                )
                total_expected_events += 1
            elif fmt_choice == 2:
                # CEF
                log_file = sub_dir / f"log_{file_num}.cef"
                log_file.write_text(
                    f"CEF:0|CyberVendor|Firewall|1.0|100|Drop Packet|medium|src=198.51.100.{f_idx} dst=10.0.0.1 spt=4500 dpt=80 proto=TCP act=drop\n",
                    encoding="utf-8"
                )
                total_expected_events += 1
            else:
                # Multi-line NDJSON (3 events per file)
                log_file = sub_dir / f"log_{file_num}.ndjson"
                log_file.write_text(
                    f'{{"src_ip": "10.1.{sub_idx}.1", "dst_ip": "192.168.1.1", "action": "allow"}}\n'
                    f'{{"src_ip": "10.1.{sub_idx}.2", "dst_ip": "192.168.1.1", "action": "deny"}}\n'
                    f'{{"src_ip": "10.1.{sub_idx}.3", "dst_ip": "192.168.1.1", "action": "drop"}}\n',
                    encoding="utf-8"
                )
                total_expected_events += 3

    output_file = tmp_path / "output_parallel.jsonl"

    # Simulate CLI call with --workers 4
    args = argparse.Namespace(
        path=str(batch_dir),
        output=str(output_file),
        output_format="jsonl",
        format=None,
        vendor=None,
        enrich=False,
        workers=4
    )

    cmd_process(args)

    # Verify output file exists and has correct event count
    assert output_file.is_file()
    with open(output_file, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    assert len(lines) == total_expected_events
    print(f"Verified all {total_expected_events} events processed in parallel across 100 files!")
