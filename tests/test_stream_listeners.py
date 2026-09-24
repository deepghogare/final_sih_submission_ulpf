"""
Automated Pytest Suite for Real-Time Streaming Ingestion Listeners (UDP & TCP).
"""

import asyncio
import socket
import time
import pytest
from pathlib import Path

from app.core.stream_listener import StreamListenerManager
from app.core.pipeline import Pipeline
from app.storage.json_writer import JsonWriter


def test_udp_stream_listener(tmp_path):
    async def run_test():
        output_file = tmp_path / "stream_udp_out.jsonl"
        writer = JsonWriter(output_file)
        manager = StreamListenerManager(output_writer=writer)

        udp_port = 15140
        await manager.start_udp_listener(host="127.0.0.1", port=udp_port)
        assert manager._running_udp is True

        # Send a sample UDP syslog packet
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sample_log = "<34>1 2026-09-23T23:50:00Z firewall %ASA-6-302013: Built TCP connection 192.168.1.1:5000 -> 10.0.0.1:80"
        sock.sendto(sample_log.encode("utf-8"), ("127.0.0.1", udp_port))
        sock.close()

        # Allow asyncio loop to process datagram
        await asyncio.sleep(0.3)

        await manager.stop_udp_listener()
        assert manager._running_udp is False
        assert manager.events_received_stream >= 1

        # Verify event written to output JSONL
        assert output_file.exists()
        content = output_file.read_text(encoding="utf-8")
        assert "ULPF-" in content
        assert "192.168.1.1" in content or "firewall" in content or "raw" in content

    asyncio.run(run_test())


def test_tcp_stream_listener(tmp_path):
    async def run_test():
        output_file = tmp_path / "stream_tcp_out.jsonl"
        writer = JsonWriter(output_file)
        manager = StreamListenerManager(output_writer=writer)

        tcp_port = 15141
        await manager.start_tcp_listener(host="127.0.0.1", port=tcp_port)
        assert manager._running_tcp is True

        # Connect TCP socket and stream 2 lines
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", tcp_port))

        line1 = '{"timestamp":"2026-09-23T23:51:00Z","src_ip":"10.0.0.5","action":"ALLOW"}\n'
        line2 = 'CEF:0|VendorX|AppY|1.0|100|Login|5|src=172.16.0.1 dst=10.0.0.2 act=DENY\n'

        client.sendall(line1.encode("utf-8"))
        client.sendall(line2.encode("utf-8"))
        client.close()

        await asyncio.sleep(0.3)

        await manager.stop_tcp_listener()
        assert manager._running_tcp is False
        assert manager.events_received_stream >= 2

    asyncio.run(run_test())


def test_listener_status_summary():
    manager = StreamListenerManager()
    status = manager.get_status()
    assert "udp" in status
    assert "tcp" in status
    assert "kafka" in status
    assert "stats" in status
    assert status["udp"]["active"] is False
    assert status["tcp"]["active"] is False

