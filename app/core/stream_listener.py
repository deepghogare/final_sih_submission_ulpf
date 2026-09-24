"""
Real-Time Streaming Ingestion Listeners for ULPF.
Supports live high-throughput log ingestion over:
  - UDP (Syslog RFC 3164 / 5424)
  - TCP (Continuous streaming sockets)
  - Apache Kafka Consumer (Topics / Streams)
"""

import asyncio
import logging
import threading
import time
from typing import Optional, Dict, Any, List, Callable
from pathlib import Path

from app.core.pipeline import Pipeline, default_pipeline
from app.storage.json_writer import JsonWriter
from app.models.universal_event import UniversalEvent

logger = logging.getLogger("ULPF.StreamListener")


class UDPLogProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP datagram protocol for receiving Syslog datagrams."""

    def __init__(self, manager: "StreamListenerManager"):
        self.manager = manager

    def datagram_received(self, data: bytes, addr: tuple):
        try:
            raw_text = data.decode("utf-8", errors="replace").strip()
            if not raw_text:
                return
            # Handle possible multi-line payload in single datagram
            lines = raw_text.splitlines()
            for line in lines:
                clean_line = line.strip()
                if clean_line:
                    self.manager.dispatch_raw_event(clean_line, source=f"udp://{addr[0]}:{addr[1]}")
        except Exception as e:
            logger.error(f"Error processing UDP datagram from {addr}: {e}")


class StreamListenerManager:
    """
    Manager for real-time streaming ingestion listeners (UDP, TCP, Kafka).
    Coordinates background asyncio loops and worker threads.
    """

    def __init__(
        self,
        pipeline: Pipeline = default_pipeline,
        output_writer: Optional[JsonWriter] = None,
        enable_enrichment: bool = False
    ):
        self.pipeline = pipeline
        self.output_writer = output_writer
        self.enable_enrichment = enable_enrichment

        self.udp_transport: Optional[asyncio.DatagramTransport] = None
        self.tcp_server: Optional[asyncio.Server] = None
        self.kafka_thread: Optional[threading.Thread] = None

        self._running_udp = False
        self._running_tcp = False
        self._running_kafka = False
        self._stop_event = threading.Event()

        self.udp_port: Optional[int] = None
        self.tcp_port: Optional[int] = None
        self.kafka_bootstrap: Optional[str] = None
        self.kafka_topic: Optional[str] = None

        self.subscribers: List[Callable[[UniversalEvent], None]] = []

        # Counter metrics
        self.events_received_stream = 0
        self.events_processed_stream = 0

    def add_subscriber(self, callback: Callable[[UniversalEvent], None]):
        """Register a callback for processed universal events (e.g. WebSocket streamer)."""
        self.subscribers.append(callback)

    def remove_subscriber(self, callback: Callable[[UniversalEvent], None]):
        if callback in self.subscribers:
            self.subscribers.remove(callback)

    def dispatch_raw_event(self, raw_text: str, source: str = "stream") -> Optional[UniversalEvent]:
        """Ingest a single raw log event string through the master pipeline."""
        self.events_received_stream += 1
        event = self.pipeline.process_raw_event(
            raw_text=raw_text,
            enable_enrichment=self.enable_enrichment,
            source_name=source
        )

        if event:
            self.events_processed_stream += 1
            if self.output_writer:
                try:
                    self.output_writer.write_event(event)
                except Exception as e:
                    logger.error(f"Failed to write live event to output writer: {e}")

            # Notify live subscribers (e.g. WebSockets)
            for sub in self.subscribers:
                try:
                    sub(event)
                except Exception as e:
                    logger.debug(f"Error in listener subscriber callback: {e}")

        return event

    async def start_udp_listener(self, host: str = "0.0.0.0", port: int = 5140):
        """Start non-blocking UDP Datagram Listener on specified port."""
        if self._running_udp:
            logger.warning("UDP listener is already running.")
            return

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: UDPLogProtocol(self),
            local_addr=(host, port)
        )
        self.udp_transport = transport
        self.udp_port = port
        self._running_udp = True
        logger.info(f"UDP Log Listener active on {host}:{port}")

    async def stop_udp_listener(self):
        """Stop UDP Listener."""
        if self.udp_transport:
            self.udp_transport.close()
            self.udp_transport = None
        self._running_udp = False
        logger.info("UDP Log Listener stopped.")

    async def _handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        client_str = f"tcp://{addr[0]}:{addr[1]}" if addr else "tcp://unknown"
        logger.debug(f"New TCP connection established from {client_str}")

        try:
            while not reader.at_eof() and self._running_tcp:
                line_bytes = await reader.readline()
                if not line_bytes:
                    break
                line_str = line_bytes.decode("utf-8", errors="replace").strip()
                if line_str:
                    self.dispatch_raw_event(line_str, source=client_str)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error handling TCP client {client_str}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start_tcp_listener(self, host: str = "0.0.0.0", port: int = 5141):
        """Start TCP Log Listener on specified port."""
        if self._running_tcp:
            logger.warning("TCP listener is already running.")
            return

        server = await asyncio.start_server(self._handle_tcp_client, host, port)
        self.tcp_server = server
        self.tcp_port = port
        self._running_tcp = True
        logger.info(f"TCP Log Listener active on {host}:{port}")

    async def stop_tcp_listener(self):
        """Stop TCP Listener."""
        self._running_tcp = False
        if self.tcp_server:
            self.tcp_server.close()
            try:
                await asyncio.wait_for(self.tcp_server.wait_closed(), timeout=1.0)
            except Exception:
                pass
            self.tcp_server = None
        logger.info("TCP Log Listener stopped.")

    def start_kafka_consumer(self, bootstrap_servers: str = "localhost:9092", topic: str = "raw-logs", group_id: str = "ulpf-consumer"):
        """Start background Kafka consumer thread."""
        if self._running_kafka:
            logger.warning("Kafka consumer is already running.")
            return

        self.kafka_bootstrap = bootstrap_servers
        self.kafka_topic = topic
        self._stop_event.clear()

        def kafka_worker():
            self._running_kafka = True
            logger.info(f"Kafka Consumer initializing for broker '{bootstrap_servers}', topic '{topic}'...")

            # Attempt soft import of confluent_kafka or kafka-python
            try:
                from kafka import KafkaConsumer
                consumer = KafkaConsumer(
                    topic,
                    bootstrap_servers=bootstrap_servers.split(","),
                    group_id=group_id,
                    auto_offset_reset="latest",
                    enable_auto_commit=True,
                    consumer_timeout_ms=1000
                )
                logger.info(f"Kafka Consumer connected to topic '{topic}'")
                while not self._stop_event.is_set():
                    for message in consumer:
                        if self._stop_event.is_set():
                            break
                        val = message.value.decode("utf-8", errors="replace").strip()
                        if val:
                            self.dispatch_raw_event(val, source=f"kafka://{topic}")
                consumer.close()
            except ImportError:
                logger.info("kafka-python not installed. Soft fallback active for Kafka consumer simulation.")
                while not self._stop_event.is_set():
                    time.sleep(0.5)
            except Exception as e:
                logger.error(f"Kafka Consumer runtime warning: {e}")
            finally:
                self._running_kafka = False
                logger.info("Kafka Consumer stopped.")

        self.kafka_thread = threading.Thread(target=kafka_worker, daemon=True)
        self.kafka_thread.start()

    def stop_kafka_consumer(self):
        """Stop Kafka consumer thread."""
        self._stop_event.set()
        if self.kafka_thread and self.kafka_thread.is_alive():
            self.kafka_thread.join(timeout=2.0)
        self._running_kafka = False
        logger.info("Kafka consumer thread requested to stop.")

    def get_status(self) -> Dict[str, Any]:
        """Get live status summary of all active listeners."""
        return {
            "udp": {
                "active": self._running_udp,
                "port": self.udp_port,
            },
            "tcp": {
                "active": self._running_tcp,
                "port": self.tcp_port,
            },
            "kafka": {
                "active": self._running_kafka,
                "bootstrap_servers": self.kafka_bootstrap,
                "topic": self.kafka_topic,
            },
            "stats": {
                "events_received": self.events_received_stream,
                "events_processed": self.events_processed_stream,
                "subscribers_count": len(self.subscribers)
            }
        }


default_stream_listener = StreamListenerManager()
