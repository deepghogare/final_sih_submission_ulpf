"""
FastAPI REST API Interface for ULPF.
Provides endpoints for online log ingestion, event query, plugin inspection,
health check, and real-time metrics.
"""

from typing import List, Optional, Dict, Any
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, UploadFile, File, Form, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
import tempfile
import os
import asyncio

from app.core.config import default_settings
from app.core.pipeline import default_pipeline
from app.core.stream_listener import default_stream_listener
from app.plugins.loader import default_plugin_loader
from app.models.universal_event import UniversalEvent

TEMPLATE_PATH = Path(__file__).parent.parent / "templates" / "dashboard.html"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Discover and activate plugins automatically
    default_plugin_loader.discover_and_load(default_settings.plugins_dir)
    yield


from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="ULPF - Universal Log Pre-processing Framework API",
    version="1.0.0",
    description="Standardization and pre-processing layer for heterogeneous cybersecurity logs (SIH 2026 - NTRO).",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EventIngestRequest(BaseModel):
    raw_event: str = Field(description="Raw log event string")
    format: Optional[str] = Field(default=None, description="Optional format override")
    vendor: Optional[str] = Field(default=None, description="Optional vendor override")
    enable_enrichment: Optional[bool] = Field(default=False, description="Enable local asset enrichment")


class BatchEventIngestRequest(BaseModel):
    events: List[str] = Field(description="List of raw log event strings")
    format: Optional[str] = Field(default=None)
    vendor: Optional[str] = Field(default=None)
    enable_enrichment: Optional[bool] = Field(default=False)


@app.get("/api/v1/health", tags=["System"])
def health_check():
    """System health and readiness check."""
    return {
        "status": "healthy",
        "service": "ULPF",
        "version": "1.0.0",
        "mode": "air-gapped-compatible"
    }


@app.get("/api/v1/metrics", tags=["System"])
def get_metrics():
    """Real-time processing throughput, latency percentiles, and failure distributions."""
    return default_pipeline.metrics.get_snapshot()


@app.get("/api/v1/formats", tags=["Discovery"])
def get_supported_formats():
    """List all registered log format parsers and content detectors."""
    return {
        "supported_formats": default_pipeline.registry.list_parsers()
    }


@app.get("/api/v1/plugins", tags=["Discovery"])
def get_plugins():
    """List loaded dynamic plugins and their metadata."""
    return {
        "plugins": [
            {
                "name": p.name,
                "version": p.version,
                "author": p.author,
                "description": p.description,
                "supported_vendors": p.supported_vendors,
                "supported_formats": p.supported_formats,
                "status": "active"
            }
            for p in default_pipeline.plugin_registry.list_plugins()
        ]
    }


@app.post("/api/v1/plugins/reload", tags=["Discovery"])
def reload_plugins():
    """Dynamically scan plugins/ directory and hot-reload all new and updated plugins."""
    count = default_plugin_loader.discover_and_load(default_settings.plugins_dir)
    active = default_pipeline.plugin_registry.list_plugins()
    return {
        "status": "success",
        "loaded_count": count,
        "total_active": len(active),
        "plugins": [p.name for p in active]
    }


@app.get("/", response_class=HTMLResponse, tags=["Dashboard"], include_in_schema=False)
@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
def get_dashboard():
    """Renders the built-in SIEM Cyber Operations Dashboard."""
    if TEMPLATE_PATH.is_file():
        return HTMLResponse(content=TEMPLATE_PATH.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>ULPF Dashboard template not found</h1>", status_code=500)


@app.get("/api/v1/dashboard/stats", tags=["Dashboard"])
def get_dashboard_stats():
    """Aggregated security and operational metrics for the SIEM dashboard."""
    stats = default_pipeline.sqlite_storage.get_dashboard_summary()
    metrics = default_pipeline.metrics.get_snapshot()

    live_eps = metrics.get("events_per_second", 0.0)
    avg_latency = metrics.get("average_latency_ms", 0.0)

    if avg_latency == 0.0:
        avg_latency = stats.get("db_average_latency_ms", 0.0)
        if avg_latency == 0.0 and stats.get("total_events", 0) > 0:
            avg_latency = default_pipeline.sqlite_storage.get_average_latency()

    stats["throughput_eps"] = live_eps
    stats["average_latency_ms"] = avg_latency
    stats["events_failed"] = metrics.get("events_failed", 0)
    return stats


@app.post("/api/v1/events", tags=["Ingestion"], response_model=UniversalEvent)
def ingest_single_event(request: EventIngestRequest):
    """Ingest a single raw event and return the standardized Universal Event JSON."""
    event = default_pipeline.process_raw_event(
        raw_text=request.raw_event,
        force_format=request.format,
        force_vendor=request.vendor,
        enable_enrichment=request.enable_enrichment
    )
    if not event:
        raise HTTPException(status_code=400, detail="Failed to process raw event. Recorded in dead-letter storage.")
    return event


@app.post("/api/v1/process", tags=["Ingestion"])
async def process_log_file(
    file: UploadFile = File(...),
    format_override: Optional[str] = Form(None),
    vendor_override: Optional[str] = Form(None),
    enable_enrichment: bool = Form(False)
):
    """Upload a log file containing 1 to N events and process it into Universal Events."""
    content = await file.read()
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{file.filename}") as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        events = default_pipeline.process_file(
            file_path=tmp_path,
            force_format=format_override,
            force_vendor=vendor_override,
            enable_enrichment=enable_enrichment
        )
        return {
            "filename": file.filename,
            "events_processed": len(events),
            "events": [ev.model_dump() for ev in events]
        }
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.get("/api/v1/events", tags=["Storage"])
def list_events(
    limit: int = 50,
    offset: int = 0,
    query: Optional[str] = None,
    action: Optional[str] = None,
    severity: Optional[str] = None
):
    """Query processed events stored in local SQLite database with optional filters."""
    return default_pipeline.sqlite_storage.list_events(
        limit=limit,
        offset=offset,
        query=query,
        action=action,
        severity=severity
    )


@app.get("/api/v1/events/{event_id}", tags=["Storage"])
def get_event_by_id(event_id: str):
    """Retrieve a single Universal Event by its event_id."""
    event = default_pipeline.sqlite_storage.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found")
    return event


# ==============================================================================
# Blockchain & Cryptographic Ledger Endpoints
# ==============================================================================

@app.get("/api/v1/blockchain/blocks", tags=["Blockchain"])
def get_blockchain_blocks(limit: int = 20, offset: int = 0):
    """List sealed cryptographic blocks from the immutable ledger."""
    return {
        "blocks": default_pipeline.blockchain.get_blocks(limit=limit, offset=offset),
        "pending_events": default_pipeline.blockchain.get_pending_count()
    }


@app.get("/api/v1/blockchain/audit", tags=["Blockchain"])
def audit_blockchain():
    """Runs a full cryptographic audit verifying hashes, prev_hash links, and contiguity."""
    return default_pipeline.blockchain.verify_chain()


@app.get("/api/v1/blockchain/proof/{event_id}", tags=["Blockchain"])
def get_merkle_proof(event_id: str):
    """Retrieves an O(log N) Merkle audit path for selective disclosure."""
    proof_data = default_pipeline.blockchain.get_merkle_proof_for_event(event_id)
    if not proof_data:
        raise HTTPException(status_code=404, detail=f"No sealed block found for event '{event_id}'")
    return proof_data


@app.post("/api/v1/blockchain/seal", tags=["Blockchain"])
def seal_pending_block():
    """Manually forces any buffered events to be sealed into a new cryptographic block."""
    block = default_pipeline.blockchain.seal_block()
    if not block:
        return {"message": "No pending events to seal.", "sealed": False}
    return {"message": f"Sealed Block #{block.index}", "sealed": True, "block": block.to_dict()}


@app.post("/api/v1/blockchain/simulate-tamper", tags=["Blockchain"])
def simulate_blockchain_tamper(block_index: int = 1):
    """Simulates a database tamper attack on a block to demonstrate detection in evaluations."""
    default_pipeline.blockchain.simulate_tamper(block_index=block_index)
    return {
        "status": "tamper_injected",
        "target_block": block_index,
        "message": "Block hash was artificially corrupted. Run audit to observe detection!"
    }


@app.post("/api/v1/blockchain/repair", tags=["Blockchain"])
def repair_blockchain():
    """Restores the blockchain ledger by recalculating authentic cryptographic hashes."""
    count = default_pipeline.blockchain.repair_tamper()
    return {"status": "repaired", "blocks_restored": count}


@app.post("/api/v1/events/clear", tags=["Ingestion"])
def clear_all_events():
    """Clears all stored events from SQLite and resets the blockchain ledger back to Genesis."""
    from app.storage.sqlite_storage import default_sqlite_storage
    from app.integrity.blockchain import default_blockchain_ledger
    default_sqlite_storage.clear_all()
    default_blockchain_ledger.reset_ledger()
    return {"status": "cleared", "message": "All events and blocks cleared. System reset to 0 events."}


@app.get("/api/v1/siem/status", tags=["SIEM Integration"])
def get_siem_status():
    """Returns the live operational status and metrics of the Wazuh SIEM forwarder."""
    return default_pipeline.siem_forwarder.get_status()


# ==============================================================================
# Streaming Ingestion Listeners (UDP/TCP/Kafka) & WebSockets
# ==============================================================================

class StartListenerRequest(BaseModel):
    protocol: str = Field(description="Protocol to start ('udp', 'tcp', 'kafka')")
    port: Optional[int] = Field(default=None, description="Port for UDP or TCP listener")
    host: Optional[str] = Field(default="0.0.0.0", description="Host bind IP")
    kafka_bootstrap: Optional[str] = Field(default="localhost:9092")
    kafka_topic: Optional[str] = Field(default="raw-logs")


@app.get("/api/v1/listeners/status", tags=["Streaming Listeners"])
def get_listeners_status():
    """Get status of UDP, TCP, and Kafka real-time listeners."""
    return default_stream_listener.get_status()


@app.post("/api/v1/listeners/start", tags=["Streaming Listeners"])
async def start_listener(req: StartListenerRequest):
    """Start UDP, TCP, or Kafka background listener."""
    proto = req.protocol.lower()
    if proto == "udp":
        port = req.port or 5140
        await default_stream_listener.start_udp_listener(host=req.host or "0.0.0.0", port=port)
        return {"status": "success", "message": f"UDP Listener started on {req.host}:{port}"}
    elif proto == "tcp":
        port = req.port or 5141
        await default_stream_listener.start_tcp_listener(host=req.host or "0.0.0.0", port=port)
        return {"status": "success", "message": f"TCP Listener started on {req.host}:{port}"}
    elif proto == "kafka":
        default_stream_listener.start_kafka_consumer(
            bootstrap_servers=req.kafka_bootstrap or "localhost:9092",
            topic=req.kafka_topic or "raw-logs"
        )
        return {"status": "success", "message": f"Kafka Consumer started for topic '{req.kafka_topic}'"}
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported protocol '{req.protocol}'")


@app.post("/api/v1/listeners/stop", tags=["Streaming Listeners"])
async def stop_listener(protocol: str):
    """Stop active streaming listener ('udp', 'tcp', 'kafka')."""
    proto = protocol.lower()
    if proto == "udp":
        await default_stream_listener.stop_udp_listener()
        return {"status": "success", "message": "UDP Listener stopped"}
    elif proto == "tcp":
        await default_stream_listener.stop_tcp_listener()
        return {"status": "success", "message": "TCP Listener stopped"}
    elif proto == "kafka":
        default_stream_listener.stop_kafka_consumer()
        return {"status": "success", "message": "Kafka Consumer stopped"}
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported protocol '{protocol}'")


@app.websocket("/api/v1/ws/live-stream")
async def websocket_live_stream(websocket: WebSocket):
    """Real-time WebSocket endpoint streaming normalized Universal Events live."""
    await websocket.accept()
    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def on_event(ev: UniversalEvent):
        loop.call_soon_threadsafe(queue.put_nowait, ev.model_dump())

    default_stream_listener.add_subscriber(on_event)

    try:
        while True:
            ev_dict = await queue.get()
            await websocket.send_json(ev_dict)
    except WebSocketDisconnect:
        logger.debug("WebSocket client disconnected.")
    except Exception as e:
        logger.debug(f"WebSocket error: {e}")
    finally:
        default_stream_listener.remove_subscriber(on_event)



