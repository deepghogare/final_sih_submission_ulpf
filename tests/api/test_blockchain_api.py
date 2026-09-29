"""
Tests for the Cryptographic Blockchain Ledger REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from app.api.routes import app
from app.core.pipeline import default_pipeline


@pytest.fixture(autouse=True)
def ensure_clean_ledger_state():
    """Ensure blockchain is in a repaired/valid state before and after each test."""
    default_pipeline.blockchain.repair_tamper()
    yield
    default_pipeline.blockchain.repair_tamper()


def test_blockchain_blocks_endpoint():
    """Verify that /api/v1/blockchain/blocks returns the chain with valid blocks."""
    with TestClient(app) as client:
        res = client.get("/api/v1/blockchain/blocks?limit=10000")
        assert res.status_code == 200
        data = res.json()
        assert "blocks" in data
        assert "pending_events" in data
        assert len(data["blocks"]) >= 1
        genesis = data["blocks"][-1]
        assert genesis["index"] == 0
        assert genesis["prev_hash"] == "0" * 64


def test_blockchain_audit_endpoint():
    """Verify that /api/v1/blockchain/audit performs full cryptographic verification."""
    with TestClient(app) as client:
        res = client.get("/api/v1/blockchain/audit")
        assert res.status_code == 200
        audit = res.json()
        assert "is_valid" in audit
        assert "total_blocks" in audit
        assert audit["is_valid"] is True
        assert audit["broken_at_block"] is None


def test_blockchain_seal_endpoint():
    """Verify that /api/v1/blockchain/seal manually seals buffered events."""
    with TestClient(app) as client:
        # Buffer an unsealed event directly
        default_pipeline.blockchain.add_event(
            event_id="test-seal-manual-001",
            raw_event_hash="a" * 64
        )

        # Seal
        seal_res = client.post("/api/v1/blockchain/seal")
        assert seal_res.status_code == 200
        seal_data = seal_res.json()
        assert seal_data["sealed"] is True
        assert "block" in seal_data
        block = seal_data["block"]
        assert block["index"] >= 1
        assert block["event_count"] >= 1
        assert block["block_hash"] is not None
        assert block["merkle_root"] is not None


def test_blockchain_merkle_proof_endpoint():
    """Verify that /api/v1/blockchain/proof/{event_id} returns an audit proof."""
    with TestClient(app) as client:
        # Ingest a specific event
        ingest_payload = {
            "raw_event": '{"src_ip": "192.168.100.5", "dst_ip": "8.8.8.8", "action": "drop", "severity": "critical", "vendor": "ProofTest"}',
            "format": "json"
        }
        ingest_res = client.post("/api/v1/events", json=ingest_payload)
        assert ingest_res.status_code == 200
        event_id = ingest_res.json()["event_id"]

        # Seal the block so the event is put into a merkle tree
        client.post("/api/v1/blockchain/seal")

        # Request proof
        proof_res = client.get(f"/api/v1/blockchain/proof/{event_id}")
        assert proof_res.status_code == 200
        proof_data = proof_res.json()
        assert proof_data["event_id"] == event_id
        assert proof_data["is_valid"] is True
        assert "merkle_root" in proof_data
        assert "block_hash" in proof_data
        assert "proof" in proof_data


def test_blockchain_tamper_and_repair_simulation():
    """Verify that /simulate-tamper alerts the auditor and /repair restores integrity."""
    with TestClient(app) as client:
        # 1. Ingest and ensure at least one block exists
        client.post("/api/v1/events", json={
            "raw_event": '{"src_ip": "10.1.1.1", "dst_ip": "10.2.2.2", "action": "alert", "severity": "medium", "vendor": "TamperTest"}',
            "format": "json"
        })

        # 2. Simulate tamper attack
        tamper_res = client.post("/api/v1/blockchain/simulate-tamper?block_index=1")
        assert tamper_res.status_code == 200
        tamper_data = tamper_res.json()
        assert tamper_data["status"] == "tamper_injected"

        # 3. Audit must detect the tamper
        audit_res = client.get("/api/v1/blockchain/audit")
        assert audit_res.status_code == 200
        audit_data = audit_res.json()
        assert audit_data["is_valid"] is False
        assert audit_data["broken_at_block"] is not None

        # 4. Repair the chain
        repair_res = client.post("/api/v1/blockchain/repair")
        assert repair_res.status_code == 200
        repair_data = repair_res.json()
        assert repair_data["status"] == "repaired"

        # 5. Audit must now pass
        audit_res2 = client.get("/api/v1/blockchain/audit")
        assert audit_res2.status_code == 200
        audit_data2 = audit_res2.json()
        assert audit_data2["is_valid"] is True
        assert audit_data2["broken_at_block"] is None
