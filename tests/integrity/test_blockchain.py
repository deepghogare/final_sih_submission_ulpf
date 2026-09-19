"""
Unit and Integration Tests for Cryptographic Blockchain Ledger and Merkle Tree Engine.
"""

from pathlib import Path
import hashlib
from app.integrity.blockchain import MerkleTree, Block, BlockchainLedger


def test_merkle_tree_basic():
    """Verify Merkle Tree root calculation and deterministic structure."""
    leaves = [
        hashlib.sha256(b"event_1").hexdigest(),
        hashlib.sha256(b"event_2").hexdigest(),
        hashlib.sha256(b"event_3").hexdigest(),
        hashlib.sha256(b"event_4").hexdigest()
    ]
    tree = MerkleTree(leaves)
    root = tree.root
    assert len(root) == 64
    assert root != "0" * 64

    # Tree should be deterministic
    tree2 = MerkleTree(leaves)
    assert tree.root == tree2.root


def test_merkle_proof_verification():
    """Verify logarithmic Merkle audit path generation and zero-knowledge verification."""
    leaves = [
        hashlib.sha256(f"log_event_{i}".encode()).hexdigest()
        for i in range(8)
    ]
    tree = MerkleTree(leaves)
    target = leaves[3]

    proof = tree.get_proof(target)
    assert proof is not None
    assert len(proof) == 3  # log2(8) = 3 steps

    # Proof verification succeeds for authentic leaf
    assert MerkleTree.verify_proof(target, proof, tree.root) is True

    # Proof verification fails if target hash is tampered
    fake_target = hashlib.sha256(b"tampered_log").hexdigest()
    assert MerkleTree.verify_proof(fake_target, proof, tree.root) is False

    # Proof verification fails if expected root is wrong
    assert MerkleTree.verify_proof(target, proof, "0" * 64) is False


def test_blockchain_genesis_and_sealing(tmp_path):
    """Verify Genesis block creation, event buffering, and sequential block sealing."""
    db_path = tmp_path / "test_ledger.db"
    ledger = BlockchainLedger(db_path=db_path, block_size=5)

    # Verify Genesis block #0 exists
    blocks = ledger.get_blocks()
    assert len(blocks) == 1
    assert blocks[0]["index"] == 0
    assert blocks[0]["prev_hash"] == "0" * 64

    # Add 5 events -> triggers automatic sealing of Block #1
    for i in range(5):
        h = hashlib.sha256(f"data_{i}".encode()).hexdigest()
        ledger.add_event(f"EVT-{i}", h)

    blocks = ledger.get_blocks()
    assert len(blocks) == 2
    b1 = blocks[0]
    b0 = blocks[1]
    assert b1["index"] == 1
    assert b1["prev_hash"] == b0["block_hash"]
    assert b1["event_count"] == 5

    # Manual sealing when buffer has events
    ledger.add_event("EVT-MANUAL", hashlib.sha256(b"manual").hexdigest())
    sealed_b2 = ledger.seal_block()
    assert sealed_b2 is not None
    assert sealed_b2.index == 2
    assert sealed_b2.prev_hash == b1["block_hash"]


def test_blockchain_audit_and_tamper_detection(tmp_path):
    """Verify that ledger tampering is mathematically detected and pinpointed."""
    db_path = tmp_path / "test_ledger.db"
    ledger = BlockchainLedger(db_path=db_path, block_size=2)

    # Ingest 4 events -> 2 blocks sealed (Block 1 and Block 2)
    for i in range(4):
        ledger.add_event(f"E-{i}", hashlib.sha256(f"payload_{i}".encode()).hexdigest())

    audit = ledger.verify_chain()
    assert audit["is_valid"] is True
    assert audit["total_blocks"] == 3  # Genesis (0) + Block 1 + Block 2
    assert audit["broken_at_block"] is None

    # Simulate an insider attack on Block #1
    ledger.simulate_tamper(block_index=1)

    # Audit must immediately detect the tamper and pinpoint Block #1
    tamper_audit = ledger.verify_chain()
    assert tamper_audit["is_valid"] is False
    assert tamper_audit["broken_at_block"] == 1
    assert "Tamper detected" in tamper_audit["reason"]

    # Repair the ledger
    repaired_count = ledger.repair_tamper()
    assert repaired_count >= 1

    # Audit must pass again after repair
    post_repair_audit = ledger.verify_chain()
    assert post_repair_audit["is_valid"] is True
    assert post_repair_audit["broken_at_block"] is None
