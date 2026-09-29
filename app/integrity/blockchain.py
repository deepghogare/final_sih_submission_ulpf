"""
Embedded Cryptographic Blockchain Ledger & Merkle Tree Verification Engine for ULPF.
Provides tamper-evident chronological block chaining, anti-deletion / anti-insertion
auditing, and logarithmic zero-knowledge Merkle proofs for high-speed log streams.
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import logging
import random

logger = logging.getLogger("ULPF.Blockchain")


def hash_pair(left: str, right: str) -> str:
    """Computes SHA-256 digest of concatenated child hashes."""
    combined = f"{left}{right}".encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


class MerkleTree:
    """
    Binary Merkle Tree implementation for cryptographic batch log validation.
    Generates verifiable logarithmic O(log N) proofs for selective disclosure.
    """
    def __init__(self, leaf_hashes: List[str]):
        self.leaf_hashes = leaf_hashes if leaf_hashes else ["0" * 64]
        self.levels: List[List[str]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        current = list(self.leaf_hashes)
        self.levels = [current]

        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left
                next_level.append(hash_pair(left, right))
            current = next_level
            self.levels.append(current)

    @property
    def root(self) -> str:
        """Returns the 32-byte hexadecimal Merkle Root digest."""
        if not self.levels or not self.levels[-1]:
            return "0" * 64
        return self.levels[-1][0]

    def get_proof(self, target_hash: str) -> Optional[List[Dict[str, str]]]:
        """
        Generates an O(log N) Merkle audit path for the given event hash.
        Returns a list of sibling nodes needed to reconstruct the Merkle Root.
        """
        if target_hash not in self.leaf_hashes:
            return None

        index = self.leaf_hashes.index(target_hash)
        proof: List[Dict[str, str]] = []

        for level in self.levels[:-1]:
            is_right = (index % 2 == 1)
            sibling_idx = index - 1 if is_right else index + 1
            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
            else:
                sibling_hash = level[index]  # Odd leaf duplicated

            proof.append({
                "position": "left" if is_right else "right",
                "hash": sibling_hash
            })
            index //= 2

        return proof

    @staticmethod
    def verify_proof(target_hash: str, proof: List[Dict[str, str]], expected_root: str) -> bool:
        """
        Verifies whether an event hash belongs to a block with the given Merkle Root
        without requiring access to any other event in that block.
        """
        current = target_hash.lower()
        for step in proof:
            sibling = step["hash"].lower()
            if step["position"] == "left":
                current = hash_pair(sibling, current)
            else:
                current = hash_pair(current, sibling)
        return hmac.compare_digest(current.lower(), expected_root.lower())


@dataclass
class Block:
    """
    Immutable cryptographic block sealing a batch of normalized events.
    """
    index: int
    timestamp: str
    prev_hash: str
    merkle_root: str
    event_ids: List[str]
    event_count: int
    block_hash: str = ""

    def calculate_hash(self) -> str:
        """Calculates deterministic SHA-256 header digest."""
        header = f"{self.index}|{self.timestamp}|{self.prev_hash}|{self.merkle_root}|{self.event_count}"
        return hashlib.sha256(header.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "merkle_root": self.merkle_root,
            "event_ids": self.event_ids,
            "event_count": self.event_count,
            "block_hash": self.block_hash
        }


class BlockchainLedger:
    """
    Thread-safe embedded blockchain ledger managing micro-batch block sealing,
    unbroken chain of custody, and cryptographic integrity verification.
    """
    def __init__(self, db_path: Path = None, block_size: int = 20):
        # Use ULPF_DB_PATH env var (set by Docker) or fall back to local output path
        if db_path is None:
            env_path = os.environ.get("ULPF_DB_PATH")
            db_path = Path(env_path) if env_path else Path("output/ulpf_events.db")
        self.db_path = Path(db_path)
        self.block_size = block_size
        self._lock = threading.Lock()
        self._pending_events: List[Dict[str, str]] = []  # List of {"event_id": ..., "hash": ...}
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_ledger_table()
        self._ensure_genesis_block()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_ledger_table(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                # Try WAL mode; fall back to DELETE on Windows Docker Desktop bind-mounts
                try:
                    result = conn.execute("PRAGMA journal_mode=WAL;").fetchone()
                    if result and result[0].lower() != "wal":
                        conn.execute("PRAGMA journal_mode=DELETE;")
                except Exception:
                    conn.execute("PRAGMA journal_mode=DELETE;")
                conn.execute("PRAGMA synchronous=NORMAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS blockchain_ledger (
                        block_index INTEGER PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        merkle_root TEXT NOT NULL,
                        block_hash TEXT NOT NULL,
                        event_count INTEGER NOT NULL,
                        event_ids_json TEXT NOT NULL,
                        block_json TEXT NOT NULL,
                        is_tampered INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ledger_hash ON blockchain_ledger(block_hash)")
                conn.commit()

    def _ensure_genesis_block(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute("SELECT COUNT(*) as count FROM blockchain_ledger")
                if cur.fetchone()["count"] == 0:
                    genesis_time = "2026-01-01T00:00:00Z"
                    genesis_prev = "0" * 64
                    genesis_merkle = "0" * 64
                    genesis = Block(
                        index=0,
                        timestamp=genesis_time,
                        prev_hash=genesis_prev,
                        merkle_root=genesis_merkle,
                        event_ids=[],
                        event_count=0
                    )
                    genesis.block_hash = genesis.calculate_hash()
                    conn.execute("""
                        INSERT INTO blockchain_ledger (
                            block_index, timestamp, prev_hash, merkle_root,
                            block_hash, event_count, event_ids_json, block_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        genesis.index, genesis.timestamp, genesis.prev_hash,
                        genesis.merkle_root, genesis.block_hash, genesis.event_count,
                        json.dumps(genesis.event_ids), json.dumps(genesis.to_dict())
                    ))
                    conn.commit()
                    logger.info("Genesis block #0 successfully sealed and initialized.")

    def add_event(self, event_id: str, raw_event_hash: str) -> Optional[Block]:
        """
        Adds an ingested event to the pending block buffer.
        Automatically seals a block if threshold block_size is reached.
        """
        with self._lock:
            self._pending_events.append({"event_id": event_id, "hash": raw_event_hash})
            if len(self._pending_events) >= self.block_size:
                return self._seal_pending_internal()
            return None

    def seal_block(self) -> Optional[Block]:
        """Manually seals any currently pending events into a new block."""
        with self._lock:
            return self._seal_pending_internal()

    def _seal_pending_internal(self) -> Optional[Block]:
        """Internal worker to seal pending events. Must be called within self._lock."""
        if not self._pending_events:
            return None

        with self._get_connection() as conn:
            # 1. Get latest block
            cur = conn.execute("SELECT block_index, block_hash FROM blockchain_ledger ORDER BY block_index DESC LIMIT 1")
            last_row = cur.fetchone()
            last_index = last_row["block_index"]
            last_hash = last_row["block_hash"]

            # 2. Build Merkle Tree
            leaf_hashes = [e["hash"] for e in self._pending_events]
            event_ids = [e["event_id"] for e in self._pending_events]
            tree = MerkleTree(leaf_hashes)

            # 3. Create new Block
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            new_block = Block(
                index=last_index + 1,
                timestamp=now_iso,
                prev_hash=last_hash,
                merkle_root=tree.root,
                event_ids=event_ids,
                event_count=len(event_ids)
            )
            new_block.block_hash = new_block.calculate_hash()

            # 4. Save to Database
            conn.execute("""
                INSERT INTO blockchain_ledger (
                    block_index, timestamp, prev_hash, merkle_root,
                    block_hash, event_count, event_ids_json, block_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                new_block.index, new_block.timestamp, new_block.prev_hash,
                new_block.merkle_root, new_block.block_hash, new_block.event_count,
                json.dumps(new_block.event_ids), json.dumps(new_block.to_dict())
            ))
            conn.commit()

            self._pending_events.clear()
            logger.info(f"Sealed Block #{new_block.index} ({new_block.event_count} events) | Hash: {new_block.block_hash[:12]}...")
            return new_block

    def get_blocks(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Retrieves list of sealed blocks in descending order."""
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute(
                    """SELECT block_index, timestamp, prev_hash, merkle_root, 
                              block_hash, event_count, is_tampered, block_json 
                       FROM blockchain_ledger ORDER BY block_index DESC LIMIT ? OFFSET ?""",
                    (limit, offset)
                )
                blocks = []
                for row in cur.fetchall():
                    try:
                        b_dict = json.loads(row["block_json"])
                    except Exception:
                        b_dict = {}
                    # Ensure live database column values always take precedence
                    b_dict["index"] = row["block_index"]
                    b_dict["timestamp"] = row["timestamp"]
                    b_dict["block_hash"] = row["block_hash"]
                    b_dict["prev_hash"] = row["prev_hash"]
                    b_dict["merkle_root"] = row["merkle_root"]
                    b_dict["event_count"] = row["event_count"]
                    b_dict["is_tampered"] = bool(row["is_tampered"])
                    blocks.append(b_dict)
                return blocks

    def get_pending_count(self) -> int:
        """Returns the number of events waiting in the current unsealed block."""
        with self._lock:
            return len(self._pending_events)

    def verify_chain(self) -> Dict[str, Any]:
        """
        Audits the entire blockchain ledger from Genesis to the latest block.
        Mathematically confirms that:
          1. Every block's internal hash matches calculated header digest.
          2. Every block's prev_hash strictly equals preceding block_hash.
          3. Chain sequence is contiguous without gaps or deletions.
        """
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute("SELECT * FROM blockchain_ledger ORDER BY block_index ASC")
                rows = cur.fetchall()

                if not rows:
                    return {
                        "is_valid": False,
                        "total_blocks": 0,
                        "broken_at_block": None,
                        "reason": "Blockchain ledger is empty (missing Genesis block)."
                    }

                total_events = 0
                prev_hash_expected = "0" * 64

                for idx, row in enumerate(rows):
                    block_index = row["block_index"]
                    timestamp = row["timestamp"]
                    prev_hash = row["prev_hash"]
                    merkle_root = row["merkle_root"]
                    block_hash = row["block_hash"]
                    event_count = row["event_count"]
                    total_events += event_count

                    # 1. Contiguity check
                    if block_index != idx:
                        return {
                            "is_valid": False,
                            "total_blocks": len(rows),
                            "broken_at_block": block_index,
                            "reason": f"Block sequence broken! Expected block index {idx}, found {block_index} (Possible deletion)."
                        }

                    # 2. Previous Hash Linkage check
                    if prev_hash.lower() != prev_hash_expected.lower():
                        return {
                            "is_valid": False,
                            "total_blocks": len(rows),
                            "broken_at_block": block_index,
                            "reason": f"Linkage broken at Block #{block_index}! prev_hash ({prev_hash[:12]}...) does not match previous block hash ({prev_hash_expected[:12]}...)."
                        }

                    # 3. Header Hash Authenticity check
                    calc_header = f"{block_index}|{timestamp}|{prev_hash}|{merkle_root}|{event_count}"
                    recalculated_hash = hashlib.sha256(calc_header.encode("utf-8")).hexdigest()
                    if recalculated_hash.lower() != block_hash.lower():
                        return {
                            "is_valid": False,
                            "total_blocks": len(rows),
                            "broken_at_block": block_index,
                            "reason": f"Tamper detected in Block #{block_index}! Stored hash ({block_hash[:12]}...) != Recalculated ({recalculated_hash[:12]}...)."
                        }

                    prev_hash_expected = block_hash

                return {
                    "is_valid": True,
                    "total_blocks": len(rows),
                    "total_events": total_events,
                    "broken_at_block": None,
                    "reason": "Blockchain ledger is 100% verified and mathematically intact."
                }

    def get_merkle_proof_for_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Locates the block containing the event and computes its Merkle proof receipt.
        """
        with self._lock:
            with self._get_connection() as conn:
                # Find block containing event_id
                cur = conn.execute("SELECT * FROM blockchain_ledger WHERE event_ids_json LIKE ?", (f"%{event_id}%",))
                row = cur.fetchone()
                if not row:
                    return None

                block_json = json.loads(row["block_json"])
                event_ids = json.loads(row["event_ids_json"])

                # Fetch raw event hashes from universal_events table
                placeholders = ",".join(["?"] * len(event_ids))
                ev_cur = conn.execute(
                    f"SELECT event_id, raw_hash FROM universal_events WHERE event_id IN ({placeholders})",
                    tuple(event_ids)
                )
                hash_map = {r["event_id"]: r["raw_hash"] for r in ev_cur.fetchall()}
                leaf_hashes = [hash_map.get(eid, "0" * 64) for eid in event_ids]

                target_hash = hash_map.get(event_id)
                if not target_hash:
                    return None

                tree = MerkleTree(leaf_hashes)
                proof = tree.get_proof(target_hash)

                return {
                    "event_id": event_id,
                    "block_index": block_json["index"],
                    "block_hash": block_json["block_hash"],
                    "merkle_root": block_json["merkle_root"],
                    "raw_event_hash": target_hash,
                    "proof": proof,
                    "is_valid": MerkleTree.verify_proof(target_hash, proof, block_json["merkle_root"]) if proof is not None else False
                }

    def simulate_tamper(self, block_index: Optional[int] = None) -> Dict[str, Any]:
        """
        Simulates an insider database attack by altering a historical block's hash.
        Randomly selects a block if no block_index is provided.
        Used to demonstrate real-time tamper-evident alerting for SIH evaluations.
        """
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute("SELECT block_index, block_json FROM blockchain_ledger ORDER BY block_index ASC")
                rows = cur.fetchall()
                if not rows:
                    return {"status": "error", "message": "No blocks present in ledger to tamper."}

                available_indices = [r["block_index"] for r in rows]
                # Target a recent block so the user sees it in the top 20 block UI stream
                if block_index is None or block_index not in available_indices or block_index <= 0:
                    non_genesis = [idx for idx in available_indices if idx > 0]
                    target_idx = random.choice(non_genesis[-15:]) if non_genesis else random.choice(available_indices)
                else:
                    target_idx = block_index

                cur = conn.execute("SELECT block_index, block_json FROM blockchain_ledger WHERE block_index = ?", (target_idx,))
                row = cur.fetchone()
                
                fake_hash = "deadbeef" * 8
                b_dict = json.loads(row["block_json"]) if (row and row["block_json"]) else {}
                original_hash = b_dict.get("block_hash", "0" * 64)
                
                b_dict["block_hash"] = fake_hash
                b_dict["is_tampered"] = True
                b_dict["original_hash"] = original_hash

                conn.execute(
                    "UPDATE blockchain_ledger SET block_hash = ?, block_json = ?, is_tampered = 1 WHERE block_index = ?",
                    (fake_hash, json.dumps(b_dict), target_idx)
                )
                conn.commit()
                logger.warning(f"SIMULATED TAMPER APPLIED to Block #{target_idx}!")

                # Build Merkle Tree structure for UI visualization
                event_ids = b_dict.get("event_ids", [])
                leaf_hashes = [hashlib.sha256(str(eid).encode("utf-8")).hexdigest() for eid in event_ids] if event_ids else [fake_hash[:64]]
                tree = MerkleTree(leaf_hashes)

                # Recalculate real header hash
                b_idx = target_idx
                ts = b_dict.get("timestamp", "")
                p_hash = b_dict.get("prev_hash", "")
                m_root = b_dict.get("merkle_root", tree.root)
                cnt = b_dict.get("event_count", len(event_ids))
                calc_header = f"{b_idx}|{ts}|{p_hash}|{m_root}|{cnt}"
                expected_real_hash = hashlib.sha256(calc_header.encode("utf-8")).hexdigest()

                return {
                    "status": "tamper_injected",
                    "target_block": target_idx,
                    "fake_hash": fake_hash,
                    "original_hash": expected_real_hash,
                    "prev_hash": p_hash,
                    "merkle_root": m_root,
                    "event_count": cnt,
                    "event_ids": event_ids,
                    "merkle_levels": tree.levels,
                    "message": f"Block #{target_idx} hash was corrupted to demonstrate real-time Merkle tree tamper detection!"
                }

    def repair_tamper(self) -> int:
        """
        Restores cryptographic integrity by recalculating authentic hashes.
        """
        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute("SELECT * FROM blockchain_ledger ORDER BY block_index ASC")
                rows = cur.fetchall()
                repaired = 0
                prev_hash = "0" * 64

                for row in rows:
                    b_idx = row["block_index"]
                    ts = row["timestamp"]
                    m_root = row["merkle_root"]
                    cnt = row["event_count"]
                    e_json = row["event_ids_json"]

                    # Recalculate authentic block hash
                    payload = f"{b_idx}|{ts}|{prev_hash}|{m_root}|{cnt}"
                    real_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

                    block_dict = {
                        "index": b_idx,
                        "timestamp": ts,
                        "prev_hash": prev_hash,
                        "merkle_root": m_root,
                        "event_ids": json.loads(e_json),
                        "event_count": cnt,
                        "block_hash": real_hash
                    }

                    conn.execute("""
                        UPDATE blockchain_ledger 
                        SET prev_hash = ?, block_hash = ?, block_json = ?, is_tampered = 0
                        WHERE block_index = ?
                    """, (prev_hash, real_hash, json.dumps(block_dict), b_idx))

                    prev_hash = real_hash
                    repaired += 1

                conn.commit()
                logger.info(f"Repaired and re-synchronized {repaired} blocks in the blockchain ledger.")
                return repaired

    def reset_ledger(self) -> None:
        """Resets the blockchain ledger back to only the Genesis block."""
        with self._lock:
            self._pending_events.clear()
            with self._get_connection() as conn:
                conn.execute("DELETE FROM blockchain_ledger WHERE block_index > 0")
                conn.commit()
                logger.info("Blockchain ledger reset to Genesis block.")


default_blockchain_ledger = BlockchainLedger()

