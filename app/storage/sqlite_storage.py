"""
SQLite Storage Adapter for ULPF.
Provides local, offline queryable indexing of processed Universal Events.
"""

from typing import Optional, List, Dict, Any
from pathlib import Path
import sqlite3
import json
import threading

import os

from app.models.universal_event import UniversalEvent


def _default_db_path() -> Path:
    """Reads ULPF_DB_PATH env var (set by Docker) or falls back to output/ulpf_events.db."""
    env_path = os.environ.get("ULPF_DB_PATH")
    if env_path:
        return Path(env_path)
    return Path("output/ulpf_events.db")


class SqliteStorage:
    def __init__(self, db_path: Path = None):
        self.db_path = Path(db_path) if db_path else _default_db_path()
        self._lock = threading.Lock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock:
            with self._get_connection() as conn:
                # Try WAL mode for best concurrency; fall back to DELETE on
                # Windows Docker Desktop bind-mounts where shm_open is unavailable.
                try:
                    result = conn.execute("PRAGMA journal_mode=WAL;").fetchone()
                    if result and result[0].lower() != "wal":
                        conn.execute("PRAGMA journal_mode=DELETE;")
                except Exception:
                    conn.execute("PRAGMA journal_mode=DELETE;")
                conn.execute("PRAGMA synchronous=NORMAL;")
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS universal_events (
                        event_id TEXT PRIMARY KEY,
                        timestamp TEXT,
                        source_ip TEXT,
                        destination_ip TEXT,
                        action TEXT,
                        severity TEXT,
                        vendor TEXT,
                        product TEXT,
                        raw_hash TEXT,
                        event_json TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON universal_events(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_src ON universal_events(source_ip)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_dst ON universal_events(destination_ip)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_events_action ON universal_events(action)")
                conn.commit()

    def save_event(self, event: UniversalEvent) -> None:
        """Stores a Universal Event into SQLite."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO universal_events (
                        event_id, timestamp, source_ip, destination_ip,
                        action, severity, vendor, product, raw_hash, event_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id,
                    event.event.timestamp,
                    event.source.ip,
                    event.destination.ip,
                    event.event.action,
                    event.event.severity,
                    event.device.vendor,
                    event.device.product,
                    event.metadata.raw_event_hash,
                    event.model_dump_json()
                ))
                conn.commit()

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single Universal Event by its unique ID."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT event_json FROM universal_events WHERE event_id = ?", (event_id,))
                row = cursor.fetchone()
                if row:
                    return json.loads(row["event_json"])
        return None

    def list_events(
        self,
        limit: int = 100,
        offset: int = 0,
        query: Optional[str] = None,
        action: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves a paginated and optionally filtered list of events."""
        with self._lock:
            with self._get_connection() as conn:
                clauses = ["1=1"]
                params: List[Any] = []

                if query:
                    term = f"%{query.strip()}%"
                    clauses.append("(event_id LIKE ? OR source_ip LIKE ? OR destination_ip LIKE ? OR vendor LIKE ? OR product LIKE ?)")
                    params.extend([term, term, term, term, term])

                if action:
                    clauses.append("LOWER(action) = LOWER(?)")
                    params.append(action.strip())

                if severity:
                    clauses.append("LOWER(severity) = LOWER(?)")
                    params.append(severity.strip())

                where_stmt = " AND ".join(clauses)
                sql = f"SELECT event_json FROM universal_events WHERE {where_stmt} ORDER BY created_at DESC LIMIT ? OFFSET ?"
                params.extend([limit, offset])

                cursor = conn.execute(sql, tuple(params))
                return [json.loads(row["event_json"]) for row in cursor.fetchall()]

    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Calculates aggregated security and operational metrics from stored events."""
        with self._lock:
            with self._get_connection() as conn:
                # 1. Total event count
                total_cursor = conn.execute("SELECT COUNT(*) as total FROM universal_events")
                total_events = total_cursor.fetchone()["total"]

                # 2. Action distribution
                action_cursor = conn.execute(
                    "SELECT COALESCE(NULLIF(action, ''), 'unknown') as action, COUNT(*) as count "
                    "FROM universal_events GROUP BY action ORDER BY count DESC"
                )
                action_distribution = {row["action"]: row["count"] for row in action_cursor.fetchall()}

                # 3. Severity distribution
                sev_cursor = conn.execute(
                    "SELECT COALESCE(NULLIF(severity, ''), 'unspecified') as severity, COUNT(*) as count "
                    "FROM universal_events GROUP BY severity ORDER BY count DESC"
                )
                severity_distribution = {row["severity"]: row["count"] for row in sev_cursor.fetchall()}

                # 4. Top source IPs
                src_cursor = conn.execute(
                    "SELECT source_ip, COUNT(*) as count FROM universal_events "
                    "WHERE source_ip IS NOT NULL AND source_ip != '' "
                    "GROUP BY source_ip ORDER BY count DESC LIMIT 5"
                )
                top_sources = [{"ip": row["source_ip"], "count": row["count"]} for row in src_cursor.fetchall()]

                # 5. Top destination IPs
                dst_cursor = conn.execute(
                    "SELECT destination_ip, COUNT(*) as count FROM universal_events "
                    "WHERE destination_ip IS NOT NULL AND destination_ip != '' "
                    "GROUP BY destination_ip ORDER BY count DESC LIMIT 5"
                )
                top_destinations = [{"ip": row["destination_ip"], "count": row["count"]} for row in dst_cursor.fetchall()]

                # 6. Top vendors
                vendor_cursor = conn.execute(
                    "SELECT COALESCE(NULLIF(vendor, ''), 'generic') as vendor, COUNT(*) as count "
                    "FROM universal_events GROUP BY vendor ORDER BY count DESC LIMIT 5"
                )
                top_vendors = {row["vendor"]: row["count"] for row in vendor_cursor.fetchall()}

                # 7. Average Latency from recent stored events
                avg_lat = 0.0
                try:
                    lat_cursor = conn.execute("SELECT event_json FROM universal_events ORDER BY created_at DESC LIMIT 50")
                    lat_rows = lat_cursor.fetchall()
                    lats = []
                    for r in lat_rows:
                        try:
                            d = json.loads(r["event_json"])
                            pt = d.get("metadata", {}).get("processing_time_ms")
                            if pt is not None:
                                lats.append(float(pt))
                        except Exception:
                            pass
                    if lats:
                        avg_lat = round(sum(lats) / len(lats), 3)
                except Exception:
                    pass

                return {
                    "total_events": total_events,
                    "action_distribution": action_distribution,
                    "severity_distribution": severity_distribution,
                    "top_sources": top_sources,
                    "top_destinations": top_destinations,
                    "top_vendors": top_vendors,
                    "db_average_latency_ms": avg_lat,
                }

    def get_average_latency(self, limit: int = 50) -> float:
        """Computes average processing latency from recent stored events."""
        with self._lock:
            with self._get_connection() as conn:
                try:
                    cursor = conn.execute("SELECT event_json FROM universal_events ORDER BY created_at DESC LIMIT ?", (limit,))
                    rows = cursor.fetchall()
                    lats = []
                    for r in rows:
                        try:
                            d = json.loads(r["event_json"])
                            pt = d.get("metadata", {}).get("processing_time_ms")
                            if pt is not None:
                                lats.append(float(pt))
                        except Exception:
                            pass
                    return round(sum(lats) / len(lats), 3) if lats else 0.0
                except Exception:
                    return 0.0

    def clear_all(self) -> None:
        """Clears all stored events from the database."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM universal_events")
                conn.commit()


default_sqlite_storage = SqliteStorage()

