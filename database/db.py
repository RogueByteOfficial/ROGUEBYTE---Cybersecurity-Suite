"""
ROGUEBYTE SQLite Database Manager
Handles schema migration, diagnostic results persistence, audit logs, and queries.
"""

import sqlite3
import json
import os
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

class DatabaseManager:
    def __init__(self, db_path: str = "roguebyte.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.init_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self) -> None:
        """Initialize tables if they do not exist."""
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Diagnostic tests table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS diagnostics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    target TEXT NOT NULL,
                    port INTEGER,
                    status TEXT NOT NULL,
                    latency_ms REAL,
                    dns_time_ms REAL,
                    packet_loss_pct REAL,
                    details_json TEXT,
                    environment TEXT
                )
            """)

            # Load tests table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS load_tests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    total_requests INTEGER NOT NULL,
                    concurrency INTEGER NOT NULL,
                    success_count INTEGER NOT NULL,
                    failure_count INTEGER NOT NULL,
                    duration_sec REAL NOT NULL,
                    rps REAL NOT NULL,
                    p50_ms REAL,
                    p95_ms REAL,
                    p99_ms REAL,
                    config_json TEXT,
                    details_json TEXT
                )
            """)

            # DoS Detection alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dos_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    source_ip TEXT,
                    request_rate REAL,
                    description TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    evidence_json TEXT
                )
            """)

            # System audit logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    module TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    metadata_json TEXT
                )
            """)

            conn.commit()
            conn.close()

    def record_diagnostic(self, target: str, port: Optional[int], status: str,
                          latency_ms: Optional[float], dns_time_ms: Optional[float],
                          packet_loss_pct: Optional[float] = 0.0,
                          details: Optional[Dict[str, Any]] = None,
                          environment: str = "local") -> int:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            ts = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO diagnostics 
                (timestamp, target, port, status, latency_ms, dns_time_ms, packet_loss_pct, details_json, environment)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts, target, port, status, latency_ms, dns_time_ms, packet_loss_pct,
                  json.dumps(details or {}), environment))
            rec_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return rec_id

    def record_load_test(self, target_url: str, total_requests: int, concurrency: int,
                         success_count: int, failure_count: int, duration_sec: float,
                         rps: float, p50_ms: float, p95_ms: float, p99_ms: float,
                         config: Dict[str, Any], details: Dict[str, Any]) -> int:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            ts = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO load_tests
                (timestamp, target_url, total_requests, concurrency, success_count, failure_count,
                 duration_sec, rps, p50_ms, p95_ms, p99_ms, config_json, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts, target_url, total_requests, concurrency, success_count, failure_count,
                  duration_sec, rps, p50_ms, p95_ms, p99_ms, json.dumps(config), json.dumps(details)))
            rec_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return rec_id

    def record_dos_alert(self, severity: str, alert_type: str, source_ip: Optional[str],
                         request_rate: float, description: str, recommendation: str,
                         evidence: Optional[Dict[str, Any]] = None) -> int:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            ts = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO dos_alerts
                (timestamp, severity, alert_type, source_ip, request_rate, description, recommendation, evidence_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts, severity, alert_type, source_ip, request_rate, description, recommendation,
                  json.dumps(evidence or {})))
            rec_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return rec_id

    def record_audit(self, module: str, event_type: str, message: str,
                     metadata: Optional[Dict[str, Any]] = None) -> int:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            ts = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO audit_logs (timestamp, module, event_type, message, metadata_json)
                VALUES (?, ?, ?, ?, ?)
            """, (ts, module, event_type, message, json.dumps(metadata or {})))
            rec_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return rec_id

    def get_diagnostics_history(self, limit: int = 50, filter_target: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            if filter_target:
                cursor.execute("""
                    SELECT * FROM diagnostics WHERE target LIKE ? ORDER BY id DESC LIMIT ?
                """, (f"%{filter_target}%", limit))
            else:
                cursor.execute("SELECT * FROM diagnostics ORDER BY id DESC LIMIT ?", (limit,))
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows

    def get_load_test_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM load_tests ORDER BY id DESC LIMIT ?", (limit,))
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows

    def get_dos_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            if severity:
                cursor.execute("""
                    SELECT * FROM dos_alerts WHERE severity = ? ORDER BY id DESC LIMIT ?
                """, (severity.upper(), limit))
            else:
                cursor.execute("SELECT * FROM dos_alerts ORDER BY id DESC LIMIT ?", (limit,))
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows

    def get_audit_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return rows

_db_instance: Optional[DatabaseManager] = None

def get_db(db_path: str = "roguebyte.db") -> DatabaseManager:
    global _db_instance
    if _db_instance is None or _db_instance.db_path != db_path:
        _db_instance = DatabaseManager(db_path)
    return _db_instance
