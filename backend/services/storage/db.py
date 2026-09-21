import sqlite3
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from backend.config import settings

logger = logging.getLogger("ulpf.storage")

class Database:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or settings.DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Sources table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS sources (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                vendor TEXT NOT NULL,
                product TEXT NOT NULL,
                format_type TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'network',
                description TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                event_count INTEGER NOT NULL DEFAULT 0,
                last_event_at TEXT
            );
            """)

            # 2. Parsers table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS parsers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                vendor TEXT NOT NULL,
                product TEXT NOT NULL,
                format_type TEXT NOT NULL,
                description TEXT,
                target_ocsf_class INTEGER NOT NULL DEFAULT 4001,
                rule_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'candidate',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                validation_json TEXT,
                tested INTEGER NOT NULL DEFAULT 0,
                approved_by TEXT,
                approved_at TEXT
            );
            """)

            # 3. Raw Logs table (lossless storage)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS raw_logs (
                id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                raw_text TEXT NOT NULL,
                raw_hash TEXT NOT NULL,
                ingested_at TEXT NOT NULL,
                format_detected TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'ingested',
                error_message TEXT,
                FOREIGN KEY (source_id) REFERENCES sources (id) ON DELETE CASCADE
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_raw_logs_hash ON raw_logs (raw_hash);")

            # 4. Normalized Events table (OCSF v1.1.0)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS normalized_events (
                id TEXT PRIMARY KEY,
                sequence_num INTEGER UNIQUE NOT NULL,
                raw_id TEXT NOT NULL,
                class_uid INTEGER NOT NULL,
                class_name TEXT NOT NULL,
                category_uid INTEGER NOT NULL,
                category_name TEXT NOT NULL,
                activity_id INTEGER NOT NULL,
                activity_name TEXT NOT NULL,
                severity_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                time TEXT NOT NULL,
                time_epoch_ms INTEGER NOT NULL,
                src_ip TEXT,
                src_port INTEGER,
                dst_ip TEXT,
                dst_port INTEGER,
                protocol TEXT,
                action TEXT,
                disposition TEXT,
                user_name TEXT,
                finding_title TEXT,
                normalized_json TEXT NOT NULL,
                unmapped_json TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (raw_id) REFERENCES raw_logs (id) ON DELETE CASCADE
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_norm_events_time ON normalized_events (time_epoch_ms);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_norm_events_src_ip ON normalized_events (src_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_norm_events_dst_ip ON normalized_events (dst_ip);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_norm_events_user ON normalized_events (user_name);")

            # 5. Cryptographic Integrity Ledger (Hash Chain)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS integrity_ledger (
                sequence_num INTEGER PRIMARY KEY,
                event_id TEXT UNIQUE NOT NULL,
                raw_id TEXT NOT NULL,
                raw_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES normalized_events (id) ON DELETE CASCADE,
                FOREIGN KEY (raw_id) REFERENCES raw_logs (id) ON DELETE CASCADE
            );
            """)

            # 6. Incidents table (RCA)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence_score REAL NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """)

            # 7. Tamper Backup table (for demo simulation & restoration)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_tamper_backup (
                sequence_num INTEGER PRIMARY KEY,
                original_json TEXT NOT NULL,
                tampered_json TEXT NOT NULL,
                tampered_at TEXT NOT NULL
            );
            """)
            
            conn.commit()

db = Database()
