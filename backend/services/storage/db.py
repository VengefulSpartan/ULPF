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

            # 8. Delivery ledger: what happened to each stored event at each output (hash-chained batches)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS delivery_outputs (
                output TEXT PRIMARY KEY,
                type TEXT,
                target TEXT,
                first_seq INTEGER NOT NULL,
                added_at TEXT NOT NULL
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS delivery_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                output TEXT NOT NULL,
                outcome TEXT NOT NULL,
                trigger TEXT NOT NULL,
                at TEXT NOT NULL,
                count INTEGER NOT NULL,
                detail TEXT,
                events_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                batch_hash TEXT NOT NULL
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS delivery_events (
                batch_id INTEGER NOT NULL,
                output TEXT NOT NULL,
                sequence_num INTEGER NOT NULL,
                event_uid TEXT,
                outcome TEXT NOT NULL
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_delivery_events_output_seq "
                           "ON delivery_events (output, sequence_num);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_delivery_events_batch ON delivery_events (batch_id);")

            # 9. Log formats no parser pack knows, grouped by structure (see services/parsing/formats.py)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_formats (
                format_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                delimiter TEXT,
                app TEXT,
                template TEXT NOT NULL,
                size INTEGER,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 0,
                confidence_sum REAL NOT NULL DEFAULT 0,
                samples INTEGER NOT NULL DEFAULT 0,
                sources_json TEXT,
                status TEXT NOT NULL DEFAULT 'new',
                parser_id TEXT,
                drift_from TEXT
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_format_aliases (
                alias TEXT PRIMARY KEY,
                format_id TEXT NOT NULL
            );
            """)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS log_format_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                format_id TEXT NOT NULL,
                raw_id TEXT,
                raw_text TEXT NOT NULL,
                source_name TEXT,
                added_at TEXT NOT NULL
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_format_samples ON log_format_samples (format_id);")

            # 10. Re-parsed events: a new chained event that supersedes an earlier one for the same raw line
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_revisions (
                event_id TEXT PRIMARY KEY,
                sequence_num INTEGER NOT NULL,
                supersedes_event_id TEXT NOT NULL,
                supersedes_sequence INTEGER NOT NULL,
                raw_id TEXT NOT NULL,
                parser_id TEXT,
                reason TEXT,
                created_at TEXT NOT NULL
            );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_revisions_raw ON event_revisions (raw_id);")

            # Migration: chain-of-custody metadata for streamed logs. raw_encoding
            # records how raw bytes were decoded, so raw_text.encode(raw_encoding)
            # always gives back the exact bytes received.
            existing = {row[1] for row in cursor.execute("PRAGMA table_info(raw_logs)")}
            for column, ddl in (
                ("raw_encoding", "TEXT NOT NULL DEFAULT 'utf-8'"),
                ("transport", "TEXT"),
                ("input_name", "TEXT"),
                ("peer_ip", "TEXT"),
                ("received_at", "TEXT"),
            ):
                if column not in existing:
                    cursor.execute(f"ALTER TABLE raw_logs ADD COLUMN {column} {ddl}")
            # Migration: the format id of lines the generic parser handled (for re-parsing them later)
            if "format_id" not in existing:
                cursor.execute("ALTER TABLE raw_logs ADD COLUMN format_id TEXT")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_raw_logs_format ON raw_logs (format_id);")
            # Migration: an event re-parsed later points to its revision. Not part of the hashed record: the
            # revision itself is chained and names the event it supersedes.
            existing_ev = {row[1] for row in cursor.execute("PRAGMA table_info(normalized_events)")}
            if "superseded_by" not in existing_ev:
                cursor.execute("ALTER TABLE normalized_events ADD COLUMN superseded_by TEXT")

            conn.commit()

db = Database()
