import time
import json
import sqlite3
from typing import Optional, List, Dict, Any, Tuple
from backend.services.storage.db import db
from backend.services.integrity.hasher import Hasher
from backend.models.integrity import (
    LedgerEntry, IntegrityVerificationResult, VerificationIssue,
    TamperRecordResponse
)

class IntegrityLedger:
    """
    Cryptographic Hash Chain Ledger (USP 2: Chain-of-Custody Integrity).
    Enforces transaction-safe sequential linking and strict tamper verification.
    """

    @classmethod
    def get_latest_entry(cls, conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT sequence_num, record_hash FROM integrity_ledger ORDER BY sequence_num DESC LIMIT 1"
        )
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    @classmethod
    def append_event(
        cls,
        conn: sqlite3.Connection,
        event_id: str,
        raw_id: str,
        raw_hash: str,
        normalized_data: Dict[str, Any]
    ) -> Tuple[int, str, str]:
        """
        Atomically appends an event to the ledger within an existing SQLite transaction.
        Returns: (sequence_num, prev_hash, record_hash)
        """
        cursor = conn.cursor()
        
        # Get latest entry under active write transaction
        latest = cls.get_latest_entry(conn)
        if latest is None:
            seq_num = 1
            prev_hash = Hasher.GENESIS_PREV_HASH
        else:
            seq_num = latest["sequence_num"] + 1
            prev_hash = latest["record_hash"]

        # Calculate record hash
        record_hash = Hasher.compute_record_hash(prev_hash, seq_num, raw_hash, normalized_data)

        # Insert into ledger
        cursor.execute(
            """
            INSERT INTO integrity_ledger (sequence_num, event_id, raw_id, raw_hash, record_hash, prev_hash, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
            """,
            (seq_num, event_id, raw_id, raw_hash, record_hash, prev_hash)
        )
        return seq_num, prev_hash, record_hash

    @classmethod
    def verify_chain(cls) -> IntegrityVerificationResult:
        """
        Performs exhaustive cryptographic verification across all ledger entries:
        1. Raw event payload integrity: SHA-256(raw_text) == raw_hash
        2. Sequence monotonicity: current.seq_num == previous.seq_num + 1 (detects deletion & reordering)
        3. Chain continuity: current.prev_hash == previous.record_hash (detects splice/reordering)
        4. Record integrity: recomputed record_hash == stored record_hash (detects modification)
        """
        start_time = time.time()
        issues: List[VerificationIssue] = []
        verified_count = 0
        failed_count = 0
        first_corrupted_seq = None

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT 
                    l.sequence_num, l.event_id, l.raw_id, l.raw_hash, l.record_hash, l.prev_hash,
                    r.raw_text, n.normalized_json
                FROM integrity_ledger l
                LEFT JOIN raw_logs r ON l.raw_id = r.id
                LEFT JOIN normalized_events n ON l.event_id = n.id
                ORDER BY l.sequence_num ASC
                """
            )
            rows = cursor.fetchall()

        total_records = len(rows)
        if total_records == 0:
            return IntegrityVerificationResult(
                is_valid=True,
                total_records=0,
                verified_records=0,
                failed_records=0,
                issues=[],
                verification_time_ms=0.0
            )

        expected_prev_hash = Hasher.GENESIS_PREV_HASH
        expected_seq = 1

        for row in rows:
            seq_num = row["sequence_num"]
            event_id = row["event_id"]
            raw_hash = row["raw_hash"]
            stored_record_hash = row["record_hash"]
            stored_prev_hash = row["prev_hash"]
            raw_text = row["raw_text"]
            norm_json_str = row["normalized_json"]

            record_failed = False

            # Check 1: Sequence monotonicity (detects deletion or reordering)
            if seq_num != expected_seq:
                issues.append(VerificationIssue(
                    sequence_num=seq_num,
                    event_id=event_id,
                    issue_type="SEQUENCE_GAP_OR_REORDER",
                    description=f"Sequence number gap or reordering detected at entry {seq_num}",
                    expected=str(expected_seq),
                    actual=str(seq_num)
                ))
                record_failed = True

            # Check 2: Raw payload preservation & hash
            if raw_text is None:
                issues.append(VerificationIssue(
                    sequence_num=seq_num,
                    event_id=event_id,
                    issue_type="RAW_PAYLOAD_MISSING",
                    description="Raw log payload record is missing from storage",
                    expected=raw_hash,
                    actual="NULL"
                ))
                record_failed = True
            else:
                recomputed_raw_hash = Hasher.hash_raw_bytes(raw_text)
                if recomputed_raw_hash != raw_hash:
                    issues.append(VerificationIssue(
                        sequence_num=seq_num,
                        event_id=event_id,
                        issue_type="RAW_HASH_MISMATCH",
                        description=f"Raw log payload modified for record {seq_num}",
                        expected=raw_hash,
                        actual=recomputed_raw_hash
                    ))
                    record_failed = True

            # Check 3: Chain continuity (prev_hash)
            if stored_prev_hash != expected_prev_hash:
                issues.append(VerificationIssue(
                    sequence_num=seq_num,
                    event_id=event_id,
                    issue_type="BROKEN_CHAIN",
                    description=f"Hash chain pointer mismatch at record {seq_num}",
                    expected=expected_prev_hash,
                    actual=stored_prev_hash
                ))
                record_failed = True

            # Check 4: Record hash verification
            if norm_json_str is None:
                issues.append(VerificationIssue(
                    sequence_num=seq_num,
                    event_id=event_id,
                    issue_type="NORMALIZED_DATA_MISSING",
                    description="Normalized event record is missing from storage",
                    expected=stored_record_hash,
                    actual="NULL"
                ))
                record_failed = True
            else:
                try:
                    norm_dict = json.loads(norm_json_str)
                    recomputed_record_hash = Hasher.compute_record_hash(
                        stored_prev_hash, seq_num, raw_hash, norm_dict
                    )
                except Exception as e:
                    recomputed_record_hash = "INVALID_JSON"

                if recomputed_record_hash != stored_record_hash:
                    issues.append(VerificationIssue(
                        sequence_num=seq_num,
                        event_id=event_id,
                        issue_type="HASH_MISMATCH",
                        description=f"Cryptographic record hash mismatch at record {seq_num} (Tampering detected!)",
                        expected=stored_record_hash,
                        actual=recomputed_record_hash
                    ))
                    record_failed = True

            if record_failed:
                failed_count += 1
                if first_corrupted_seq is None:
                    first_corrupted_seq = seq_num
            else:
                verified_count += 1

            # Advance expected chain pointer
            expected_prev_hash = stored_record_hash
            expected_seq = seq_num + 1

        duration_ms = (time.time() - start_time) * 1000.0

        return IntegrityVerificationResult(
            is_valid=(failed_count == 0),
            total_records=total_records,
            verified_records=verified_count,
            failed_records=failed_count,
            first_corrupted_seq=first_corrupted_seq,
            issues=issues,
            verification_time_ms=round(duration_ms, 2)
        )

    @classmethod
    def simulate_tampering(cls, sequence_num: int, field: str = "disposition", new_value: str = "tampered_action") -> TamperRecordResponse:
        """
        Controlled Demonstration: Deliberately tampers with a stored normalized event record
        in SQLite to demonstrate how the hash chain immediately flags the violation.
        Saves a backup to allow restoration.
        """
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, normalized_json FROM normalized_events WHERE sequence_num = ?",
                (sequence_num,)
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Record with sequence number {sequence_num} not found")

            event_id = row["id"]
            original_json_str = row["normalized_json"]
            data = json.loads(original_json_str)
            original_val = str(data.get(field, "none"))

            # Tamper the data
            data[field] = new_value
            tampered_json_str = json.dumps(data)

            # Backup original
            cursor.execute(
                """
                INSERT OR REPLACE INTO audit_tamper_backup (sequence_num, original_json, tampered_json, tampered_at)
                VALUES (?, ?, ?, datetime('now'))
                """,
                (sequence_num, original_json_str, tampered_json_str)
            )

            # Apply modification to normalized_events table
            cursor.execute(
                "UPDATE normalized_events SET normalized_json = ?, disposition = ? WHERE sequence_num = ?",
                (tampered_json_str, new_value, sequence_num)
            )
            conn.commit()

            return TamperRecordResponse(
                success=True,
                sequence_num=sequence_num,
                event_id=event_id,
                original_value=original_val,
                tampered_value=new_value,
                message=f"Deliberately altered '{field}' from '{original_val}' to '{new_value}' in SQLite for sequence #{sequence_num}. Integrity verification will now fail."
            )

    @classmethod
    def restore_tampered_record(cls, sequence_num: int) -> bool:
        """
        Restores a tampered record back to its legitimate original state from the backup ledger.
        """
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT original_json FROM audit_tamper_backup WHERE sequence_num = ?",
                (sequence_num,)
            )
            row = cursor.fetchone()
            if not row:
                return False

            original_json = row["original_json"]
            orig_data = json.loads(original_json)
            cursor.execute(
                "UPDATE normalized_events SET normalized_json = ?, disposition = ? WHERE sequence_num = ?",
                (original_json, orig_data.get("disposition"), sequence_num)
            )
            cursor.execute("DELETE FROM audit_tamper_backup WHERE sequence_num = ?", (sequence_num,))
            conn.commit()
            return True
