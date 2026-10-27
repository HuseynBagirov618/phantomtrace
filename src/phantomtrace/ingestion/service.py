import json
import re
from datetime import datetime, timezone

from phantomtrace.database.event_store import EventStore
from phantomtrace.normalization.auth import normalize_auth_event
from phantomtrace.normalization.sysmon import normalize_sysmon_event
from phantomtrace.normalization.powershell import normalize_powershell_event
from phantomtrace.parsers.evtx_parser import parse_evtx


NORMALIZERS = {
    "Security.evtx": normalize_auth_event,
    "Sysmon.evtx": normalize_sysmon_event,
    "PowerShell.evtx": normalize_powershell_event,
}


class EvidenceIngestionService:
    """Parse registered EVTX evidence and persist normalized events."""

    def __init__(self, db, storage):
        self.db = db
        self.storage = storage
        self.events = EventStore(db)

    def ingest(self, case_id, evidence_sha256):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
            raise ValueError("Invalid case ID")

        if not re.fullmatch(r"[a-fA-F0-9]{64}", evidence_sha256):
            raise ValueError("Invalid SHA-256")

        evidence_sha256 = evidence_sha256.lower()

        # Only ingest evidence registered in this investigation.
        records = self.db.get_evidence(case_id)
        record = next(
            (
                item for item in records
                if item["sha256"] == evidence_sha256
            ),
            None,
        )

        if record is None:
            raise ValueError("Evidence is not registered")

        filename = record["source_name"]
        if filename not in NORMALIZERS:
            raise ValueError(f"Unsupported evidence source: {filename}")

        # Check the stored evidence before parsing it.
        if not self.storage.verify_evidence(case_id, evidence_sha256):
            raise ValueError("Evidence integrity verification failed")

        evidence_path = (
            self.storage.base_path
            / case_id
            / "evidence"
            / evidence_sha256
        )

        normalizer = NORMALIZERS[filename]
        parsed_count = 0
        supported_count = 0
        inserted_count = 0

        # Parse and insert within one transaction. If parsing fails,
        # SQLite rolls back the inserts made during this invocation.
        with self.db.connect() as conn:
            for raw_event in parse_evtx(str(evidence_path)):
                parsed_count += 1

                # The stored file is named by its SHA-256; restore the
                # registered original filename in normalized metadata.
                raw_event["source_file"] = filename
                event = normalizer(raw_event)

                if event is None:
                    continue

                supported_count += 1
                if not event.get("timestamp_utc"):
                    raise ValueError("Normalized event has no timestamp")

                cursor = conn.execute(
                    """
                    INSERT OR IGNORE INTO event_records (
                        case_id,
                        evidence_sha256,
                        record_id,
                        event_id,
                        event_type,
                        timestamp_utc,
                        normalized_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        evidence_sha256,
                        int(event["record_id"]),
                        int(event["event_id"]),
                        event["event_type"],
                        event["timestamp_utc"],
                        json.dumps(event, ensure_ascii=False),
                    ),
                )
                inserted_count += cursor.rowcount

            conn.execute(
                """
                INSERT INTO audit_log (
                    actor,
                    timestamp,
                    action,
                    object_id,
                    details
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "local-analyst",
                    datetime.now(timezone.utc).isoformat(),
                    "EVIDENCE_INGESTED",
                    f"{case_id}:{evidence_sha256}",
                    json.dumps({
                        "parsed": parsed_count,
                        "supported": supported_count,
                        "inserted": inserted_count,
                    }),
                ),
            )

        return {
            "case_id": case_id,
            "filename": filename,
            "evidence_sha256": evidence_sha256,
            "parsed_records": parsed_count,
            "supported_events": supported_count,
            "inserted_events": inserted_count,
            "duplicate_events": supported_count - inserted_count,
        }
