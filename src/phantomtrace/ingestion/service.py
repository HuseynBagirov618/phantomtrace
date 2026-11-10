import json
import re
from datetime import datetime, timezone

from phantomtrace.database.event_store import EventStore
from phantomtrace.database.raw_store import RawRecordStore
from phantomtrace.normalization.auth import normalize_auth_event
from phantomtrace.normalization.powershell import normalize_powershell_event
from phantomtrace.normalization.sysmon import normalize_sysmon_event
from phantomtrace.parsers.evtx_parser import parse_evtx
from phantomtrace.schema.identity import build_event_id, record_locator
from phantomtrace.schema.versions import PARSER_VERSION, SCHEMA_VERSION


NORMALIZERS = {
    "Security.evtx": normalize_auth_event,
    "Sysmon.evtx": normalize_sysmon_event,
    "PowerShell.evtx": normalize_powershell_event,
}


class EvidenceIngestionService:
    """Parse registered EVTX evidence and persist custody plus events."""

    def __init__(self, db, storage):
        self.db = db
        self.storage = storage
        self.events = EventStore(db)
        self.raw_records = RawRecordStore(db)

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
        raw_inserted_count = 0
        raw_duplicate_count = 0

        # Raw records and normalized events are written in one
        # transaction. If a record fails, SQLite rolls back the whole
        # invocation so no half-parsed state survives.
        with self.db.connect() as conn:
            for raw_event in parse_evtx(str(evidence_path)):
                parsed_count += 1

                # The stored file is named by its SHA-256; restore the
                # registered original filename in normalized metadata.
                raw_event["source_file"] = filename

                record_number = self._record_number(raw_event)
                channel = self._channel(raw_event)
                raw_xml = raw_event.get("raw_xml")

                if raw_xml is None or not str(raw_xml).strip():
                    raise ValueError(
                        "Parsed record "
                        f"{record_number} has no raw XML"
                    )

                locator = record_locator(
                    evidence_sha256,
                    channel,
                    record_number,
                )

                if self.raw_records.add_raw_record(
                    case_id=case_id,
                    file_sha256=evidence_sha256,
                    channel=channel,
                    record_number=record_number,
                    raw_xml=raw_xml,
                    conn=conn,
                ):
                    raw_inserted_count += 1
                else:
                    raw_duplicate_count += 1

                event = normalizer(raw_event)

                if event is None:
                    continue

                supported_count += 1

                if not event.get("@timestamp"):
                    raise ValueError(
                        "Normalized event has no timestamp"
                    )

                event["event_id"] = build_event_id(
                    evidence_sha256,
                    locator,
                    PARSER_VERSION,
                    SCHEMA_VERSION,
                )
                event["raw_ref"] = locator
                event["parser_version"] = PARSER_VERSION
                event["schema_version"] = SCHEMA_VERSION

                pt = event.setdefault("pt", {})
                pt.setdefault("parse_warnings", [])
                pt["evidence"] = {
                    "sha256": evidence_sha256,
                    "channel": channel,
                    "record_number": record_number,
                    "record_locator": locator,
                }

                if self.events.add_event(
                    case_id,
                    evidence_sha256,
                    event,
                    conn=conn,
                ):
                    inserted_count += 1

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
                        "raw_inserted": raw_inserted_count,
                        "raw_duplicate": raw_duplicate_count,
                        "parser_version": PARSER_VERSION,
                        "schema_version": SCHEMA_VERSION,
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
            "raw_records_inserted": raw_inserted_count,
            "raw_records_duplicate": raw_duplicate_count,
            "parser_version": PARSER_VERSION,
            "schema_version": SCHEMA_VERSION,
        }

    @staticmethod
    def _record_number(raw_event) -> int:
        value = raw_event.get("record_id")

        if value is None:
            raise ValueError("Parsed record has no record number")

        return int(value)

    @staticmethod
    def _channel(raw_event) -> str:
        value = raw_event.get("channel")

        if value is None or not str(value).strip():
            return "unknown"

        return str(value)
