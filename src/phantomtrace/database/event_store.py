import json
import re

from phantomtrace.database.db import PhantomTraceDB


class EventStore:
    """
    Persistent storage for normalized forensic events.

    Each event is uniquely identified within an evidence
    file by its original Windows Event Record ID.
    """

    def __init__(self, db: PhantomTraceDB):
        self.db = db
        self.initialize()

    def initialize(self):
        with self.db.connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS event_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    case_id TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL,

                    record_id INTEGER NOT NULL
                        CHECK(record_id >= 0),

                    event_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,

                    normalized_json TEXT NOT NULL,

                    UNIQUE (
                        case_id,
                        evidence_sha256,
                        record_id
                    ),

                    FOREIGN KEY (
                        case_id,
                        evidence_sha256
                    )
                    REFERENCES evidence_files(
                        case_id,
                        sha256
                    )
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_event_timeline
                ON event_records(
                    case_id,
                    timestamp_utc
                )
            """)

    def add_event(
        self,
        case_id: str,
        evidence_sha256: str,
        event: dict
    ) -> bool:
        """
        Insert a normalized event.

        Returns True when inserted, False when the
        same source record already exists.
        """
        if not re.fullmatch(
            r"[A-Za-z0-9_-]{1,64}", case_id
        ):
            raise ValueError("Invalid case ID")

        if not re.fullmatch(
            r"[a-fA-F0-9]{64}", evidence_sha256
        ):
            raise ValueError("Invalid evidence SHA-256")

        required = (
            "record_id",
            "event_id",
            "event_type",
            "timestamp_utc",
        )

        if any(event.get(key) is None for key in required):
            raise ValueError("Missing required event fields")

        record_id = int(event["record_id"])
        event_id = int(event["event_id"])

        if record_id < 0:
            raise ValueError("Invalid record ID")

        normalized_json = json.dumps(
            event,
            ensure_ascii=False
        )

        with self.db.connect() as conn:
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
                    evidence_sha256.lower(),
                    record_id,
                    event_id,
                    event["event_type"],
                    event["timestamp_utc"],
                    normalized_json,
                )
            )

            return cursor.rowcount == 1

    def get_timeline(self, case_id: str):
        """
        Retrieve normalized events in chronological order.
        """

        with self.db.connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    evidence_sha256,
                    record_id,
                    normalized_json
                FROM event_records
                WHERE case_id = ?
                ORDER BY
                    timestamp_utc,
                    evidence_sha256,
                    record_id
                """,
                (case_id,)
            ).fetchall()

        timeline = []

        for row in rows:
            event = json.loads(row["normalized_json"])

            event["evidence_sha256"] = (
                row["evidence_sha256"]
            )

            timeline.append(event)

        return timeline
    def query_timeline(
        self,
        case_id: str,
        limit: int = 100,
        offset: int = 0,
        start_utc: str | None = None,
        end_utc: str | None = None,
        event_type: str | None = None,
        evidence_sha256: str | None = None,
    ) -> dict:
        """
        Query normalized events using SQLite-side filtering
        and pagination. Dates must be canonical UTC ISO strings.
        """

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
            raise ValueError("Invalid case ID")

        if not 1 <= limit <= 1000:
            raise ValueError("Limit must be between 1 and 1000")

        if offset < 0:
            raise ValueError("Offset must be non-negative")

        conditions = ["case_id = ?"]
        parameters = [case_id]

        if start_utc is not None:
            conditions.append("timestamp_utc >= ?")
            parameters.append(start_utc)

        if end_utc is not None:
            conditions.append("timestamp_utc < ?")
            parameters.append(end_utc)

        if event_type is not None:
            conditions.append("event_type = ?")
            parameters.append(event_type)

        if evidence_sha256 is not None:
            if not re.fullmatch(r"[a-fA-F0-9]{64}", evidence_sha256):
                raise ValueError("Invalid evidence SHA-256")

            conditions.append("evidence_sha256 = ?")
            parameters.append(evidence_sha256.lower())

        where_clause = " AND ".join(conditions)

        with self.db.connect() as conn:
            total = conn.execute(
                f"""
                SELECT COUNT(*)
                FROM event_records
                WHERE {where_clause}
                """,
                parameters,
            ).fetchone()[0]

            rows = conn.execute(
                f"""
                SELECT
                    evidence_sha256,
                    record_id,
                    normalized_json
                FROM event_records
                WHERE {where_clause}
                ORDER BY
                    timestamp_utc,
                    evidence_sha256,
                    record_id
                LIMIT ? OFFSET ?
                """,
                [*parameters, limit, offset],
            ).fetchall()

        events = []

        for row in rows:
            event = json.loads(row["normalized_json"])
            event["evidence_sha256"] = row["evidence_sha256"]
            events.append(event)

        return {
            "case_id": case_id,
            "total_events": total,
            "limit": limit,
            "offset": offset,
            "events": events,
        }
    def get_event(
        self,
        case_id: str,
        evidence_sha256: str,
        record_id: int,
    ) -> dict | None:
        """
        Retrieve an individual normalized event and
        its registered evidence provenance.
        """

        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
            raise ValueError("Invalid case ID")

        if not re.fullmatch(r"[a-fA-F0-9]{64}", evidence_sha256):
            raise ValueError("Invalid evidence SHA-256")

        if record_id < 0:
            raise ValueError("Invalid record ID")

        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT
                    er.record_id,
                    er.event_id,
                    er.timestamp_utc,
                    er.normalized_json,
                    er.evidence_sha256,
                    ef.source_name,
                    ef.byte_length
                FROM event_records AS er
                JOIN evidence_files AS ef
                    ON er.case_id = ef.case_id
                    AND er.evidence_sha256 = ef.sha256
                WHERE
                    er.case_id = ?
                    AND er.evidence_sha256 = ?
                    AND er.record_id = ?
                """,
                (
                    case_id,
                    evidence_sha256.lower(),
                    record_id,
                ),
            ).fetchone()

        if row is None:
            return None

        event = json.loads(row["normalized_json"])

        return {
            "case_id": case_id,
            "evidence": {
                "filename": row["source_name"],
                "sha256": row["evidence_sha256"],
                "byte_length": row["byte_length"],
            },
            "event": event,
            "provenance": {
                "event_record_id": row["record_id"],
                "event_id": row["event_id"],
                "timestamp_utc": row["timestamp_utc"],
            },
        }