import json
import re

from phantomtrace.database.db import PhantomTraceDB


CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")
SHA256_PATTERN = re.compile(r"[a-fA-F0-9]{64}")
EVENT_ID_PATTERN = re.compile(r"[a-f0-9]{64}")

REQUIRED_EVENT_FIELDS = (
    "event_id",
    "raw_ref",
    "parser_version",
    "schema_version",
    "event.code",
    "event_type",
    "@timestamp",
    "winlog.record_id",
)


class EventStore:
    """Persistent storage for normalized forensic events.

    Event identity is the deterministic ``event_id`` hash derived from
    the evidence hash, record locator, parser version, and schema
    version. Re-importing the same record at the same parser version
    upserts instead of duplicating. ``winlog.record_id`` stays stored
    for provenance lookups.
    """

    def __init__(self, db: PhantomTraceDB):
        self.db = db
        self.initialize()

    def initialize(self):
        with self.db.connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    case_id TEXT NOT NULL,
                    evidence_sha256 TEXT NOT NULL,

                    record_id INTEGER NOT NULL
                        CHECK(record_id >= 0),

                    event_id TEXT NOT NULL,
                    raw_ref TEXT NOT NULL,
                    event_code TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp_utc TEXT NOT NULL,

                    normalized_json TEXT NOT NULL,

                    UNIQUE (case_id, event_id),

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
                CREATE INDEX IF NOT EXISTS idx_events_timeline
                ON events(
                    case_id,
                    timestamp_utc
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_evidence
                ON events(
                    case_id,
                    evidence_sha256,
                    record_id
                )
            """)

    def add_event(
        self,
        case_id: str,
        evidence_sha256: str,
        event: dict,
        conn=None,
    ) -> bool:
        """
        Insert a normalized event.

        Returns True when inserted, False when the same deterministic
        event ID already exists.
        """
        if not CASE_ID_PATTERN.fullmatch(str(case_id)):
            raise ValueError("Invalid case ID")

        if not SHA256_PATTERN.fullmatch(str(evidence_sha256)):
            raise ValueError("Invalid evidence SHA-256")

        missing = [
            key
            for key in REQUIRED_EVENT_FIELDS
            if event.get(key) is None
        ]

        if missing:
            raise ValueError(
                "Missing required event fields: "
                + ", ".join(missing)
            )

        event_id = str(event["event_id"])

        if not EVENT_ID_PATTERN.fullmatch(event_id):
            raise ValueError("Invalid deterministic event ID")

        record_id = int(event["winlog.record_id"])

        if record_id < 0:
            raise ValueError("Invalid record ID")

        normalized_json = json.dumps(
            event,
            ensure_ascii=False
        )

        parameters = (
            case_id,
            str(evidence_sha256).lower(),
            record_id,
            event_id,
            str(event["raw_ref"]),
            str(event["event.code"]),
            str(event["event_type"]),
            str(event["@timestamp"]),
            normalized_json,
        )

        sql = """
            INSERT INTO events (
                case_id,
                evidence_sha256,
                record_id,
                event_id,
                raw_ref,
                event_code,
                event_type,
                timestamp_utc,
                normalized_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id, event_id) DO NOTHING
        """

        if conn is None:
            with self.db.connect() as own_connection:
                cursor = own_connection.execute(sql, parameters)
                return cursor.rowcount == 1

        return conn.execute(sql, parameters).rowcount == 1

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
                FROM events
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

        if not CASE_ID_PATTERN.fullmatch(str(case_id)):
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
            if not SHA256_PATTERN.fullmatch(str(evidence_sha256)):
                raise ValueError("Invalid evidence SHA-256")

            conditions.append("evidence_sha256 = ?")
            parameters.append(str(evidence_sha256).lower())

        where_clause = " AND ".join(conditions)

        with self.db.connect() as conn:
            total = conn.execute(
                f"""
                SELECT COUNT(*)
                FROM events
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
                FROM events
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

        if not CASE_ID_PATTERN.fullmatch(str(case_id)):
            raise ValueError("Invalid case ID")

        if not SHA256_PATTERN.fullmatch(str(evidence_sha256)):
            raise ValueError("Invalid evidence SHA-256")

        if record_id < 0:
            raise ValueError("Invalid record ID")

        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT
                    er.record_id,
                    er.event_id,
                    er.raw_ref,
                    er.event_code,
                    er.timestamp_utc,
                    er.normalized_json,
                    er.evidence_sha256,
                    ef.source_name,
                    ef.byte_length
                FROM events AS er
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
                    str(evidence_sha256).lower(),
                    record_id,
                ),
            ).fetchone()

        if row is None:
            return None

        return self._build_event_result(case_id, row)

    def get_event_by_id(
        self,
        case_id: str,
        event_id: str,
    ) -> dict | None:
        """
        Retrieve a normalized event by its deterministic event ID.
        """

        if not CASE_ID_PATTERN.fullmatch(str(case_id)):
            raise ValueError("Invalid case ID")

        if not EVENT_ID_PATTERN.fullmatch(str(event_id)):
            raise ValueError("Invalid deterministic event ID")

        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT
                    er.record_id,
                    er.event_id,
                    er.raw_ref,
                    er.event_code,
                    er.timestamp_utc,
                    er.normalized_json,
                    er.evidence_sha256,
                    ef.source_name,
                    ef.byte_length
                FROM events AS er
                JOIN evidence_files AS ef
                    ON er.case_id = ef.case_id
                    AND er.evidence_sha256 = ef.sha256
                WHERE
                    er.case_id = ?
                    AND er.event_id = ?
                """,
                (case_id, str(event_id).lower()),
            ).fetchone()

        if row is None:
            return None

        return self._build_event_result(case_id, row)

    def _build_event_result(self, case_id, row) -> dict:
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
                "event_code": row["event_code"],
                "raw_ref": row["raw_ref"],
                "timestamp_utc": row["timestamp_utc"],
            },
        }
