import re

from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.schema.identity import (
    raw_xml_hash,
    record_locator,
)


CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")
SHA256_PATTERN = re.compile(r"[a-fA-F0-9]{64}")


class RawRecordStore:
    """Append-only custody of raw event records.

    Raw XML is stored once per evidence file, channel, and record number.
    Nothing here updates or deletes a stored record.
    """

    def __init__(self, db: PhantomTraceDB):
        self.db = db
        self.initialize()

    def initialize(self):
        with self.db.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS raw_records (
                    case_id TEXT NOT NULL,
                    file_sha256 TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    record_number INTEGER NOT NULL
                        CHECK(record_number >= 0),
                    record_locator TEXT NOT NULL,
                    raw_hash TEXT NOT NULL,
                    raw_xml TEXT NOT NULL,

                    PRIMARY KEY (case_id, record_locator),

                    FOREIGN KEY (case_id, file_sha256)
                        REFERENCES evidence_files(case_id, sha256)
                )
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_raw_records_evidence
                ON raw_records(
                    case_id,
                    file_sha256,
                    record_number
                )
                """
            )

    def add_raw_record(
        self,
        case_id: str,
        file_sha256: str,
        channel: str,
        record_number: int,
        raw_xml: str,
        conn=None,
    ) -> bool:
        """Store one raw record.

        Returns True when inserted, False when the same locator already
        exists. Re-reading the same evidence never duplicates rows.
        """
        if not CASE_ID_PATTERN.fullmatch(str(case_id)):
            raise ValueError("Invalid case ID")

        if not SHA256_PATTERN.fullmatch(str(file_sha256)):
            raise ValueError("Invalid evidence SHA-256")

        locator = record_locator(
            file_sha256,
            channel,
            int(record_number),
        )

        stored_hash = raw_xml_hash(raw_xml)

        parameters = (
            case_id,
            str(file_sha256).lower(),
            str(channel),
            int(record_number),
            locator,
            stored_hash,
            str(raw_xml),
        )

        sql = """
            INSERT INTO raw_records (
                case_id,
                file_sha256,
                channel,
                record_number,
                record_locator,
                raw_hash,
                raw_xml
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id, record_locator) DO NOTHING
        """

        if conn is None:
            with self.db.connect() as own_connection:
                cursor = own_connection.execute(sql, parameters)
                return cursor.rowcount == 1

        return conn.execute(sql, parameters).rowcount == 1

    def get_raw_record(
        self,
        case_id: str,
        locator: str,
    ) -> dict | None:
        if not CASE_ID_PATTERN.fullmatch(str(case_id)):
            raise ValueError("Invalid case ID")

        if not str(locator).strip():
            raise ValueError("Invalid record locator")

        with self.db.connect() as conn:
            row = conn.execute(
                """
                SELECT
                    case_id,
                    file_sha256,
                    channel,
                    record_number,
                    record_locator,
                    raw_hash,
                    raw_xml
                FROM raw_records
                WHERE case_id = ? AND record_locator = ?
                """,
                (case_id, locator),
            ).fetchone()

        return dict(row) if row else None

    def count_raw_records(
        self,
        case_id: str,
        file_sha256: str | None = None,
    ) -> int:
        if not CASE_ID_PATTERN.fullmatch(str(case_id)):
            raise ValueError("Invalid case ID")

        with self.db.connect() as conn:
            if file_sha256 is None:
                row = conn.execute(
                    """
                    SELECT COUNT(*) FROM raw_records
                    WHERE case_id = ?
                    """,
                    (case_id,),
                ).fetchone()
            else:
                if not SHA256_PATTERN.fullmatch(str(file_sha256)):
                    raise ValueError("Invalid evidence SHA-256")

                row = conn.execute(
                    """
                    SELECT COUNT(*) FROM raw_records
                    WHERE case_id = ? AND file_sha256 = ?
                    """,
                    (case_id, str(file_sha256).lower()),
                ).fetchone()

        return int(row[0])
