import sqlite3

from datetime import datetime, timezone
from pathlib import Path


class PhantomTraceDB:
    """
    SQLite database for PhantomTrace.

    Stores investigation cases, evidence metadata,
    and append-only evidence handling audit records.
    """

    def __init__(self, db_path="data/phantomtrace.db"):
        self.db_path = Path(db_path)

        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.initialize_database()

    def connect(self):
        connection = sqlite3.connect(self.db_path)

        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")

        return connection

    def initialize_database(self):
        with self.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    description TEXT
                );

                CREATE TABLE IF NOT EXISTS evidence_files (
                    case_id TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    byte_length INTEGER NOT NULL
                        CHECK(byte_length >= 0),

                    PRIMARY KEY (case_id, sha256),

                    FOREIGN KEY (case_id)
                        REFERENCES cases(case_id)
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    action TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    details TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_audit_object
                    ON audit_log(object_id);
            """)

    def create_case(
        self,
        case_id,
        name,
        description=None
    ):
        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO cases (
                    case_id,
                    name,
                    created_at,
                    description
                )
                VALUES (?, ?, ?, ?)
                """,
                (
                    case_id,
                    name,
                    created_at,
                    description
                )
            )

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
                    "system",
                    created_at,
                    "CASE_CREATED",
                    case_id,
                    name
                )
            )

        return case_id

    def add_evidence(
        self,
        case_id,
        sha256,
        source_name,
        byte_length,
        actor="system"
    ):
        collected_at = datetime.now(
            timezone.utc
        ).isoformat()

        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT OR IGNORE INTO evidence_files (
                    case_id,
                    sha256,
                    source_name,
                    collected_at,
                    byte_length
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    sha256,
                    source_name,
                    collected_at,
                    byte_length
                )
            )

            inserted = cursor.rowcount == 1

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
                    actor,
                    collected_at,
                    (
                        "EVIDENCE_REGISTERED"
                        if inserted
                        else "EVIDENCE_DUPLICATE"
                    ),
                    f"{case_id}:{sha256}",
                    source_name
                )
            )

        return inserted

    def log_action(
        self,
        actor,
        action,
        object_id,
        details=None
    ):
        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        with self.connect() as conn:
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
                    actor,
                    timestamp,
                    action,
                    object_id,
                    details
                )
            )

    def get_case(self, case_id):
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM cases WHERE case_id = ?",
                (case_id,)
            ).fetchone()

        return dict(row) if row else None

    def get_evidence(self, case_id):
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM evidence_files
                WHERE case_id = ?
                ORDER BY collected_at
                """,
                (case_id,)
            ).fetchall()

        return [dict(row) for row in rows]

    def get_audit_log(self, object_id=None):
        with self.connect() as conn:
            if object_id is None:
                rows = conn.execute(
                    "SELECT * FROM audit_log ORDER BY id"
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT *
                    FROM audit_log
                    WHERE object_id = ?
                    ORDER BY id
                    """,
                    (object_id,)
                ).fetchall()

        return [dict(row) for row in rows]