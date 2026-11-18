"""Case analysis history and append-only analyst review actions."""
from datetime import datetime, timezone
import json
from uuid import uuid4

from phantomtrace.database.event_store import EventStore
from phantomtrace.investigation.engine import analyze, compare_incident_stages
from phantomtrace.investigation.graph import VERSION as GRAPH_VERSION
from phantomtrace.investigation.rules import ATTACK_RELEASE, VERSION as RULE_VERSION
from phantomtrace.schema.versions import PARSER_VERSION, SCHEMA_VERSION

MAX_ANALYSIS_EVENTS = 50_000


class AnalysisStore:
    def __init__(self, db):
        self.db = db
        EventStore(db)
        with db.connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    sequence INTEGER PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    run_id TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    snapshot TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_runs_case ON analysis_runs(case_id, sequence);
                CREATE TABLE IF NOT EXISTS review_actions (
                    sequence INTEGER PRIMARY KEY,
                    case_id TEXT NOT NULL REFERENCES cases(case_id),
                    run_id TEXT NOT NULL REFERENCES analysis_runs(run_id),
                    target TEXT NOT NULL,
                    operation TEXT NOT NULL CHECK(operation IN ('CONFIRM','REJECT','QUESTION')),
                    actor TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_review_case ON review_actions(case_id, sequence);
                CREATE TRIGGER IF NOT EXISTS reviews_no_update BEFORE UPDATE ON review_actions
                BEGIN SELECT RAISE(ABORT, 'Review actions are append only'); END;
                CREATE TRIGGER IF NOT EXISTS reviews_no_delete BEFORE DELETE ON review_actions
                BEGIN SELECT RAISE(ABORT, 'Review actions are append only'); END;
                CREATE TRIGGER IF NOT EXISTS runs_no_update BEFORE UPDATE ON analysis_runs
                BEGIN SELECT RAISE(ABORT, 'Analysis runs are append only'); END;
                CREATE TRIGGER IF NOT EXISTS runs_no_delete BEFORE DELETE ON analysis_runs
                BEGIN SELECT RAISE(ABORT, 'Analysis runs are append only'); END;
            """)

    def latest(self, case_id, run_id=None, *, conn=None):
        if conn is None:
            with self.db.connect() as connection:
                return self.latest(case_id, run_id, conn=connection)
        if run_id:
            row = conn.execute(
                "SELECT snapshot FROM analysis_runs WHERE case_id = ? AND run_id = ?",
                (case_id, run_id),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT snapshot FROM analysis_runs WHERE case_id = ? ORDER BY sequence DESC LIMIT 1",
                (case_id,),
            ).fetchone()
        return json.loads(row["snapshot"]) if row else None

    def run(self, case_id, config):
        with self.db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous = self.latest(case_id, conn=conn)
            return self._save(conn, case_id, config if config is not None else (previous or {}).get("config", {}), previous)

    def review(self, case_id, edge_id, expected_run, operation, actor, rationale):
        with self.db.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            before = self.latest(case_id, conn=conn)
            if not before or before["run_id"] != expected_run:
                raise ValueError("Analysis run changed. Refresh the case before reviewing.")
            if not any(edge["edge_id"] == edge_id for edge in before["edges"]):
                raise LookupError("Edge is absent from the current analysis run.")
            timestamp = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """INSERT INTO review_actions (case_id, run_id, target, operation, actor, rationale, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (case_id, expected_run, edge_id, operation, actor, rationale, timestamp),
            )
            conn.execute(
                "INSERT INTO audit_log (actor, timestamp, action, object_id, details) VALUES (?, ?, ?, ?, ?)",
                (actor, timestamp, "EDGE_REVIEWED", f"{case_id}:{edge_id}", operation),
            )
            return self._save(conn, case_id, before["config"], before, reuse_evidence=True)

    def _save(self, conn, case_id, config, previous, *, reuse_evidence=False):
        if reuse_evidence:
            events = self.events(case_id, previous["event_ids"], conn=conn)
            evidence = previous["evidence"]
        else:
            rows = conn.execute(
                """SELECT e.normalized_json, e.evidence_sha256 FROM events AS e
                   WHERE case_id = ? AND NOT EXISTS (
                       SELECT 1 FROM events AS newer
                       WHERE newer.case_id = e.case_id AND newer.raw_ref = e.raw_ref AND newer.id > e.id
                   )
                   LIMIT ?""",
                (case_id, MAX_ANALYSIS_EVENTS + 1),
            )
            events = [json.loads(row["normalized_json"]) | {"evidence_sha256": row["evidence_sha256"]} for row in rows]
            if len(events) > MAX_ANALYSIS_EVENTS:
                raise ValueError(f"Analysis supports at most {MAX_ANALYSIS_EVENTS:,} normalized events per case")
            evidence = self._evidence(conn, case_id)
        channels = {channel.casefold() for item in evidence for channel in item["channels"]}
        channels.update(channel.casefold() for event in events if (channel := event.get("winlog.channel")))
        reviews = [dict(row) for row in conn.execute(
            "SELECT run_id, target, operation, actor, rationale, timestamp FROM review_actions WHERE case_id = ? ORDER BY sequence",
            (case_id,),
        )]
        snapshot = analyze(events, config, channels, reviews, incomplete=any(item["status"] != "SUCCESS" for item in evidence))
        snapshot.update({
            "case_id": case_id, "run_id": uuid4().hex, "created_at": datetime.now(timezone.utc).isoformat(),
            "previous_run_id": previous["run_id"] if previous else None, "reviews": reviews,
            "evidence": evidence, "versions": {"parser": PARSER_VERSION, "schema": SCHEMA_VERSION,
                                               "graph": GRAPH_VERSION, "rules": RULE_VERSION, "attack": ATTACK_RELEASE},
        })
        snapshot["stage_changes"] = compare_incident_stages(previous, snapshot) if previous else []
        conn.execute(
            "INSERT INTO analysis_runs (case_id, run_id, created_at, snapshot) VALUES (?, ?, ?, ?)",
            (case_id, snapshot["run_id"], snapshot["created_at"], json.dumps(snapshot)),
        )
        return snapshot

    @staticmethod
    def _evidence(conn, case_id):
        rows = conn.execute(
            """SELECT ef.*, a.action, a.details
               FROM evidence_files AS ef LEFT JOIN audit_log AS a ON a.id = (
                   SELECT a2.id FROM audit_log AS a2 WHERE a2.object_id = ef.case_id || ':' || ef.sha256
                   AND a2.action IN ('EVIDENCE_INGESTED','EVIDENCE_INGEST_FAILED')
                   ORDER BY a2.id DESC LIMIT 1
               ) WHERE ef.case_id = ? ORDER BY ef.sha256""",
            (case_id,),
        )
        evidence = []
        for row in rows:
            details = json.loads(row["details"]) if row["details"] else {}
            status = {"EVIDENCE_INGESTED": "PARTIAL" if details.get("errors") else "SUCCESS",
                      "EVIDENCE_INGEST_FAILED": "FAILED_WITH_REASON"}.get(row["action"], "PENDING")
            evidence.append({"sha256": row["sha256"], "filename": row["source_name"],
                             "byte_length": row["byte_length"], "status": status,
                             "channels": details.get("channels", []),
                             "errors": details.get("errors", []), "reason": details.get("reason")})
        return evidence

    def events(self, case_id, identifiers, *, conn=None):
        if conn is None:
            with self.db.connect() as connection:
                return self.events(case_id, identifiers, conn=connection)
        results = {}
        for start in range(0, len(identifiers), 500):
            batch = identifiers[start:start + 500]
            placeholders = ",".join("?" for _ in batch)
            rows = conn.execute(
                f"SELECT event_id, normalized_json, evidence_sha256 FROM events WHERE case_id = ? AND event_id IN ({placeholders})",
                (case_id, *batch),
            )
            for row in rows:
                results[row["event_id"]] = json.loads(row["normalized_json"]) | {
                    "evidence_sha256": row["evidence_sha256"]}
        return [results[ident] for ident in identifiers if ident in results]
