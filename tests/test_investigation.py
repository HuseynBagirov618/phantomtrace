import csv
import io
import json
import sqlite3

from fastapi.testclient import TestClient
import pytest

from apps.api import main
from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.database.event_store import EventStore
from phantomtrace.evidence.storage import EvidenceStorage
from phantomtrace.investigation.engine import analyze
from phantomtrace.investigation.evaluate import score
from phantomtrace.investigation.rules import CHAIN, ENCODED
from phantomtrace.investigation.sample import DEMO_CONFIG, seed
from phantomtrace.investigation.store import AnalysisStore


@pytest.fixture
def workbench(tmp_path, monkeypatch):
    db = PhantomTraceDB(tmp_path / "cases.db")
    storage = EvidenceStorage(tmp_path / "evidence")
    monkeypatch.setattr(main, "db", db)
    monkeypatch.setattr(main, "storage", storage)
    for scenario in ("indicator", "benign", "concurrent"):
        seed(db, storage, tmp_path / "samples", scenario, scenario)
    with TestClient(main.app) as client:
        yield client, db


def start(client, name, config=DEMO_CONFIG):
    response = client.post(f"/cases/{name}/analysis", json=config)
    assert response.status_code == 201, response.text
    return response.json()


def test_evidence_trace_review_and_exports(workbench):
    client, db = workbench
    case = "/cases/indicator"
    before = start(client, "indicator")
    candidate, = before["incidents"]
    assert candidate["status"] == "correlated"
    stages = {stage["id"]: stage for stage in candidate["stages"]}
    assert len(stages["failed_logons"]["event_ids"]) == 5
    assert stages["transfer"]["state"] == "unknown"
    session, = stages["session"]["event_ids"]
    process, = stages["powershell"]["event_ids"]
    task, = stages["task"]["event_ids"]
    file, = stages["file"]["event_ids"]

    graph_path = f"{case}/incidents/{candidate['incident_id']}/graph"
    graph = client.get(graph_path).json()
    edge = next(edge for edge in graph["edges"] if edge["kind"] == "belongs_to_session")
    assert edge["matched_fields"] == {"LogonId": "0x20"}
    for identifier in edge["support_event_ids"]:
        raw = client.get(f"{case}/events/{identifier}/raw")
        assert raw.status_code == 200
        assert raw.json()["event_id"] == identifier
    assert sum(item["action"] == "RAW_EVIDENCE_READ" for item in db.get_audit_log()) == 2

    backward = client.get(f"{case}/trace", params={"seed": task, "dir": "back"}).json()
    forward = client.get(f"{case}/trace", params={"seed": session, "dir": "forward"}).json()
    assert session in backward["event_ids"]
    assert {task, process, file} <= set(forward["event_ids"])

    review_path = f"{case}/edges/{edge['edge_id']}/review"
    decision = {"operation": "REJECT", "actor": "Analyst", "rationale": "Demonstration exclusion",
                "run_id": before["run_id"]}
    response = client.post(review_path, json=decision)
    assert response.status_code == 201, response.text
    after = response.json()
    assert after["previous_run_id"] == before["run_id"]
    assert any(change["stage"] == "powershell" and change["before"] == [process]
               and not change["after"] for change in after["stage_changes"])
    assert not any(hit["rule_id"] == CHAIN for hit in after["hits"])
    surviving_task = next(stage for stage in after["incidents"][0]["stages"] if stage["id"] == "task")
    assert surviving_task["event_ids"] == [task]
    assert client.post(review_path, json=decision).status_code == 409
    assert next(e for e in client.get(graph_path).json()["edges"]
                if e["edge_id"] == edge["edge_id"])["review_status"] == "REJECT"
    historical = client.get(graph_path, params={"run_id": before["run_id"]}).json()
    assert next(e for e in historical["edges"] if e["edge_id"] == edge["edge_id"])["review_status"] is None
    rerun = start(client, "indicator", None)
    assert rerun["reviews"] == after["reviews"]
    assert all(hit["rule_id"] != CHAIN for hit in rerun["hits"])

    exported = client.get(f"{case}/export/timeline.csv")
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    by_id = {row["event_id"]: row for row in rows}
    assert by_id[process]["source_sha256"] in by_id[process]["record_locator"]
    assert after["reviews"][0]["rationale"] in client.get(f"{case}/export/report.md").text
    assert len(client.get(f"{case}/export/manifest.json").json()["evidence"]) == 3
    with db.connect() as conn, pytest.raises(sqlite3.IntegrityError, match="append only"):
        conn.execute("DELETE FROM review_actions")


def test_benign_and_concurrent_session_controls(workbench):
    client, _ = workbench
    benign = start(client, "benign")
    assert not benign["incidents"]
    assert not any(hit["rule_id"] in {CHAIN, ENCODED} for hit in benign["hits"])
    concurrent = start(client, "concurrent")
    assert len(concurrent["incidents"]) == 2
    first, second = (set(incident["graph"]["event_ids"]) for incident in concurrent["incidents"])
    assert not first.intersection(second)


def test_missing_and_ambiguous_boot_scope_stay_visible(workbench):
    client, db = workbench
    no_scope = start(client, "indicator", {})
    assert all(hit["rule_id"] != CHAIN for hit in no_scope["hits"])
    saved = AnalysisStore(db).latest("indicator")
    assert any(gap["reason"] == "Shared boot scope is unverified" for gap in saved["gaps"])

    events = EventStore(db).get_timeline("indicator")
    successful = next(event for event in events if event["event.code"] == "4624")
    duplicate = successful | {"event_id": "duplicate-session"}
    assessment = analyze([*events, duplicate], DEMO_CONFIG, {"security"})
    assert any(gap["reason"] == "Identifier is ambiguous in scope" and len(gap["candidates"]) == 2
               for gap in assessment["gaps"])
    assert all(edge["kind"] != "belongs_to_session" for edge in assessment["edges"])

    without_script = [event for event in events if event["event.code"] != "4104"]
    assessment = analyze(without_script, DEMO_CONFIG, {"security", "microsoft-windows-powershell/operational"})
    assert assessment["coverage"]["powershell_content"]["state"] == "UNKNOWN"


def test_evaluation_reports_undefined_denominators_and_missed_edge(workbench):
    client, db = workbench
    start(client, "indicator")
    run = AnalysisStore(db).latest("indicator")
    events = EventStore(db).get_timeline("indicator")
    refs = {event["event_id"]: event["raw_ref"] for event in events}
    chain = next(hit for hit in run["hits"] if hit["rule_id"] == CHAIN)
    edge = next(edge for edge in run["edges"] if edge["kind"] == "belongs_to_session")
    ground_truth = {"name": "synthetic", "split": "validation",
                    "detections": [{"rule": CHAIN, "record": refs[chain["seed_event_id"]]}],
                    "edges": [{"kind": edge["kind"], "from": refs[edge["from_id"]],
                               "to": refs[edge["to_id"]]}],
                    "incident_groups": [[refs[identifier] for identifier in chain["event_ids"]]]}
    result = score(ground_truth, run, events)["configurations"]
    assert result["rules_only"]["edge_precision"]["value"] is None
    assert result["rules_only"]["example_missed_edge"][0] == "belongs_to_session"
    assert result["identifier_graph"]["edge_recall"] == {"numerator": 1, "denominator": 1, "value": 1}


def test_corrupt_evidence_is_audited_and_unsafe_http_is_rejected(workbench):
    client, db = workbench
    route = "/cases/indicator/evidence"
    assert client.post(route, files={"file": ("corrupt.evtx", b"ElfFile\0x")},
                       headers={"Origin": "https://example.test"}).status_code == 403
    assert client.get("/health", headers={"Host": "example.test"}).status_code == 400
    upload = client.post(route, files={"file": ("corrupt.evtx", b"ElfFile\0x")})
    assert upload.status_code == 201
    digest = upload.json()["sha256"]
    failure = client.post(f"{route}/{digest}/ingest")
    assert failure.status_code == 409
    assert failure.json()["detail"]["status"] == "FAILED_WITH_REASON"
    action = next(row for row in db.get_audit_log(f"indicator:{digest}") if row["action"] == "EVIDENCE_INGEST_FAILED")
    assert json.loads(action["details"])["parser_version"]
    analysis = start(client, "indicator")
    assert len(analysis["incidents"]) == 1
    assert next(item for item in analysis["evidence"] if item["sha256"] == digest)["status"] == "FAILED_WITH_REASON"
