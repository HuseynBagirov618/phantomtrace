import hashlib

import pytest
from fastapi.testclient import TestClient

from apps.api import main as api
from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.database.raw_store import RawRecordStore
from phantomtrace.evidence.storage import EvidenceStorage
from phantomtrace.ingestion import service as ingestion_module


RAW_XML = (
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/'
    'events/event"><System><EventID>4625</EventID></System>'
    "</Event>"
)

RAW_HASH = hashlib.sha256(RAW_XML.encode("utf-8")).hexdigest()


def fake_parser(path):
    yield {
        "event_id": "4625",
        "record_id": "100",
        "timestamp": "2026-10-16 19:09:26.775558",
        "computer": "TEST-VM",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "source_file": "Security.evtx",
        "event_data": [
            {"name": "TargetUserName", "value": "Stark"},
            {"name": "LogonType", "value": "10"},
            {"name": "TargetLogonId", "value": "0xC270DA"},
            {"name": "IpAddress", "value": "192.168.14.128"},
        ],
        "raw_xml": RAW_XML,
    }


@pytest.fixture
def environment(tmp_path, monkeypatch):
    db = PhantomTraceDB(str(tmp_path / "test.db"))
    storage = EvidenceStorage(str(tmp_path / "cases"))

    monkeypatch.setattr(api, "db", db)
    monkeypatch.setattr(api, "storage", storage)
    monkeypatch.setattr(
        ingestion_module, "parse_evtx", fake_parser
    )

    db.create_case("TEST-001", "Raw record API test")

    source = tmp_path / "Security.evtx"
    source.write_bytes(b"ElfFile\x00raw-record-test")

    stored = storage.store_evidence("TEST-001", str(source))

    db.add_evidence(
        "TEST-001",
        stored["sha256"],
        "Security.evtx",
        source.stat().st_size,
    )

    with TestClient(api.app) as client:
        yield client, db, stored["sha256"]


def ingest(client, sha256):
    response = client.post(
        f"/cases/TEST-001/evidence/{sha256}/ingest"
    )

    assert response.status_code == 200

    return response.json()


def test_raw_record_endpoint_returns_custody(environment):
    client, db, sha256 = environment

    result = ingest(client, sha256)

    assert result["raw_records_inserted"] == 1
    assert result["inserted_events"] == 1

    timeline = client.get("/cases/TEST-001/timeline").json()
    event = timeline["events"][0]

    assert len(event["event_id"]) == 64
    assert event["raw_ref"] == f"{sha256}:Security:100"
    assert event["pt"]["evidence"]["sha256"] == sha256
    assert event["pt"]["evidence"]["channel"] == "Security"
    assert event["pt"]["evidence"]["record_number"] == 100

    # Canonical field mapping from the roadmap.
    assert event["winlog.logon.id"] == "0xc270da"
    assert event["winlog.logon.type"] == "10"
    assert event["source.ip"] == "192.168.14.128"
    assert event["@timestamp"].endswith("+00:00")
    assert event["timestamp_original"] == (
        "2026-10-16 19:09:26.775558"
    )

    raw = client.get(
        f"/cases/TEST-001/events/{event['event_id']}/raw"
    )

    assert raw.status_code == 200

    body = raw.json()

    assert body["raw_xml"] == RAW_XML
    assert body["raw_hash"] == RAW_HASH
    assert body["event_id"] == event["event_id"]
    assert body["raw_ref"] == event["raw_ref"]
    assert body["evidence"]["sha256"] == sha256
    assert body["evidence"]["channel"] == "Security"
    assert body["evidence"]["record_number"] == 100

    actions = db.get_audit_log(
        f"TEST-001:{event['raw_ref']}"
    )

    assert actions[-1]["action"] == "RAW_EVIDENCE_READ"
    assert actions[-1]["details"] == RAW_HASH


def test_raw_record_is_not_duplicated_on_reimport(environment):
    client, db, sha256 = environment

    ingest(client, sha256)

    second = ingest(client, sha256)
    assert second["raw_records_inserted"] == 0
    assert second["raw_records_duplicate"] == 1

    timeline = client.get("/cases/TEST-001/timeline").json()

    assert timeline["total_events"] == 1
    assert RawRecordStore(db).count_raw_records(
        "TEST-001", sha256
    ) == 1


def test_unknown_event_id_returns_404(environment):
    client, db, sha256 = environment

    response = client.get(
        f"/cases/TEST-001/events/{'b' * 64}/raw"
    )

    assert response.status_code == 404


def test_invalid_event_id_returns_422(environment):
    client, db, sha256 = environment

    response = client.get(
        "/cases/TEST-001/events/not-an-event-id/raw"
    )

    assert response.status_code == 422


def test_missing_raw_record_returns_404(environment):
    client, db, sha256 = environment

    ingest(client, sha256)

    event = client.get(
        "/cases/TEST-001/timeline"
    ).json()["events"][0]

    # Simulate a custody failure: the normalized event exists but its
    # raw record was lost.
    with db.connect() as conn:
        conn.execute(
            "DELETE FROM raw_records WHERE case_id = ?",
            ("TEST-001",),
        )

    response = client.get(
        f"/cases/TEST-001/events/{event['event_id']}/raw"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == (
        "Raw record not found for this event."
    )
