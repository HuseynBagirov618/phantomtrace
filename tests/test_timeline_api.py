import hashlib

import pytest
from fastapi.testclient import TestClient

from apps.api import main as api
from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.evidence.storage import EvidenceStorage
from phantomtrace.ingestion import service as ingestion_module


RAW_XML = "<Event><System><EventID>4625</EventID></System></Event>"


@pytest.fixture
def environment(tmp_path, monkeypatch):
    db = PhantomTraceDB(str(tmp_path / "test.db"))
    storage = EvidenceStorage(str(tmp_path / "cases"))

    monkeypatch.setattr(api, "db", db)
    monkeypatch.setattr(api, "storage", storage)

    db.create_case("TEST-001", "Timeline API test")

    # Signature-valid test fixture, not a complete EVTX file.
    source = tmp_path / "Security.evtx"
    source.write_bytes(b"ElfFile\x00test-data")

    stored = storage.store_evidence("TEST-001", str(source))

    db.add_evidence(
        case_id="TEST-001",
        sha256=stored["sha256"],
        source_name="Security.evtx",
        byte_length=source.stat().st_size,
    )

    with TestClient(api.app) as client:
        yield client, db, stored["sha256"]


def fake_evtx_parser(path):
    for record_id, timestamp in [
        (100, "2026-10-16 19:09:26.775558"),
        (101, "2026-10-16 19:33:37.335949"),
    ]:
        yield {
            "event_id": "4625" if record_id == 100 else "4624",
            "record_id": str(record_id),
            "timestamp": timestamp,
            "computer": "TEST-VM",
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "source_file": "Security.evtx",
            "event_data": [
                {
                    "name": "TargetUserName",
                    "value": "Stark",
                },
                {
                    "name": "IpAddress",
                    "value": "192.168.14.128",
                },
                {
                    "name": "LogonType",
                    "value": "3",
                },
            ],
            "raw_xml": RAW_XML,
        }


def test_ingest_and_retrieve_timeline(environment, monkeypatch):
    client, db, sha256 = environment

    monkeypatch.setattr(
        ingestion_module,
        "parse_evtx",
        fake_evtx_parser
    )

    response = client.post(
        f"/cases/TEST-001/evidence/{sha256}/ingest"
    )

    assert response.status_code == 200
    assert response.json()["inserted_events"] == 2
    assert response.json()["raw_records_inserted"] == 2

    timeline_response = client.get(
        "/cases/TEST-001/timeline"
    )

    assert timeline_response.status_code == 200

    result = timeline_response.json()

    assert result["total_events"] == 2
    assert len(result["events"]) == 2

    first = result["events"][0]
    second = result["events"][1]

    assert first["winlog.record_id"] == "100"
    assert second["winlog.record_id"] == "101"

    assert first["event.code"] == "4625"
    assert first["event.outcome"] == "failure"
    assert first["@timestamp"].endswith("+00:00")
    assert first["host.name"] == "TEST-VM"
    assert first["source.ip"] == "192.168.14.128"

    # Every timeline row must point at its raw record.
    assert first["raw_ref"] == f"{sha256}:Security:100"
    assert len(first["event_id"]) == 64
    assert "100" in first["raw_ref"]

    assert all(
        event["evidence_sha256"] == sha256
        for event in result["events"]
    )


def test_duplicate_ingestion(environment, monkeypatch):
    client, db, sha256 = environment

    monkeypatch.setattr(
        ingestion_module,
        "parse_evtx",
        fake_evtx_parser
    )

    first = client.post(
        f"/cases/TEST-001/evidence/{sha256}/ingest"
    )

    second = client.post(
        f"/cases/TEST-001/evidence/{sha256}/ingest"
    )

    assert first.status_code == 200
    assert second.status_code == 200

    assert first.json()["inserted_events"] == 2
    assert second.json()["inserted_events"] == 0
    assert second.json()["duplicate_events"] == 2
    assert second.json()["raw_records_inserted"] == 0


def test_timeline_pagination(environment, monkeypatch):
    client, db, sha256 = environment

    monkeypatch.setattr(
        ingestion_module,
        "parse_evtx",
        fake_evtx_parser
    )

    client.post(
        f"/cases/TEST-001/evidence/{sha256}/ingest"
    )

    response = client.get(
        "/cases/TEST-001/timeline",
        params={"limit": 1, "offset": 1}
    )

    assert response.status_code == 200
    assert response.json()["total_events"] == 2
    assert len(response.json()["events"]) == 1
    assert response.json()["events"][0]["winlog.record_id"] == (
        "101"
    )


def test_missing_case_returns_404(environment):
    client, db, sha256 = environment

    response = client.get(
        "/cases/UNKNOWN/timeline"
    )

    assert response.status_code == 404


def test_unregistered_evidence_returns_404(environment):
    client, db, sha256 = environment

    response = client.post(
        f"/cases/TEST-001/evidence/{'b' * 64}/ingest"
    )

    assert response.status_code == 404


def test_invalid_timeline_limit_returns_422(environment):
    client, db, sha256 = environment

    response = client.get(
        "/cases/TEST-001/timeline",
        params={"limit": 5000}
    )

    assert response.status_code == 422
