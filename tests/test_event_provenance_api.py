import os

import pytest
from fastapi.testclient import TestClient

from apps.api import main as api
from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.database.event_store import EventStore
from phantomtrace.evidence.storage import EvidenceStorage


@pytest.fixture
def environment(tmp_path, monkeypatch):
    db = PhantomTraceDB(str(tmp_path / "test.db"))
    storage = EvidenceStorage(str(tmp_path / "cases"))

    monkeypatch.setattr(api, "db", db)
    monkeypatch.setattr(api, "storage", storage)

    db.create_case("TEST-001", "Provenance API test")

    source = tmp_path / "Sysmon.evtx"
    source.write_bytes(b"ElfFile\x00test-record")

    stored = storage.store_evidence("TEST-001", str(source))
    sha256 = stored["sha256"]

    db.add_evidence(
        "TEST-001",
        sha256,
        "Sysmon.evtx",
        source.stat().st_size,
    )

    events = EventStore(db)
    events.add_event(
        "TEST-001",
        sha256,
        {
            "record_id": "5718",
            "event_id": 1,
            "event_type": "process_creation",
            "timestamp_utc": "2026-10-16T20:23:24+00:00",
            "process_guid": "{test-process}",
        },
    )

    with TestClient(api.app) as client:
        yield client, db, storage, sha256


def test_event_provenance(environment):
    client, db, storage, sha256 = environment

    response = client.get(
        f"/cases/TEST-001/evidence/{sha256}/events/5718"
    )

    assert response.status_code == 200

    result = response.json()

    assert result["evidence"]["filename"] == "Sysmon.evtx"
    assert result["evidence"]["sha256"] == sha256
    assert result["evidence"]["integrity_ok"] is True
    assert result["provenance"]["event_record_id"] == 5718
    assert result["event"]["process_guid"] == "{test-process}"


def test_missing_event_returns_404(environment):
    client, db, storage, sha256 = environment

    response = client.get(
        f"/cases/TEST-001/evidence/{sha256}/events/9999"
    )

    assert response.status_code == 404


def test_invalid_hash_returns_422(environment):
    client, db, storage, sha256 = environment

    response = client.get(
        "/cases/TEST-001/evidence/invalid-hash/events/5718"
    )

    assert response.status_code == 422


def test_modified_evidence_reports_failure(environment):
    client, db, storage, sha256 = environment

    evidence_path = (
        storage.base_path / "TEST-001" / "evidence" / sha256
    )

    # Only alter isolated temporary test evidence.
    os.chmod(evidence_path, 0o666)

    with evidence_path.open("r+b") as file:
        file.seek(0)
        file.write(b"X")

    response = client.get(
        f"/cases/TEST-001/evidence/{sha256}/events/5718"
    )

    assert response.status_code == 200
    assert response.json()["evidence"]["integrity_ok"] is False


def test_verification_is_audited(environment):
    client, db, storage, sha256 = environment

    response = client.get(
        f"/cases/TEST-001/evidence/{sha256}/events/5718"
    )

    assert response.status_code == 200

    actions = db.get_audit_log(f"TEST-001:{sha256}")

    assert actions[-1]["action"] == "EVIDENCE_VERIFIED"
    assert actions[-1]["details"] == "PASS"