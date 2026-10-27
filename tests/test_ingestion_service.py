import pytest

from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.database.event_store import EventStore
from phantomtrace.evidence.storage import EvidenceStorage
from phantomtrace.ingestion import service as ingestion_module
from phantomtrace.ingestion.service import EvidenceIngestionService


@pytest.fixture
def environment(tmp_path):
    db = PhantomTraceDB(str(tmp_path / "test.db"))
    storage = EvidenceStorage(str(tmp_path / "cases"))

    db.create_case("TEST-001", "Ingestion test")

    source = tmp_path / "Security.evtx"
    source.write_bytes(b"ElfFile\x00test-fixture")

    result = storage.store_evidence("TEST-001", str(source))

    db.add_evidence(
        case_id="TEST-001",
        sha256=result["sha256"],
        source_name="Security.evtx",
        byte_length=source.stat().st_size,
    )

    service = EvidenceIngestionService(db, storage)

    return db, service, result["sha256"]


def make_event(record_id):
    return {
        "event_id": "4625",
        "record_id": str(record_id),
        "timestamp": "2026-10-16 19:09:26.775558",
        "computer": "TEST-VM",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "source_file": "Security.evtx",
        "event_data": [
            {"name": "TargetUserName", "value": "Stark"},
            {"name": "IpAddress", "value": "192.168.14.128"},
            {"name": "LogonType", "value": "3"},
        ],
    }


def test_successful_ingestion(environment, monkeypatch):
    db, service, sha256 = environment

    def fake_parser(path):
        yield make_event(100)
        yield make_event(101)

    monkeypatch.setattr(
        ingestion_module, "parse_evtx", fake_parser
    )

    result = service.ingest("TEST-001", sha256)

    assert result["parsed_records"] == 2
    assert result["supported_events"] == 2
    assert result["inserted_events"] == 2

    timeline = EventStore(db).get_timeline("TEST-001")

    assert len(timeline) == 2
    assert all(
        event["evidence_sha256"] == sha256
        for event in timeline
    )


def test_duplicate_ingestion(environment, monkeypatch):
    db, service, sha256 = environment

    monkeypatch.setattr(
        ingestion_module,
        "parse_evtx",
        lambda path: iter([make_event(100)])
    )

    first = service.ingest("TEST-001", sha256)
    second = service.ingest("TEST-001", sha256)

    assert first["inserted_events"] == 1
    assert second["inserted_events"] == 0
    assert second["duplicate_events"] == 1

    assert len(
        EventStore(db).get_timeline("TEST-001")
    ) == 1


def test_parser_failure_rolls_back(environment, monkeypatch):
    db, service, sha256 = environment

    def broken_parser(path):
        yield make_event(100)
        raise ValueError("Simulated EVTX parsing failure")

    monkeypatch.setattr(
        ingestion_module, "parse_evtx", broken_parser
    )

    with pytest.raises(
        ValueError,
        match="Simulated EVTX parsing failure"
    ):
        service.ingest("TEST-001", sha256)

    # The first event must not remain after rollback.
    assert EventStore(db).get_timeline("TEST-001") == []

    # No success audit entry should be recorded.
    actions = db.get_audit_log(f"TEST-001:{sha256}")

    assert not any(
        action["action"] == "EVIDENCE_INGESTED"
        for action in actions
    )


def test_unregistered_evidence_rejected(environment):
    db, service, sha256 = environment

    with pytest.raises(ValueError, match="not registered"):
        service.ingest("TEST-001", "b" * 64)