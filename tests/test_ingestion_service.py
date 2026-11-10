import pytest

from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.database.event_store import EventStore
from phantomtrace.database.raw_store import RawRecordStore
from phantomtrace.evidence.storage import EvidenceStorage
from phantomtrace.ingestion import service as ingestion_module
from phantomtrace.ingestion.service import EvidenceIngestionService
from phantomtrace.schema.identity import build_event_id
from phantomtrace.schema.versions import (
    PARSER_VERSION,
    SCHEMA_VERSION,
)


RAW_XML = "<Event><System><EventID>4625</EventID></System></Event>"


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

    return db, storage, service, result["sha256"]


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
            {"name": "TargetLogonId", "value": "0x1E169"},
        ],
        "raw_xml": RAW_XML,
    }


def test_successful_ingestion(environment, monkeypatch):
    db, storage, service, sha256 = environment

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
    assert result["raw_records_inserted"] == 2
    assert result["raw_records_duplicate"] == 0
    assert result["parser_version"] == PARSER_VERSION
    assert result["schema_version"] == SCHEMA_VERSION

    timeline = EventStore(db).get_timeline("TEST-001")

    assert len(timeline) == 2
    assert all(
        event["evidence_sha256"] == sha256
        for event in timeline
    )


def test_event_identity_is_deterministic(environment, monkeypatch):
    db, storage, service, sha256 = environment

    monkeypatch.setattr(
        ingestion_module,
        "parse_evtx",
        lambda path: iter([make_event(100)])
    )

    service.ingest("TEST-001", sha256)

    event = EventStore(db).get_timeline("TEST-001")[0]

    expected_locator = f"{sha256}:Security:100"
    expected_id = build_event_id(
        sha256,
        expected_locator,
        PARSER_VERSION,
        SCHEMA_VERSION,
    )

    assert event["raw_ref"] == expected_locator
    assert event["event_id"] == expected_id
    assert event["pt"]["evidence"]["record_locator"] == (
        expected_locator
    )
    assert event["pt"]["evidence"]["channel"] == "Security"
    assert event["pt"]["evidence"]["record_number"] == 100


def test_raw_record_custody(environment, monkeypatch):
    db, storage, service, sha256 = environment

    monkeypatch.setattr(
        ingestion_module,
        "parse_evtx",
        lambda path: iter([make_event(100)])
    )

    service.ingest("TEST-001", sha256)

    raw_store = RawRecordStore(db)
    locator = f"{sha256}:Security:100"
    raw_record = raw_store.get_raw_record("TEST-001", locator)

    assert raw_record is not None
    assert raw_record["raw_xml"] == RAW_XML
    assert raw_record["channel"] == "Security"
    assert raw_record["record_number"] == 100
    assert raw_store.count_raw_records("TEST-001", sha256) == 1


def test_unsupported_events_still_keep_raw_custody(
    environment, monkeypatch
):
    db, storage, service, sha256 = environment

    unsupported = make_event(150)
    unsupported["event_id"] = "4688"

    monkeypatch.setattr(
        ingestion_module,
        "parse_evtx",
        lambda path: iter([unsupported])
    )

    result = service.ingest("TEST-001", sha256)

    assert result["parsed_records"] == 1
    assert result["supported_events"] == 0
    assert result["raw_records_inserted"] == 1
    assert EventStore(db).get_timeline("TEST-001") == []
    assert RawRecordStore(db).count_raw_records(
        "TEST-001", sha256
    ) == 1


def test_duplicate_ingestion(environment, monkeypatch):
    db, storage, service, sha256 = environment

    monkeypatch.setattr(
        ingestion_module,
        "parse_evtx",
        lambda path: iter([make_event(100)])
    )

    first = service.ingest("TEST-001", sha256)
    second = service.ingest("TEST-001", sha256)

    assert first["inserted_events"] == 1
    assert first["raw_records_inserted"] == 1
    assert second["inserted_events"] == 0
    assert second["duplicate_events"] == 1
    assert second["raw_records_inserted"] == 0
    assert second["raw_records_duplicate"] == 1

    assert len(
        EventStore(db).get_timeline("TEST-001")
    ) == 1
    assert RawRecordStore(db).count_raw_records(
        "TEST-001", sha256
    ) == 1


def test_parser_failure_rolls_back(environment, monkeypatch):
    db, storage, service, sha256 = environment

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

    # Neither events nor raw records survive a failed parse.
    assert EventStore(db).get_timeline("TEST-001") == []
    assert RawRecordStore(db).count_raw_records(
        "TEST-001", sha256
    ) == 0

    # No success audit entry should be recorded.
    actions = db.get_audit_log(f"TEST-001:{sha256}")

    assert not any(
        action["action"] == "EVIDENCE_INGESTED"
        for action in actions
    )


def test_unregistered_evidence_rejected(environment):
    db, storage, service, sha256 = environment

    with pytest.raises(ValueError, match="not registered"):
        service.ingest("TEST-001", "b" * 64)
