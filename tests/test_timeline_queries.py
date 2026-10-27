import pytest

from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.database.event_store import EventStore


@pytest.fixture
def store(tmp_path):
    db = PhantomTraceDB(str(tmp_path / "timeline.db"))
    db.create_case("TEST-001", "Timeline query tests")

    db.add_evidence(
        case_id="TEST-001",
        sha256="a" * 64,
        source_name="Security.evtx",
        byte_length=1024,
    )

    db.add_evidence(
        case_id="TEST-001",
        sha256="b" * 64,
        source_name="Sysmon.evtx",
        byte_length=2048,
    )

    event_store = EventStore(db)

    fixtures = [
        (
            "a" * 64,
            100,
            4625,
            "authentication",
            "2026-10-16T19:09:00+00:00",
        ),
        (
            "a" * 64,
            101,
            4624,
            "authentication",
            "2026-10-16T19:33:00+00:00",
        ),
        (
            "b" * 64,
            200,
            1,
            "process_creation",
            "2026-10-16T20:23:00+00:00",
        ),
        (
            "b" * 64,
            201,
            11,
            "file_creation",
            "2026-10-16T20:35:00+00:00",
        ),
    ]

    for sha256, record_id, event_id, event_type, timestamp in fixtures:
        event_store.add_event(
            "TEST-001",
            sha256,
            {
                "record_id": str(record_id),
                "event_id": event_id,
                "event_type": event_type,
                "timestamp_utc": timestamp,
            },
        )

    return event_store


def test_query_all_events(store):
    result = store.query_timeline("TEST-001")

    assert result["total_events"] == 4
    assert len(result["events"]) == 4


def test_filter_by_event_type(store):
    result = store.query_timeline(
        "TEST-001",
        event_type="authentication",
    )

    assert result["total_events"] == 2
    assert all(
        e["event_type"] == "authentication"
        for e in result["events"]
    )


def test_filter_by_time_window(store):
    result = store.query_timeline(
        "TEST-001",
        start_utc="2026-10-16T20:00:00+00:00",
        end_utc="2026-10-16T21:00:00+00:00",
    )

    assert result["total_events"] == 2
    assert [e["record_id"] for e in result["events"]] == [
        "200", "201"
    ]


def test_filter_by_evidence_hash(store):
    result = store.query_timeline(
        "TEST-001",
        evidence_sha256="b" * 64,
    )

    assert result["total_events"] == 2
    assert all(
        e["evidence_sha256"] == "b" * 64
        for e in result["events"]
    )


def test_pagination(store):
    first = store.query_timeline(
        "TEST-001", limit=2, offset=0
    )
    second = store.query_timeline(
        "TEST-001", limit=2, offset=2
    )

    assert first["total_events"] == 4
    assert second["total_events"] == 4
    assert [e["record_id"] for e in first["events"]] == [
        "100", "101"
    ]
    assert [e["record_id"] for e in second["events"]] == [
        "200", "201"
    ]


def test_invalid_limit_rejected(store):
    with pytest.raises(ValueError):
        store.query_timeline("TEST-001", limit=5000)


def test_invalid_offset_rejected(store):
    with pytest.raises(ValueError):
        store.query_timeline("TEST-001", offset=-1)


def test_invalid_hash_rejected(store):
    with pytest.raises(ValueError):
        store.query_timeline(
            "TEST-001",
            evidence_sha256="../../outside",
        )