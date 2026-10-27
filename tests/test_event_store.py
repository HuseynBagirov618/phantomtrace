import sqlite3

import pytest

from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.database.event_store import EventStore


@pytest.fixture
def setup_store(tmp_path):
    db = PhantomTraceDB(
        str(tmp_path / "test.db")
    )

    db.create_case(
        "TEST-001",
        "Event storage test"
    )

    db.add_evidence(
        case_id="TEST-001",
        sha256="a" * 64,
        source_name="Security.evtx",
        byte_length=1024
    )

    return EventStore(db)


def sample_event(record_id="100"):
    return {
        "record_id": record_id,
        "event_id": 4625,
        "event_type": "authentication",
        "timestamp_utc": "2026-10-16T19:09:26+00:00",
        "source_file": "Security.evtx",
        "username": "Stark",
        "source_ip": "192.168.14.128",
    }


def test_insert_and_retrieve_event(setup_store):
    store = setup_store

    inserted = store.add_event(
        "TEST-001",
        "a" * 64,
        sample_event()
    )

    assert inserted is True

    timeline = store.get_timeline("TEST-001")

    assert len(timeline) == 1
    assert timeline[0]["event_id"] == 4625
    assert timeline[0]["username"] == "Stark"
    assert timeline[0]["evidence_sha256"] == "a" * 64


def test_duplicate_event_is_not_inserted(setup_store):
    store = setup_store

    assert store.add_event(
        "TEST-001", "a" * 64, sample_event()
    ) is True

    assert store.add_event(
        "TEST-001", "a" * 64, sample_event()
    ) is False

    assert len(store.get_timeline("TEST-001")) == 1


def test_missing_evidence_rejected(setup_store):
    store = setup_store

    with pytest.raises(sqlite3.IntegrityError):
        store.add_event(
            "TEST-001",
            "b" * 64,
            sample_event()
        )


def test_chronological_order(setup_store):
    store = setup_store

    later = sample_event("200")
    later["timestamp_utc"] = "2026-10-16T20:00:00+00:00"

    earlier = sample_event("100")
    earlier["timestamp_utc"] = "2026-10-16T19:00:00+00:00"

    store.add_event("TEST-001", "a" * 64, later)
    store.add_event("TEST-001", "a" * 64, earlier)

    timeline = store.get_timeline("TEST-001")

    assert [
        e["record_id"] for e in timeline
    ] == ["100", "200"]