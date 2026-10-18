import sqlite3

import pytest

from phantomtrace.database.db import PhantomTraceDB


@pytest.fixture
def db(tmp_path):
    return PhantomTraceDB(
        str(tmp_path / "phantomtrace.db")
    )


def test_create_case(db):
    db.create_case(
        case_id="CASE-001",
        name="Scenario M"
    )

    case = db.get_case("CASE-001")

    assert case is not None
    assert case["name"] == "Scenario M"


def test_duplicate_case_rejected(db):
    db.create_case("CASE-001", "First case")

    with pytest.raises(sqlite3.IntegrityError):
        db.create_case("CASE-001", "Duplicate case")


def test_add_evidence(db):
    db.create_case("CASE-001", "Scenario M")

    inserted = db.add_evidence(
        case_id="CASE-001",
        sha256="a" * 64,
        source_name="Security.evtx",
        byte_length=1024
    )

    assert inserted is True

    evidence = db.get_evidence("CASE-001")

    assert len(evidence) == 1
    assert evidence[0]["source_name"] == "Security.evtx"


def test_duplicate_evidence(db):
    db.create_case("CASE-001", "Scenario M")

    first = db.add_evidence(
        "CASE-001",
        "a" * 64,
        "Security.evtx",
        1024
    )

    second = db.add_evidence(
        "CASE-001",
        "a" * 64,
        "Security.evtx",
        1024
    )

    assert first is True
    assert second is False

    assert len(db.get_evidence("CASE-001")) == 1


def test_evidence_requires_existing_case(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.add_evidence(
            "UNKNOWN",
            "a" * 64,
            "Security.evtx",
            1024
        )


def test_audit_log_created(db):
    db.create_case("CASE-001", "Scenario M")

    actions = db.get_audit_log("CASE-001")

    assert len(actions) == 1
    assert actions[0]["action"] == "CASE_CREATED"


def test_evidence_audit_log(db):
    db.create_case("CASE-001", "Scenario M")

    db.add_evidence(
        "CASE-001",
        "a" * 64,
        "Security.evtx",
        1024,
        actor="analyst"
    )

    actions = db.get_audit_log(
        "CASE-001:" + "a" * 64
    )

    assert len(actions) == 1
    assert actions[0]["actor"] == "analyst"
    assert actions[0]["action"] == "EVIDENCE_REGISTERED"


def test_database_persistence(tmp_path):
    path = tmp_path / "persistent.db"

    first = PhantomTraceDB(str(path))
    first.create_case("CASE-001", "Persistent case")

    second = PhantomTraceDB(str(path))

    case = second.get_case("CASE-001")

    assert case is not None
    assert case["name"] == "Persistent case"