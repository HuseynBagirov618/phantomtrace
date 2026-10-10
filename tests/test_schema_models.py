from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from phantomtrace.schema.models import (
    Case,
    Edge,
    EvidenceFile,
    NormalizedEvent,
    RawRecord,
    ReviewAction,
)


HASH = "a" * 64
NOW = datetime.now(timezone.utc)


def test_case_accepts_valid_data() -> None:
    case = Case(
        case_id="case-001",
        name="Demo case",
        created_at=NOW,
    )

    assert case.case_id == "case-001"


def test_case_rejects_missing_case_id() -> None:
    with pytest.raises(ValidationError):
        Case(
            name="Demo case",
            created_at=NOW,
        )


def test_evidence_file_accepts_valid_data() -> None:
    evidence = EvidenceFile(
        case_id="case-001",
        sha256=HASH,
        source_name="Security.evtx",
        collected_at=NOW,
        byte_length=1024,
    )

    assert evidence.sha256 == HASH


def test_evidence_file_rejects_missing_sha256() -> None:
    with pytest.raises(ValidationError):
        EvidenceFile(
            case_id="case-001",
            source_name="Security.evtx",
            collected_at=NOW,
            byte_length=1024,
        )


def test_raw_record_accepts_valid_data() -> None:
    record = RawRecord(
        file_sha256=HASH,
        channel="Security",
        record_locator="Security:1001",
        raw_hash=HASH,
        raw_xml="<Event></Event>",
    )

    assert record.record_locator == "Security:1001"


def test_raw_record_rejects_missing_record_locator() -> None:
    with pytest.raises(ValidationError):
        RawRecord(
            file_sha256=HASH,
            channel="Security",
            raw_hash=HASH,
            raw_xml="<Event></Event>",
        )


def test_normalized_event_accepts_valid_data() -> None:
    event = NormalizedEvent(
        event_id="ev-001",
        raw_ref="Security:1001",
        parser_version="0.1.0",
        schema_version="0.1.0",
        timestamp=NOW,
        event_code="4624",
        host_id="H01",
        host_name="WIN-LAB",
        event_data={"winlog.logon.id": "0x52a4c"},
        pt={
            "coverage_state": "SUPPORTED",
            "parse_warnings": [],
            "evidence": {"sha256": HASH, "record": "Security:1001"},
        },
    )

    assert event.event_code == "4624"


def test_normalized_event_rejects_missing_event_id() -> None:
    with pytest.raises(ValidationError):
        NormalizedEvent(
            raw_ref="Security:1001",
            parser_version="0.1.0",
            schema_version="0.1.0",
            timestamp=NOW,
            event_code="4624",
        )


def test_edge_accepts_valid_data() -> None:
    edge = Edge(
        edge_id="edge-001",
        kind="belongs_to_session",
        strength="HARD",
        from_id="logon-001",
        to_id="process-001",
        rule_id="REL-SESSION-001",
        rule_version="1.0",
        support_event_ids=["ev-4624-001", "ev-sysmon1-001"],
        scope={"host_id": "H01", "boot_id": "BOOT1"},
        explanation="Matching scoped LogonId",
    )

    assert edge.strength == "HARD"


def test_edge_rejects_missing_explanation() -> None:
    with pytest.raises(ValidationError):
        Edge(
            edge_id="edge-001",
            kind="belongs_to_session",
            strength="HARD",
            from_id="logon-001",
            to_id="process-001",
            rule_id="REL-SESSION-001",
            rule_version="1.0",
        )


def test_review_action_accepts_valid_data() -> None:
    action = ReviewAction(
        actor="analyst",
        timestamp=NOW,
        target="edge-001",
        operation="REJECT",
        rationale="The LogonId belongs to another session.",
    )

    assert action.operation == "REJECT"


def test_review_action_rejects_missing_rationale() -> None:
    with pytest.raises(ValidationError):
        ReviewAction(
            actor="analyst",
            timestamp=NOW,
            target="edge-001",
            operation="REJECT",
        )