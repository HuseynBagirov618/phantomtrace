import hashlib

import pytest

from phantomtrace.evidence.storage import EvidenceStorage


def test_store_and_verify_evidence(tmp_path):
    storage = EvidenceStorage(str(tmp_path / "cases"))

    source = tmp_path / "sample.evtx"
    content = b"PhantomTrace test evidence"

    source.write_bytes(content)

    expected_hash = hashlib.sha256(content).hexdigest()

    result = storage.store_evidence(
        case_id="CASE-001",
        source_path=str(source)
    )

    assert result["status"] == "stored"
    assert result["sha256"] == expected_hash

    assert storage.verify_evidence(
        "CASE-001",
        expected_hash
    ) is True


def test_duplicate_evidence(tmp_path):
    storage = EvidenceStorage(str(tmp_path / "cases"))

    source = tmp_path / "sample.evtx"
    source.write_bytes(b"Duplicate test")

    first = storage.store_evidence("CASE-001", str(source))
    second = storage.store_evidence("CASE-001", str(source))

    assert first["status"] == "stored"
    assert second["status"] == "already_exists"


def test_invalid_case_id(tmp_path):
    storage = EvidenceStorage(str(tmp_path / "cases"))

    source = tmp_path / "sample.evtx"
    source.write_bytes(b"Test")

    with pytest.raises(ValueError):
        storage.store_evidence(
            "../outside",
            str(source)
        )


def test_invalid_hash(tmp_path):
    storage = EvidenceStorage(str(tmp_path / "cases"))

    with pytest.raises(ValueError):
        storage.verify_evidence(
            "CASE-001",
            "../../wrong"
        )


def test_missing_evidence(tmp_path):
    storage = EvidenceStorage(str(tmp_path / "cases"))

    assert storage.verify_evidence(
        "CASE-001",
        "a" * 64
    ) is False