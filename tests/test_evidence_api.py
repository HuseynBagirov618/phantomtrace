import hashlib
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.evidence.storage import EvidenceStorage
from apps.api import main as api


@pytest.fixture
def environment(tmp_path, monkeypatch):
    """
    Isolate API tests from real investigation data.
    """

    database = PhantomTraceDB(
        str(tmp_path / "test.db")
    )

    storage = EvidenceStorage(
        str(tmp_path / "cases")
    )

    monkeypatch.setattr(api, "db", database)
    monkeypatch.setattr(api, "storage", storage)
    monkeypatch.chdir(tmp_path)

    database.create_case(
        "TEST-001",
        "Security testing"
    )

    with TestClient(api.app) as client:
        yield client, database, storage


def make_evtx(content=b"PhantomTrace test content"):
    """
    Create a signature-valid EVTX-like test fixture.

    This is not a structurally valid Windows Event Log.
    """
    return b"ElfFile\x00" + content


def test_valid_evtx_upload(environment):
    client, database, storage = environment

    payload = make_evtx()

    response = client.post(
        "/cases/TEST-001/evidence",
        files={
            "file": (
                "Security.evtx",
                payload,
                "application/octet-stream"
            )
        }
    )

    assert response.status_code == 201

    data = response.json()

    assert data["sha256"] == hashlib.sha256(
        payload
    ).hexdigest()

    assert data["registered"] is True

    assert storage.verify_evidence(
        "TEST-001",
        data["sha256"]
    )


def test_invalid_evtx_signature(environment):
    client, database, storage = environment

    response = client.post(
        "/cases/TEST-001/evidence",
        files={
            "file": (
                "invalid.evtx",
                b"This is not an EVTX file",
                "application/octet-stream"
            )
        }
    )

    assert response.status_code == 400
    assert database.get_evidence("TEST-001") == []


def test_filename_path_traversal(environment):
    client, database, storage = environment

    response = client.post(
        "/cases/TEST-001/evidence",
        files={
            "file": (
                "../../outside.evtx",
                make_evtx(),
                "application/octet-stream"
            )
        }
    )

    assert response.status_code == 400


def test_duplicate_upload(environment):
    client, database, storage = environment

    payload = make_evtx()

    first = client.post(
        "/cases/TEST-001/evidence",
        files={"file": ("test.evtx", payload)}
    )

    second = client.post(
        "/cases/TEST-001/evidence",
        files={"file": ("test.evtx", payload)}
    )

    assert first.status_code == 201
    assert second.status_code == 201

    assert first.json()["registered"] is True
    assert second.json()["registered"] is False

    assert len(database.get_evidence("TEST-001")) == 1


def test_modified_evidence_detected(environment):
    client, database, storage = environment

    payload = make_evtx()

    uploaded = client.post(
        "/cases/TEST-001/evidence",
        files={"file": ("test.evtx", payload)}
    )

    assert uploaded.status_code == 201

    sha256 = uploaded.json()["sha256"]

    stored_file = (
        Path(storage.base_path)
        / "TEST-001"
        / "evidence"
        / sha256
    )

    # Temporarily remove read-only protection
    # on this test fixture only.
    os.chmod(stored_file, 0o666)

    with open(stored_file, "r+b") as file:
        file.seek(0)
        file.write(b"X")

    response = client.get(
        f"/cases/TEST-001/evidence/{sha256}/verify"
    )

    assert response.status_code == 200
    assert response.json()["integrity_ok"] is False
    assert response.json()["status"] == "integrity_failure"

    audit = database.get_audit_log(
        f"TEST-001:{sha256}"
    )

    assert audit[-1]["action"] == "EVIDENCE_VERIFIED"
    assert audit[-1]["details"] == "FAIL"


def test_missing_case_rejected(environment):
    client, database, storage = environment

    response = client.post(
        "/cases/UNKNOWN/evidence",
        files={"file": ("test.evtx", make_evtx())}
    )

    assert response.status_code == 404


def test_oversized_upload_rejected(environment, monkeypatch):
    client, database, storage = environment

    # Lower the limit for this test to avoid
    # allocating a 100 MiB test payload.
    monkeypatch.setattr(api, "MAX_UPLOAD_SIZE", 16)

    response = client.post(
        "/cases/TEST-001/evidence",
        files={
            "file": (
                "large.evtx",
                make_evtx(b"A" * 32)
            )
        }
    )

    assert response.status_code == 413
    assert database.get_evidence("TEST-001") == []