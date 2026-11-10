import re
import sqlite3
import hashlib
import tempfile

from datetime import datetime, timezone

from fastapi import Query
from phantomtrace.database.event_store import EventStore
from phantomtrace.database.raw_store import RawRecordStore
from phantomtrace.ingestion.service import EvidenceIngestionService
from pathlib import Path, PurePosixPath, PureWindowsPath
from fastapi import File, UploadFile

from phantomtrace.evidence.storage import EvidenceStorage
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from phantomtrace.database.db import PhantomTraceDB


app = FastAPI(
    title="PhantomTrace API",
    description="Evidence-Driven Cyberattack Reconstruction",
    version="0.1.0"
)

# Initialize the database
db = PhantomTraceDB()

storage = EvidenceStorage()

MAX_UPLOAD_SIZE = 100 * 1024 * 1024  # 100 MiB
EVTX_SIGNATURE = b"ElfFile\x00"

class CaseCreateRequest(BaseModel):
    case_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9_-]+$"
    )

    name: str = Field(min_length=1)
    description: str | None = None


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "application": "PhantomTrace",
        "version": "0.1.0"
    }


@app.post("/cases", status_code=201)
def create_case(case: CaseCreateRequest):
    """
    Create a new forensic investigation case.
    """

    try:
        db.create_case(
            case_id=case.case_id,
            name=case.name,
            description=case.description
        )

    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="A case with this ID already exists."
        )

    return {
        "message": "Investigation case created successfully",
        "case_id": case.case_id,
        "name": case.name
    }


@app.get("/cases/{case_id}")
def get_case(case_id: str):
    """
    Retrieve information about an investigation.
    """

    case = db.get_case(case_id)

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found."
        )

    return case

@app.post("/cases/{case_id}/evidence", status_code=201)
async def upload_evidence(
    case_id: str,
    file: UploadFile = File(...)
):
    """
    Upload and register original Windows EVTX evidence.
    """

    # 1. Validate the investigation case.
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
        raise HTTPException(
            status_code=422,
            detail="Invalid case ID."
        )

    case = db.get_case(case_id)

    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found."
        )

    # 2. Validate the supplied filename.
    filename = file.filename or ""

    if (
        not filename
        or PureWindowsPath(filename).name != filename
        or PurePosixPath(filename).name != filename
        or not filename.lower().endswith(".evtx")
    ):
        raise HTTPException(
            status_code=400,
            detail="A valid EVTX filename is required."
        )

    # 3. Stream the upload into a temporary file.
    upload_dir = Path("data/uploads")
    upload_dir.mkdir(parents=True, exist_ok=True)

    temp_path = None
    sha256 = hashlib.sha256()
    total_size = 0

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=upload_dir,
            prefix=".evtx-upload-",
            delete=False
        ) as temporary:

            temp_path = Path(temporary.name)

            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="Evidence exceeds the 100 MiB limit."
                    )

                sha256.update(chunk)
                temporary.write(chunk)

        # 4. Check the EVTX file signature.
        with open(temp_path, "rb") as evidence:
            signature = evidence.read(8)

        if signature != EVTX_SIGNATURE:
            raise HTTPException(
                status_code=400,
                detail="Invalid Windows EVTX file signature."
            )

        # 5. Store the evidence under its SHA-256 hash.
        result = storage.store_evidence(
            case_id=case_id,
            source_path=str(temp_path)
        )

        if result["sha256"] != sha256.hexdigest():
            raise HTTPException(
                status_code=500,
                detail="Evidence integrity mismatch during storage."
            )

        # 6. Register metadata and audit the operation.
        inserted = db.add_evidence(
            case_id=case_id,
            sha256=result["sha256"],
            source_name=filename,
            byte_length=total_size,
            actor="local-analyst"
        )

        return {
            "case_id": case_id,
            "filename": filename,
            "sha256": result["sha256"],
            "byte_length": total_size,
            "status": result["status"],
            "registered": inserted
        }

    finally:
        await file.close()

        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

@app.get("/cases/{case_id}/evidence/{sha256}/verify")
def verify_evidence(case_id: str, sha256: str):
    """
    Recalculate the stored evidence SHA-256 hash
    and report whether its integrity is intact.
    """

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
        raise HTTPException(
            status_code=422,
            detail="Invalid case ID."
        )

    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        raise HTTPException(
            status_code=422,
            detail="Invalid SHA-256 hash."
        )

    evidence_records = db.get_evidence(case_id)

    registered = any(
        record["sha256"].lower() == sha256.lower()
        for record in evidence_records
    )

    if not registered:
        raise HTTPException(
            status_code=404,
            detail="Evidence not registered in this investigation."
        )

    integrity_ok = storage.verify_evidence(
        case_id=case_id,
        evidence_hash=sha256.lower()
    )

    db.log_action(
        actor="local-analyst",
        action="EVIDENCE_VERIFIED",
        object_id=f"{case_id}:{sha256.lower()}",
        details=(
            "PASS" if integrity_ok else "FAIL"
        )
    )

    return {
        "case_id": case_id,
        "sha256": sha256.lower(),
        "integrity_ok": integrity_ok,
        "status": (
            "verified" if integrity_ok else "integrity_failure"
        )
    }
@app.post("/cases/{case_id}/evidence/{sha256}/ingest")
def ingest_evidence(case_id: str, sha256: str):
    """
    Parse registered evidence and store normalized events.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
        raise HTTPException(
            status_code=422,
            detail="Invalid case ID."
        )

    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        raise HTTPException(
            status_code=422,
            detail="Invalid SHA-256."
        )

    if db.get_case(case_id) is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found."
        )

    sha256 = sha256.lower()

    registered = any(
        item["sha256"] == sha256
        for item in db.get_evidence(case_id)
    )

    if not registered:
        raise HTTPException(
            status_code=404,
            detail="Evidence not registered in this case."
        )

    service = EvidenceIngestionService(db, storage)

    try:
        result = service.ingest(case_id, sha256)

    except ValueError as error:
        # Current MVP: unsupported sources and integrity failures
        # are reported as conflicts rather than server errors.
        raise HTTPException(
            status_code=409,
            detail=str(error)
        ) from error

    return result
@app.get("/cases/{case_id}/timeline")
def get_case_timeline(
    case_id: str,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    start_utc: datetime | None = None,
    end_utc: datetime | None = None,
    event_type: str | None = None,
    evidence_sha256: str | None = None,
):
    """
    Retrieve a filtered, paginated forensic timeline.
    All time filters are converted to UTC.
    """

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
        raise HTTPException(
            status_code=422,
            detail="Invalid case ID."
        )

    if db.get_case(case_id) is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found."
        )

    def format_utc(value):
        if value is None:
            return None

        if value.tzinfo is None:
            raise HTTPException(
                status_code=422,
                detail="Timestamps must include a timezone."
            )

        return value.astimezone(timezone.utc).isoformat()

    start = format_utc(start_utc)
    end = format_utc(end_utc)

    if start is not None and end is not None and start >= end:
        raise HTTPException(
            status_code=422,
            detail="start_utc must be earlier than end_utc."
        )

    store = EventStore(db)

    try:
        return store.query_timeline(
            case_id=case_id,
            limit=limit,
            offset=offset,
            start_utc=start,
            end_utc=end,
            event_type=event_type,
            evidence_sha256=evidence_sha256,
        )
    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error
    """
    Retrieve a chronological forensic timeline.

    Pagination is applied after retrieving the events
    from SQLite in the current MVP implementation.
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
        raise HTTPException(
            status_code=422,
            detail="Invalid case ID."
        )

    if db.get_case(case_id) is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found."
        )

    if not 1 <= limit <= 1000:
        raise HTTPException(
            status_code=422,
            detail="Limit must be between 1 and 1000."
        )

    if offset < 0:
        raise HTTPException(
            status_code=422,
            detail="Offset must be non-negative."
        )

    store = EventStore(db)
    events = store.get_timeline(case_id)

    return {
        "case_id": case_id,
        "total_events": len(events),
        "limit": limit,
        "offset": offset,
        "events": events[offset:offset + limit],
    }
@app.get("/cases/{case_id}/evidence/{sha256}/events/{record_id}")
def get_evidence_event(
    case_id: str,
    sha256: str,
    record_id: int,
):
    """
    Retrieve a normalized event with evidence provenance.
    """

    store = EventStore(db)

    try:
        result = store.get_event(
            case_id=case_id,
            evidence_sha256=sha256,
            record_id=record_id,
        )

    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Event not found.",
        )

    # Check the original evidence file again.
    integrity_ok = storage.verify_evidence(
        case_id,
        sha256.lower(),
    )

    # Audit the evidence-integrity verification.
    db.log_action(
        actor="local-analyst",
        action="EVIDENCE_VERIFIED",
        object_id=f"{case_id}:{sha256.lower()}",
        details="PASS" if integrity_ok else "FAIL",
    )

    result["evidence"]["integrity_ok"] = integrity_ok

    return result


@app.get("/cases/{case_id}/events/{event_id}/raw")
def get_event_raw(case_id: str, event_id: str):
    """
    Return the original raw record behind a normalized event,
    with its custody hashes. Raw evidence reads are audited.
    """

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
        raise HTTPException(
            status_code=422,
            detail="Invalid case ID."
        )

    if not re.fullmatch(r"[a-fA-F0-9]{64}", event_id):
        raise HTTPException(
            status_code=422,
            detail="Invalid event ID."
        )

    if db.get_case(case_id) is None:
        raise HTTPException(
            status_code=404,
            detail="Investigation case not found."
        )

    event = EventStore(db).get_event_by_id(
        case_id,
        event_id.lower(),
    )

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Event not found."
        )

    raw_ref = event["provenance"]["raw_ref"]

    raw_record = RawRecordStore(db).get_raw_record(
        case_id,
        raw_ref,
    )

    if raw_record is None:
        raise HTTPException(
            status_code=404,
            detail="Raw record not found for this event."
        )

    db.log_action(
        actor="local-analyst",
        action="RAW_EVIDENCE_READ",
        object_id=f"{case_id}:{raw_ref}",
        details=raw_record["raw_hash"],
    )

    return {
        "case_id": case_id,
        "event_id": event["provenance"]["event_id"],
        "raw_ref": raw_ref,
        "evidence": {
            "sha256": raw_record["file_sha256"],
            "channel": raw_record["channel"],
            "record_number": raw_record["record_number"],
        },
        "raw_hash": raw_record["raw_hash"],
        "raw_xml": raw_record["raw_xml"],
    }