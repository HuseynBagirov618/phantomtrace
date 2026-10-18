import re
import sqlite3
import hashlib
import tempfile

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
