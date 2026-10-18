import hashlib
import os
import re
import tempfile
from pathlib import Path


class EvidenceStorage:
    """Store and verify content-addressed forensic evidence."""

    def __init__(self, base_path: str = "data/cases"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def calculate_sha256(self, file_path: str) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def store_evidence(self, case_id: str, source_path: str) -> dict:
        """Stage, verify, and publish without replacing existing evidence.

        Hard-link publication requires a filesystem supporting hard links,
        such as local NTFS. Read-only attributes are not a security boundary.
        """
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
            raise ValueError("Invalid case ID")

        source = Path(source_path)
        if not source.is_file():
            raise FileNotFoundError(source_path)

        evidence_dir = self.base_path / case_id / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        temp_path = None
        published_new = False

        try:
            sha256 = hashlib.sha256()
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=evidence_dir, prefix=".upload-", delete=False
            ) as temp_file:
                temp_path = Path(temp_file.name)
                with source.open("rb") as original:
                    for chunk in iter(lambda: original.read(1024 * 1024), b""):
                        sha256.update(chunk)
                        temp_file.write(chunk)
                temp_file.flush()
                os.fsync(temp_file.fileno())

            evidence_hash = sha256.hexdigest()
            destination = evidence_dir / evidence_hash

            if self.calculate_sha256(str(temp_path)) != evidence_hash:
                raise ValueError("Staged evidence failed integrity verification")

            try:
                # Atomic publication with no overwrite on local NTFS.
                os.link(temp_path, destination)
                published_new = True
                status = "stored"
            except FileExistsError:
                status = "already_exists"

            if self.calculate_sha256(str(destination)) != evidence_hash:
                raise ValueError("Published evidence failed integrity verification")

            # Remove the temporary link *before* applying the Windows
            # read-only attribute shared by all hard links to the file.
            temp_path.unlink()
            temp_path = None

            if published_new:
                os.chmod(destination, 0o444)

            return {
                "case_id": case_id,
                "sha256": evidence_hash,
                "path": str(destination),
                "status": status,
            }
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

    def verify_evidence(self, case_id: str, evidence_hash: str) -> bool:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", case_id):
            raise ValueError("Invalid case ID")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", evidence_hash):
            raise ValueError("Invalid SHA-256 hash")

        evidence_path = self.base_path / case_id / "evidence" / evidence_hash.lower()
        if not evidence_path.is_file():
            return False
        return self.calculate_sha256(str(evidence_path)) == evidence_hash.lower()
