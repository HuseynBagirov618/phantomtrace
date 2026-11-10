import hashlib
import re

from phantomtrace.schema.versions import PARSER_VERSION, SCHEMA_VERSION


SHA256_PATTERN = re.compile(r"[a-fA-F0-9]{64}")


def record_locator(
    file_sha256: str,
    channel: str,
    record_number: int,
) -> str:
    """Build the locator for one raw record inside one evidence file.

    A record number alone is not unique across files, so the locator
    always carries the file hash and the channel.
    """
    if not SHA256_PATTERN.fullmatch(str(file_sha256)):
        raise ValueError("Invalid file SHA-256")

    channel_name = str(channel).strip()

    if not channel_name:
        raise ValueError("Invalid channel")

    number = int(record_number)

    if number < 0:
        raise ValueError("Invalid record number")

    return f"{str(file_sha256).lower()}:{channel_name}:{number}"


def build_event_id(
    file_sha256: str,
    locator: str,
    parser_version: str = PARSER_VERSION,
    schema_version: str = SCHEMA_VERSION,
) -> str:
    """Derive the deterministic event ID from custody and version inputs.

    event_id = sha256(file sha256, record locator, parser version,
    schema version), so re-importing the same record at the same parser
    version always produces the same identity.
    """
    if not SHA256_PATTERN.fullmatch(str(file_sha256)):
        raise ValueError("Invalid file SHA-256")

    for name, value in (
        ("record locator", locator),
        ("parser version", parser_version),
        ("schema version", schema_version),
    ):
        if value is None or not str(value).strip():
            raise ValueError(f"Invalid {name}")

    material = "|".join(
        [
            str(file_sha256).lower(),
            str(locator),
            str(parser_version),
            str(schema_version),
        ]
    )

    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def raw_xml_hash(raw_xml: str) -> str:
    """Hash the exact stored raw record XML so a read can be verified."""
    if raw_xml is None or not str(raw_xml).strip():
        raise ValueError("Raw record XML is empty")

    return hashlib.sha256(str(raw_xml).encode("utf-8")).hexdigest()
