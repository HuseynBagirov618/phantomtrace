import pytest

from phantomtrace.schema.identity import (
    build_event_id,
    raw_xml_hash,
    record_locator,
)


SHA256 = "a" * 64


def test_record_locator_scopes_by_file_channel_and_record():
    locator = record_locator(SHA256, "Security", 100)

    assert locator == f"{SHA256}:Security:100"

    # The same record number in another file or channel is different.
    assert record_locator("b" * 64, "Security", 100) != locator
    assert record_locator(
        SHA256, "Sysmon/Operational", 100
    ) != locator

    # Hashes are normalized to lowercase.
    assert record_locator("A" * 64, "Security", 100) == locator


def test_record_locator_rejects_invalid_input():
    with pytest.raises(ValueError):
        record_locator("not-a-hash", "Security", 100)

    with pytest.raises(ValueError):
        record_locator(SHA256, "", 100)

    with pytest.raises(ValueError):
        record_locator(SHA256, "Security", -1)


def test_event_id_is_deterministic():
    locator = record_locator(SHA256, "Security", 100)

    assert build_event_id(SHA256, locator) == build_event_id(
        SHA256, locator
    )


def test_event_id_changes_with_parser_version():
    locator = record_locator(SHA256, "Security", 100)

    assert build_event_id(
        SHA256, locator, parser_version="0.2.0"
    ) != build_event_id(SHA256, locator)


def test_event_id_changes_with_schema_version():
    locator = record_locator(SHA256, "Security", 100)

    assert build_event_id(
        SHA256, locator, schema_version="0.2.0"
    ) != build_event_id(SHA256, locator)


def test_event_id_rejects_invalid_hash():
    with pytest.raises(ValueError):
        build_event_id(
            "not-a-hash",
            record_locator(SHA256, "Security", 100),
        )


def test_raw_xml_hash_is_stable():
    raw_xml = "<Event><System /></Event>"

    assert raw_xml_hash(raw_xml) == raw_xml_hash(raw_xml)
    assert raw_xml_hash(raw_xml) != raw_xml_hash(
        raw_xml + " "
    )


def test_raw_xml_hash_rejects_empty():
    with pytest.raises(ValueError):
        raw_xml_hash("")

    with pytest.raises(ValueError):
        raw_xml_hash("   ")
