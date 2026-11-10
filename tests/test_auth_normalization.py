from phantomtrace.normalization.auth import (
    normalize_auth_event,
)


def test_failed_rdp_authentication():
    raw_event = {
        "event_id": "4625",
        "record_id": "100",
        "timestamp": "2026-10-16 19:09:26.775558",
        "computer": "TEST-VM",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "source_file": "Security.evtx",
        "event_data": [
            {"name": "TargetUserName", "value": "Stark"},
            {"name": "IpAddress", "value": "192.168.14.128"},
            {"name": "LogonType", "value": "3"},
            {"name": "Status", "value": "0xc000006d"},
        ],
    }

    result = normalize_auth_event(raw_event)

    assert result["event.code"] == "4625"
    assert result["event.outcome"] == "failure"
    assert result["source.ip"] == "192.168.14.128"
    assert result["winlog.logon.type"] == "3"
    assert result["winlog.logon.type_name"] == "Network"
    assert result["@timestamp"].endswith("+00:00")
    assert result["timestamp_original"] == (
        "2026-10-16 19:09:26.775558"
    )
    assert result["host.name"] == "TEST-VM"
    assert result["winlog.channel"] == "Security"
    assert result["winlog.record_id"] == "100"
    assert result["winlog.logon.id"] is None
    assert "missing field: winlog.logon.id" in (
        result["pt"]["parse_warnings"]
    )


def test_successful_rdp_authentication():
    raw_event = {
        "event_id": "4624",
        "record_id": "101",
        "timestamp": "2026-10-16 19:33:37.335949",
        "computer": "TEST-VM",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "source_file": "Security.evtx",
        "event_data": [
            {"name": "TargetUserName", "value": "Stark"},
            {"name": "IpAddress", "value": "192.168.14.128"},
            {"name": "LogonType", "value": "10"},
            {"name": "TargetLogonId", "value": "0xC270DA"},
        ],
    }

    result = normalize_auth_event(raw_event)

    assert result["event.code"] == "4624"
    assert result["event.outcome"] == "success"
    assert result["winlog.logon.type_name"] == (
        "RemoteInteractive"
    )
    # LogonId is a scoped key, so it is normalized to lowercase hex.
    assert result["winlog.logon.id"] == "0xc270da"
    assert result["pt"]["parse_warnings"] == []


def test_unrecognized_event_data_is_preserved():
    raw_event = {
        "event_id": "4625",
        "record_id": "102",
        "timestamp": "2026-10-16 19:10:00.000000",
        "computer": "TEST-VM",
        "provider": "Microsoft-Windows-Security-Auditing",
        "channel": "Security",
        "source_file": "Security.evtx",
        "event_data": [
            {"name": "TargetUserName", "value": "Stark"},
            {"name": "IpPort", "value": "49712"},
            {"name": "UnmappedField", "value": "kept"},
        ],
    }

    result = normalize_auth_event(raw_event)

    assert result["winlog.event_data"]["IpPort"] == "49712"
    assert result["winlog.event_data"]["UnmappedField"] == "kept"


def test_unsupported_event():
    assert normalize_auth_event({
        "event_id": "4688"
    }) is None
