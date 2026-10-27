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

    assert result["outcome"] == "failure"
    assert result["source_ip"] == "192.168.14.128"
    assert result["logon_type_name"] == "Network"
    assert result["timestamp_utc"].endswith("+00:00")
    assert result["logon_id"] is None


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
            {"name": "TargetLogonId", "value": "0xc270da"},
        ],
    }

    result = normalize_auth_event(raw_event)

    assert result["outcome"] == "success"
    assert result["logon_type_name"] == "RemoteInteractive"
    assert result["logon_id"] == "0xc270da"


def test_unsupported_event():
    assert normalize_auth_event({
        "event_id": "4688"
    }) is None