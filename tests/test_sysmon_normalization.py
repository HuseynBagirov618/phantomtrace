from phantomtrace.normalization.sysmon import (
    normalize_sysmon_event,
)


def make_event(event_id, data):
    return {
        "event_id": str(event_id),
        "record_id": "100",
        "timestamp": "2026-10-16 20:00:00.000000",
        "computer": "TEST-VM",
        "provider": "Microsoft-Windows-Sysmon",
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "source_file": "Sysmon.evtx",
        "event_data": [
            {"name": key, "value": value}
            for key, value in data.items()
        ],
    }


def test_process_creation():
    event = make_event(1, {
        "ProcessGuid": "{process-001}",
        "ProcessId": "4992",
        "Image": (
            r"C:\Windows\System32\WindowsPowerShell\v1.0"
            r"\powershell.exe"
        ),
        "CommandLine": "powershell.exe -NoProfile",
        "ParentProcessGuid": "{parent-001}",
        "ParentImage": r"C:\Windows\explorer.exe",
        "User": r"TEST-VM\Stark",
        "LogonId": "0x1E169",
    })

    result = normalize_sysmon_event(event)

    assert result["event_type"] == "process_creation"
    assert result["event.code"] == "1"
    assert result["process.entity_id"] == "{process-001}"
    assert result["process.parent.entity_id"] == (
        "{parent-001}"
    )
    assert result["process.command_line"] == (
        "powershell.exe -NoProfile"
    )
    assert result["process.parent.executable"].endswith(
        "explorer.exe"
    )
    # Sysmon LogonId is a scoped hex key.
    assert result["process.logon.id"] == "0x1e169"
    assert result["winlog.record_id"] == "100"
    assert result["pt"]["parse_warnings"] == []


def test_file_creation():
    event = make_event(11, {
        "ProcessGuid": "{process-001}",
        "ProcessId": "4992",
        "Image": "powershell.exe",
        "TargetFilename": (
            r"C:\Users\Stark\AppData\Local\Temp\test.cmd"
        ),
        "CreationUtcTime": "2026-10-16 20:00:01.000",
    })

    result = normalize_sysmon_event(event)

    assert result["event_type"] == "file_creation"
    assert result["event.code"] == "11"
    assert result["file.path"].endswith("test.cmd")
    assert result["file.creation_utc_time"] == (
        "2026-10-16 20:00:01.000"
    )


def test_unsupported_event():
    event = make_event(3, {})

    assert normalize_sysmon_event(event) is None


def test_missing_optional_fields():
    event = make_event(1, {
        "ProcessGuid": "{process-002}"
    })

    result = normalize_sysmon_event(event)

    assert result["process.entity_id"] == "{process-002}"
    assert result["process.command_line"] is None
    assert result["process.parent.entity_id"] is None
    assert (
        "missing field: process.parent.entity_id"
        in result["pt"]["parse_warnings"]
    )
