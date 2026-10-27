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
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -NoProfile",
        "ParentProcessGuid": "{parent-001}",
        "User": r"TEST-VM\Stark",
        "LogonId": "0x1e169",
    })

    result = normalize_sysmon_event(event)

    assert result["event_type"] == "process_creation"
    assert result["process_guid"] == "{process-001}"
    assert result["parent_process_guid"] == "{parent-001}"
    assert result["command_line"] == "powershell.exe -NoProfile"
    assert result["logon_id"] == "0x1e169"


def test_file_creation():
    event = make_event(11, {
        "ProcessGuid": "{process-001}",
        "ProcessId": "4992",
        "Image": "powershell.exe",
        "TargetFilename": r"C:\Users\Stark\Downloads\test.cmd",
        "CreationUtcTime": "2026-10-16 20:00:01.000",
    })

    result = normalize_sysmon_event(event)

    assert result["event_type"] == "file_creation"
    assert result["target_filename"].endswith("test.cmd")
    assert result["creation_utc_time"] == "2026-10-16 20:00:01.000"
    

def test_unsupported_event():
    event = make_event(3, {})

    assert normalize_sysmon_event(event) is None


def test_missing_optional_fields():
    event = make_event(1, {
        "ProcessGuid": "{process-002}"
    })

    result = normalize_sysmon_event(event)

    assert result["process_guid"] == "{process-002}"
    assert result["command_line"] is None
    assert result["parent_process_guid"] is None