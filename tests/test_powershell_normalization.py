from phantomtrace.normalization.powershell import (
    normalize_powershell_event,
)


def make_event(event_id="4104", message_number="1",
               message_total="1"):
    return {
        "event_id": event_id,
        "record_id": "492",
        "timestamp": "2026-10-16 20:23:24.892498",
        "computer": "DESKTOP-N99TDNI",
        "provider": "Microsoft-Windows-PowerShell",
        "channel": "Microsoft-Windows-PowerShell/Operational",
        "source_file": "PowerShell.evtx",
        "event_data": [
            {
                "name": "ScriptBlockText",
                "value": 'Write-Output "PhantomTrace Scenario M Encoded Test"'
            },
            {
                "name": "ScriptBlockId",
                "value": "dc0c8444-fa32-4bbb-98e9-14355340453d"
            },
            {
                "name": "MessageNumber",
                "value": message_number
            },
            {
                "name": "MessageTotal",
                "value": message_total
            },
        ],
    }


def test_script_block_normalization():
    result = normalize_powershell_event(make_event())

    assert result["event_type"] == "powershell_script_block"
    assert result["event_id"] == 4104
    assert "PhantomTrace Scenario M" in result["script_text"]
    assert result["record_id"] == "492"
    assert result["timestamp_utc"].endswith("+00:00")
    assert result["is_fragmented"] is False


def test_fragmented_script_block():
    result = normalize_powershell_event(
        make_event(message_number="2", message_total="3")
    )

    assert result["message_number"] == 2
    assert result["message_total"] == 3
    assert result["is_fragmented"] is True


def test_unsupported_event():
    assert normalize_powershell_event(
        make_event(event_id="400")
    ) is None


def test_missing_optional_fields():
    event = make_event()
    event["event_data"] = []

    result = normalize_powershell_event(event)

    assert result["script_text"] is None
    assert result["script_block_id"] is None
    assert result["message_number"] is None