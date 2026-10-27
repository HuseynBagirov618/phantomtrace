from phantomtrace.normalization.auth import normalize_timestamp


def normalize_powershell_event(event):
    """
    Normalize PowerShell Event 4104.

    Each fragment remains a separate source record.
    Script block reconstruction happens in a later stage.
    """
    if str(event.get("event_id")) != "4104":
        return None

    fields = {
        item["name"]: item["value"]
        for item in event.get("event_data", [])
        if item.get("name")
    }

    script_text = fields.get("ScriptBlockText")

    def optional_integer(value):
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    return {
        "event_type": "powershell_script_block",
        "event_id": 4104,
        "timestamp_utc": normalize_timestamp(
            event.get("timestamp")
        ),
        "computer": event.get("computer"),
        "provider": event.get("provider"),
        "channel": event.get("channel"),
        "record_id": event.get("record_id"),
        "source_file": event.get("source_file"),
        "script_block_id": fields.get("ScriptBlockId"),
        "script_text": script_text,
        "message_number": optional_integer(
            fields.get("MessageNumber")
        ),
        "message_total": optional_integer(
            fields.get("MessageTotal")
        ),
        "script_path": fields.get("Path"),
        "is_fragmented": (
            optional_integer(fields.get("MessageTotal")) or 1
        ) > 1,
    }