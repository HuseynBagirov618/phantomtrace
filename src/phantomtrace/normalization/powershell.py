from phantomtrace.normalization.common import (
    event_data_fields,
    missing_field,
    normalize_text,
    normalize_timestamp,
)


def normalize_powershell_event(event):
    """Normalize PowerShell Event 4104.

    Each fragment remains a separate source record.
    Script block reconstruction happens in a later stage.
    """
    if str(event.get("event_id")) != "4104":
        return None

    fields = event_data_fields(event)

    timestamp = normalize_timestamp(event.get("timestamp"))
    script_text = normalize_text(fields.get("ScriptBlockText"))
    script_block_id = normalize_text(fields.get("ScriptBlockId"))

    def optional_integer(value):
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    message_number = optional_integer(fields.get("MessageNumber"))
    message_total = optional_integer(fields.get("MessageTotal"))

    warnings = []
    missing_field(warnings, "@timestamp", timestamp)
    missing_field(warnings, "powershell.script_text", script_text)
    missing_field(
        warnings, "powershell.script_block_id", script_block_id
    )

    return {
        "event_type": "powershell_script_block",
        "event.code": "4104",
        "@timestamp": timestamp,
        "timestamp_original": event.get("timestamp"),
        "host.name": normalize_text(event.get("computer")),
        "winlog.channel": normalize_text(event.get("channel")),
        "winlog.provider_name": normalize_text(event.get("provider")),
        "winlog.record_id": normalize_text(event.get("record_id")),
        "powershell.script_block_id": script_block_id,
        "powershell.script_text": script_text,
        "powershell.message_number": message_number,
        "powershell.message_total": message_total,
        "powershell.script_path": normalize_text(fields.get("Path")),
        "powershell.fragmented": (message_total or 1) > 1,
        "winlog.event_data": fields,
        "pt": {"parse_warnings": warnings},
    }
