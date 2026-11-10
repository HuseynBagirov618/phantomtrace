from phantomtrace.normalization.common import (
    event_data_fields,
    missing_field,
    normalize_hex_identifier,
    normalize_text,
    normalize_timestamp,
)


SYSMON_EVENT_TYPES = {
    "1": "process_creation",
    "11": "file_creation",
}


def normalize_sysmon_event(event):
    """Normalize Sysmon Event IDs 1 and 11.

    GUIDs are the join keys; PIDs and image paths stay supporting evidence.
    Return None for unsupported events.
    """
    event_code = str(event["event_id"])

    if event_code not in SYSMON_EVENT_TYPES:
        return None

    fields = event_data_fields(event)

    timestamp = normalize_timestamp(event.get("timestamp"))
    process_guid = normalize_text(fields.get("ProcessGuid"))

    normalized = {
        "event_type": SYSMON_EVENT_TYPES[event_code],
        "event.code": event_code,
        "@timestamp": timestamp,
        "timestamp_original": event.get("timestamp"),
        "host.name": normalize_text(event.get("computer")),
        "winlog.channel": normalize_text(event.get("channel")),
        "winlog.provider_name": normalize_text(event.get("provider")),
        "winlog.record_id": normalize_text(event.get("record_id")),
        "process.entity_id": process_guid,
        "process.pid": normalize_text(fields.get("ProcessId")),
        "process.executable": normalize_text(fields.get("Image")),
        "process.user.name": normalize_text(fields.get("User")),
        "process.logon.id": normalize_hex_identifier(
            fields.get("LogonId")
        ),
        "winlog.event_data": fields,
    }

    warnings = []
    missing_field(warnings, "@timestamp", timestamp)
    missing_field(warnings, "process.entity_id", process_guid)

    if event_code == "1":
        parent_guid = normalize_text(
            fields.get("ParentProcessGuid")
        )

        normalized.update({
            "process.command_line": normalize_text(
                fields.get("CommandLine")
            ),
            "process.parent.entity_id": parent_guid,
            "process.parent.executable": normalize_text(
                fields.get("ParentImage")
            ),
            "process.parent.command_line": normalize_text(
                fields.get("ParentCommandLine")
            ),
        })

        missing_field(
            warnings, "process.parent.entity_id", parent_guid
        )

    elif event_code == "11":
        file_path = normalize_text(fields.get("TargetFilename"))

        normalized.update({
            "file.path": file_path,
            "file.creation_utc_time": normalize_text(
                fields.get("CreationUtcTime")
            ),
        })

        missing_field(warnings, "file.path", file_path)

    normalized["pt"] = {"parse_warnings": warnings}

    return normalized
