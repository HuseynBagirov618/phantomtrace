from phantomtrace.normalization.auth import normalize_timestamp


SYSMON_EVENT_TYPES = {
    "1": "process_creation",
    "11": "file_creation",
}


def normalize_sysmon_event(event):
    """
    Normalize Sysmon Event IDs 1 and 11.

    Preserve process identifiers and source provenance.
    Return None for unsupported events.
    """

    event_id = str(event["event_id"])

    if event_id not in SYSMON_EVENT_TYPES:
        return None

    fields = {
        item["name"]: item["value"]
        for item in event.get("event_data", [])
        if item.get("name")
    }

    normalized = {
        "event_type": SYSMON_EVENT_TYPES[event_id],
        "event_id": int(event_id),
        "timestamp_utc": normalize_timestamp(
            event.get("timestamp")
        ),
        "computer": event.get("computer"),
        "provider": event.get("provider"),
        "channel": event.get("channel"),
        "record_id": event.get("record_id"),
        "source_file": event.get("source_file"),
        "process_guid": fields.get("ProcessGuid"),
        "process_id": fields.get("ProcessId"),
        "image": fields.get("Image"),
        "user": fields.get("User"),
    }

    if event_id == "1":
        normalized.update({
            "command_line": fields.get("CommandLine"),
            "parent_process_guid": fields.get(
                "ParentProcessGuid"
            ),
            "parent_image": fields.get("ParentImage"),
            "parent_command_line": fields.get(
                "ParentCommandLine"
            ),
            "logon_guid": fields.get("LogonGuid"),
            "logon_id": fields.get("LogonId"),
        })

    elif event_id == "11":
        normalized.update({
            "target_filename": fields.get("TargetFilename"),
            "creation_utc_time": fields.get(
                "CreationUtcTime"
            ),
        })

    return normalized