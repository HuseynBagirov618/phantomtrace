from datetime import datetime, timezone


LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}


def normalize_timestamp(value):
    """
    Normalize a UTC EVTX timestamp into ISO 8601.

    The current parser provides timestamps without a
    timezone suffix. EVTX SystemTime is defined in UTC.
    """
    if value is None:
        return None

    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc).isoformat()


def normalize_auth_event(event):
    """
    Normalize Windows Security events 4624 and 4625.

    Returns None for unsupported event IDs.
    """

    event_id = str(event["event_id"])

    if event_id not in ("4624", "4625"):
        return None

    fields = {
        item["name"]: item["value"]
        for item in event.get("event_data", [])
        if item.get("name")
    }

    logon_type = fields.get("LogonType")

    source_ip = fields.get("IpAddress")

    if source_ip in ("-", "", None):
        source_ip = None

    return {
        "event_type": "authentication",
        "event_id": int(event_id),
        "outcome": (
            "success" if event_id == "4624"
            else "failure"
        ),
        "timestamp_utc": normalize_timestamp(
            event["timestamp"]
        ),
        "computer": event["computer"],
        "provider": event["provider"],
        "channel": event["channel"],
        "record_id": event["record_id"],
        "source_file": event["source_file"],
        "username": fields.get("TargetUserName"),
        "domain": fields.get("TargetDomainName"),
        "source_ip": source_ip,
        "logon_type": logon_type,
        "logon_type_name": LOGON_TYPES.get(
            logon_type, "Unknown"
        ),
        "logon_id": fields.get("TargetLogonId"),
        "status_code": fields.get("Status"),
        "substatus_code": fields.get("SubStatus"),
    }