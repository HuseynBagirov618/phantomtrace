from phantomtrace.normalization.common import (
    event_data_fields,
    missing_field,
    normalize_hex_identifier,
    normalize_ip,
    normalize_text,
    normalize_timestamp,
)


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


def normalize_auth_event(event):
    """Normalize Windows Security events 4624 and 4625.

    Returns None for unsupported event IDs. The global event ID is a
    number; the record identity hash is added by the ingestion service.
    """
    event_code = str(event["event_id"])

    if event_code not in ("4624", "4625"):
        return None

    fields = event_data_fields(event)

    timestamp = normalize_timestamp(event.get("timestamp"))
    logon_id = normalize_hex_identifier(fields.get("TargetLogonId"))
    logon_type = normalize_text(fields.get("LogonType"))
    source_ip = normalize_ip(fields.get("IpAddress"))
    username = normalize_text(fields.get("TargetUserName"))

    warnings = []
    missing_field(warnings, "@timestamp", timestamp)
    missing_field(warnings, "winlog.logon.id", logon_id)
    missing_field(warnings, "user.name", username)

    return {
        "event_type": "authentication",
        "event.code": event_code,
        "event.outcome": (
            "success" if event_code == "4624" else "failure"
        ),
        "@timestamp": timestamp,
        "timestamp_original": event.get("timestamp"),
        "host.name": normalize_text(event.get("computer")),
        "winlog.channel": normalize_text(event.get("channel")),
        "winlog.provider_name": normalize_text(event.get("provider")),
        "winlog.record_id": normalize_text(event.get("record_id")),
        "winlog.logon.id": logon_id,
        "winlog.logon.type": logon_type,
        "winlog.logon.type_name": LOGON_TYPES.get(
            logon_type, "Unknown"
        ),
        "source.ip": source_ip,
        "user.name": username,
        "user.domain": normalize_text(fields.get("TargetDomainName")),
        "error.code": normalize_text(fields.get("Status")),
        "error.substatus": normalize_text(fields.get("SubStatus")),
        "winlog.event_data": fields,
        "pt": {"parse_warnings": warnings},
    }
