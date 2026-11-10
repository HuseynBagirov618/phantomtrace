from datetime import datetime, timezone


def normalize_timestamp(value):
    """Normalize a UTC EVTX timestamp into ISO 8601.

    EVTX SystemTime is defined in UTC. The original string is kept
    beside the normalized value by each normalizer.
    """
    if value is None:
        return None

    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc).isoformat()


def event_data_fields(event):
    """Return every EventData field so unrecognized values are never dropped."""
    return {
        item["name"]: item["value"]
        for item in event.get("event_data") or []
        if item.get("name")
    }


def normalize_text(value):
    if value is None:
        return None

    text = str(value)

    return text if text.strip() else None


def normalize_hex_identifier(value):
    """Lowercase a Windows hex identifier; '-' and blanks mean absent."""
    text = normalize_text(value)

    if text is None or text == "-":
        return None

    return text.lower()


def normalize_ip(value):
    text = normalize_text(value)

    if text is None or text == "-":
        return None

    return text


def missing_field(warnings, field_name, value):
    if value is None:
        warnings.append(f"missing field: {field_name}")
