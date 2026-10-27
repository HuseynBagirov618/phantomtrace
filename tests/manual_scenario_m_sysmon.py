import sys
from datetime import datetime, timezone

from phantomtrace.parsers.evtx_parser import parse_evtx
from phantomtrace.normalization.sysmon import normalize_sysmon_event


START = datetime(2026, 10, 16, tzinfo=timezone.utc)
END = datetime(2026, 10, 17, tzinfo=timezone.utc)

KEYWORDS = (
    "phantomtrace",
    "encodedcommand",
    "-enc ",
    "schtasks.exe",
)

matches = []

for raw_event in parse_evtx(sys.argv[1]):
    event = normalize_sysmon_event(raw_event)

    if event is None or not event["timestamp_utc"]:
        continue

    timestamp = datetime.fromisoformat(event["timestamp_utc"])

    if not START <= timestamp < END:
        continue

    # Search only investigation-relevant fields,
    # not every field in the normalized event.
    searchable_text = " ".join(
    str(event.get(field) or "").lower()
    for field in (
        "command_line",
        "target_filename",
        "image",
    )
)

    if not any(word in searchable_text for word in KEYWORDS):
        continue

    matches.append(event)


matches.sort(
    key=lambda event: (
        event["timestamp_utc"],
        int(event["record_id"])
    )
)

print(f"\nFound {len(matches)} matching Sysmon events.\n")

for event in matches:
    print("=" * 70)
    print("Timestamp:", event["timestamp_utc"])
    print("Event ID:", event["event_id"])
    print("Event type:", event["event_type"])
    print("Record ID:", event["record_id"])
    print("Process GUID:", event.get("process_guid"))
    print("Process ID:", event.get("process_id"))
    print("Image:", event.get("image"))

    if event["event_type"] == "process_creation":
        print("Command line:", event.get("command_line"))
        print("Parent process:", event.get("parent_image"))
        print("Parent GUID:", event.get("parent_process_guid"))
        print("Logon ID:", event.get("logon_id"))

    elif event["event_type"] == "file_creation":
        print("Target file:", event.get("target_filename"))