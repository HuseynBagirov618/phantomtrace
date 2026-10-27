import sys
from datetime import datetime, timezone

from phantomtrace.parsers.evtx_parser import parse_evtx


START = datetime(2026, 10, 16, tzinfo=timezone.utc)
END = datetime(2026, 10, 17, tzinfo=timezone.utc)

KEYWORDS = (
    "phantomtrace",
    "write-output",
)

matches = []

for event in parse_evtx(sys.argv[1]):

    if str(event["event_id"]) != "4104":
        continue

    if not event["timestamp"]:
        continue

    timestamp = datetime.fromisoformat(
        str(event["timestamp"]).replace("Z", "+00:00")
    )

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    if not START <= timestamp < END:
        continue

    fields = {
        item["name"]: item["value"]
        for item in event.get("event_data", [])
        if item.get("name")
    }

    script_text = fields.get("ScriptBlockText") or ""

    if not any(word in script_text.lower() for word in KEYWORDS):
        continue

    matches.append({
        "timestamp": timestamp.isoformat(),
        "record_id": event["record_id"],
        "script_block_id": fields.get("ScriptBlockId"),
        "message_number": fields.get("MessageNumber"),
        "message_total": fields.get("MessageTotal"),
        "script_text": script_text,
    })


print(f"\nFound {len(matches)} matching PowerShell 4104 records.\n")

for event in matches[:10]:
    print("=" * 65)
    print("Timestamp:", event["timestamp"])
    print("Record ID:", event["record_id"])
    print("ScriptBlock ID:", event["script_block_id"])
    print(
        "Fragment:",
        event["message_number"],
        "of",
        event["message_total"]
    )
    print("Script text:")
    print(event["script_text"][:1000])