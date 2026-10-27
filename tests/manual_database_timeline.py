from collections import Counter
from datetime import datetime, timezone

from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.database.event_store import EventStore


CASE_ID = "PT-SCENARIO-M"
SOURCE_IP = "192.168.14.128"

START = datetime(2026, 10, 16, tzinfo=timezone.utc)
END = datetime(2026, 10, 17, tzinfo=timezone.utc)

SYSMON_RECORDS = {"5718", "5750", "5752", "5753"}
POWERSHELL_RECORDS = {"488", "492", "527"}

db = PhantomTraceDB()
store = EventStore(db)

timeline = store.get_timeline(CASE_ID)
# Resolve original filenames using registered evidence hashes.
evidence_names = {
    record["sha256"]: record["source_name"]
    for record in db.get_evidence(CASE_ID)
}

print(f"Total stored events: {len(timeline)}")

selected = []

for event in timeline:
    timestamp_text = event.get("timestamp_utc")

    if not timestamp_text:
        continue

    timestamp = datetime.fromisoformat(timestamp_text)

    if not START <= timestamp < END:
        continue

    source = evidence_names.get(event["evidence_sha256"])
    record_id = str(event.get("record_id"))

    if source == "Security.evtx":
        if (
            event.get("event_type") != "authentication"
            or event.get("source_ip") != SOURCE_IP
        ):
            continue

    elif source == "Sysmon.evtx":
        if record_id not in SYSMON_RECORDS:
            continue

    elif source == "PowerShell.evtx":
        if record_id not in POWERSHELL_RECORDS:
            continue

    else:
        continue

    event["source_file"] = source
    selected.append(event)


selected.sort(
    key=lambda event: (
        event["timestamp_utc"],
        event["evidence_sha256"],
        int(event["record_id"]),
    )
)

print(f"Scenario M selected events: {len(selected)}")

counts = Counter(
    event["source_file"]
    for event in selected
)

print("\nEvents by source:")

for source, count in sorted(counts.items()):
    print(f"  {source}: {count}")

print("\nUnified timeline:\n")

for event in selected:
    event_type = event["event_type"]

    if event_type == "authentication":
        detail = (
            f"{event['outcome'].upper()} "
            f"user={event['username']} "
            f"ip={event['source_ip']} "
            f"logon_type={event['logon_type']}"
        )

    elif event_type == "process_creation":
        detail = (
            f"PROCESS image={event.get('image')} "
            f"pid={event.get('process_id')}"
        )

    elif event_type == "file_creation":
        detail = (
            f"FILE target={event.get('target_filename')}"
        )

    elif event_type == "powershell_script_block":
        script = event.get("script_text") or ""
        preview = " ".join(script.split())[:100]
        detail = f"SCRIPT {preview}"

    else:
        detail = event_type

    print(
        f"{event['timestamp_utc']} | "
        f"{event['source_file']:<16} | "
        f"ID {event['event_id']:<4} | "
        f"Record {event['record_id']:<5} | "
        f"{detail}"
    )