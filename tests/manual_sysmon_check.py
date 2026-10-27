import sys

from phantomtrace.parsers.evtx_parser import parse_evtx


TARGET_IDS = {"1", "11"}
MAX_PER_TYPE = 2

counts = {"1": 0, "11": 0}

IMPORTANT_FIELDS = {
    "1": [
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "CommandLine",
        "ParentProcessGuid",
        "ParentImage",
        "User",
        "LogonGuid",
        "LogonId",
    ],
    "11": [
        "UtcTime",
        "ProcessGuid",
        "ProcessId",
        "Image",
        "TargetFilename",
        "CreationUtcTime",
        "User",
    ],
}


for event in parse_evtx(sys.argv[1]):
    event_id = str(event["event_id"])

    if event_id not in TARGET_IDS:
        continue

    if counts[event_id] >= MAX_PER_TYPE:
        continue

    fields = {
        item["name"]: item["value"]
        for item in event.get("event_data", [])
        if item.get("name")
    }

    print("\n" + "=" * 65)
    print("Sysmon Event ID:", event_id)
    print("Record ID:", event["record_id"])
    print("Timestamp:", event["timestamp"])
    print("Computer:", event["computer"])

    print("\nEvent details:")

    for name in IMPORTANT_FIELDS[event_id]:
        if name in fields:
            print(f"  {name}: {fields[name]}")

    counts[event_id] += 1

    if all(counts[event_type] >= MAX_PER_TYPE for event_type in TARGET_IDS):
        break


print("\nRecords displayed:", counts)