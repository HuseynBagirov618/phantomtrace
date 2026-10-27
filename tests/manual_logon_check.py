import sys

from phantomtrace.parsers.evtx_parser import parse_evtx


file_path = sys.argv[1]

for event in parse_evtx(file_path):
    if event["event_id"] == "4625":
        print("FAILED LOGON DETECTED")
        print("Record ID:", event["record_id"])
        print("Timestamp:", event["timestamp"])
        print("Computer:", event["computer"])

        print("\nEvent details:")

        for field in event["event_data"]:
            print(f"  {field['name']}: {field['value']}")

        break
else:
    print("No Event ID 4625 found.")