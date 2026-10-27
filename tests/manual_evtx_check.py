import sys

from phantomtrace.parsers.evtx_parser import parse_evtx


file_path = sys.argv[1]

for event in parse_evtx(file_path, limit=5):
    print("-" * 60)

    print("Event ID:", event["event_id"])
    print("Record ID:", event["record_id"])
    print("Timestamp:", event["timestamp"])
    print("Provider:", event["provider"])
    print("Channel:", event["channel"])
    print("Computer:", event["computer"])