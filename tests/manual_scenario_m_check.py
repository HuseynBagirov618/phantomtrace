import sys

from phantomtrace.parsers.evtx_parser import parse_evtx


SOURCE_IP = "192.168.14.128"

file_path = sys.argv[1]

matches = []

for event in parse_evtx(file_path):

    if event["event_id"] not in ("4624", "4625"):
        continue

    fields = {
        item["name"]: item["value"]
        for item in event["event_data"]
        if item["name"]
    }

    ip_address = fields.get("IpAddress", "")

    if ip_address != SOURCE_IP:
        continue

    matches.append({
        "record_id": event["record_id"],
        "timestamp": event["timestamp"],
        "event_id": event["event_id"],
        "username": fields.get("TargetUserName"),
        "logon_type": fields.get("LogonType"),
        "source_ip": ip_address,
        "logon_id": fields.get("TargetLogonId"),
    })


print(f"\nFound {len(matches)} authentication events from {SOURCE_IP}\n")

for event in matches:
    status = (
        "SUCCESS" if event["event_id"] == "4624"
        else "FAILED"
    )

    print("-" * 65)
    print("Status:", status)
    print("Record ID:", event["record_id"])
    print("Timestamp:", event["timestamp"])
    print("Username:", event["username"])
    print("Logon type:", event["logon_type"])
    print("Source IP:", event["source_ip"])
    print("Logon ID:", event["logon_id"])