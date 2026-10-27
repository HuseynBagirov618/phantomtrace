import sys
from datetime import datetime, timezone

from phantomtrace.parsers.evtx_parser import parse_evtx
from phantomtrace.normalization.auth import normalize_auth_event


SOURCE_IP = "192.168.14.128"

START = datetime(2026, 10, 16, tzinfo=timezone.utc)
END = datetime(2026, 10, 17, tzinfo=timezone.utc)


def build_timeline(file_path):
    timeline = []

    for raw_event in parse_evtx(file_path):
        event = normalize_auth_event(raw_event)

        if event is None:
            continue

        if event["source_ip"] != SOURCE_IP:
            continue

        if not event["timestamp_utc"]:
            continue

        timestamp = datetime.fromisoformat(
            event["timestamp_utc"]
        )

        if not START <= timestamp < END:
            continue

        timeline.append(event)

    return sorted(
        timeline,
        key=lambda event: (
            event["timestamp_utc"],
            int(event["record_id"])
        )
    )


if __name__ == "__main__":
    timeline = build_timeline(sys.argv[1])

    print(f"\nAuthentication events found: {len(timeline)}\n")

    for event in timeline:
        print(
            f"{event['timestamp_utc']} | "
            f"{event['outcome'].upper():7} | "
            f"ID {event['event_id']} | "
            f"Type {event['logon_type']:>2} | "
            f"{event['username']} | "
            f"Record {event['record_id']}"
        )