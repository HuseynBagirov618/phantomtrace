import sys
from pathlib import Path
from datetime import datetime, timezone

from phantomtrace.parsers.evtx_parser import parse_evtx
from phantomtrace.normalization.auth import normalize_auth_event
from phantomtrace.normalization.sysmon import normalize_sysmon_event
from phantomtrace.normalization.powershell import normalize_powershell_event


SOURCE_IP = "192.168.14.128"

START = datetime(2026, 10, 16, tzinfo=timezone.utc)
END = datetime(2026, 10, 17, tzinfo=timezone.utc)

# Confirmed Scenario M artifacts from our earlier investigation.
SYSMON_RECORDS = {"5718", "5750", "5752", "5753"}

POWERSHELL_RECORDS = {"488", "492", "527"}


def within_window(event):
    value = event.get("timestamp_utc")

    if not value:
        return False

    timestamp = datetime.fromisoformat(value)

    return START <= timestamp < END


def describe(event):
    event_type = event["event_type"]

    if event_type == "authentication":
        return (
            f"{event['outcome'].upper()} "
            f"user={event['username']} "
            f"ip={event['source_ip']} "
            f"logon_type={event['logon_type']}"
        )

    if event_type == "process_creation":
        return (
            f"PROCESS image={event.get('image')} "
            f"pid={event.get('process_id')}"
        )

    if event_type == "file_creation":
        return (
            f"FILE target={event.get('target_filename')}"
        )

    if event_type == "powershell_script_block":
        text = event.get("script_text") or ""
        preview = " ".join(text.split())[:120]

        return f"SCRIPT {preview}"

    return event_type


def build_timeline(folder):
    folder = Path(folder)
    timeline = []

    sources = [
        (
            "Security.evtx",
            normalize_auth_event
        ),
        (
            "Sysmon.evtx",
            normalize_sysmon_event
        ),
        (
            "PowerShell.evtx",
            normalize_powershell_event
        ),
    ]

    for filename, normalizer in sources:
        path = folder / filename

        if not path.is_file():
            raise FileNotFoundError(path)

        for raw in parse_evtx(str(path)):
            event = normalizer(raw)

            if event is None or not within_window(event):
                continue

            record_id = str(event["record_id"])

            if filename == "Security.evtx":
                if event["source_ip"] != SOURCE_IP:
                    continue

            elif filename == "Sysmon.evtx":
                if record_id not in SYSMON_RECORDS:
                    continue

            elif filename == "PowerShell.evtx":
                if record_id not in POWERSHELL_RECORDS:
                    continue

            timeline.append(event)

    timeline.sort(
        key=lambda event: (
            event["timestamp_utc"],
            event["source_file"],
            int(event["record_id"])
        )
    )

    return timeline


if __name__ == "__main__":
    folder = sys.argv[1]

    timeline = build_timeline(folder)

    print(f"\nUnified timeline: {len(timeline)} events\n")

    for event in timeline:
        print(
            f"{event['timestamp_utc']} | "
            f"{event['source_file']:<16} | "
            f"ID {event['event_id']:<4} | "
            f"Record {event['record_id']:<5} | "
            f"{describe(event)}"
        )