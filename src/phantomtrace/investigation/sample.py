"""Synthetic observations for the demo and regression tests."""
from datetime import datetime, timedelta, timezone
import json
from xml.etree import ElementTree as ET

from phantomtrace.database.event_store import EventStore
from phantomtrace.database.raw_store import RawRecordStore
from phantomtrace.normalization.windows import normalize_windows_event
from phantomtrace.schema.identity import build_event_id, record_locator
from phantomtrace.schema.versions import PARSER_VERSION, SCHEMA_VERSION

SECURITY = "Security"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"
PROVIDERS = {SECURITY: "Microsoft-Windows-Security-Auditing", SYSMON: "Microsoft-Windows-Sysmon",
             POWERSHELL: "Microsoft-Windows-PowerShell"}
START = datetime(2026, 1, 1, tzinfo=timezone.utc)
DEMO_CONFIG = {"boot_ranges": [{"host": "DEMO-WS", "start": START.isoformat(),
                                "end": (START + timedelta(hours=1)).isoformat(),
                                "reference": "Synthetic demonstration interval"}], "verified_policy": {}}


def demo_records(scenario="indicator"):
    """Return inert sample records. No command is run to produce them."""
    records = []

    def record(channel, code, minute, fields):
        number = len(records) + 1
        timestamp = (START + timedelta(minutes=minute)).isoformat()
        root = ET.Element("Event")
        system = ET.SubElement(root, "System")
        ET.SubElement(system, "Provider", Name=PROVIDERS[channel])
        ET.SubElement(system, "EventID").text = str(code)
        ET.SubElement(system, "EventRecordID").text = str(number)
        ET.SubElement(system, "Channel").text = channel
        ET.SubElement(system, "Computer").text = "DEMO-WS"
        ET.SubElement(system, "TimeCreated", SystemTime=timestamp)
        data = ET.SubElement(root, "EventData")
        for name, value in fields.items():
            ET.SubElement(data, "Data", Name=name).text = value
        records.append({
            "event_id": str(code), "channel": channel, "provider": PROVIDERS[channel],
            "record_id": str(number), "computer": "DEMO-WS", "timestamp": timestamp,
            "event_data": [{"name": key, "value": value} for key, value in fields.items()],
            "raw_xml": ET.tostring(root, encoding="unicode"),
        })

    account = {"TargetUserName": "Taylor", "TargetDomainName": "DEMO",
               "IpAddress": "192.0.2.10", "LogonType": "10"}
    if scenario == "indicator":
        for minute in range(1, 6):
            record(SECURITY, 4625, minute, account)
    record(SECURITY, 4624, 6, account | {"TargetLogonId": "0x20"})
    image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    first = "11111111-1111-1111-1111-111111111111"
    second = "22222222-2222-2222-2222-222222222222"
    command = "powershell.exe -EncodedCommand U0FNUExF" if scenario != "benign" else "powershell.exe -NoProfile"
    record(SYSMON, 1, 7, {"Image": image, "CommandLine": command, "ProcessGuid": first,
                           "LogonId": "0x20", "User": "DEMO\\Taylor"})
    record(SYSMON, 11, 8, {"Image": image, "ProcessGuid": first,
                            "TargetFilename": r"C:\Users\Taylor\AppData\Local\Temp\example.txt"})
    record(SECURITY, 4698, 9, {"SubjectLogonId": "0x20", "SubjectUserName": "Taylor",
                               "SubjectDomainName": "DEMO", "TaskName": r"\Example Task"})
    record(POWERSHELL, 4104, 10, {"ScriptBlockText": "<img src=x onerror=alert(1)>",
                                  "ScriptBlockId": "33333333-3333-3333-3333-333333333333"})
    if scenario == "concurrent":
        record(SECURITY, 4624, 6, account | {"TargetLogonId": "0x21"})
        record(SYSMON, 1, 7, {"Image": image, "CommandLine": command, "ProcessGuid": second,
                              "LogonId": "0x21", "User": "DEMO\\Taylor", "ParentProcessGuid": first})
        for key, minute in ((first, 8), (second, 9)):
            record(SYSMON, 3, minute, {"ProcessGuid": key, "DestinationIp": "192.0.2.53", "DestinationPort": "53"})
    return records


def seed(db, storage, directory, case_id, scenario):
    """Create a labeled synthetic case with inspectable XML evidence."""
    directory.mkdir(parents=True, exist_ok=True)
    if not db.get_case(case_id):
        db.create_case(case_id, f"Synthetic demonstration · {scenario}",
                       "Generated XML observations for demonstration. These are synthetic records.")
    events, raw = EventStore(db), RawRecordStore(db)
    records = demo_records(scenario)
    for index, channel in enumerate(PROVIDERS):
        subset = [item for item in records if item["channel"] == channel]
        path = directory / f"synthetic-source-{index + 1}.xml"
        path.write_text("<Events>\n" + "\n".join(item["raw_xml"] for item in subset) + "\n</Events>", encoding="utf-8")
        digest = storage.store_evidence(case_id, path)["sha256"]
        db.add_evidence(case_id, digest, path.name, path.stat().st_size, "synthetic-demo")
        with db.connect() as conn:
            for item in subset:
                number = int(item["record_id"])
                raw.add_raw_record(case_id, digest, channel, number, item["raw_xml"], conn=conn)
                locator = record_locator(digest, channel, number)
                event = normalize_windows_event(item)
                event.update({"event_id": build_event_id(digest, locator), "raw_ref": locator,
                              "parser_version": PARSER_VERSION, "schema_version": SCHEMA_VERSION})
                events.add_event(case_id, digest, event, conn=conn)
        db.log_action("synthetic-demo", "EVIDENCE_INGESTED", f"{case_id}:{digest}",
                      json.dumps({"channels": [channel], "errors": []}))
