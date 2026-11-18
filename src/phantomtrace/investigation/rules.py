"""Native indicators evaluated against already collected Windows logs."""
from collections import defaultdict, deque
from datetime import timedelta
from ipaddress import ip_address
import re
from pathlib import PureWindowsPath

from phantomtrace.investigation.graph import stable_id, text, time

VERSION = "1.0.0"
ATTACK_RELEASE = "17.1"
# Mappings describe observed behavior. They do not assert malicious intent.
TECHNIQUES = {"PT-PS-ENC-001": ["T1059.001"], "PT-TASK-001": ["T1053.005"]}
ENCODED = "PT-PS-ENC-001"
BURST = "PT-AUTH-FAIL-BURST-001"
TEMP = "PT-FILE-TEMP-001"
TASK = "PT-TASK-001"
CHAIN = "PT-CHAIN-AUTH-PS-001"
FAILURE_THRESHOLD = 5
FAILURE_WINDOW = timedelta(minutes=5)
CHAIN_WINDOW = timedelta(minutes=15)
POWERSHELL = {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}
ENCODED_SWITCH = re.compile(r'(?:^|\s)["\']?-(?:e|ec|enc|encodedcommand)["\']?\s+["\']?[A-Za-z0-9+/]{8,}={0,2}(?=["\']?(?:\s|$))', re.I)
USER_TEMP = re.compile(r"^[a-z]:\\users\\[^\\]+\\appdata\\local\\temp\\", re.I)

CAPABILITIES = {
    "logon": ({"security"}, {"4624", "4625"}, ("user.name", "winlog.logon.type")),
    "process_lineage": ({"microsoft-windows-sysmon/operational"}, {"1"}, ("process.entity_id", "process.parent.entity_id")),
    "powershell_content": ({"microsoft-windows-powershell/operational", "powershellcore/operational"}, {"4104"}, ("powershell.script_text",)),
    "scheduled_tasks": ({"security"}, {"4698"}, ("task.name", "winlog.logon.id")),
    "network_process_link": ({"microsoft-windows-sysmon/operational"}, {"3"}, ("process.entity_id", "destination.ip")),
    "file_creation": ({"microsoft-windows-sysmon/operational"}, {"11"}, ("process.entity_id", "file.path")),
}
RULES = {
    ENCODED: (("process_lineage",), ("process.executable", "process.command_line")),
    BURST: (("logon",), ("user.name", "user.domain", "source.ip")),
    TEMP: (("file_creation",), ("process.executable", "file.path")),
    TASK: (("scheduled_tasks",), ("task.name",)),
    CHAIN: (("logon", "process_lineage"), ("source.ip", "winlog.logon.id", "process.logon.id")),
}


def readiness(events, channels, policy, incomplete=False):
    result = {}
    for name, (sources, codes, fields) in CAPABILITIES.items():
        found = [event for event in events if event["event.code"] in codes
                 and text(event.get("winlog.channel")) in sources]
        declared = policy.get(name)
        if not channels.intersection(sources):
            state, reason = ("UNKNOWN", "A source failed or is pending ingestion") if incomplete else (
                "UNSUPPORTED", "Required channel is absent from ingested evidence")
        elif not found:
            state, reason = "UNKNOWN", "No matching observation in the ingested channel"
        elif not declared:
            state, reason = "PARTIAL", "Logging policy has no verification reference"
        elif any(not all(text(event.get(field)) for field in fields) for event in found):
            state, reason = "PARTIAL", "At least one record lacks required fields"
        elif incomplete:
            state, reason = "PARTIAL", "Some registered evidence was incomplete"
        else:
            state, reason = "SUPPORTED", "Records and fields are present and policy was attested"
        result[name] = {"state": state, "reason": reason, "records": len(found), "policy_reference": declared}
    return result


def image(event):
    return PureWindowsPath(event.get("process.executable") or "").name.casefold()


def principal(event):
    user, domain = text(event.get("user.name")), text(event.get("user.domain"))
    if not user or not domain:
        return None
    return domain, user


def source_address(event):
    try:
        address = ip_address(event.get("source.ip"))
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return str(getattr(address, "ipv4_mapped", None) or address)


def match_key(event, scopes):
    principal_key = principal(event)
    address = source_address(event)
    scope = scopes.get(event["event_id"])
    if principal_key and address and scope:
        return scope, principal_key, address
    return None


def detect(events, scopes, active_edges, coverage):
    matches = []
    failures = defaultdict(deque)
    preceding_bursts = {}
    by_id = {event["event_id"]: event for event in events}

    def hit(rule, ids, explanation):
        caps, fields = RULES[rule]
        readiness_states = {coverage[cap]["state"] for cap in caps}
        assessment = "READY" if readiness_states == {"SUPPORTED"} else "PARTIAL"
        detected = {"hit_id": stable_id(rule, VERSION, ids), "rule_id": rule,
                    "rule_version": VERSION, "event_ids": ids, "seed_event_id": ids[-1],
                    "assessment": assessment, "explanation": explanation,
                    "required_fields": fields, "result": "indicator_only",
                    "attack_techniques": TECHNIQUES.get(rule, [])}
        matches.append(detected)
        return detected

    encoded = set()
    for event in events:
        identifier = event["event_id"]
        kind = event["event_type"]
        when = time(event["@timestamp"])
        if kind in {"process_creation", "security_process_creation"} and (
            image(event) in POWERSHELL and ENCODED_SWITCH.search(event.get("process.command_line") or "")
        ):
            hit(ENCODED, [identifier], "The PowerShell command line contains an encoded command argument.")
            encoded.add(identifier)
        elif kind == "file_creation" and image(event) in POWERSHELL and USER_TEMP.match(event.get("file.path") or ""):
            hit(TEMP, [identifier], "Sysmon recorded PowerShell creating a file under a user Temp directory.")
        elif kind == "scheduled_task_creation" and text(event.get("task.name")):
            hit(TASK, [identifier], "Windows recorded scheduled task registration.")
        elif kind == "authentication":
            key = match_key(event, scopes)
            if not key:
                continue
            entries = failures[key]
            while entries and when - time(entries[0]["@timestamp"]) > FAILURE_WINDOW:
                entries.popleft()
            if event["event.code"] == "4625":
                entries.append(event)
                if len(entries) == FAILURE_THRESHOLD:
                    hit(BURST, [entry["event_id"] for entry in entries],
                        "Windows recorded five failed logons for the same account and source within five minutes.")
            elif event.get("winlog.logon.type") == "10" and len(entries) >= FAILURE_THRESHOLD:
                earlier = [item["event_id"] for item in entries if time(item["@timestamp"]) < when]
                if len(earlier) >= FAILURE_THRESHOLD:
                    preceding_bursts[identifier] = earlier[-FAILURE_THRESHOLD:]
                    entries.clear()

    for edge in active_edges:
        if edge["kind"] != "belongs_to_session" or edge["to_id"] not in encoded:
            continue
        session_id, process_id = edge["from_id"], edge["to_id"]
        preceding = preceding_bursts.get(session_id)
        if preceding and time(by_id[process_id]["@timestamp"]) - time(by_id[preceding[0]]["@timestamp"]) <= CHAIN_WINDOW:
            hit(CHAIN, [*preceding, session_id, process_id],
                "A matching failed-logon burst preceded a remote logon. The scoped LogonId links the recorded process to that session.")

    assessments = {}
    for rule, (caps, required_fields) in RULES.items():
        states = {coverage[cap]["state"] for cap in caps}
        assessments[rule] = {
            "state": "READY" if states == {"SUPPORTED"} else (
                "NOT ASSESSED" if states <= {"UNKNOWN", "UNSUPPORTED"} else "PARTIAL"),
            "required_fields": required_fields,
        }
    return matches, assessments
