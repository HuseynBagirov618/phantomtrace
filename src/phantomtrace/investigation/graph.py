"""Identifier-backed relationships between Windows observations."""
from bisect import bisect_right
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from uuid import UUID

from phantomtrace.schema.models import Edge

VERSION = "1.0.0"


def stable_id(*values):
    return sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def time(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Timestamps require an explicit timezone")
    return parsed.astimezone(timezone.utc)


def text(value):
    return value.strip().casefold() if isinstance(value, str) and value.strip() not in ("", "-") else None


def logon_id(value):
    try:
        if not isinstance(value, str) or not value.lower().startswith("0x"):
            return None
        number = int(value, 16)
        return hex(number) if 0 < number < 2**64 else None
    except ValueError:
        return None


def guid(value):
    try:
        identifier = UUID(str(value))
        return str(identifier) if identifier.int else None
    except ValueError:
        return None


def order(event):
    return time(event["@timestamp"]), event["event_id"]


def assign_scopes(events, windows):
    starts = defaultdict(set)
    supplied = defaultdict(list)
    for event in events:
        host = text(event.get("host.name"))
        if host and event["event_type"] == "boot_started":
            try:
                started = time(event.get("system.boot_started") or event["@timestamp"])
            except ValueError:
                continue
            starts[host].add(started)
    starts = {host: sorted(values) for host, values in starts.items()}
    for window in windows:
        host = text(window["host"])
        start, end = time(window["start"]), time(window["end"])
        if not host or start >= end:
            raise ValueError("Boot ranges require a host and start before end")
        if any(start < prior_end and prior_start < end for prior_start, prior_end, _ in supplied[host]):
            raise ValueError("Boot ranges overlap for the same host")
        if any(start < boot < end for boot in starts.get(host, ())):
            raise ValueError("A Windows startup record contradicts a supplied boot range")
        supplied[host].append((start, end, window["reference"]))

    scopes = {}
    for event in events:
        host = text(event.get("host.name"))
        if not host:
            continue
        when = time(event["@timestamp"])
        matching = next((window for window in supplied[host] if window[0] <= when < window[1]), None)
        boots = starts.get(host, ())
        position = bisect_right(boots, when)
        if matching:
            boot = "verified:" + matching[0].isoformat()
        elif 0 < position < len(boots):
            boot = "system:" + boots[position - 1].isoformat()
        else:
            boot = "file:" + event["evidence_sha256"]
        scopes[event["event_id"]] = (host, boot)
    return scopes


def build_graph(events, windows):
    scopes = assign_scopes(events, windows)
    logons, processes = defaultdict(list), defaultdict(list)
    for event in events:
        scope = scopes.get(event["event_id"])
        if not scope:
            continue
        if event["event_type"] == "authentication" and event["event.code"] == "4624":
            key = logon_id(event.get("winlog.logon.id"))
            if key and not scope[1].startswith("file:"):
                logons[scope, key].append(event)
        if event["event_type"] == "process_creation":
            key = guid(event.get("process.entity_id"))
            if key:
                processes[scope, key].append(event)

    edges, gaps = [], []
    for event in events:
        target = event["event_id"]
        scope = scopes.get(target)
        kind = event["event_type"]
        joins = []
        if kind == "process_creation":
            joins = [
                ("belongs_to_session", logon_id(event.get("process.logon.id")), logons, "LogonId"),
                ("spawned", guid(event.get("process.parent.entity_id")), processes, "ParentProcessGuid"),
            ]
        elif kind in {"file_creation", "network_connection"}:
            relation = {"file_creation": "created_file", "network_connection": "connected_to"}[kind]
            joins = [(relation, guid(event.get("process.entity_id")), processes, "ProcessGuid")]
        elif kind == "scheduled_task_creation":
            joins = [("registered_task_in_session", logon_id(event.get("winlog.logon.id")), logons, "SubjectLogonId")]

        for relation, key, index, field in joins:
            candidates = index.get((scope, key), [])
            reason = None
            if not scope:
                reason = "Host identity is missing"
            elif index is logons and scope[1].startswith("file:"):
                reason = "Shared boot scope is unverified"
            elif not key:
                reason = f"{field} is missing or invalid"
            elif len(candidates) != 1:
                reason = "Identifier is ambiguous in scope" if candidates else "Source observation is missing in scope"
            else:
                source = candidates[0]
                elapsed = time(event["@timestamp"]) - time(source["@timestamp"])
                if source["event_id"] == target or elapsed <= timedelta(0):
                    reason = "Source must strictly precede target"
                elif index is logons and elapsed > timedelta(hours=12):
                    reason = "Session link exceeds the 12 hour window"
                elif relation == "belongs_to_session" and account_conflicts(source, event):
                    reason = "Process and session accounts disagree"
                elif relation == "registered_task_in_session" and task_account_conflicts(source, event):
                    reason = "Task and session accounts disagree"
            if reason:
                gaps.append({"event_id": target, "relation": relation, "reason": reason,
                             "candidates": [candidate["event_id"] for candidate in candidates[:3]]})
                continue
            source_id = candidates[0]["event_id"]
            explanation = f"Matched {field} on host {scope[0]} with an earlier source observation."
            if scope[1].startswith("file:"):
                explanation += " The ProcessGuid match is confined to one evidence file. Boot coverage is unverified."
            edges.append(Edge(
                edge_id=stable_id(relation, source_id, target, VERSION),
                kind=relation, strength="HARD", from_id=source_id, to_id=target,
                rule_id=f"PT-REL-{relation.upper()}", rule_version=VERSION,
                support_event_ids=[source_id, target], scope={"host": scope[0], "boot": scope[1]},
                explanation=explanation,
            ).model_dump() | {"matched_fields": {field: key}})
    return edges, gaps, scopes


def account_conflicts(session, process):
    account = text(process.get("process.user.name"))
    username = text(session.get("user.name"))
    domain = text(session.get("user.domain"))
    if not account or not username:
        return False
    if "\\" in account:
        process_domain, process_user = account.rsplit("\\", 1)
        return process_user != username or bool(domain and process_domain != domain)
    return account != username


def task_account_conflicts(session, task):
    for field in ("user.sid", "user.domain", "user.name"):
        left, right = text(session.get(field)), text(task.get(field))
        if left and right and left not in {"s-1-0-0"} and right not in {"s-1-0-0"} and left != right:
            return True
    return False


def trace(edges, seed, direction, hops, cap=250, *, exclude=()):
    adjacent = defaultdict(list)
    excluded = set(exclude)
    for edge in edges:
        if edge.get("review_status") == "REJECT" or edge["kind"] in excluded:
            continue
        left, right = edge["from_id"], edge["to_id"]
        source, target = (left, right) if direction == "forward" else (right, left)
        adjacent[source].append((target, edge))
    seen, reached, included = {seed}, [seed], {}
    queue = deque([(seed, 0)])
    truncated = False
    while queue:
        source, distance = queue.popleft()
        if distance >= hops:
            truncated |= any(target not in seen for target, _ in adjacent[source])
            continue
        for target, edge in adjacent[source]:
            if target not in seen:
                if len(seen) >= cap:
                    truncated = True
                    continue
                seen.add(target)
                reached.append(target)
                queue.append((target, distance + 1))
            included[edge["edge_id"]] = edge
    return {"event_ids": reached, "edges": list(included.values()), "truncated": truncated}
