"""Build case candidates using hard relationships and explicitly reported gaps."""
from collections import defaultdict

from phantomtrace.investigation.graph import build_graph, order, stable_id, trace
from phantomtrace.investigation.rules import CHAIN, ENCODED, detect, readiness

STAGES = (
    ("failed_logons", "Failed logons"),
    ("session", "Successful logon"),
    ("powershell", "Encoded PowerShell observation"),
    ("file", "File creation"),
    ("task", "Scheduled task registration"),
    ("transfer", "Transfer"),
)


def analyze(events, config, channels, reviews=(), *, incomplete=False):
    events = sorted(events, key=order)
    edges, gaps, scopes = build_graph(events, config.get("boot_ranges", []))
    latest = {action["target"]: action for action in reviews}
    for edge in edges:
        action = latest.get(edge["edge_id"])
        edge["review_status"] = action["operation"] if action else None
    active = [edge for edge in edges if edge["review_status"] != "REJECT"]
    coverage = readiness(events, channels, config.get("verified_policy", {}), incomplete)
    hits, assessments = detect(events, scopes, active, coverage)
    incidents = build_incidents(events, active, edges, hits)
    return {
        "coverage": coverage, "rule_readiness": assessments, "hits": hits,
        "edges": edges, "gaps": gaps, "incidents": incidents,
        "event_ids": [event["event_id"] for event in events],
        "config": config, "incomplete_evidence": incomplete,
    }


def build_incidents(events, active, all_edges, hits):
    by_id = {event["event_id"]: event for event in events}
    active_sessions = {edge["to_id"]: edge["from_id"] for edge in active if edge["kind"] == "belongs_to_session"}
    original_sessions = {edge["to_id"]: edge["from_id"] for edge in all_edges if edge["kind"] == "belongs_to_session"}
    chains = {hit["seed_event_id"]: hit for hit in hits if hit["rule_id"] == CHAIN}
    assignments = defaultdict(list)
    for hit in hits:
        seed = hit["seed_event_id"]
        if hit["rule_id"] == ENCODED:
            # Retain the original candidate on review so a comparable before/after exists.
            assignments[original_sessions.get(seed, seed)].append(seed)

    incidents = []
    for anchor, seeds in assignments.items():
        linked = [seed for seed in seeds if active_sessions.get(seed) == anchor]
        rejected = anchor not in seeds and not linked
        graph = trace(active, anchor, "forward", 6)
        # Prevent a process path from crossing into a different known session.
        conflicts = {event_id for event_id in graph["event_ids"]
                     if original_sessions.get(event_id, anchor) != anchor}
        if conflicts:
            allowed_edges = [edge for edge in graph["edges"]
                             if not conflicts.intersection((edge["from_id"], edge["to_id"]))]
            graph = trace(allowed_edges, anchor, "forward", 6)
        nodes = graph["event_ids"]
        failed = list(dict.fromkeys(event_id for seed in linked if seed in chains
                                    for event_id in chains[seed]["event_ids"][:-2]))
        encoded = linked or ([] if anchor not in seeds else seeds)
        stage_ids = {
            "failed_logons": failed,
            "session": [anchor] if anchor not in seeds else [],
            "powershell": encoded,
            "file": [event_id for event_id in nodes if by_id[event_id]["event_type"] == "file_creation"],
            "task": [event_id for event_id in nodes if by_id[event_id]["event_type"] == "scheduled_task_creation"],
            "transfer": [],
        }
        stages = []
        for key, label in STAGES:
            support = sorted(stage_ids[key], key=lambda item: order(by_id[item]))
            if key == "transfer":
                reason = "Endpoint activity alone does not establish a transfer."
            elif key == "powershell" and rejected:
                reason = "The session relationship was rejected during review."
            else:
                reason = "No observation supports this stage on the current path."
            stage = {"id": key, "label": label, "event_ids": support, "state": (
                "correlated" if support and key in {"failed_logons", "file", "task"} else (
                    "observed" if support else "unknown")), "reason": None if support else reason}
            stages.append(stage)
        stages.sort(key=lambda stage: (0, *order(by_id[stage["event_ids"][0]])) if stage["event_ids"] else (1,))
        ordered_nodes = list(dict.fromkeys([*nodes, *failed]))
        graph["event_ids"] = ordered_nodes[:250]
        graph["truncated"] |= len(ordered_nodes) > 250
        support_set = set(graph["event_ids"])
        incidents.append({
            "incident_id": stable_id("incident", anchor), "anchor_event_id": anchor,
            "status": "correlated" if failed else "candidate", "stages": stages, "graph": graph,
            "hit_ids": [hit["hit_id"] for hit in hits if set(hit["event_ids"]) <= support_set],
        })
    return incidents


def compare_incident_stages(before, after):
    previous = {(item["incident_id"], stage["id"]): stage["event_ids"]
                for item in before["incidents"] for stage in item["stages"]}
    current = {(item["incident_id"], stage["id"]): stage["event_ids"]
               for item in after["incidents"] for stage in item["stages"]}
    return [
        {"incident_id": key[0], "stage": key[1], "before": previous.get(key, []), "after": current.get(key, [])}
        for key in sorted(previous.keys() | current.keys()) if previous.get(key, []) != current.get(key, [])
    ]
