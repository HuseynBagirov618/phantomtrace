"""Reproducible offline evaluation of labeled EVTX scenarios."""
from collections import defaultdict
from datetime import timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from phantomtrace.investigation.config import AnalysisConfig
from phantomtrace.database.db import PhantomTraceDB
from phantomtrace.database.event_store import EventStore
from phantomtrace.evidence.storage import EvidenceStorage
from phantomtrace.ingestion.service import EvidenceIngestionService
from phantomtrace.investigation.graph import time
from phantomtrace.investigation.rules import source_address
from phantomtrace.investigation.store import AnalysisStore


def ratio(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def evaluate(manifest, *, split):
    data = json.loads(manifest.read_text(encoding="utf-8"))
    scenarios = [scenario for scenario in data["scenarios"] if scenario["split"] == split]
    if not scenarios:
        raise ValueError(f"No {split} scenarios in the manifest.")
    return [evaluate_scenario(manifest.parent, spec) for spec in scenarios]


def evaluate_scenario(parent, spec):
    with TemporaryDirectory() as tmp:
        db = PhantomTraceDB(Path(tmp) / "eval.db")
        storage = EvidenceStorage(Path(tmp) / "cases")
        case_id = db.create_case("EVAL", spec["name"])
        ingest = EvidenceIngestionService(db, storage)
        for entry in spec["sources"]:
            path = parent / entry["path"]
            if path.suffix.lower() != ".evtx" or not path.is_file():
                raise ValueError(f"Expected an EVTX file: {path}")
            digest = storage.calculate_sha256(path)
            if digest != entry["sha256"]:
                raise ValueError(f"Evidence hash mismatch: {path}")
            stored = storage.store_evidence(case_id, path)
            if stored["sha256"] != digest:
                raise ValueError(f"Evidence changed during evaluation: {path}")
            db.add_evidence(case_id, digest, path.name, path.stat().st_size, "evaluation")
            result = ingest.ingest(case_id, digest)
            if result["status"] != "SUCCESS":
                raise ValueError(f"Incomplete evidence: {path}")
        config = AnalysisConfig.model_validate(spec.get("config", {})).model_dump(mode="json")
        analysis = AnalysisStore(db).run(case_id, config)
        events = EventStore(db).get_timeline(case_id)
        return score(spec, analysis, events)


def score(spec, analysis, events):
    by_id = {event["event_id"]: event for event in events}
    reverse = {event["raw_ref"]: event["event_id"] for event in events}

    def qualified(locators):
        missing = set(locators) - reverse.keys()
        if missing:
            raise ValueError(f"Ground truth points to absent records: {sorted(missing)}")
        return {reverse[locator] for locator in locators}

    expected_hits = {(entry["rule"], next(iter(qualified([entry["record"]])))) for entry in spec["detections"]}
    expected_edges = {(entry["kind"], reverse[entry["from"]], reverse[entry["to"]]) for entry in spec["edges"]}
    truth_groups = [qualified(group) for group in spec["incident_groups"]]
    if sum(map(len, truth_groups)) != len(set().union(*truth_groups)):
        raise ValueError("Ground truth cannot assign one record to two incidents.")

    indicator_hits = {(hit["rule_id"], hit["seed_event_id"]) for hit in analysis["hits"]}
    base_hits = {hit for hit in indicator_hits if not hit[0].startswith("PT-CHAIN-")}
    seeds = [seed for _, seed in sorted(base_hits)]
    naive_groups = defaultdict(set)
    for seed in seeds:
        event = by_id[seed]
        source = source_address(event)
        minute = int(time(event["@timestamp"]).astimezone(timezone.utc).timestamp()) // 600
        # Missing IP does not identify a shared source.
        naive_groups[event.get("host.name"), source or seed, minute].add(seed)
    graph_edges = {(edge["kind"], edge["from_id"], edge["to_id"]) for edge in analysis["edges"]}
    graph_groups = [set(item["graph"]["event_ids"]) for item in analysis["incidents"]]
    alternatives = {
        "rules_only": (base_hits, set(), [{seed} for seed in seeds]),
        "rules_and_fixed_window": (base_hits, set(), list(naive_groups.values())),
        "identifier_graph": (indicator_hits, graph_edges, graph_groups),
    }

    def explain(identifiers):
        return sorted(by_id[identifier]["raw_ref"] for identifier in identifiers)

    scores = {}
    for name, (hits, edges, groups) in alternatives.items():
        purity = sum(max((len(group & reference) for reference in truth_groups), default=0) for group in groups)
        missed = sorted(expected_edges - edges)
        false_merge = next((explain(group) for group in groups if sum(bool(group & item) for item in truth_groups) > 1), None)
        scores[name] = {
            "detection_precision": ratio(len(hits & expected_hits), len(hits)),
            "detection_recall": ratio(len(hits & expected_hits), len(expected_hits)),
            "edge_precision": ratio(len(edges & expected_edges), len(edges)),
            "edge_recall": ratio(len(edges & expected_edges), len(expected_edges)),
            "incident_purity": ratio(purity, sum(map(len, groups))),
            "alerts_per_output_group": ratio(len(hits), len(groups)),
            "example_false_merge": false_merge,
            "example_missed_edge": ([missed[0][0], by_id[missed[0][1]]["raw_ref"],
                                     by_id[missed[0][2]]["raw_ref"]] if missed else None),
        }
    return {"scenario": spec["name"], "split": spec["split"], "versions": analysis["versions"],
            "source_sha256": [item["sha256"] for item in analysis["evidence"]], "configurations": scores}


def markdown(results):
    lines = ["# PhantomTrace evaluation", "",
             "| Scenario | Configuration | Detection P | Detection R | Edge P | Edge R | Purity | Alerts per group |",
             "|---|---|---:|---:|---:|---:|---:|---:|"]
    for item in results:
        for config, metrics in item["configurations"].items():
            cells = [item["scenario"].replace("|", "\\|"), config]
            for name in ("detection_precision", "detection_recall", "edge_precision", "edge_recall",
                         "incident_purity", "alerts_per_output_group"):
                count = metrics[name]
                cells.append(f'{count["numerator"]}/{count["denominator"]}')
            lines.append("| " + " | ".join(cells) + " |")
    lines.extend(["", "A zero denominator means the ratio is undefined. Confusion examples are in the JSON report."])
    return "\n".join(lines) + "\n"
