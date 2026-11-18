"""HTTP surface for analyst work on stored evidence."""
from typing import Annotated, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, StringConstraints

from phantomtrace.investigation.config import AnalysisConfig, NonBlank
from phantomtrace.investigation.export import report, timeline_csv
from phantomtrace.investigation.graph import trace
from phantomtrace.investigation.rules import CAPABILITIES
from phantomtrace.investigation.store import AnalysisStore

class ReviewRequest(BaseModel):
    actor: NonBlank
    rationale: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=2000)]
    operation: Literal["CONFIRM", "REJECT", "QUESTION"]
    run_id: Annotated[str, StringConstraints(pattern=r"^[a-f0-9]{32}$")]


def build_router(get_db):
    router = APIRouter()

    def get_store(case_id):
        db = get_db()
        if db.get_case(case_id) is None:
            raise HTTPException(404, "Investigation case not found.")
        return AnalysisStore(db)

    def saved(case_id, run_id=None):
        store = get_store(case_id)
        snapshot = store.latest(case_id, run_id)
        if snapshot is None:
            raise HTTPException(404, "Analysis run not found. Run the case analysis first.")
        return store, snapshot

    def overview(run):
        return {field: run[field] for field in (
            "case_id", "run_id", "previous_run_id", "created_at", "coverage", "rule_readiness", "hits",
            "incidents", "evidence", "reviews", "stage_changes", "versions", "config",
        )}

    @router.post("/cases/{case_id}/analysis", status_code=201)
    def analyze_case(case_id: str, config: AnalysisConfig | None = None):
        store = get_store(case_id)
        if config and config.verified_policy.keys() - CAPABILITIES.keys():
            raise HTTPException(422, "Unknown telemetry capability in policy verification.")
        try:
            return overview(store.run(case_id, config.model_dump(mode="json") if config else None))
        except ValueError as error:
            raise HTTPException(422, str(error)) from error

    @router.get("/cases/{case_id}/analysis")
    def get_analysis(case_id: str, run_id: str | None = None):
        return overview(saved(case_id, run_id)[1])

    @router.get("/cases/{case_id}/coverage")
    def get_coverage(case_id: str, run_id: str | None = None):
        snapshot = saved(case_id, run_id)[1]
        return {"run_id": snapshot["run_id"], "capabilities": snapshot["coverage"],
                "rules": snapshot["rule_readiness"]}

    @router.get("/cases/{case_id}/incidents/{incident_id}/graph")
    def get_graph(case_id: str, incident_id: str, run_id: str | None = None,
                  offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=250)):
        store, snapshot = saved(case_id, run_id)
        incident = next((item for item in snapshot["incidents"] if item["incident_id"] == incident_id), None)
        if incident is None:
            raise HTTPException(404, "Incident not found in this run.")
        graph = incident["graph"]
        ids = graph["event_ids"][offset:offset + limit]
        visible = set(ids)
        # Include crossing links with their original endpoint IDs for paginated views.
        edges = [edge for edge in snapshot["edges"] if
                 edge["from_id"] in visible or edge["to_id"] in visible
                 if edge in graph["edges"] or edge["review_status"] == "REJECT"]
        return {"run_id": snapshot["run_id"], "total_nodes": len(graph["event_ids"]),
                "offset": offset, "nodes": summaries(store.events(case_id, ids)), "edges": edges,
                "gaps": [gap for gap in snapshot["gaps"] if gap["event_id"] in visible],
                "truncated": graph["truncated"]}

    @router.get("/cases/{case_id}/trace")
    def trace_case(case_id: str, seed: str, dir: Literal["back", "forward"], run_id: str | None = None,
                   max_hops: int = Query(8, ge=0, le=12), exclude: list[str] = Query(default=[])):
        store, snapshot = saved(case_id, run_id)
        hit = next((item for item in snapshot["hits"] if item["hit_id"] == seed), None)
        seed = hit["seed_event_id"] if hit else seed
        if seed not in snapshot["event_ids"]:
            raise HTTPException(404, "Trace start is absent from this analysis.")
        result = trace(snapshot["edges"], seed, dir, max_hops, exclude=exclude)
        visited = set(result["event_ids"])
        result["nodes"] = summaries(store.events(case_id, result["event_ids"]))
        result["gaps"] = [gap for gap in snapshot["gaps"] if gap["event_id"] in visited]
        result["reviewed_out"] = [edge["edge_id"] for edge in snapshot["edges"] if edge["review_status"] == "REJECT"
                                  and visited.intersection((edge["from_id"], edge["to_id"]))]
        result["run_id"] = snapshot["run_id"]
        return result

    @router.post("/cases/{case_id}/edges/{edge_id}/review", status_code=201)
    def review_edge(case_id: str, edge_id: str, request: ReviewRequest):
        store = get_store(case_id)
        try:
            return overview(store.review(case_id, edge_id, request.run_id, request.operation,
                                         request.actor, request.rationale))
        except LookupError as error:
            raise HTTPException(404, str(error)) from error
        except ValueError as error:
            raise HTTPException(409, str(error)) from error

    @router.get("/cases/{case_id}/export/{format}")
    def export_case(case_id: str, format: Literal["timeline.csv", "report.md", "manifest.json"], run_id: str | None = None):
        store, snapshot = saved(case_id, run_id)
        if format == "manifest.json":
            return {key: snapshot[key] for key in ("case_id", "run_id", "created_at", "evidence", "versions", "config")}
        if format == "report.md":
            content, media = report(snapshot), "text/markdown"
        else:
            content = timeline_csv(store.events(case_id, snapshot["event_ids"]))
            media = "text/csv"
        return Response(content, media_type=media,
                        headers={"Content-Disposition": f'attachment; filename="{format}"',
                                 "X-Content-Type-Options": "nosniff"})

    return router


def summaries(events):
    fields = ("event_id", "event_type", "event.code", "@timestamp", "host.name", "evidence_sha256",
              "process.executable", "file.path", "task.name", "user.name", "destination.ip")
    return [{key: event[key] for key in fields if key in event} for event in events]
