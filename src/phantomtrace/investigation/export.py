"""Export a saved analysis with raw evidence references."""
import csv
import html
import io
import re


def safe_csv(value):
    value = str(value or "")
    if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def timeline_csv(events):
    output = io.StringIO(newline="")
    fields = ("@timestamp", "host.name", "event_id", "event.code", "evidence_sha256", "raw_ref",
              "parser_version", "schema_version")
    writer = csv.writer(output)
    writer.writerow(("timestamp_utc", "host", "event_id", "event_code", "source_sha256", "record_locator",
                     "parser_version", "schema_version"))
    writer.writerows([safe_csv(event.get(key)) for key in fields] for event in events)
    return output.getvalue()


def literal(value):
    cleaned = html.escape(str(value)).replace("\r", " ").replace("\n", " ")
    return re.sub(r"([\\`*_{}\[\]#!|])", r"\\\1", cleaned)


def report(snapshot):
    lines = [
        "# PhantomTrace investigation", "",
        f"Case {literal(snapshot['case_id'])}, analysis run `{snapshot['run_id']}`", "",
        "## Evidence", "",
    ]
    for source in snapshot["evidence"]:
        lines.append(f"- {literal(source['filename'])}, SHA-256 `{source['sha256']}`, {source['status']}")
    lines.extend(["", "## Coverage", ""])
    for name, state in snapshot["coverage"].items():
        lines.append(f"- {literal(name)} — {state['state']}. {literal(state['reason'])}")
    for incident in snapshot["incidents"]:
        lines.extend(["", f"## Incident {incident['incident_id']}", "", incident["status"], ""])
        for stage in incident["stages"]:
            evidence = ", ".join(f"`{ident}`" for ident in stage["event_ids"]) or stage["reason"]
            lines.append(f"- {stage['label']} ({stage['state']}) — {evidence}")
        for edge in incident["graph"]["edges"]:
            lines.append(f"- {edge['rule_id']} v{edge['rule_version']}: {literal(edge['explanation'])} "
                         f"({', '.join(edge['support_event_ids'])})")
    lines.extend(["", "## Review history", ""])
    for action in snapshot["reviews"]:
        lines.append(f"- {action['timestamp']} {literal(action['actor'])} {action['operation']} "
                     f"`{action['target']}` — {literal(action['rationale'])}")
    lines.extend(["", "## Versions", ""])
    lines.extend(f"- {key}: {literal(value)}" for key, value in snapshot["versions"].items())
    return "\n".join(lines) + "\n"
