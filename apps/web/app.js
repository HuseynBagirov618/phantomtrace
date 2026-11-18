const $ = (id) => document.getElementById(id);
const title = (value) => value.replaceAll("_", " ");
let caseId = "", offset = 0, eventType = "", snapshot = null;

function node(tag, value, parent) {
  const element = document.createElement(tag);
  if (value !== undefined && value !== null) element.textContent = value;
  if (parent) parent.append(element);
  return element;
}

function button(label, parent, handler) {
  const control = node("button", label, parent);
  control.type = "button";
  control.addEventListener("click", () => job(handler));
  return control;
}

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    const err = await response.json().catch(() => ({}));
    const detail = typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail ?? response.statusText);
    const problem = new Error(detail);
    problem.status = response.status;
    throw problem;
  }
  return response.json();
}

function post(body) {
  return {method: "POST", ...(body === undefined ? {} : {
    headers: {"Content-Type": "application/json"}, body: JSON.stringify(body),
  })};
}

function path(suffix) {
  return "/cases/" + encodeURIComponent(caseId) + suffix;
}

async function job(action) {
  $("status").textContent = "";
  try { await action(); }
  catch (error) {
    if ($("drawer").open) {
      const body = $("drawer-body");
      body.querySelector("[role=alert]")?.remove();
      node("p", error.message, body).setAttribute("role", "alert");
    } else $("status").textContent = error.message;
  }
}

function form(id, handler) {
  $(id).addEventListener("submit", (event) => {
    event.preventDefault();
    job(() => handler(new FormData(event.currentTarget)));
  });
}

async function cases(select = caseId) {
  const list = await api("/cases");
  $("cases").replaceChildren();
  for (const item of list) {
    node("option", item.name + " (" + item.case_id + ")", $("cases")).value = item.case_id;
  }
  if (list.some((item) => item.case_id === select)) $("cases").value = select;
  await selectCase();
}

async function selectCase() {
  caseId = $("cases").value;
  offset = 0;
  eventType = "";
  $("timeline-filter").reset();
  snapshot = null;
  $("workspace").hidden = !caseId;
  $("config").querySelector("textarea").value = "";
  if (caseId) await loadAnalysis();
}

async function timeline() {
  const query = new URLSearchParams({limit: 50, offset});
  if (eventType) query.set("event_type", eventType);
  const data = await api(path("/timeline?" + query));
  if (data.case_id !== caseId) return;
  const rows = $("timeline");
  rows.replaceChildren();
  for (const event of data.events) {
    const row = node("tr", null, rows);
    for (const value of [event["@timestamp"], event["host.name"], event["event.code"], summary(event), event.evidence_sha256.slice(0, 12)]) {
      node("td", value ?? "—", row);
    }
    const actions = node("td", null, row);
    button("Raw", actions, () => openRaw(event.event_id));
    if (snapshot) button("Trace", actions, () => openTrace(event.event_id, "back"));
  }
  $("prev").disabled = !offset;
  $("next").disabled = offset + data.events.length >= data.total_events;
  $("timeline-count").textContent = data.total_events ? `${offset + 1}–${offset + data.events.length} of ${data.total_events}` : "No normalized records.";
}

function summary(event) {
  return event["file.path"] || event["task.name"] || event["process.executable"] ||
    event["user.name"] || event.event_type || "Observation";
}

async function loadAnalysis() {
  try {
    const data = await api(path("/analysis"));
    if (data.case_id === caseId) snapshot = data;
  } catch (error) {
    if (error.status !== 404) throw error;
  }
  render();
  await timeline();
}

async function analyze(config) {
  const data = await api(path("/analysis"), post(config));
  if (data.case_id !== caseId) return;
  snapshot = data;
  render();
  await timeline();
  $("status").textContent = "Analysis saved.";
}

function render() {
  for (const id of ["evidence-status", "coverage", "incidents", "hits", "history", "exports"]) $(id).replaceChildren();
  if (!snapshot) {
    node("p", "Run analysis to inspect coverage and incident candidates.", $("coverage"));
    return;
  }
  $("config").querySelector("textarea").value = JSON.stringify(snapshot.config, null, 2);
  for (const file of snapshot.evidence) node("li", `${file.filename} · ${file.status} · ${file.sha256.slice(0, 16)}${file.reason ? " · " + file.reason : ""}${file.errors.length ? " · " + file.errors.length + " record errors" : ""}`, $("evidence-status"));
  const coverage = node("ul", null, $("coverage"));
  for (const [capability, value] of Object.entries(snapshot.coverage)) {
    const row = node("li", null, coverage);
    node("strong", title(capability) + " ", row);
    node("span", value.state, row).className = "tag";
    node("span", " " + value.reason, row).className = "muted";
  }
  for (const [file, label] of [["timeline.csv", "CSV"], ["report.md", "Report"], ["manifest.json", "Manifest"]]) {
    const link = node("a", label, $("exports"));
    link.href = path("/export/" + file + "?run_id=" + snapshot.run_id);
    link.download = file;
    $("exports").append(" ");
  }
  for (const incident of snapshot.incidents) {
    const card = node("details", null, $("incidents"));
    node("summary", `${incident.status} · ${incident.incident_id.slice(0, 12)}`, card);
    const stages = node("ul", null, card);
    for (const stage of incident.stages) {
      const item = node("li", `${stage.label} · ${stage.state} `, stages);
      if (stage.reason) node("span", stage.reason, item).className = "muted";
      for (const id of stage.event_ids) button("Evidence " + id.slice(0, 8), item, () => openRaw(id));
    }
    button("Inspect graph", card, () => openGraph(incident.incident_id));
  }
  if (!snapshot.incidents.length) node("p", "No candidates in this run. See coverage and individual indicators.", $("incidents"));
  const hits = node("ul", null, $("hits"));
  for (const hit of snapshot.hits) {
    const row = node("li", `${hit.rule_id} · ${hit.assessment} · ${hit.explanation} `, hits);
    button("Trace", row, () => openTrace(hit.hit_id, "back"));
  }
  if (!snapshot.hits.length) node("p", "No indicators in the available observations.", $("hits"));
  const log = node("ul", null, $("history"));
  for (const action of snapshot.reviews) node("li", `${action.timestamp} · ${action.actor} · ${action.operation} · ${action.rationale}`, log);
  for (const change of snapshot.stage_changes) node("li", `${title(change.stage)} · evidence before: ${change.before.map((id) => id.slice(0, 8)).join(", ") || "none"} · after: ${change.after.map((id) => id.slice(0, 8)).join(", ") || "none"}`, log);
}

function drawer(label) {
  $("drawer-title").textContent = label;
  $("drawer-body").replaceChildren();
  if (!$("drawer").open) $("drawer").showModal();
  return $("drawer-body");
}

async function openRaw(id, back) {
  const record = await api(path("/events/" + id + "/raw"));
  const body = drawer("Raw Windows event record");
  if (back) button("Back to links", body, back);
  node("p", `${record.evidence.channel} · record ${record.evidence.record_number}`, body);
  node("p", "Evidence SHA-256 " + record.evidence.sha256, body);
  node("p", "XML SHA-256 " + record.raw_hash, body);
  node("pre", record.raw_xml, body);
  if (snapshot) button("Trace from this record", body, () => openTrace(id, "back"));
}

async function openGraph(incident, page = 0) {
  const restore = () => openGraph(incident, page);
  const data = await api(path(`/incidents/${incident}/graph?limit=50&offset=${page}&run_id=${snapshot.run_id}`));
  const body = drawer("Incident graph");
  if (page) button("Previous nodes", body, () => openGraph(incident, page - 50));
  if (data.total_nodes > page + data.nodes.length) button("Next nodes", body, () => openGraph(incident, page + 50));
  graphContents(body, data, restore);
}

function graphContents(body, data, restore) {
  if (data.truncated) node("p", "The graph reached its traversal limit.", body);
  drawGraph(body, data.nodes, data.edges);
  const observed = node("ul", null, body);
  for (const item of data.nodes) {
    const row = node("li", `${item["event.code"]} · ${summary(item)} `, observed);
    button("Raw", row, () => openRaw(item.event_id, restore));
    button("Back trace", row, () => openTrace(item.event_id, "back"));
    button("Forward trace", row, () => openTrace(item.event_id, "forward"));
  }
  node("h3", "Relationships", body);
  const edges = node("ul", null, body);
  for (const edge of data.edges) {
    const row = node("li", null, edges);
    button(`${title(edge.kind)} · ${edge.from_id.slice(0, 7)} → ${edge.to_id.slice(0, 7)}${edge.review_status ? " · " + edge.review_status : ""}`, row, () => inspectEdge(edge, restore));
  }
  for (const gap of data.gaps) {
    const row = node("p", `${title(gap.relation)} · ${gap.reason} `, body);
    for (const id of gap.candidates) button("Candidate " + id.slice(0, 8), row, () => openRaw(id, restore));
  }
  if (data.reviewed_out?.length) node("p", `${data.reviewed_out.length} rejected relationship(s) excluded.`, body);
}

function drawGraph(body, nodes, edges) {
  if (!nodes.length) return;
  const wrap = node("div", null, body);
  wrap.className = "table-wrap";
  function svgChild(tag, parent, attrs) {
    const element = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [name, value] of Object.entries(attrs)) element.setAttribute(name, value);
    parent.append(element);
    return element;
  }
  const columns = 4;
  const svg = svgChild("svg", wrap, {viewBox: `0 0 620 ${Math.ceil(nodes.length / columns) * 64}`, role: "img", "aria-label": "Observation relationship diagram"});
  const positions = new Map(nodes.map((item, index) => [item.event_id, [75 + index % columns * 155, 23 + Math.floor(index / columns) * 64]]));
  for (const edge of edges) {
    const from = positions.get(edge.from_id), to = positions.get(edge.to_id);
    if (from && to) svgChild("line", svg, {x1: from[0], y1: from[1], x2: to[0], y2: to[1], class: edge.review_status === "REJECT" ? "rejected" : ""});
  }
  for (const item of nodes) {
    const [x, y] = positions.get(item.event_id);
    if (item.event_type === "authentication") svgChild("circle", svg, {cx:x, cy:y, r:12});
    else if (item.event_type === "file_creation") svgChild("polygon", svg, {points:`${x},${y-13} ${x+13},${y} ${x},${y+13} ${x-13},${y}`});
    else svgChild("rect", svg, {x:x-15, y:y-10, width:30, height:20, rx: item.event_type === "process_creation" ? 6 : 1});
    svgChild("text", svg, {x, y:y+27, "text-anchor":"middle"}).textContent = item["event.code"] + " · " + item.event_id.slice(0, 7);
  }
}

async function openTrace(id, direction) {
  if (!snapshot) return;
  const restore = () => openTrace(id, direction);
  const trace = await api(path(`/trace?seed=${id}&dir=${direction}&run_id=${snapshot.run_id}`));
  const body = drawer(direction === "back" ? "Backward trace" : "Forward trace");
  button("Reverse direction", body, () => openTrace(id, direction === "back" ? "forward" : "back"));
  graphContents(body, trace, restore);
}

function inspectEdge(edge, restore) {
  const body = drawer("Relationship evidence");
  button("Back to links", body, restore);
  node("p", `${title(edge.kind)} · ${edge.strength} · ${edge.rule_id} v${edge.rule_version}`, body);
  node("p", edge.explanation, body);
  node("pre", JSON.stringify({scope:edge.scope, matched_fields:edge.matched_fields}, null, 2), body);
  for (const id of edge.support_event_ids) button("Raw record " + id.slice(0, 8), body, () => openRaw(id, () => inspectEdge(edge, restore)));
  const review = node("form", null, body);
  const author = node("input", null, node("label", "Analyst ", review));
  author.required = true;
  author.maxLength = 512;
  const reason = node("textarea", null, node("label", "Rationale", review));
  reason.required = true;
  reason.maxLength = 2000;
  const choice = node("select", null, node("label", "Decision ", review));
  for (const operation of ["QUESTION", "CONFIRM", "REJECT"]) node("option", operation, choice).value = operation;
  node("button", "Save review", review).type = "submit";
  review.addEventListener("submit", (event) => {
    event.preventDefault();
    job(async () => {
      snapshot = await api(path(`/edges/${edge.edge_id}/review`), post({
        actor:author.value, rationale:reason.value, operation:choice.value, run_id:snapshot.run_id,
      }));
      render();
      const diff = drawer("Review saved");
      node("p", "Analysis " + snapshot.run_id, diff);
      for (const change of snapshot.stage_changes) node("p", `${title(change.stage)} · ${change.before.length} → ${change.after.length} supporting observations`, diff);
      if (!snapshot.stage_changes.length) node("p", "No incident stages changed.", diff);
    });
  });
}

$("cases").addEventListener("change", () => job(selectCase));
$("analyze").addEventListener("click", () => job(() => analyze()));
$("prev").addEventListener("click", () => { offset -= 50; job(timeline); });
$("next").addEventListener("click", () => { offset += 50; job(timeline); });
form("timeline-filter", async (data) => {
  eventType = data.get("event_type");
  offset = 0;
  await timeline();
});
form("create", async (data) => {
  const result = await api("/cases", post(Object.fromEntries(data)));
  $("create").reset();
  await cases(result.case_id);
});
form("config", async () => analyze(JSON.parse($("config").querySelector("textarea").value || "{}")));
form("upload", async (data) => {
  const selected = caseId;
  const failures = [];
  for (const file of data.getAll("file")) {
    if (selected !== caseId) return;
    try {
      const body = new FormData();
      body.append("file", file);
      const item = await api(path("/evidence"), {method:"POST", body});
      await api("/cases/" + encodeURIComponent(selected) + `/evidence/${item.sha256}/ingest`, post());
    } catch (error) { failures.push(file.name + ": " + error.message); }
  }
  if (selected !== caseId) return;
  await analyze();
  if (failures.length) $("status").textContent = failures.join(" · ");
});
job(cases);
