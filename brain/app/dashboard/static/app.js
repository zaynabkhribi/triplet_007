
"use strict";

const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";
const ACTIVE = new Set(["ACTIVE", "DETECTED", "ESCALATED"]);
const IMPORTANT = new Set([
  "incident_updated",
  "decision_transition",
  "command_transition",
  "event_processing_failed",
  "forecast_failed"
]);

let csrf = "", role = "", current = null, selectedSensor = null;
let stream = null, timer = null, busy = false;
const sensorHistory = new Map();
const seenEvents = new Set();
const seenOrder = [];

function node(tag, text = "", className = "") {
  const result = document.createElement(tag);
  result.textContent = text == null ? "" : String(text);
  if (className) result.className = className;
  return result;
}

function svg(tag, attributes = {}, text = null) {
  const element = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes))
    element.setAttribute(name, String(value));
  if (text !== null) element.textContent = String(text);
  return element;
}

function tag(text, state = "") {
  return node("span", text || "—", `tag ${state}`);
}

function empty(title, description) {
  const box = node("div", "", "empty");
  box.append(node("strong", title), node("span", description));
  return box;
}

function number(value, digits = 0) {
  const n = Number(value);
  return Number.isFinite(n)
    ? n.toLocaleString(undefined, { maximumFractionDigits: digits })
    : "—";
}

function valueText(value) {
  if (value === null || value === undefined) return "—";
  const n = Number(value);
  return Number.isFinite(n) ? number(n, 2) : String(value);
}

function duration(value) {
  if (value === null || value === undefined ||
      !Number.isFinite(Number(value))) return "—";
  const ms = Number(value);
  return ms < 1000 ? `${number(ms, 0)} ms` : `${number(ms / 1000, 1)} s`;
}

function clock(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? "—"
    : d.toLocaleTimeString([], {
        hour: "2-digit", minute: "2-digit", second: "2-digit"
      });
}

function timeLabel(iso) {
  if (!iso) return "No trusted timestamp";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Invalid timestamp";
  return `Updated ${clock(iso)}`;
}

function human(value) {
  return String(value || "unknown")
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function stateClass(value) {
  const v = String(value || "").toLowerCase();
  if ([
    "trusted", "available", "active", "approved", "executed",
    "running", "connected", "succeeded", "resolved"
  ].includes(v)) return "good";
  if ([
    "untrusted", "quarantined", "failed", "rejected",
    "expired", "offline", "critical", "unknown"
  ].includes(v)) return "bad";
  return "warn";
}

async function request(url, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { ...(options.headers || {}) };
  if (method !== "GET") headers["Content-Type"] = "application/json";

  const response = await fetch(url, {
    credentials: "same-origin", ...options, headers
  });

  if (!response.ok)
    throw new Error(`Request failed (${response.status})`);

  return response.json();
}

function showNotice(text) {
  const box = $("toast");
  box.textContent = text;
  box.classList.toggle("hidden", !text);
}

function enter(session) {
  csrf = session.csrf;
  role = session.role;
  $("login").classList.add("hidden");
  $("console").classList.remove("hidden");
  $("role").textContent = human(role);

  document.querySelectorAll(".control").forEach((button) => {
    button.disabled = role !== "brain";
  });
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("login-error").textContent = "";

  try {
    const session = await request("/dashboard/session", {
      method: "POST",
      headers: { "X-API-Key": $("api-key").value },
      body: "{}"
    });
    $("api-key").value = "";
    enter(session);
    boot();
  } catch (error) {
    $("login-error").textContent = error.message.includes("401")
      ? "Invalid service API key."
      : "Unable to authenticate.";
  }
});

$("logout").addEventListener("click", async () => {
  try {
    await request("/dashboard/session", {
      method: "DELETE",
      headers: { "X-Dashboard-CSRF": csrf },
      body: "{}"
    });
  } catch {}
  if (stream) stream.close();
  if (timer) clearInterval(timer);
  location.reload();
});

function metric(label, value, note, color = "") {
  const card = node("div", "", `metric ${color}`);
  card.append(
    node("span", label, "metric-label"),
    node("strong", value, "metric-value"),
    node("small", note, "metric-note")
  );
  return card;
}

function renderMetrics(m) {
  $("metrics").replaceChildren(
    metric("Incoming rate", `${number(m.incoming_events_per_second, 1)}/s`,
      "Last 10 seconds", "good"),
    metric("Processed", number(m.processed_observations), "Cumulative"),
    metric("Trusted", number(m.trusted_readings),
      "Eligible readings", "good"),
    metric("Rejected", number(m.rejected_readings),
      "Untrusted / expired", m.rejected_readings ? "warn" : ""),
    metric("Active incidents", number(m.active_incidents),
      "Current city state", m.active_incidents ? "critical" : ""),
    metric("Decisions",
      `${number(m.approved_decisions)} / ${number(m.rejected_decisions)}`,
      "Approved / rejected"),
    metric("Executed", number(m.executed_commands),
      "Confirmed commands", "good"),
    metric("Processing p95", duration(m.latency_p95_ms),
      `p50 ${duration(m.latency_p50_ms)} · queue ${number(m.backlog)}`)
  );
}

function rememberReadings(readings) {
  const ordered = [...(readings || [])]
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at));

  for (const reading of ordered) {
    if (!reading || !reading.event_id ||
        seenEvents.has(reading.event_id)) continue;

    if (reading.currently_eligible !== true) continue;
    seenEvents.add(reading.event_id);
    seenOrder.push(reading.event_id);

    if (seenOrder.length > 10000)
      seenEvents.delete(seenOrder.shift());

    if (reading.trust !== "TRUSTED" ||
        !Number.isFinite(Number(reading.value))) continue;

    if (!sensorHistory.has(reading.sensor_id))
      sensorHistory.set(reading.sensor_id, []);

    const series = sensorHistory.get(reading.sensor_id);
    series.push({
      at: reading.at,
      value: Number(reading.value),
      unit: reading.unit
    });

    if (series.length > 120)
      series.splice(0, series.length - 120);
  }
}

function renderCity(city, incidents) {
  const zones = Object.entries(city?.zones || {});
  const allSensors = city?.sensors || {};
  const valid = Object.entries(allSensors)
    .filter(([, sensor]) => sensor.availability === "available").length;

  $("city-state").textContent =
    `${valid}/${Object.keys(allSensors).length} sensors eligible`;

  if (!zones.length) {
    $("city-map").replaceChildren(
      empty("No registered zones",
        "Configure the demonstration city registry.")
    );
    return;
  }

  const container = node("div", "", "districts");

  for (const [zoneId, definition] of zones) {
    const incidentCount = (incidents || []).filter(
      (item) => item.zone_id === zoneId && ACTIVE.has(item.status)
    ).length;

    const district = node(
      "section", "",
      `district ${incidentCount ? "active" : ""}`
    );

    const heading = node("h3", human(zoneId));
    const meta = node("div", "", "district-meta");

    meta.append(node(
      "span",
      incidentCount
        ? `${incidentCount} active incident${incidentCount === 1 ? "" : "s"}`
        : "Normal monitoring"
    ));

    meta.append(node(
      "span", `${(definition.sensors || []).length} sensors`,
      "district-count"
    ));

    const sensorGrid = node("div", "", "district-sensors");

    for (const id of definition.sensors || []) {
      const sensor = allSensors[id];
      if (!sensor) continue;

      const status = sensor.availability === "available"
        ? "good"
        : sensor.availability === "quarantined" ? "bad" : "warn";

      const button = node(
        "button", "",
        `sensor-button ${selectedSensor === id ? "selected" : ""}`
      );

      button.type = "button";
      button.title = `${id}: ${sensor.availability}`;
      button.setAttribute("aria-label", `Inspect ${id}`);

      const top = node("span", "", "sensor-top");
      top.append(
        node("span", "", `sensor-dot ${status}`),
        node("span", id, "sensor-name")
      );

      const reading = node(
        "span", valueText(sensor.value), "sensor-reading"
      );

      reading.append(node(
        "small", sensor.unit ? ` ${sensor.unit}` : ""
      ));

      // Raw fallback (7.3F-2): when trust fusion has no eligible value, the
      // tile still shows the latest STORED observation, clearly labeled raw.
      const rawNow = current?.raw_latest?.[id];
      if ((sensor.value === null || sensor.value === undefined) && rawNow) {
        reading.append(node(
          "small", ` (raw ${rawNow.value}${rawNow.unit ? " " + rawNow.unit : ""})`
        ));
      }

      button.append(top, reading);

      button.addEventListener("click", () => {
        selectedSensor = id;
        renderCity(current.city, current.incidents);
        renderSelected();
      });

      sensorGrid.append(button);
    }

    district.append(heading, meta, sensorGrid);
    container.append(district);
  }

  $("city-map").replaceChildren(container);
}

function recordRow(title, note, status, statusText) {
  const row = node("div", "", "record-row");
  const text = node("div");

  text.append(
    node("div", title, "record-title"),
    node("div", note, "record-note")
  );

  row.append(
    text,
    tag(statusText || human(status), stateClass(status))
  );
  return row;
}

function renderIncidents(data) {
  const list = $("response-list");
  list.replaceChildren();

  const incidents = [...(data.incidents || [])].sort(
    (a, b) => Number(ACTIVE.has(b.status)) -
              Number(ACTIVE.has(a.status))
  );

  const active = incidents.filter((item) => ACTIVE.has(item.status));
  $("active-count").textContent = `${active.length} active`;

  if (!incidents.length) {
    list.append(empty(
      "No incidents detected",
      "The Brain is monitoring incoming trusted measurements."
    ));
  }

  for (const incident of incidents.slice(0, 5)) {
    const card = node(
      "div", "",
      `incident-card ${String(incident.severity || "").toLowerCase()} ` +
      `${incident.status === "RESOLVED" ? "resolved" : ""}`
    );

    const head = node("div", "", "incident-head");

    head.append(
      node("span", human(incident.incident_type), "incident-name"),
      tag(incident.status, stateClass(incident.status))
    );

    card.append(
      head,
      node("div",
        `${human(incident.zone_id)} · ${human(incident.severity)} severity`,
        "incident-meta")
    );

    const foot = node("div", "", "incident-foot");

    foot.append(node(
      "span",
      `Evidence: ${(incident.signals || []).length} supporting signal(s)`
    ));

    const linked = (data.decisions || []).find(
      (decision) => (decision.incident_ids || []).includes(incident.id)
    );

    if (linked) {
      const names = (linked.selected_actions || [])
        .map((action) => human(action.action_type))
        .join(", ");

      foot.append(node(
        "span",
        `Decision: ${human(linked.status)}${names ? ` · ${names}` : ""}`
      ));

      const command = (data.actions || []).find(
        (action) => action.decision_id === linked.id
      );
      if (role === "brain" && linked.status === "EVALUATED") {
        const approve = node("button", "Approve decision", "button primary");
        approve.type = "button";
        approve.addEventListener("click", () => approveDecision(linked.id));
        foot.append(approve);
      } else if (role === "brain" && linked.status === "APPROVED" && !command) {
        const execute = node("button", "Enqueue approved action", "button primary");
        execute.type = "button";
        execute.addEventListener("click", () => executeDecision(linked.id));
        foot.append(execute);
      }
    } else {
      foot.append(node(
        "span", "Decision: no linked plan in current snapshot"
      ));
      if (role === "brain" && ACTIVE.has(incident.status)) {
        const evaluate = node("button", "Evaluate optimal response", "button primary");
        evaluate.type = "button";
        evaluate.addEventListener("click", evaluateDecision);
        foot.append(evaluate);
      }
    }

    foot.append(node(
      "span",
      `Last change: ${clock(incident.updated_at || incident.at)}`
    ));

    card.append(foot);
    list.append(card);
  }

  if (!active.length && incidents.length) {
    list.prepend(empty(
      "No active incidents",
      "Recent incident history is shown below."
    ));
  }
}

async function decisionAction(path, payload = {}) {
  try {
    await request(path, {
      method: "POST",
      headers: { "X-Dashboard-CSRF": csrf },
      body: JSON.stringify(payload)
    });
    await refresh();
  } catch (error) {
    showNotice(`Decision action failed: ${error.message}`);
  }
}

function evaluateDecision() {
  return decisionAction("/dashboard/api/decisions/evaluate");
}

function approveDecision(decisionId) {
  const reason = window.prompt("Approval reason (required):", "Approved mock simulation response");
  if (!reason) return;
  return decisionAction(`/dashboard/api/decisions/${decisionId}/approve`, { reason });
}

function executeDecision(decisionId) {
  return decisionAction(`/dashboard/api/decisions/${decisionId}/execute`);
}

function renderSelected() {
  const sensor = current?.city?.sensors?.[selectedSensor];

  if (!sensor) {
    $("detail-title").textContent = "Select a sensor";
    $("detail-status").textContent = "No selection";
    $("detail-status").className = "tag";
    $("detail-body").textContent = "Choose a sensor in the city overview.";
    $("sensor-chart").replaceChildren(
      empty("No selected sensor", "Sensor readings will appear here.")
    );
    return;
  }

  $("detail-title").textContent = selectedSensor;
  $("detail-status").textContent = human(sensor.availability);
  $("detail-status").className =
    `tag ${stateClass(sensor.availability)}`;

  const body = $("detail-body");
  body.replaceChildren(
    node("span",
      `${human(sensor.measurement)} · ${valueText(sensor.value)} ${sensor.unit || ""}`),
    node("span", human(sensor.trust_status)),
    node("span", timeLabel(sensor.last_observed_at))
  );

  // Raw/untrusted observations are distinct from trusted eligible state:
  // show the latest real readings even when nothing is trust-eligible yet.
  const rawNow = current?.raw_latest?.[selectedSensor];
  const rawRecent = (current?.readings || [])
    .filter((r) => r.sensor_id === selectedSensor)
    .slice(0, 3);
  if (rawNow) {
    const label = node("span",
      `raw observed: ${rawNow.value} ${rawNow.unit} (${timeLabel(rawNow.at)})` +
      (rawRecent.length > 1 ? ` · +${rawRecent.length - 1} older` : ""));
    label.className = "tag";
    body.append(label);
  }

  drawChart(selectedSensor, sensor.unit);
}

function drawChart(id, unit) {
  const host = $("sensor-chart");
  const points = (sensorHistory.get(id) || [])
    .filter((p) => Number.isFinite(p.value));

  if (points.length < 2) {
    host.replaceChildren(empty(
      "Waiting for measurements",
      "The chart needs two trusted readings observed while this page is open."
    ));
    return;
  }

  const w = 760, h = 190;
  const left = 53, right = 12, top = 15, bottom = 30;
  const values = points.map((p) => p.value);

  let low = Math.min(...values);
  let high = Math.max(...values);

  const margin = Math.max(
    (high - low) * 0.16,
    Math.abs(high) * 0.01,
    0.1
  );

  low -= margin;
  high += margin;

  const minT = Date.parse(points[0].at);
  const maxT = Date.parse(points[points.length - 1].at);

  const usableTime =
    Number.isFinite(minT) &&
    Number.isFinite(maxT) &&
    maxT > minT;

  const x = (p, index) => usableTime
    ? left + (Date.parse(p.at) - minT) / (maxT - minT) *
        (w - left - right)
    : left + index / (points.length - 1) * (w - left - right);

  const y = (v) =>
    top + (high - v) / (high - low) * (h - top - bottom);

  const canvas = svg("svg", {
    viewBox: `0 0 ${w} ${h}`,
    role: "img",
    "aria-label": `Recent trusted ${human(id)} measurements`
  });

  for (let i = 0; i < 4; i++) {
    const yy = top + i * (h - top - bottom) / 3;

    canvas.append(svg("line", {
      x1: left, y1: yy, x2: w - right, y2: yy,
      class: "chart-grid"
    }));

    canvas.append(svg(
      "text",
      { x: 3, y: yy + 4, class: "chart-axis" },
      number(high - (high - low) * i / 3, 1)
    ));
  }

  const path = points.map((p, i) =>
    `${i ? "L" : "M"}${x(p, i).toFixed(2)},${y(p.value).toFixed(2)}`
  ).join(" ");

  canvas.append(svg("path", {
    d: path, class: "chart-line"
  }));

  const last = points[points.length - 1];

  canvas.append(svg("circle", {
    cx: x(last, points.length - 1),
    cy: y(last.value),
    r: 5,
    class: "chart-marker"
  }));

  canvas.append(svg(
    "text",
    { x: left, y: h - 5, class: "chart-axis" },
    clock(points[0].at)
  ));

  canvas.append(svg(
    "text",
    {
      x: w - right, y: h - 5,
      "text-anchor": "end", class: "chart-axis"
    },
    `${clock(last.at)} · ${unit || ""}`
  ));

  host.replaceChildren(canvas);
}

function renderGuardian(data) {
  const m = data.metrics || {};
  const all = m.registered_sensors || 0;

  const percent = all
    ? `${number(100 * (m.eligible_sensors || 0) / all, 1)}% sensors eligible now`
    : "No verdicts";

  $("trust-summary").textContent = percent;

  const target = $("trust-list");
  target.replaceChildren();

  // Evidence reconciliation status (7.3F-1): audit-tail matches are
  // verification-only evidence and MUST NOT be shown as TRUSTED grants.
  if (data.evidence_mode === "audit_tail_reconciliation") {
    const banner = node("span",
      `Evidence reconciliation: ${data.audit_verified_matches ?? "?"} audit events accounted ` +
      `· ${data.audit_pending ?? "?"} pending exact-match retries · TRUSTED grants: ${m.trusted_readings || 0}`);
    banner.className = "tag";
    target.append(banner);
  }

  if (data.evidence_mode === "guardian_passports") {
    target.append(recordRow("Authenticated Guardian Passports",
      `${m.eligible_sensors || 0}/${all} sensors eligible · ${m.trusted_readings || 0} readings eligible now`, m.eligible_sensors ? "available" : "stale"));
    target.append(node("p", "Signatures and observation freshness checked. Eligibility expires; Passport TTL does not prove current Guardian revocation or quarantine status."));
    target.append(node("p", `Durable TRUSTED records: ${m.durable_trusted_readings || 0}. Audit reconciliation remains verification-only.`));
    return;
  }
  const verdicts = data.verdicts || [];

  if (!verdicts.length) {
    target.append(empty(
      "Awaiting Guardian",
      "No verdicts received yet."
    ));
    return;
  }

  const counts = new Map();

  for (const verdict of verdicts) {
    const key = `${verdict.status || "UNKNOWN"} · ` +
                `${verdict.reason_code || "Unspecified"}`;

    counts.set(key, (counts.get(key) || 0) + 1);
  }

  for (const [label, count] of [...counts.entries()]
    .sort((a, b) => b[1] - a[1]).slice(0, 6)) {

    const status = label.split(" · ")[0];

    target.append(recordRow(
      human(status),
      `${human(label.split(" · ").slice(1).join(" · "))} · latest ${verdicts.length} verdicts`,
      status,
      `${count}`
    ));
  }
}

function renderActions(actions) {
  const host = $("action-list");
  host.replaceChildren();

  if (!actions?.length) {
    host.append(empty(
      "No actuator commands",
      "Approved responses will appear after execution."
    ));
    return;
  }

  for (const action of actions.slice(0, 6)) {
    const actionType =
      action.command?.action ||
      action.candidate?.action_type ||
      "Actuator command";

    host.append(recordRow(
      human(action.actuator_id),
      `${human(actionType)} · ${clock(action.created_at)}`,
      action.status
    ));
  }
}

function renderForecasts(forecasts) {
  const host = $("forecast-state");
  host.replaceChildren();

  if (!forecasts?.length) {
    host.append(empty(
      "No eligible forecasts",
      "Forecasts require model artifacts and compatible trusted historical data."
    ));
    return;
  }

  for (const forecast of forecasts.slice(0, 5)) {
    host.append(recordRow(
      human(forecast.family || forecast.model_family || "Forecast"),
      `${clock(forecast.at)} · ` +
      `${forecast.currently_eligible ? "Currently eligible" : "Not currently eligible"}`,
      forecast.currently_eligible ? "available" : "unverified",
      forecast.currently_eligible ? "Eligible" : "Historical"
    ));
  }
}

function timelineMessage(item) {
  const data = item.detail || {};
  const stage = item.stage;

  if (stage === "incident_updated")
    return `${human(data.incident_type)} · ${human(data.status)}`;

  if (stage === "decision_transition")
    return `Decision ${human(data.status)}`;

  if (stage === "command_transition")
    return `Command ${human(data.status)}` +
      `${data.actuator_id ? ` · ${data.actuator_id}` : ""}`;

  if (stage === "event_processing_failed")
    return "Sensor event processing failed";

  if (stage === "forecast_failed")
    return "Forecast execution failed";

  return human(stage);
}

function renderTimeline(items) {
  const host = $("timeline");
  host.replaceChildren();

  const important = (items || []).filter(
    (item) => item.source !== "scenario" &&
              IMPORTANT.has(item.stage)
  );

  if (!important.length) {
    host.append(empty(
      "Monitoring events",
      "Major incidents, decisions, and command transitions will appear here."
    ));
    return;
  }

  for (const item of important.slice(0, 24)) {
    const row = node("div", "", "activity-row");
    row.append(node("span", clock(item.at), "activity-time"));

    const dot = node(
      "span", "",
      `activity-dot ${stateClass(item.detail?.status || "")}`
    );

    row.append(dot);

    const content = node("div");

    content.append(node(
      "div", timelineMessage(item), "activity-message"
    ));

    const details = document.createElement("details");

    const summary = node(
      "summary",
      `${human(item.stage)} · details`,
      "activity-detail"
    );

    const pre = node(
      "pre",
      JSON.stringify(item.detail || {}, null, 2),
      "activity-detail"
    );

    pre.style.whiteSpace = "pre-wrap";
    pre.style.overflowWrap = "anywhere";

    details.append(summary, pre);
    content.append(details);
    row.append(content);
    host.append(row);
  }
}

function setService(id, text, connected) {
  const target = $(id);
  target.textContent = text;
  target.className =
    `service ${connected ? "online" : "offline"}`;
}

function render(snapshot) {
  snapshot = expireAuthorization(snapshot);
  current = snapshot;
  rememberReadings(snapshot.readings);

  const sensorIds = Object.keys(snapshot.city?.sensors || {});

  if (!selectedSensor ||
      !snapshot.city.sensors[selectedSensor]) {
    selectedSensor = sensorIds.find(
      (id) => snapshot.city.sensors[id].availability === "available"
    ) || sensorIds[0] || null;
  }

  const evidenceMode = snapshot.evidence_mode === "guardian_passports"
      ? "AUTHENTICATED GUARDIAN PASSPORTS · time-limited eligibility"
      : snapshot.evidence_mode === "audit_tail_reconciliation"
      ? "VERIFIED EVIDENCE (audit reconciliation, not authorized trust)"
      : "GUARDIAN VERDICTS";
  $("env").textContent =
    `${human(snapshot.environment)} / ${evidenceMode}`;
  document.body.dataset.mode = snapshot.environment;

  $("updated").textContent =
    `Operational snapshot · ${clock(snapshot.generated_at)} · Values from Brain database`;

  const security = snapshot.security || {};
  $("runtime-context").textContent = security.mock_controls_enabled ? "Configured Twin controls" : "Live sensor observations";
  $("runtime-safety").textContent = `Actuator execution: ${security.actuator_execution_enabled ? "enabled" : "disabled"} · Automatic approval: ${security.automatic_approval_enabled ? "enabled" : "disabled"}`;
  document.querySelectorAll(".control, [data-injection]").forEach(b => { b.disabled = role !== "brain" || !security.mock_controls_enabled; });
  renderMetrics(snapshot.metrics);
  renderCity(snapshot.city, snapshot.incidents);
  renderIncidents(snapshot);
  renderSelected();
  renderGuardian(snapshot);
  renderActions(snapshot.actions);
  renderForecasts(snapshot.forecasts);
}

async function refresh() {
  if (busy) return;
  busy = true;

  try {
    const snapshot = await request("/dashboard/api/snapshot");
    render(snapshot);
  } catch (error) {
    setService("brain-status", "Brain: unavailable", false);
    showNotice(`Dashboard refresh failed. ${error.message}`);
  } finally {
    busy = false;
  }
}

let providersBusy = false;
async function refreshProviders() {
  if (providersBusy) return;
  providersBusy = true;
  try {
    const providers = await request("/dashboard/api/operations");
    setService(
      "brain-status",
      providers.brain?.processing ? "Brain: processing" : "Brain: idle",
      Boolean(providers.brain?.processing)
    );

    // Remote Twin: liveness is inferred from Orion entity freshness (the
    // publisher is the partner's hosted Twin, not a local process).
    if (providers.twin?.connected) {
      setService(
        "twin-status",
        providers.twin.running
          ? `Twin: publishing (age ${providers.twin.last_publish_age_s ?? "?"}s)`
          : `Twin: stale (last publish ${providers.twin.last_publish_age_s ?? "?"}s ago)`,
        Boolean(providers.twin.running)
      );
    } else {
      setService("twin-status", "Twin: not connected", false);
    }

    setService(
      "guardian-status",
      providers.guardian?.connected ? "Guardian: connected" : "Guardian: offline",
      Boolean(providers.guardian?.connected)
    );
  } catch {
    setService("guardian-status", "Guardian: status unavailable", false);
    setService("twin-status", "Twin: status unavailable", false);
  } finally { providersBusy = false; }
}

async function control(action, payload = {}) {
  showNotice("");

  try {
    await request(`/dashboard/api/operations/${action}`, {
      method: "POST",
      headers: { "X-Dashboard-CSRF": csrf },
      body: JSON.stringify(payload)
    });

    if (action === "inject") {
      const desired = {
        traffic: "traffic-central-01",
        fire: "smoke-north-01",
        water: "water-riverside-01"
      }[payload.injection];

      if (desired) selectedSensor = desired;
    }

    await refresh();
  } catch (error) {
    showNotice(`Operation failed: ${error.message}`);
  }
}

$("start").addEventListener("click", () => control("start"));
$("stop").addEventListener("click", () => control("stop"));
$("clear").addEventListener("click", () => control("clear"));

document.querySelectorAll("[data-injection]").forEach((button) => {
  button.addEventListener("click", () =>
    control("inject", { injection: button.dataset.injection })
  );
});

function connect() {
  if (stream) stream.close();

  stream = new EventSource("/dashboard/events");

  stream.addEventListener("open", () => {
    $("stream-state").textContent = "Connected";
    $("stream-state").className = "tag good";
  });

  stream.addEventListener("error", () => {
    $("stream-state").textContent = "Reconnecting";
    $("stream-state").className = "tag warn";
  });

  stream.addEventListener("timeline", (event) => {
    try {
      renderTimeline(JSON.parse(event.data));
    } catch {
      $("stream-state").textContent = "Timeline error";
    }
  });
}

function boot() {
  if (timer) clearInterval(timer);
  refresh();
  connect();
  refreshProviders();
  timer = setInterval(() => { refresh(); refreshProviders(); }, 1000);
}

async function restore() {
  try {
    enter(await request("/dashboard/session"));
    boot();
  } catch {}
}

restore();

// Expire visible authorization even when network refreshes fail or are delayed.
function expireAuthorization(snapshot, now = Date.now()) {
  let changed = false;
  const next = structuredClone(snapshot);
  for (const sensor of Object.values(next.city?.sensors || {})) {
    if (sensor.availability !== "available") continue;
    const live = sensor.evidence.filter(e => !e.authorization_expires_at || Date.parse(e.authorization_expires_at) > now);
    if (live.length !== sensor.evidence.length) {
      // Do not continue displaying a fused value after any contributing grant expires.
      sensor.evidence = [];
      sensor.value = null;
      sensor.statistics = {};
      sensor.availability = "stale";
      sensor.trust_status = "unverified";
      sensor.last_observed_at = null;
      changed = true;
    }
  }
  if (!changed) return snapshot;
  const eligible = new Set(Object.values(next.city.sensors).flatMap(s => s.evidence.map(e => e.event_id)));
  next.metrics.trusted_readings = eligible.size;
  next.metrics.eligible_sensors = Object.values(next.city.sensors).filter(s => s.availability === "available").length;
  next.readings = next.readings.map(r => ({...r, currently_eligible: eligible.has(r.event_id), trust: eligible.has(r.event_id) ? "TRUSTED" : "EXPIRED"}));
  return next;
}

setInterval(() => {
  if (!current) return;
  const next = expireAuthorization(current);
  if (next !== current) render(next);
}, 250);

