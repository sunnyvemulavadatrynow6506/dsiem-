// Griffendo v5 - Detections, rules, timeline, endpoint and the home page's detection overview.
// Detection happens on the server (detection engine); this file only displays, filters and manages.

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];
const SEVERITY_NOTES = { Critical: "INVESTIGATE NOW", High: "REVIEW SAME DAY", Medium: "DAILY TRIAGE", Low: "REVIEW AS CONTEXT", Informational: "CONTEXT" };
const VERDICTS = { true_positive: "True positive", false_positive: "False positive", benign: "Benign / expected", needs_investigation: "Needs investigation" };
const DET_STATUSES = ["New", "Investigating", "Resolved"];
const SOURCE_LABELS = { rule: "Rule matcher", chain: "Chain correlator", behavior: "Behaviour model" };
const KIND_LABELS = { single: "Single event", sequence: "Sequence", threshold: "Threshold", new_terms: "First seen", wazuh: "Wazuh tree", chain: "Chain", behavior: "Behaviour" };
const SUPPORT_LABELS = { fully_supported: "Fully supported", requires_optional_source: "Optional source", partially_supported: "Partial", custom: "Custom" };
const ORIGIN_LABELS = { elastic: "Elastic", wazuh: "Wazuh", catalog: "Catalog", griffendo: "Griffendo", custom: "Custom" };

state.det = { scope: "active", offset: 0, limit: 50, total: 0, timer: null, refreshSeconds: 60, lastHtml: "", selected: null, debounce: null, ruleId: null, loadedAt: null };
state.rulesView = { tab: "rules", offset: 0, limit: 100, total: 0, debounce: null, schema: null, items: [] };
state.metrics = state.metrics || { displayLatencySeconds: null, lastLiveRefresh: null, timelineRenderMs: null };
window.__griffendo = state.metrics;

const sevClass = (severity) => `sev-${String(severity || "").toLowerCase().replace(/[^a-z]/g, "")}`;
const sevPill = (severity) => `<span class="sev-pill ${sevClass(severity)}">${escapeHtml(severity)}</span>`;
const statusPill = (status) => `<span class="status-pill status-${String(status || "new").toLowerCase().replace(/\s+/g, "-")}">${escapeHtml(status || "New")}</span>`;
const fullTime = (value) => { const date = new Date(value); return Number.isNaN(date.getTime()) ? String(value || "") : `${date.toLocaleString()} (local) · ${date.toISOString()} UTC`; };
const dayTime = (value) => { const date = new Date(value); return !value || Number.isNaN(date.getTime()) ? "—" : date.toLocaleString([], { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }); };
const ago = (value) => { const t = Date.parse(value); if (Number.isNaN(t)) return "never"; const s = Math.max(0, Math.round((Date.now() - t) / 1000)); return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : s < 86400 ? `${Math.round(s / 3600)}h ago` : `${Math.round(s / 86400)}d ago`; };
const riskBar = (score) => `<span class="risk-cell" title="Risk score ${Number(score).toFixed(0)}/100"><span class="risk-track"><span class="risk-fill ${sevClass(scoreSeverity(score))}" style="width:${Math.max(3, Math.min(100, score))}%"></span></span><b>${Number(score).toFixed(0)}</b></span>`;
let BANDS = { critical: 90, high: 70, medium: 40, low: 20 };
const scoreSeverity = (score) => (score >= BANDS.critical ? "Critical" : score >= BANDS.high ? "High" : score >= BANDS.medium ? "Medium" : score >= BANDS.low ? "Low" : "Informational");

async function apiSend(method, path, body) {
  const response = await fetch(path, { method, headers: { Accept: "application/json", "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(typeof data.detail === "string" ? data.detail : `Request failed (${response.status})`);
    error.status = response.status; error.data = data;
    throw error;
  }
  return data;
}

function fillSelect(select, values, label) {
  const current = select.value;
  select.innerHTML = `<option value="">${escapeHtml(label)}</option>` + values.map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value)}</option>`).join("");
  if (values.includes(current)) select.value = current;
}

// ---------- Date and time filter (Event explorer and Detections share the widget, not the selection) ----------
const PRESETS = [["", "All time"], ["15m", "Last 15 minutes"], ["1h", "Last hour"], ["6h", "Last 6 hours"], ["24h", "Last 24 hours"], ["7d", "Last 7 days"], ["custom", "Custom range…"]];

function mountTimeFilter(selector, onChange) {
  const root = $(selector);
  const preset = root.dataset.default || "";
  root.innerHTML = `<label class="tf-label">TIME <select class="filter-select tf-preset" aria-label="Time range">${PRESETS.filter(([v]) => v || preset === "").map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}</select></label>
    <span class="tf-custom" hidden>
      <label>From <input type="date" class="filter-input tf-start-date" aria-label="Start date"><input type="time" class="filter-input tf-start-time" step="1" aria-label="Start time"></label>
      <label>to <input type="date" class="filter-input tf-end-date" aria-label="End date"><input type="time" class="filter-input tf-end-time" step="1" aria-label="End time"></label>
      <button type="button" class="quick-button tf-apply">Apply</button></span>
    <button type="button" class="pager-button text-button tf-clear">Clear</button>
    <span class="tf-applied" aria-live="polite"></span><span class="tf-error" role="alert"></span>`;
  const select = $(".tf-preset", root);
  select.value = preset;
  root.dataset.applied = JSON.stringify(preset ? { range: preset } : {});
  const custom = $(".tf-custom", root);
  const showApplied = () => { $(".tf-applied", root).textContent = describeRange(JSON.parse(root.dataset.applied || "{}")); };
  select.addEventListener("change", () => {
    $(".tf-error", root).textContent = "";
    if (select.value === "custom") {
      custom.hidden = false;
      const end = new Date(), start = new Date(Date.now() - 3600000);
      const fill = (d, cls) => { $(`.tf-${cls}-date`, root).value = localDate(d); $(`.tf-${cls}-time`, root).value = localClock24(d); };
      if (!$(".tf-start-date", root).value) { fill(start, "start"); fill(end, "end"); }
      return;
    }
    custom.hidden = true;
    root.dataset.applied = JSON.stringify(select.value ? { range: select.value } : {});
    showApplied(); onChange();
  });
  $(".tf-apply", root).addEventListener("click", () => {
    const start = combine($(".tf-start-date", root).value, $(".tf-start-time", root).value);
    const end = combine($(".tf-end-date", root).value, $(".tf-end-time", root).value);
    if (!start && !end) { $(".tf-error", root).textContent = "Enter a start and/or an end."; return; }
    if (start && end && start > end) { $(".tf-error", root).textContent = "The start is later than the end."; return; }
    $(".tf-error", root).textContent = "";
    const applied = {};
    if (start) applied.start = start.toISOString();
    if (end) applied.end = end.toISOString();
    root.dataset.applied = JSON.stringify(applied);
    showApplied(); onChange();
  });
  $(".tf-clear", root).addEventListener("click", () => {
    select.value = preset; custom.hidden = true; $(".tf-error", root).textContent = "";
    root.dataset.applied = JSON.stringify(preset ? { range: preset } : {});
    showApplied(); onChange();
  });
  showApplied();
}

const localDate = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
const localClock24 = (d) => `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
function combine(date, time) {
  if (!date) return null;
  const value = new Date(`${date}T${time || "00:00:00"}`);   // local time, converted to UTC by toISOString()
  return Number.isNaN(value.getTime()) ? null : value;
}

function describeRange(applied) {
  if (applied.range) return `Showing: ${PRESETS.find(([v]) => v === applied.range)?.[1] || applied.range}`;
  if (applied.start || applied.end) {
    const fmt = (v) => (v ? new Date(v).toLocaleString([], { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false }) : "…");
    return `Showing: ${fmt(applied.start)} → ${fmt(applied.end)} (local time, ${Intl.DateTimeFormat().resolvedOptions().timeZone})`;
  }
  return "Showing: all time";
}

function timeFilterParams(selector) {
  const root = $(selector);
  if (!root || !root.dataset.applied) return [];
  return Object.entries(JSON.parse(root.dataset.applied));
}

// ---------- Home page: three-column detections overview ----------
async function loadDetectionOverview() {
  try {
    const data = await api("/api/detections/summary?range=7d&recent=4");
    renderDetectionOverview(data);
    updateDetectionBadge(data);
  } catch (error) { $("#det-columns").innerHTML = emptyState(error.message); }
}

function detectionMini(item) {
  return `<button type="button" class="det-mini" data-det-id="${escapeHtml(item.id)}"><span class="det-mini-top">${sevPill(item.severity)}<span class="det-mini-time">${escapeHtml(ago(item.det_time))}</span></span><span class="det-mini-title">${escapeHtml(item.title)}</span><span class="det-mini-sub">${escapeHtml(item.summary || item.category || "")}</span></button>`;
}

function renderDetectionOverview(data) {
  const statusText = { attention: "Critical or High detections need attention", review: "Medium detections to review", clear: "No Critical, High or Medium detections" }[data.overall_status];
  const processing = data.processing || {};
  const model = data.model || {};
  const counts = data.counts || {};
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const bar = SEVERITY_ORDER.map((s) => (counts[s] ? `<span class="dist-seg ${sevClass(s)}" style="flex:${counts[s]}" title="${s}: ${counts[s]}"></span>` : "")).join("");
  $("#det-status-row").innerHTML = `
    <div class="det-status ${data.overall_status}"><span class="det-status-dot"></span><b>${escapeHtml(statusText)}</b></div>
    <div class="det-fact"><span>LATEST DETECTION</span><b>${data.latest_detection ? `${escapeHtml(dayTime(data.latest_detection))} · ${ago(data.latest_detection)}` : "None yet"}</b></div>
    <div class="det-fact"><span>ACTIVE · SUPPRESSED</span><b>${number(data.total_active)} · ${number(data.suppressed)}</b></div>
    <div class="det-fact"><span>ENGINE</span><b>${processing.backlog_events ? `Processing ${number(processing.backlog_events)} queued events` : "Up to date"}${processing.errors ? ` · ${processing.errors} rule error(s)` : ""}</b></div>
    <div class="det-fact"><span>BEHAVIOUR MODEL</span><b>${escapeHtml(stageLabel(model.stage))}</b></div>
    <div class="det-dist" role="img" aria-label="Severity distribution">${bar || `<span class="dist-empty">No active detections</span>`}</div>`;
  const columns = [["critical_high", "Critical & High", "Critical,High"], ["medium", "Medium", "Medium"], ["low_info", "Low & Informational", "Low,Informational"]];
  $("#det-columns").innerHTML = columns.map(([key, label, filter]) => {
    const column = data.columns[key];
    const countParts = column.severities.map((s) => `<button type="button" class="det-count ${sevClass(s)}" data-go-severity="${s}"><b>${number(column.counts[s])}</b><span>${s}</span></button>`).join("");
    const recent = column.recent.length ? column.recent.map(detectionMini).join("") : `<div class="empty-state small">No ${escapeHtml(label.toLowerCase())} detections in the last 7 days.</div>`;
    return `<div class="det-column"><div class="det-column-head"><h3>${escapeHtml(label)}</h3><button type="button" class="text-action" data-go-severity="${filter}">View all ${number(column.total)} →</button></div>
      <div class="det-counts">${countParts}</div><div class="det-recent">${recent}</div></div>`;
  }).join("");
  $("#det-overview-updated").textContent = `UPDATED ${new Date(data.generated_at || Date.now()).toLocaleTimeString([], { hour12: false })}`;
}

const stageLabel = (stage) => ({ learn: "Learning (no behaviour alerts)", shadow: "Shadow (scoring, no alerts)", active: "Active (alerts on)", adapt: "Adapting to change" }[stage] || "—");

function updateDetectionBadge(summary) {
  const badge = $("#detection-nav-count");
  const urgent = (summary.counts?.Critical || 0) + (summary.counts?.High || 0);
  badge.hidden = !urgent;
  badge.textContent = urgent > 999 ? "999+" : String(urgent);
  badge.title = `${urgent} Critical/High active detections (last 7 days)`;
}

function refreshDetectionBadge(force) {
  if (!force && Date.now() - (state.det.badgeAt || 0) < state.det.refreshSeconds * 1000) return;
  state.det.badgeAt = Date.now();
  api("/api/detections/summary?range=7d&recent=1").then(updateDetectionBadge).catch(() => {});
}

function goDetections(filters = {}) {
  $("#det-severity").value = filters.severity || "";
  if (filters.severity && !Array.from($("#det-severity").options).some((o) => o.value === filters.severity)) $("#det-severity").add(new Option(filters.severity, filters.severity));
  $("#det-severity").value = filters.severity || "";
  state.det.ruleId = filters.ruleId || null;
  state.det.offset = 0;
  setView("detections");
}

// ---------- Detections page ----------
function detectionParams() {
  const params = new URLSearchParams({ limit: state.det.limit, offset: state.det.offset, scope: state.det.scope, sort: $("#det-sort").value });
  const v = (id) => $(id).value.trim();
  if (v("#det-search")) params.set("q", v("#det-search"));
  if (v("#det-severity")) params.set("severity", v("#det-severity"));
  if (v("#det-category")) params.set("category", v("#det-category"));
  if (v("#det-rule")) params.set("rule", v("#det-rule"));
  if (/^\d+$/.test(v("#det-event-id"))) params.set("event_id", v("#det-event-id"));
  if (v("#det-status")) params.set("status", v("#det-status"));
  if (v("#det-verdict")) params.set("verdict", v("#det-verdict"));
  if (v("#det-rule-state")) params.set("rule_state", v("#det-rule-state"));
  if (v("#det-source")) params.set("source", v("#det-source"));
  if (state.det.ruleId) params.set("rule_id", state.det.ruleId);
  const range = timeFilterParams("#det-time");
  range.forEach(([key, value]) => params.set(key, value));
  if (!range.length) params.set("range", "all");
  return params;
}

function occurrenceTag(item) {
  /* v6: how much evidence this one episode holds. Repetition is the difference between a
     typo and a brute-force run, so it is shown inline, not hidden in a tooltip. */
  const parts = [];
  const n = Number(item.occurrence_count || 0);
  if (n > 1) parts.push(`${number(n)} occurrences`);
  if (Number(item.signal_count || 0) > 1) parts.push(`${number(item.signal_count)} signals`);
  if (Number(item.event_count || 0) > 1) parts.push(`${number(item.event_count)} events`);
  if (!parts.length) return "";
  const escalated = item.escalated ? `<span class="escalation-tag" title="Repetition raised the score; see the explanation">escalated</span>` : "";
  return `<span class="occurrence-tag">${escapeHtml(parts.join(" · "))}${escalated}</span>`;
}

function detectionRow(item) {
  const mitre = (item.mitre || []).slice(0, 2).map((m) => m.technique).filter(Boolean).join(", ");
  const ids = (item.event_ids || []).slice(0, 4).join(", ") + ((item.event_ids || []).length > 4 ? "…" : "");
  const sources = (item.sources || []).map((s) => `<span class="src-tag src-${s}">${escapeHtml(SOURCE_LABELS[s] || s)}</span>`).join("");
  const state_ = item.active ? "" : `<span class="inactive-note">${escapeHtml(item.decision === "suppressed" ? "suppressed" : `rule ${item.rule_state}`)}</span>`;
  return `<tr class="clickable-row${item.active ? "" : " inactive-row"}${state.det.selected === item.id ? " selected-row" : ""}" data-det-id="${escapeHtml(item.id)}" tabindex="0">
    <td class="mono-cell" title="${escapeHtml(fullTime(item.det_time))}">${escapeHtml(dayTime(item.det_time))}</td>
    <td>${sevPill(item.severity)}</td><td>${riskBar(item.score)}<small class="conf">conf. ${escapeHtml(item.confidence)}</small></td>
    <td><b class="det-title">${escapeHtml(item.title)}</b><span class="det-sub">${sources}${escapeHtml(item.summary || "")}</span>${occurrenceTag(item)}${state_}</td>
    <td class="mono-cell">${escapeHtml(ids)}</td>
    <td><span class="mono-cell">${escapeHtml(item.primary_rule_id)}</span>${item.rule_ids.length > 1 ? `<small class="det-sub">+${item.rule_ids.length - 1} rule(s)</small>` : ""}</td>
    <td>${escapeHtml(item.category || "")}${mitre ? `<small class="det-sub mono-cell">${escapeHtml(mitre)}</small>` : ""}</td>
    <td>${escapeHtml(item.user_name || "—")}<small class="det-sub">${escapeHtml(item.process_name || "")}</small></td>
    <td>${statusPill(item.status)}${item.verdict ? `<small class="det-sub">${escapeHtml(VERDICTS[item.verdict] || item.verdict)}</small>` : ""}</td></tr>`;
}

async function loadDetections(options = {}) {
  const body = $("#det-body");
  const scroller = body.closest(".table-scroll");
  const scrollTop = options.preserve ? window.scrollY : 0;
  const innerTop = options.preserve && scroller ? scroller.scrollTop : 0;
  try {
    const [data, summary] = await Promise.all([api(`/api/detections?${detectionParams()}`), api(`/api/detections/summary?${new URLSearchParams(timeFilterParams("#det-time").length ? timeFilterParams("#det-time") : [["range", "all"]])}`)]);
    state.det.total = data.total;
    renderSeverityCards(summary);
    updateDetectionBadge(summary);
    const html = data.items.length ? data.items.map(detectionRow).join("") : `<tr><td colspan="9">${emptyState(state.det.scope === "active" ? "No active detections match these filters. Detections appear here as soon as the engine processes matching events." : "Nothing stored in this view for these filters.")}</td></tr>`;
    if (html !== state.det.lastHtml) { body.innerHTML = html; state.det.lastHtml = html; }
    const categories = [...new Set(data.items.map((i) => i.category).filter(Boolean))].sort();
    const select = $("#det-category");
    const known = new Set(Array.from(select.options).map((o) => o.value));
    categories.forEach((c) => { if (!known.has(c)) select.add(new Option(c, c)); });
    const label = describeRange(Object.fromEntries(timeFilterParams("#det-time")));
    $("#det-count").textContent = `${number(data.total)} detection${data.total === 1 ? "" : "s"} · ${label.replace("Showing: ", "")}`;
    $("#det-page-label").textContent = `Page ${Math.floor(state.det.offset / state.det.limit) + 1} of ${Math.max(1, Math.ceil(data.total / state.det.limit))}`;
    $("#det-prev").disabled = state.det.offset === 0;
    $("#det-next").disabled = state.det.offset + state.det.limit >= data.total;
    const chip = $("#det-rule-chip");
    chip.hidden = !state.det.ruleId;
    if (state.det.ruleId) chip.innerHTML = `Rule ${escapeHtml(state.det.ruleId)} <button type="button" aria-label="Remove rule filter">&#10005;</button>`;
    state.det.loadedAt = Date.now();
    updateDetectionRefreshNote();
    if (options.preserve) { window.scrollTo({ top: scrollTop }); if (scroller) scroller.scrollTop = innerTop; }
  } catch (error) { body.innerHTML = `<tr><td colspan="9">${emptyState(error.message)}</td></tr>`; }
}

function renderSeverityCards(summary) {
  const counts = summary.counts || {};
  $("#det-severity-grid").innerHTML = SEVERITY_ORDER.map((s) => `<button type="button" class="severity-card ${sevClass(s)}" data-go-severity="${s}"><span class="severity-name">${s}</span><span class="severity-count">${number(counts[s])}</span><span class="severity-note">${SEVERITY_NOTES[s]}</span></button>`).join("")
    + `<div class="severity-card total-card"><span class="severity-name">Active · suppressed</span><span class="severity-count">${number(summary.total_active)}</span><span class="severity-note">${number(summary.suppressed)} SUPPRESSED (NOT COUNTED)</span></div>`;
  BANDS = { ...BANDS };
}

function updateDetectionRefreshNote() {
  const note = $("#det-refresh-note");
  if (!note) return;
  const loaded = state.det.loadedAt ? new Date(state.det.loadedAt).toLocaleTimeString([], { hour12: false }) : "—";
  note.textContent = `UPDATES EVERY ${state.det.refreshSeconds}s · LAST ${loaded}`;
  note.title = "Collection continues every few seconds; this list refreshes on its own schedule so rows stay still while you read. Refresh updates it immediately.";
}

function startDetectionTimer() {
  stopDetectionTimer();
  state.det.timer = setInterval(() => { if (!document.hidden && !$("#det-dialog").open) loadDetections({ preserve: true }); }, state.det.refreshSeconds * 1000);
}
function stopDetectionTimer() { if (state.det.timer) { clearInterval(state.det.timer); state.det.timer = null; } }

function scheduleDetectionSearch() {
  clearTimeout(state.det.debounce);
  state.det.debounce = setTimeout(() => { state.det.offset = 0; loadDetections(); }, 250);
}

// ---------- Detection detail ----------
function kv(label, value) { return `<div class="detail-row"><span>${escapeHtml(label)}</span><b>${value}</b></div>`; }

function conditionHtml(node, depth = 0) {
  if (!node) return "<i>none</i>";
  if (Array.isArray(node)) return node.map((step, i) => `<div class="cond-step"><b>Step ${i + 1}${step.runs > 1 ? ` (×${step.runs})` : ""}${step.name ? ` · ${escapeHtml(step.name)}` : ""}</b>${step.by && step.by.length ? ` <small>joined on ${escapeHtml(step.by.join(", "))}</small>` : ""}${step.relation ? ` <small>${escapeHtml(JSON.stringify(step.relation))}</small>` : ""}${conditionHtml(step.condition, depth + 1)}</div>`).join("");
  if (depth > 6) return "<i>…</i>";
  if (node.all) return `<div class="cond-group"><span class="cond-op">ALL OF</span>${node.all.map((c) => conditionHtml(c, depth + 1)).join("")}</div>`;
  if (node.any) return `<div class="cond-group"><span class="cond-op">ANY OF</span>${node.any.map((c) => conditionHtml(c, depth + 1)).join("")}</div>`;
  if (node.not) return `<div class="cond-group cond-not"><span class="cond-op">NOT</span>${conditionHtml(node.not, depth + 1)}</div>`;
  if ("const" in node) return `<div class="cond-leaf">${node.const ? "always" : "never"}</div>`;
  const values = node.values ? node.values.slice(0, 8).map((v) => JSON.stringify(v)).join(", ") + (node.values.length > 8 ? ` … (+${node.values.length - 8})` : "") : (node.other || node.value || "");
  return `<div class="cond-leaf"><code>${escapeHtml(node.field)}</code> <span class="cond-verb">${escapeHtml(node.fn ? `${node.fn} ${node.op}` : node.op)}</span> <code>${escapeHtml(values)}</code>${node.ci ? " <small>(any case)</small>" : ""}</div>`;
}

function signalDetail(signal) {
  const d = signal.details || {};
  const parts = [];
  if (d.matched && d.matched.length) parts.push(`<div class="why-list"><b>Matched conditions</b>${d.matched.map((m) => `<div><code>${escapeHtml(m.condition)}</code>${m.value != null ? ` → <span class="mono-cell">${escapeHtml(Array.isArray(m.value) ? m.value.join(" ") : m.value)}</span>` : ""}</div>`).join("")}</div>`);
  if (d.sequence) parts.push(`<div class="why-list"><b>Correlated sequence</b> (within ${d.maxspan_seconds}s${Object.keys(d.join || {}).length ? `, joined on ${escapeHtml(Object.entries(d.join).map(([k, v]) => `${k}=${v}`).join(", "))}` : ""})${d.sequence.map((s) => `<div class="chain-link">${s.step}. ${escapeHtml(dayTime(s.time))} · Event ${escapeHtml(s.event_id)} · ${escapeHtml(s.channel)}</div>`).join("")}</div>`);
  if (d.chain) parts.push(`<div class="why-list"><b>Correlation path</b>${d.chain.map((s, i) => `<div class="chain-link">${i + 1}. <b>${escapeHtml(s.step)}</b> · ${escapeHtml(dayTime(s.time))} · Event ${escapeHtml(s.event_id)}${s.process ? ` · ${escapeHtml(s.process)}` : ""}${s.via && s.via !== "start" ? ` <span class="via">← ${escapeHtml(s.via)}</span>` : ""}</div>`).join("")}</div>`);
  if (d.threshold) parts.push(`<div class="why-list"><b>Threshold</b><div>${d.threshold.count} matching events (≥ ${d.threshold.required}) within ${d.threshold.window_seconds}s${Object.keys(d.threshold.group || {}).length ? ` for ${escapeHtml(JSON.stringify(d.threshold.group))}` : ""}</div></div>`);
  if (d.new_terms) parts.push(`<div class="why-list"><b>First seen</b><div>${escapeHtml(d.new_terms.fields.join(" + ") || "this query on this host")} = ${escapeHtml(JSON.stringify(d.new_terms.values))} not seen in the previous ${d.new_terms.history_days} day(s)${d.new_terms.history_covered ? "" : " (history not fully covered: recorded as learn-only)"}</div></div>`);
  if (d.wazuh_path) parts.push(`<div class="why-list"><b>Wazuh rule path</b>${d.wazuh_path.map((r) => `<div class="chain-link">${escapeHtml(r.id)} (level ${r.level}) ${escapeHtml(r.description)}</div>`).join("")}${d.frequency ? `<div>${d.frequency.count} events within ${d.frequency.timeframe_seconds}s (≥ ${d.frequency.required})${Object.keys(d.frequency.same_fields || {}).length ? ` with the same ${escapeHtml(JSON.stringify(d.frequency.same_fields))}` : ""}</div>` : ""}</div>`);
  if (d.behavior) {
    const b = d.behavior;
    if (b.rate) parts.push(`<div class="why-list"><b>Behaviour: volume</b><div>${escapeHtml(b.rate.feature)} = ${b.rate.value} in the bucket starting ${escapeHtml(dayTime(b.rate.bucket_start))} (baseline mean ${b.rate.mean}, sd ${b.rate.sd}); score ${b.rate.score}</div></div>`);
    if (b.parts) parts.push(`<div class="why-list"><b>Behaviour: feature breakdown</b> (S = ${b.S}, context ×${b.context}${(b.context_notes || []).length ? ` - ${escapeHtml(b.context_notes.join(", "))}` : ""}, R = ${b.R}, alert threshold ${b.threshold}, model stage ${escapeHtml(b.stage)})<table class="data-table compact-table"><thead><tr><th>FEATURE</th><th>VALUE</th><th>RARITY / DEVIATION</th><th>WEIGHT</th></tr></thead><tbody>${b.parts.map((p) => `<tr><td>${escapeHtml(p.feature)}</td><td class="mono-cell">${escapeHtml(p.value)}${p.new ? " <b>(never seen)</b>" : ""}${p.mean != null ? ` <small>mean ${p.mean}, sd ${p.sd}</small>` : ""}</td><td>${p.score}</td><td>${p.weight}</td></tr>`).join("")}</tbody></table></div>`);
  }
  return parts.join("");
}

async function showDetection(id) {
  state.det.selected = id;
  document.querySelectorAll("#det-body tr").forEach((row) => row.classList.toggle("selected-row", row.dataset.detId === id));
  const dialog = $("#det-dialog");
  $("#det-dialog-body").innerHTML = emptyState("Loading detection…");
  if (!dialog.open) dialog.showModal();
  try {
    const item = await api(`/api/detections/${encodeURIComponent(id)}`);
    BANDS = item.severity_bands || BANDS;
    $("#det-dialog-title").textContent = item.title;
    $("#det-dialog-kicker").textContent = `DETECTION · ${item.id.slice(0, 12)}`;
    const detail = item.explanation_detail || {};
    const signals = item.signals.map((s) => `<div class="signal-card ${s.decision !== "alert" ? "signal-muted" : ""}">
        <div class="signal-head">${sevPill(s.severity)} <b>${escapeHtml(s.rule_name)}</b> <span class="mono-cell">${escapeHtml(s.rule_id)}</span> <span class="src-tag src-${s.source}">${escapeHtml(SOURCE_LABELS[s.source] || s.source)}</span> <span class="signal-score">score ${Number(s.score).toFixed(0)}</span>
        <span class="signal-state">${escapeHtml(s.decision)}${s.rule_state !== "enabled" ? ` · rule ${escapeHtml(s.rule_state)}` : ""}${s.origin === "reevaluation" ? " · found by look-back" : ""}</span></div>
        ${signalDetail(s)}</div>`).join("");
    const rules = Object.values(item.rules).map((r) => `<details class="rule-def"><summary><b>${escapeHtml(r.name || r.rule_id)}</b> <span class="mono-cell">${escapeHtml(r.rule_id)}</span> · ${escapeHtml(r.origin_label || r.origin || "")} · ${escapeHtml(KIND_LABELS[r.kind] || r.kind || "")}${r.deleted ? " · deleted" : ""}</summary>
        <p>${escapeHtml(r.description || "")}</p>
        ${r.correlation ? `<p class="rules-note">Correlation: ${escapeHtml(JSON.stringify(r.correlation))}</p>` : ""}
        <div class="cond-tree">${conditionHtml(r.condition)}</div>
        ${(r.modifications || []).length ? `<p class="rules-note"><b>Local changes:</b> ${escapeHtml(r.modifications.join(" "))}</p>` : ""}
        ${r.support && r.support.notes ? `<p class="rules-note"><b>Support:</b> ${escapeHtml(SUPPORT_LABELS[r.support.status] || r.support.status)} - ${escapeHtml(r.support.notes)}</p>` : ""}
        <p class="rules-note">Source: ${escapeHtml((r.source || {}).platform || "")} ${escapeHtml((r.source || {}).file || "")} ${escapeHtml((r.source || {}).rule_id || "")} · Licence: ${escapeHtml((r.source || {}).license || "")}</p>
        ${r.original_query ? `<details><summary>Original query</summary><pre class="raw-event">${escapeHtml(r.original_query)}</pre></details>` : ""}</details>`).join("");
    const timeline = item.timeline.map((t) => `<div class="tl-mini ${t.available ? "" : "tl-gone"}" ${t.available ? `data-event-key="${escapeHtml(t.event_key)}" role="button" tabindex="0"` : ""}><span class="mono-cell">${escapeHtml(dayTime(t.time))}</span><span>Event ${escapeHtml(t.event_id ?? "—")} · ${escapeHtml(t.channel || "")}</span><span class="det-sub">${escapeHtml(t.summary)}</span><span class="mono-cell">${escapeHtml(t.rule_id)}</span></div>`).join("");
    const events = Object.values(item.events).slice(0, 12).map((e) => `<details class="ev-detail"><summary>Event ${e.event_id} · ${escapeHtml(e.channel)} · ${escapeHtml(dayTime(e.time))} · record ${escapeHtml(e.record_id ?? "—")}</summary>
        <div class="field-grid">${Object.entries(e.fields).slice(0, 60).map(([k, v]) => `<span>${escapeHtml(k)}</span><b class="mono-cell">${escapeHtml(String(v).slice(0, 600))}</b>`).join("")}</div>
        <button type="button" class="pager-button text-button" data-event-key="${escapeHtml(e.event_key)}">Open raw event XML</button></details>`).join("");
    const steps = item.investigation.length ? item.investigation.map((s) => `<div class="invest-step"><span class="mono-cell">${escapeHtml(s.rule_id)}</span><div class="invest-text">${escapeHtml(s.text)}</div></div>`).join("") : "<p>No guidance was supplied with these rules.</p>";
    const verdicts = item.verdicts.map((v) => `<div class="mini-row"><span>${escapeHtml(dayTime(v.at))} · ${escapeHtml(VERDICTS[v.verdict] || v.verdict)}${v.note ? ` - ${escapeHtml(v.note)}` : ""}</span>${v.applied && v.applied.model ? `<b>model: ${escapeHtml((v.applied.model.changes || []).join("; ") || "recorded")}</b>` : ""}</div>`).join("");
    $("#det-dialog-body").innerHTML = `
      <section class="det-section"><h3>1 · Summary</h3><div class="detail-grid">
        ${kv("Severity", sevPill(item.severity))}${kv("Risk score", riskBar(item.score))}${kv("Confidence", escapeHtml(item.confidence))}
        ${kv("Detection time", escapeHtml(fullTime(item.det_time)))}${kv("Last contributing event", escapeHtml(dayTime(item.last_time)))}${kv("Host", escapeHtml(item.hostname || "—"))}
        ${kv("Category", escapeHtml(item.category || "—"))}${kv("MITRE ATT&CK", escapeHtml((item.mitre || []).slice(0, 6).map((m) => `${m.technique}${m.name ? ` ${m.name}` : ""}`).join(", ") + ((item.mitre || []).length > 6 ? ` (+${item.mitre.length - 6} more in the rules below)` : "") || "—"))}${kv("Event IDs", escapeHtml(item.event_ids.join(", ")))}
        ${kv("Channels", escapeHtml(item.channels.join(", ")))}${kv("Entity", escapeHtml(item.entity_key))}${kv("State", escapeHtml(item.active ? "Active" : item.decision === "suppressed" ? "Suppressed (known good)" : "Inactive: " + item.rule_state))}
        ${kv("Correlation scope", escapeHtml(item.scope || "—"))}${kv("Occurrences", escapeHtml(String(item.occurrence_count || 1)))}${kv("Correlated rules", escapeHtml(String((item.rule_ids || []).length)))}</div>
        <p class="det-summary-line">${escapeHtml(item.summary || "")}</p></section>
      <section class="det-section"><h3>2 · Why it was triggered</h3>${signals}</section>
      <section class="det-section"><h3>3 · Risk score and severity</h3>${item.escalated ? `<p class="score-decomposition"><span>Base score <b>${Number(item.base_score).toFixed(1)}</b></span><span>+ escalation <b>+${Number(item.escalation.applied).toFixed(1)}</b> (${Number(item.occurrence_count)} occurrences, capped at ${Number(item.escalation.cap).toFixed(0)})</span><span>= episode score <b>${Number(item.score).toFixed(1)}</b></span></p>` : ""}<p>${escapeHtml(item.explanation || "")}</p>
        ${(detail.contributors || []).length ? `<table class="data-table compact-table"><thead><tr><th>CONTRIBUTING RULE</th><th>SCORE</th><th>WEIGHT</th><th>AGE DECAY</th></tr></thead><tbody>${detail.contributors.map((c) => `<tr><td class="mono-cell">${escapeHtml(c.rule_id)}</td><td>${c.score}</td><td>${c.weight}</td><td>×${c.decay}</td></tr>`).join("")}</tbody></table>` : ""}</section>
      <section class="det-section"><h3>4 · Matched rule conditions</h3>${rules || "<p>Rule definitions are unavailable.</p>"}</section>
      <section class="det-section"><h3>5-7 · Correlated sequence and contributing events (oldest first)</h3><div class="tl-mini-list">${timeline}</div>
        <p class="rules-note">Greyed entries: the event is no longer in the event store (retention); its key fields are kept with the detection.</p>
        <div class="ev-list">${events}</div></section>
      <section class="det-section"><h3>8 · Recommended investigation</h3>${steps}</section>
      <section class="det-section"><h3>9 · Analyst verdict and status</h3>
        <form class="verdict-form" id="verdict-form" data-det-id="${escapeHtml(item.id)}">
          <div class="verdict-buttons">${Object.entries(VERDICTS).map(([key, label]) => `<label class="verdict-choice"><input type="radio" name="verdict" value="${key}" ${item.verdict === key ? "checked" : ""}> ${escapeHtml(label)}</label>`).join("")}</div>
          <label class="span-2"><span>NOTE</span><input name="note" class="filter-input" maxlength="2000" placeholder="Why (kept with the detection)"></label>
          <div class="inline-fields"><label>Status <select name="status" class="filter-select">${DET_STATUSES.map((s) => `<option ${s === item.status ? "selected" : ""}>${s}</option>`).join("")}</select></label>
            <button type="submit" class="quick-button primary-button">Save verdict / status</button></div>
          <p class="rules-note">A false-positive verdict never whitelists anything by itself. On behaviour detections it updates the model for these exact values only (recorded in the model audit log).</p>
        </form>
        ${item.active && item.signals.some((s) => s.decision === "alert" && s.source !== "behavior") ? `<details class="suppress-box"><summary>Suppress identical future matches…</summary><p>Creates a suppression for these rule(s) and this exact activity fingerprint (process path, parent, command line, user, and the event's key values). Different activity still alerts. Suppressions are listed under Rules → Suppressions and can be revoked.</p><input class="filter-input" id="suppress-reason" maxlength="500" placeholder="Reason (required)"><button type="button" class="quick-button" id="suppress-button">Suppress identical</button></details>` : ""}
        ${verdicts ? `<div class="verdict-history"><b>History</b>${verdicts}</div>` : ""}
        ${item.status_history.length ? `<div class="verdict-history">${item.status_history.map((h) => `<div class="mini-row"><span>${escapeHtml(dayTime(h.changed_at))} · ${escapeHtml(h.old_status || "New")} → ${escapeHtml(h.new_status)}${h.note ? ` - ${escapeHtml(h.note)}` : ""}</span></div>`).join("")}</div>` : ""}
      </section>`;
    $("#verdict-form").addEventListener("submit", saveVerdict);
    $("#suppress-button")?.addEventListener("click", () => suppressDetection(item.id));
  } catch (error) { $("#det-dialog-body").innerHTML = emptyState(error.message); }
}

async function saveVerdict(event) {
  event.preventDefault();
  const form = event.target;
  const id = form.dataset.detId;
  const verdict = form.querySelector("input[name=verdict]:checked")?.value;
  const note = form.note.value.trim();
  try {
    if (verdict) await apiSend("POST", `/api/detections/${encodeURIComponent(id)}/verdict`, { verdict, note });
    await apiSend("POST", `/api/detections/${encodeURIComponent(id)}/status`, { status: form.status.value, note });
    toast("Saved.");
    loadDetections({ preserve: true });
    showDetection(id);
  } catch (error) { toast(`Not saved: ${error.message}`, 6000); }
}

async function suppressDetection(id) {
  const reason = $("#suppress-reason").value.trim();
  try {
    const result = await apiSend("POST", `/api/detections/${encodeURIComponent(id)}/suppress`, { reason });
    toast(`Suppression created for ${result.created.length} rule(s). The detection is now suppressed.`, 5000);
    loadDetections({ preserve: true });
    showDetection(id);
  } catch (error) { toast(`Not suppressed: ${error.message}`, 6000); }
}

// ---------- Rules view ----------
async function loadRulesView() {
  setRulesTab(state.rulesView.tab);
}

function setRulesTab(tab) {
  state.rulesView.tab = tab;
  document.querySelectorAll("[data-rules-tab]").forEach((b) => { const on = b.dataset.rulesTab === tab; b.classList.toggle("active", on); b.setAttribute("aria-selected", String(on)); });
  ["rules", "model", "suppressions", "coverage"].forEach((name) => { $(`#rules-tab-${name}`).hidden = name !== tab; });
  return ({ rules: loadRuleTable, model: loadModel, suppressions: loadSuppressions, coverage: loadCoverage })[tab]();
}

function ruleParams() {
  const params = new URLSearchParams({ limit: state.rulesView.limit, offset: state.rulesView.offset, sort: $("#rule-sort").value });
  const v = (id) => $(id).value.trim();
  if (v("#rule-search")) params.set("q", v("#rule-search"));
  if (v("#rule-origin")) params.set("origin", v("#rule-origin"));
  if (v("#rule-kind")) params.set("kind", v("#rule-kind"));
  if (v("#rule-state")) params.set("state", v("#rule-state"));
  if (v("#rule-support")) params.set("support", v("#rule-support"));
  return params;
}

function ruleRow(r) {
  const sources = r.channels.map((c) => c.replace("Microsoft-Windows-", "").replace("/Operational", "")).join(", ") + (r.event_ids.length ? ` · ${r.event_ids.slice(0, 6).join(", ")}${r.event_ids.length > 6 ? "…" : ""}` : "");
  const job = r.job && ["queued", "running"].includes(r.job.state) ? `<small class="det-sub">look-back: ${number(r.job.examined)} events checked…</small>` : "";
  return `<tr class="${r.enabled ? "" : "inactive-row"}" data-rule-id="${escapeHtml(r.rule_id)}">
    <td><button type="button" class="switch${r.enabled ? " on" : ""}" role="switch" aria-checked="${r.enabled}" aria-label="${r.enabled ? "Disable" : "Enable"} ${escapeHtml(r.name)}" title="${r.enabled ? "Enabled - click to disable" : "Disabled - click to enable"}" data-toggle-rule="${escapeHtml(r.rule_id)}" ${r.protected ? "disabled" : ""}><span class="switch-knob"></span><span class="switch-text">${r.enabled ? "ON" : "OFF"}</span></button></td>
    <td><button type="button" class="link-button" data-open-rule="${escapeHtml(r.rule_id)}">${escapeHtml(r.name)}</button><small class="det-sub mono-cell">${escapeHtml(r.rule_id)} · ${escapeHtml(ORIGIN_LABELS[r.origin] || r.origin)}${r.mitre.length ? ` · ${escapeHtml(r.mitre.join(", "))}` : ""}</small>${job}</td>
    <td>${escapeHtml(KIND_LABELS[r.kind] || r.kind)}</td><td>${sevPill(r.severity)}</td>
    <td class="mono-cell" title="${escapeHtml(r.channels.join(", "))}">${escapeHtml(sources || "—")}</td>
    <td><span class="support-tag support-${escapeHtml(r.support || "")}" title="${escapeHtml(r.optional_sources.join("; "))}">${escapeHtml(SUPPORT_LABELS[r.support] || r.support || "—")}</span></td>
    <td>${number(r.signals)}${r.suppressed ? `<small class="det-sub">${number(r.suppressed)} suppressed</small>` : ""}</td><td>${number(r.signals_7d)}</td>
    <td class="mono-cell">${r.last_signal ? escapeHtml(ago(r.last_signal)) : "never"}</td>
    <td>${r.signals ? `<button type="button" class="text-action" data-rule-detections="${escapeHtml(r.rule_id)}">Detections →</button>` : ""}</td></tr>`;
}

async function loadRuleTable() {
  const body = $("#rules-body");
  try {
    const data = await api(`/api/detections/rules?${ruleParams()}`);
    state.rulesView.total = data.total;
    state.rulesView.items = data.items;
    body.innerHTML = data.items.length ? data.items.map(ruleRow).join("") : `<tr><td colspan="10">${emptyState("No rules match these filters.")}</td></tr>`;
    $("#rule-count").textContent = `${number(data.total)} rules · ${number(data.counts.enabled)} on · ${number(data.counts.disabled)} off · ${number(data.counts.triggered)} have triggered · ${number(data.counts.never)} never${data.load_errors.length ? ` · ${data.load_errors.length} rule file(s) failed to load` : ""}`;
    $("#rule-page-label").textContent = `${number(state.rulesView.offset + 1)}-${number(Math.min(state.rulesView.offset + state.rulesView.limit, data.total))} of ${number(data.total)}`;
    $("#rule-prev").disabled = state.rulesView.offset === 0;
    $("#rule-next").disabled = state.rulesView.offset + state.rulesView.limit >= data.total;
    if (data.items.some((r) => r.job && ["queued", "running"].includes(r.job.state))) setTimeout(() => { if (state.view === "rules" && state.rulesView.tab === "rules") loadRuleTable(); }, 1500);
  } catch (error) { body.innerHTML = `<tr><td colspan="10">${emptyState(error.message)}</td></tr>`; }
}

async function toggleRule(button) {
  const ruleId = button.dataset.toggleRule;
  const wanted = button.getAttribute("aria-checked") !== "true";
  button.disabled = true;
  button.classList.add("busy");
  try {
    const result = await apiSend("PUT", `/api/detections/rules/${encodeURIComponent(ruleId)}/enabled`, { enabled: wanted });
    const job = result.job || {};
    toast(wanted ? `Enabled. Looking back over the last 7 days for this rule${job.state === "done" ? `: ${number(job.examined)} events checked, ${number(job.signals)} new match(es)` : " (continues in the background)"}.` : "Disabled. Its detections are hidden from active views and kept in History.", 5000);
    loadRuleTable();
    refreshDetectionBadge(true);
  } catch (error) { toast(`Not changed: ${error.message}`, 6000); button.disabled = false; button.classList.remove("busy"); }
}

async function openRule(ruleId) {
  const dialog = $("#rule-detail-dialog");
  $("#rule-detail-body").innerHTML = emptyState("Loading rule…");
  if (!dialog.open) dialog.showModal();
  try {
    const r = await api(`/api/detections/rules/${encodeURIComponent(ruleId)}`);
    $("#rule-detail-title").textContent = r.name;
    const src = r.source || {};
    const definition = r.condition || r.steps || (r.chain || {}).steps || (r.wazuh || {}).condition;
    $("#rule-detail-body").innerHTML = `<div class="detail-grid">
        ${kv("Rule ID", `<span class="mono-cell">${escapeHtml(r.rule_id)}</span>`)}${kv("State", r.deleted ? "Deleted" : r.enabled ? "Enabled" : "Disabled")}${kv("Kind", escapeHtml(KIND_LABELS[r.kind] || r.kind))}
        ${kv("Severity", sevPill(r.severity))}${kv("Base score", escapeHtml(r.score))}${kv("Confidence", escapeHtml(r.confidence))}
        ${kv("Category", escapeHtml(r.category))}${kv("Origin", escapeHtml(r.origin_label || r.origin))}${kv("Verified", r.verified ? "Imported / built-in" : "User-defined, not verified")}
        ${kv("Support", escapeHtml(SUPPORT_LABELS[(r.support || {}).status] || (r.support || {}).status || "—"))}${kv("Signals stored", number((r.stats || {}).signals))}${kv("Last signal", escapeHtml((r.stats || {}).last ? dayTime(r.stats.last) : "never"))}</div>
      <p>${escapeHtml(r.description || "")}</p>
      ${(r.support || {}).notes ? `<p class="rules-note"><b>Support notes:</b> ${escapeHtml(r.support.notes)}</p>` : ""}
      ${((r.support || {}).optional_sources || []).length ? `<p class="rules-note"><b>Needs:</b> ${escapeHtml(r.support.optional_sources.join("; "))}</p>` : ""}
      <h4>Event sources</h4><p class="mono-cell">${escapeHtml((r.sources || []).map((s) => `${s.channel} [${(s.event_ids || []).join(", ") || "any"}]`).join(" · ") || "—")}</p>
      ${r.correlation ? `<h4>Correlation</h4><p class="mono-cell">${escapeHtml(JSON.stringify(r.correlation))}</p>` : ""}
      <h4>Conditions</h4><div class="cond-tree">${conditionHtml(definition)}</div>
      ${(r.modifications || []).length ? `<h4>Local modifications</h4><ul>${r.modifications.map((m) => `<li>${escapeHtml(m)}</li>`).join("")}</ul>` : ""}
      ${r.investigation ? `<h4>Investigation guidance</h4><div class="invest-text">${escapeHtml(r.investigation)}</div>` : ""}
      ${(r.false_positives || []).length ? `<h4>Known false positives</h4><ul>${r.false_positives.map((m) => `<li>${escapeHtml(m)}</li>`).join("")}</ul>` : ""}
      <h4>Provenance and licence</h4><div class="detail-grid">${kv("Platform", escapeHtml(src.platform || "—"))}${kv("File", escapeHtml(src.file || "—"))}${kv("Original ID", `<span class="mono-cell">${escapeHtml(src.rule_id || "—")}</span>`)}${kv("Licence", escapeHtml(src.license || "—"))}</div>
      ${src.attribution ? `<p class="rules-note">${escapeHtml(src.attribution)}</p>` : ""}
      ${r.original_query ? `<details><summary>Original query (${escapeHtml(src.language || src.type || "")})</summary><pre class="raw-event">${escapeHtml(r.original_query)}</pre></details>` : ""}
      ${(r.changes || []).length ? `<h4>Change history</h4>${r.changes.map((c) => `<div class="mini-row"><span>${escapeHtml(dayTime(c.at))} · ${escapeHtml(c.change)}</span></div>`).join("")}` : ""}
      <div class="dialog-actions">${r.origin === "custom" && !r.deleted ? `<button type="button" class="pager-button text-button" id="edit-rule">Edit</button><button type="button" class="pager-button text-button danger" id="delete-rule">Delete</button>` : ""}<button type="button" class="quick-button" id="rule-detections">Show its detections</button></div>`;
    $("#rule-detections").addEventListener("click", () => { dialog.close(); state.det.scope = "all"; setScopeTabs(); goDetections({ ruleId: r.rule_id }); });
    $("#edit-rule")?.addEventListener("click", () => { dialog.close(); openRuleBuilder(r); });
    $("#delete-rule")?.addEventListener("click", () => deleteRule(r.rule_id));
  } catch (error) { $("#rule-detail-body").innerHTML = emptyState(error.message); }
}

async function deleteRule(ruleId) {
  if (!window.confirm(`Delete custom rule ${ruleId}? Its detections are kept in History with the rule's name.`)) return;
  try {
    await apiSend("DELETE", `/api/detections/rules/${encodeURIComponent(ruleId)}`);
    $("#rule-detail-dialog").close();
    toast("Rule deleted. Its detections remain in History.");
    loadRuleTable();
  } catch (error) { toast(`Not deleted: ${error.message}`, 6000); }
}

async function loadModel() {
  const root = $("#rules-tab-model");
  root.innerHTML = emptyState("Loading model…");
  try {
    const m = await api("/api/detections/model");
    const p = m.progress || {};
    const feats = m.features || {};
    root.innerHTML = `<div class="model-stages">${["learn", "shadow", "active", "adapt"].map((s) => `<div class="model-stage ${m.stage === s ? "current" : ""}"><b>${escapeHtml(s.toUpperCase())}</b><span>${escapeHtml({ learn: "Collect and build the baseline; no behaviour alerts", shadow: "Score and record; no behaviour alerts", active: "Behaviour alerts on; slow updates", adapt: "Drift detected; learning faster" }[s])}</span></div>`).join("")}</div>
      <div class="detail-grid">${kv("Current stage", escapeHtml(stageLabel(m.stage)))}${kv("Since", escapeHtml(dayTime(m.stage_since)))}${kv("Observations used", number(m.observations))}
        ${kv("Learning progress", `${number(p.observations)} / ${number(p.required_observations)} observations · ${p.days} / ${p.required_days} days`)}${kv("Recent new-value rate", escapeHtml((p.recent_novelty || []).map((x) => x.toFixed(3)).join(", ") || "—") + ` (target ≤ ${p.novelty_target})`)}${kv("Alert threshold (R)", escapeHtml(m.alert_threshold))}
        ${p.shadow_hours != null ? kv("Shadow run", `${p.shadow_hours} h of ${p.required_shadow_hours} h · ${p.shadow_would_alert} would-be alerts / ${number(p.shadow_observations)} observations (target ≤ ${p.shadow_target_per_1000} per 1,000)`) : ""}
        ${kv("Last model update", escapeHtml(dayTime(m.updated_at)))}${kv("Baseline version", escapeHtml(m.baseline_version))}${kv("Analyst verdicts applied", escapeHtml(JSON.stringify(m.verdicts)))}</div>
      <p class="rules-note">${escapeHtml(m.stage_reason || "")} Deterministic rules alert regardless of the model's stage; the model never suppresses a rule match.</p>
      <h4>Learned features</h4><div class="host-columns">
        <div><h4>CATEGORICAL</h4>${Object.entries(feats.categorical || {}).map(([k, v]) => `<div class="mini-row"><span>${escapeHtml(k)}</span><b>${number(v.values)} values / ${number(v.observations)}</b></div>`).join("") || "<div class='mini-row'><span>none yet</span></div>"}</div>
        <div><h4>NUMERIC</h4>${Object.entries(feats.numeric || {}).map(([k, v]) => `<div class="mini-row"><span>${escapeHtml(k)}</span><b>mean ${v.mean} · sd ${v.sd} · n ${number(v.n)}</b></div>`).join("") || "<div class='mini-row'><span>none yet</span></div>"}</div>
        <div><h4>RATES</h4>${Object.entries(feats.rates || {}).map(([k, v]) => `<div class="mini-row"><span>${escapeHtml(k)}</span><b>mean ${v.mean} · n ${number(v.n)}</b></div>`).join("") || "<div class='mini-row'><span>none yet</span></div>"}</div>
        <div><h4>NOT MODELLED (NOT COLLECTED)</h4>${(m.unavailable_features || []).map((f) => `<div class="mini-row"><span>${escapeHtml(f)}</span></div>`).join("")}</div></div>
      <h4>Recent shadow / learn-only behaviour signals</h4>${(m.shadow_signals || []).length ? m.shadow_signals.map((s) => `<div class="mini-row"><span>${escapeHtml(dayTime(s.first_time))} · ${escapeHtml(s.rule_name)}</span><b>${escapeHtml(s.decision)} · score ${Number(s.score).toFixed(0)}</b></div>`).join("") : "<p class='rules-note'>None.</p>"}
      <h4>Model audit log</h4>${(m.audit || []).length ? m.audit.slice(0, 15).map((a) => `<div class="mini-row"><span>${escapeHtml(dayTime(a.at))} · ${escapeHtml(a.action)}</span><b>${escapeHtml(JSON.stringify(a.detail).slice(0, 160))}</b></div>`).join("") : "<p class='rules-note'>No changes yet.</p>"}
      <div class="dialog-actions"><button type="button" class="pager-button text-button danger" id="reset-model">Reset baseline…</button></div>`;
    $("#reset-model").addEventListener("click", async () => {
      if (!window.confirm("Reset the learned baseline? The model returns to Learn; detection history is kept.")) return;
      try { await apiSend("POST", "/api/detections/model/reset"); toast("Baseline reset."); loadModel(); } catch (error) { toast(error.message, 6000); }
    });
  } catch (error) { root.innerHTML = emptyState(error.message); }
}

async function loadSuppressions() {
  const root = $("#rules-tab-suppressions");
  try {
    const data = await api("/api/detections/rules?limit=1");
    const items = data.suppressions || [];
    root.innerHTML = `<p class="rules-note">A suppression covers one rule and one exact activity fingerprint. Suppressed matches are still stored and counted separately; revoking a suppression makes them active again.</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>ID</th><th>RULE</th><th>REASON</th><th>FINGERPRINT FIELDS</th><th>MATCHES</th><th>CREATED</th><th></th></tr></thead><tbody>${items.length ? items.map((s) => `<tr class="${s.revoked_at ? "inactive-row" : ""}"><td class="mono-cell">${escapeHtml(s.id)}</td><td class="mono-cell">${escapeHtml(s.rule_id)}</td><td>${escapeHtml(s.reason)}</td><td class="mono-cell"><small>${escapeHtml(JSON.stringify((s.fields || {}).events || []).slice(0, 220))}</small></td><td>${number(s.matches)}</td><td>${escapeHtml(dayTime(s.created_at))}</td><td>${s.revoked_at ? `revoked ${escapeHtml(dayTime(s.revoked_at))}` : `<button type="button" class="text-action" data-revoke="${escapeHtml(s.id)}">Revoke</button>`}</td></tr>`).join("") : `<tr><td colspan="7">${emptyState("No suppressions.")}</td></tr>`}</tbody></table></div>`;
  } catch (error) { root.innerHTML = emptyState(error.message); }
}

const COVERAGE_TEXT = { verified: "Coverage verified", partial: "Partial coverage", unknown: "Coverage unknown", unavailable: "Required channel unavailable", no_data: "No data yet" };
async function loadCoverage() {
  const root = $("#rules-tab-coverage");
  root.innerHTML = emptyState("Loading coverage…");
  try {
    const [coverage, health] = await Promise.all([api("/api/anomalies/coverage"), api("/api/collector/health")]);
    root.innerHTML = `<div class="detail-grid">${kv("Collection health", escapeHtml(health.summary || health.state || "—"))}${kv("Coverage", escapeHtml(COVERAGE_TEXT[coverage.state] || coverage.state))}${kv("Last successful collection", escapeHtml(dayTime(coverage.last_successful_collection)))}</div>
      <p class="rules-note">${escapeHtml(coverage.explanation || coverage.note || "")}</p>
      <div class="table-scroll"><table class="data-table"><thead><tr><th>CHANNEL</th><th>STATE</th><th>RULES USING IT</th><th>EVENTS (7 DAYS)</th><th>COVERAGE</th><th>WHY</th><th>LAST SUCCESS</th></tr></thead><tbody>${coverage.channels.map((c) => `<tr><td>${escapeHtml(c.channel)}</td><td>${escapeHtml(c.state_label)}</td><td>${number(c.enabled_rules)}</td><td>${number(c.events_stored)}</td><td>${escapeHtml(c.coverage_label)}</td><td><small>${escapeHtml(c.coverage_note)}</small></td><td class="mono-cell">${escapeHtml(dayTime(c.last_success_at))}</td></tr>`).join("")}</tbody></table></div>`;
  } catch (error) { root.innerHTML = emptyState(error.message); }
}

// ---------- Rule builder ----------
const OPS = [["eq", "is"], ["wildcard", "matches (* ?)"], ["contains", "contains"], ["startswith", "starts with"], ["endswith", "ends with"], ["regex", "matches regex"], ["gte", "≥"], ["gt", ">"], ["lte", "≤"], ["lt", "<"], ["cidr", "in network (CIDR)"], ["exists", "is present"], ["length_gte", "length ≥"]];

async function builderSchema() {
  if (!state.rulesView.schema) {
    state.rulesView.schema = await api("/api/detections/schema");
    $("#field-options").innerHTML = state.rulesView.schema.fields.map((f) => `<option value="${escapeHtml(f.field)}">${escapeHtml(f.label)}</option>`).join("");
    $("#channel-options").innerHTML = state.rulesView.schema.channels.map((c) => `<option value="${escapeHtml(c)}"></option>`).join("");
  }
  return state.rulesView.schema;
}

function conditionRowHtml(row = {}) {
  return `<div class="cond-row"><select class="filter-select cr-not" aria-label="Negate"><option value="">where</option><option value="not" ${row.not ? "selected" : ""}>where NOT</option></select>
    <input class="filter-input cr-field" list="field-options" placeholder="field, e.g. process.name" value="${escapeHtml(row.field || "")}" aria-label="Field">
    <select class="filter-select cr-op" aria-label="Operator">${OPS.map(([v, l]) => `<option value="${v}" ${row.op === v ? "selected" : ""}>${l}</option>`).join("")}</select>
    <input class="filter-input cr-values" placeholder="value(s), comma-separated" value="${escapeHtml((row.values || []).join(", "))}" aria-label="Values">
    <label class="cr-ci"><input type="checkbox" class="cr-ci-box" ${row.ci === false ? "" : "checked"}> any case</label>
    <button type="button" class="pager-button text-button cr-remove" aria-label="Remove condition">&#10005;</button></div>`;
}

function conditionGroupHtml(group = { mode: "all", rows: [{}] }) {
  return `<div class="cond-builder"><label>Match <select class="filter-select cg-mode"><option value="all" ${group.mode === "all" ? "selected" : ""}>ALL</option><option value="any" ${group.mode === "any" ? "selected" : ""}>ANY</option></select> of these conditions</label>
    <div class="cg-rows">${group.rows.map(conditionRowHtml).join("")}</div><button type="button" class="pager-button text-button cg-add">+ Condition</button></div>`;
}

function readGroup(root) {
  const rows = Array.from(root.querySelectorAll(":scope > .cg-rows > .cond-row"));
  const leaves = rows.map((row) => {
    const field = $(".cr-field", row).value.trim();
    let op = $(".cr-op", row).value;
    const raw = $(".cr-values", row).value;
    const values = raw.split(",").map((v) => v.trim()).filter((v) => v !== "");
    const ci = $(".cr-ci-box", row).checked;
    if (!field) return null;
    let leaf;
    if (op === "exists") leaf = { field, op: "exists" };
    else if (op === "length_gte") leaf = { fn: "length", field, op: "gte", value: Number(values[0] || 0) };
    else if (["gt", "gte", "lt", "lte"].includes(op)) leaf = { field, op, values: values.map(Number) };
    else leaf = { field, op, values, ci };
    return $(".cr-not", row).value === "not" ? { not: leaf } : leaf;
  }).filter(Boolean);
  if (!leaves.length) return null;
  return leaves.length === 1 ? leaves[0] : { [$(".cg-mode", root).value]: leaves };
}

function groupFromCondition(node) {
  const leafRow = (leaf) => {
    const negated = !!leaf.not;
    const l = negated ? leaf.not : leaf;
    if (l.fn === "length") return { not: negated, field: l.field, op: "length_gte", values: [l.value] };
    return { not: negated, field: l.field, op: l.op, values: l.values || [], ci: l.ci };
  };
  if (!node) return { mode: "all", rows: [{}] };
  if (node.all || node.any) {
    const items = node.all || node.any;
    if (items.every((c) => c.field || (c.not && c.not.field))) return { mode: node.all ? "all" : "any", rows: items.map(leafRow) };
  }
  if (node.field || (node.not && node.not.field)) return { mode: "all", rows: [leafRow(node)] };
  return null;
}

function sourceRowHtml(source = {}) {
  return `<div class="source-row"><input class="filter-input sr-channel" list="channel-options" placeholder="Channel, e.g. Security" value="${escapeHtml(source.channel || "")}" aria-label="Channel"><input class="filter-input sr-ids" placeholder="Event IDs, e.g. 4624, 4625 (empty = all)" value="${escapeHtml((source.event_ids || []).join(", "))}" aria-label="Event IDs"><button type="button" class="pager-button text-button sr-remove" aria-label="Remove source">&#10005;</button></div>`;
}

function stepHtml(step = {}) {
  return `<div class="seq-step"><div class="inline-fields"><b class="step-label">Step</b><label>repeated <input class="filter-input tiny-input step-runs" inputmode="numeric" value="${step.runs || 1}"> time(s)</label><button type="button" class="pager-button text-button step-remove">Remove step</button></div>${conditionGroupHtml(groupFromCondition(step.condition) || undefined)}</div>`;
}

async function openRuleBuilder(rule) {
  await builderSchema();
  const form = $("#rule-form");
  form.reset();
  form.dataset.ruleId = rule ? rule.rule_id : "";
  $("#rule-dialog-title").textContent = rule ? `Edit ${rule.name}` : "Add rule";
  $("#rule-form-error").hidden = true;
  $("#rule-validate-note").textContent = "";
  form.rule_id.disabled = !!rule;
  $("#rule-sources").innerHTML = (rule ? rule.sources : [{ channel: "Security", event_ids: [] }]).map(sourceRowHtml).join("");
  $("#rule-condition").innerHTML = conditionGroupHtml(rule && groupFromCondition(rule.condition) || undefined);
  $("#rule-steps").innerHTML = rule && rule.steps ? rule.steps.map(stepHtml).join("") : stepHtml() + stepHtml();
  if (rule) {
    form.name.value = rule.name; form.severity.value = rule.severity; form.category.value = rule.category;
    form.kind.value = rule.kind; form.enabled.value = String(rule.enabled); form.description.value = rule.description || "";
    form.explanation.value = rule.explanation || rule.description || ""; form.investigation.value = rule.investigation || "";
    form.mitre.value = (rule.mitre || []).map((m) => m.technique).join(", "); form.rule_id.value = rule.rule_id;
    if (rule.threshold) { form.threshold_count.value = rule.threshold.count; form.threshold_window.value = rule.threshold.window_seconds; form.threshold_by.value = (rule.threshold.by || [])[0] || ""; }
    if (rule.maxspan) form.maxspan.value = rule.maxspan;
    if (rule.steps && rule.steps[0] && rule.steps[0].by) form.sequence_by.value = rule.steps[0].by[0] || "";
  }
  syncBuilderKind();
  $("#rule-dialog").showModal();
}

function syncBuilderKind() {
  const kind = $("#rule-kind-select").value;
  $("#rule-condition-block").hidden = kind === "sequence";
  $("#rule-threshold-block").hidden = kind !== "threshold";
  $("#rule-sequence-block").hidden = kind !== "sequence";
}

function builderPayload() {
  const form = $("#rule-form");
  const sources = Array.from(document.querySelectorAll("#rule-sources .source-row")).map((row) => ({
    channel: $(".sr-channel", row).value.trim(),
    event_ids: $(".sr-ids", row).value.split(",").map((v) => v.trim()).filter(Boolean).map(Number),
  })).filter((s) => s.channel);
  const kind = form.kind.value;
  const payload = {
    name: form.name.value, severity: form.severity.value, category: form.category.value, kind, enabled: form.enabled.value === "true",
    description: form.description.value, explanation: form.explanation.value, investigation: form.investigation.value,
    mitre: form.mitre.value.split(",").map((v) => v.trim()).filter(Boolean), sources,
  };
  if (!form.dataset.ruleId && form.rule_id.value.trim()) payload.rule_id = form.rule_id.value.trim();
  if (kind !== "sequence") payload.condition = readGroup($("#rule-condition .cond-builder"));
  if (kind === "threshold") payload.threshold = { count: Number(form.threshold_count.value), window_seconds: Number(form.threshold_window.value), by: form.threshold_by.value ? [form.threshold_by.value] : [] };
  if (kind === "sequence") {
    const by = form.sequence_by.value ? [form.sequence_by.value] : [];
    payload.steps = Array.from(document.querySelectorAll("#rule-steps .seq-step")).map((step) => ({ condition: readGroup($(".cond-builder", step)), by, runs: Number($(".step-runs", step).value) || 1 }));
    payload.maxspan = Number(form.maxspan.value);
  }
  return payload;
}

function showBuilderErrors(error) {
  const box = $("#rule-form-error");
  const errors = (error.data && error.data.errors) || {};
  const lines = Object.entries(errors).map(([key, message]) => `<li><b>${escapeHtml(key)}</b>: ${escapeHtml(message)}</li>`);
  box.innerHTML = `<b>${escapeHtml(error.message)}</b>${lines.length ? `<ul>${lines.join("")}</ul>` : ""}`;
  box.hidden = false;
  box.scrollIntoView({ block: "nearest" });
}

async function validateRule() {
  try {
    await apiSend("POST", "/api/detections/rules/validate", builderPayload());
    $("#rule-form-error").hidden = true;
    $("#rule-validate-note").textContent = "The rule is valid.";
  } catch (error) { $("#rule-validate-note").textContent = ""; showBuilderErrors(error); }
}

async function saveRule(event) {
  event.preventDefault();
  const form = $("#rule-form");
  const editing = form.dataset.ruleId;
  try {
    const result = editing ? await apiSend("PUT", `/api/detections/rules/${encodeURIComponent(editing)}`, builderPayload()) : await apiSend("POST", "/api/detections/rules", builderPayload());
    $("#rule-dialog").close();
    const job = result.job || {};
    toast(`${editing ? "Rule updated" : "Rule created"} (${result.rule.rule_id}).${result.rule.enabled ? ` Look-back over the last 7 days: ${job.state === "done" ? `${number(job.examined)} events checked, ${number(job.signals)} match(es)` : "running in the background"}.` : ""}`, 6000);
    loadRuleTable();
  } catch (error) { showBuilderErrors(error); }
}

// ---------- Timeline (detections, oldest first) ----------
const TL_PAGE = 200;
state.tl = { items: [], older: null, newer: null, hasOlder: false, hasNewer: false, debounce: null };

function timelineParams() {
  const params = [["limit", TL_PAGE], ["range", $("#tl-range").value || "7d"]];
  const q = $("#tl-search").value.trim(), sev = $("#tl-severity").value, eid = $("#tl-event-id").value.trim();
  if (q) params.push(["q", q]);
  if (sev) params.push(["severity", sev]);
  if (/^\d+$/.test(eid)) params.push(["event_id", eid]);
  return params;
}

const dayKey = (value) => { const d = new Date(value); return Number.isNaN(d.getTime()) ? "Unknown date" : d.toLocaleDateString([], { weekday: "long", year: "numeric", month: "long", day: "numeric" }); };

function renderTimeline() {
  const started = performance.now();
  const root = $("#timeline-list");
  if (!state.tl.items.length) { root.innerHTML = emptyState("No active detections in this window. Switched-off rules' detections are kept in Detections → History."); }
  else {
    let lastDay = null;
    root.innerHTML = state.tl.items.map((item) => {
      const day = dayKey(item.det_time);
      const header = day !== lastDay ? `<div class="timeline-day">${escapeHtml(day)}</div>` : "";
      lastDay = day;
      return `${header}<div class="timeline-entry ${sevClass(item.severity)}" data-det-id="${escapeHtml(item.id)}" role="button" tabindex="0"><time class="timeline-time" datetime="${escapeHtml(item.det_time)}" title="${escapeHtml(fullTime(item.det_time))}">${escapeHtml(new Date(item.det_time).toLocaleTimeString([], { hour12: false }))}</time><span class="timeline-rail"></span>
        <div class="timeline-body"><div class="timeline-title">${sevPill(item.severity)} <b>${escapeHtml(item.title)}</b> <span class="risk-inline">risk ${Number(item.score).toFixed(0)}</span></div>
        <div class="timeline-meta">Event ${escapeHtml(item.event_ids.join(", "))} · ${escapeHtml(item.channels.join(", "))} · rule <span class="mono-cell">${escapeHtml(item.primary_rule_id)}</span>${item.rule_ids.length > 1 ? ` +${item.rule_ids.length - 1}` : ""} · ${escapeHtml(item.summary || "")}</div></div></div>`;
    }).join("");
  }
  $("#tl-earlier").hidden = !state.tl.hasOlder;
  $("#tl-more").hidden = !state.tl.hasNewer;
  $("#tl-end").textContent = state.tl.items.length && !state.tl.hasNewer ? "End of the window - newest detection shown last." : "";
  state.metrics.timelineRenderMs = performance.now() - started;
}

async function loadTimeline(position = "start") {
  try {
    const params = new URLSearchParams([...timelineParams(), ["position", position]]);
    const data = await api(`/api/timeline/detections?${params}`);
    state.tl.items = data.items;
    state.tl.older = data.older_cursor; state.tl.newer = data.newer_cursor;
    state.tl.hasOlder = data.has_older; state.tl.hasNewer = data.has_newer;
    $("#tl-count").textContent = `${number(data.total)} active detection${data.total === 1 ? "" : "s"} · oldest first`;
    $("#timeline-updated").textContent = `UPDATED ${new Date().toLocaleTimeString([], { hour12: false })}`;
    renderTimeline();
    if (position === "end") window.scrollTo({ top: document.body.scrollHeight });
  } catch (error) { $("#timeline-list").innerHTML = emptyState(error.message); }
}

async function loadTimelineMore(direction) {
  const cursor = direction === "older" ? state.tl.older : state.tl.newer;
  if (!cursor) return;
  const params = new URLSearchParams([...timelineParams(), [direction === "older" ? "before" : "after", cursor]]);
  const data = await api(`/api/timeline/detections?${params}`);
  const seen = new Set(state.tl.items.map((i) => i.id));
  const fresh = data.items.filter((i) => !seen.has(i.id));
  state.tl.items = direction === "older" ? [...fresh, ...state.tl.items] : [...state.tl.items, ...fresh];
  if (direction === "older") { state.tl.older = data.older_cursor || state.tl.older; state.tl.hasOlder = data.has_older; }
  else { state.tl.newer = data.newer_cursor || state.tl.newer; state.tl.hasNewer = data.has_newer; }
  renderTimeline();
}

async function timelineLiveUpdate() {
  if (state.tl.hasNewer) return;               // the reader is not at the newest end: do not move the list
  const anchor = window.scrollY;
  await loadTimelineMore("newer").catch(() => {});
  if (!state.tl.newer) await loadTimeline("start");
  window.scrollTo({ top: anchor });
}

// ---------- Endpoint ----------
async function renderEndpoint() {
  const root = $("#endpoint-root");
  try {
    const data = await api("/api/endpoint");
    const host = data.hosts[0];
    const collector = data.collector || {};
    const agent = (collector.agents || [])[0] || {};
    const counts = data.detections.counts || {};
    const columns = data.detections.columns || {};
    const recent = [...(columns.critical_high?.recent || []), ...(columns.medium?.recent || []), ...(columns.low_info?.recent || [])].sort((a, b) => (a.det_time < b.det_time ? 1 : -1)).slice(0, 8);
    root.innerHTML = `<div class="endpoint-grid">
      <section class="surface endpoint-card"><span class="section-kicker">HOST IDENTITY</span><h2>${escapeHtml(host ? host.hostname : "No host has reported yet")}</h2>
        <div class="detail-grid">${kv("Operating system", escapeHtml(host?.os_name || "—"))}${kv("Agent", `<span class="mono-cell">${escapeHtml(host?.agent_id || "—")}</span>`)}${kv("Last check-in", escapeHtml(host ? `${dayTime(host.last_seen)} · ${ago(host.last_seen)}` : "—"))}</div></section>
      <section class="surface endpoint-card"><span class="section-kicker">MONITORING STATUS</span><h2>${escapeHtml(agent.state_label || collector.summary || (host ? "Receiving events" : "Not monitored"))}</h2>
        <div class="detail-grid">${kv("Collector", escapeHtml(agent.mode ? `${agent.mode} · ${agent.backend || ""}` : "—"))}${kv("Last heartbeat", escapeHtml(agent.last_heartbeat ? ago(agent.last_heartbeat) : "—"))}${kv("Detection engine", escapeHtml(data.processing.backlog_events ? `processing ${number(data.processing.backlog_events)} queued events` : "up to date"))}${kv("Behaviour model", escapeHtml(stageLabel(data.model.stage)))}</div></section>
      <section class="surface endpoint-card"><span class="section-kicker">DETECTIONS ON THIS HOST · LAST 7 DAYS</span><h2>${number(data.detections.active_total)} active</h2>
        <div class="det-counts">${SEVERITY_ORDER.map((s) => `<button type="button" class="det-count ${sevClass(s)}" data-go-severity="${s}"><b>${number(counts[s])}</b><span>${s}</span></button>`).join("")}</div>
        <p class="rules-note">Latest detection: ${escapeHtml(data.detections.latest ? `${dayTime(data.detections.latest)} (${ago(data.detections.latest)})` : "none")}</p></section>
    </div>
    <div class="endpoint-grid two">
      <section class="surface endpoint-card"><span class="section-kicker">RECENT DETECTIONS</span><div class="det-recent">${recent.length ? recent.map(detectionMini).join("") : emptyState("No detections in the last 7 days.")}</div></section>
      <section class="surface endpoint-card"><span class="section-kicker">EVENT COLLECTION</span>
        <div class="table-scroll"><table class="data-table compact-table"><thead><tr><th>CHANNEL</th><th>STATE</th><th>EVENTS</th><th>RULES</th><th>LAST SUCCESS</th></tr></thead><tbody>${data.channels.map((c) => `<tr><td title="${escapeHtml(c.channel)}">${escapeHtml(c.channel.replace(/^Microsoft-Windows-/, "").replace(/\/Operational$/, ""))}</td><td>${escapeHtml(c.state_label)}</td><td>${number(c.events_stored)}</td><td>${number(c.enabled_rules)}</td><td class="mono-cell">${escapeHtml(c.last_success_at ? ago(c.last_success_at) : "—")}</td></tr>`).join("")}</tbody></table></div>
        <h4>Optional sources</h4>${data.optional_sources.map((o) => `<div class="mini-row"><span>${escapeHtml(o.source)} <small>${escapeHtml(o.channel)}</small></span><b class="${o.state === "ok" ? "ok-text" : "warn-text"}">${escapeHtml(o.state === "ok" ? `available · ${number(o.events_stored)} events` : o.state_label)} · ${number(o.rules)} rules need it</b></div>`).join("")}</section>
    </div>`;
  } catch (error) { root.innerHTML = emptyState(error.message); }
}

// ---------- Wiring ----------
function setScopeTabs() {
  document.querySelectorAll("[data-det-scope]").forEach((b) => { const on = b.dataset.detScope === state.det.scope; b.classList.toggle("active", on); b.setAttribute("aria-selected", String(on)); });
}

function wireDetections() {
  mountTimeFilter("#det-time", () => { state.det.offset = 0; loadDetections(); });
  mountTimeFilter("#event-time", () => { state.offset = 0; loadEvents(); });
  document.querySelectorAll("[data-det-scope]").forEach((b) => b.addEventListener("click", () => { state.det.scope = b.dataset.detScope; state.det.offset = 0; setScopeTabs(); loadDetections(); }));
  ["#det-search", "#det-rule", "#det-event-id"].forEach((id) => $(id).addEventListener("input", scheduleDetectionSearch));
  ["#det-severity", "#det-category", "#det-status", "#det-verdict", "#det-rule-state", "#det-source", "#det-sort"].forEach((id) => $(id).addEventListener("change", () => { state.det.offset = 0; loadDetections(); }));
  $("#det-reset").addEventListener("click", () => {
    ["#det-search", "#det-rule", "#det-event-id"].forEach((id) => { $(id).value = ""; });
    ["#det-severity", "#det-category", "#det-status", "#det-verdict", "#det-rule-state", "#det-source"].forEach((id) => { $(id).value = ""; });
    $("#det-sort").value = "time_desc"; state.det.ruleId = null; state.det.offset = 0; loadDetections();
  });
  $("#det-rule-chip").addEventListener("click", (event) => { if (event.target.closest("button")) { state.det.ruleId = null; loadDetections(); } });
  $("#det-prev").addEventListener("click", () => { state.det.offset = Math.max(0, state.det.offset - state.det.limit); loadDetections(); });
  $("#det-next").addEventListener("click", () => { if (state.det.offset + state.det.limit < state.det.total) { state.det.offset += state.det.limit; loadDetections(); } });
  $("#det-body").addEventListener("click", (event) => { const row = event.target.closest("[data-det-id]"); if (row) showDetection(row.dataset.detId); });
  $("#det-body").addEventListener("keydown", (event) => { if (event.key === "Enter") event.target.closest("[data-det-id]")?.click(); });
  $("#close-det-dialog").addEventListener("click", () => $("#det-dialog").close());
  $("#det-dialog").addEventListener("click", (event) => {
    if (event.target === $("#det-dialog")) { $("#det-dialog").close(); return; }
    const evButton = event.target.closest("[data-event-key]");
    if (evButton) showEvent(evButton.dataset.eventKey);
  });
  document.addEventListener("click", (event) => {
    const sev = event.target.closest("[data-go-severity]");
    if (sev) { state.det.scope = "active"; setScopeTabs(); goDetections({ severity: sev.dataset.goSeverity }); return; }
    const mini = event.target.closest(".det-mini[data-det-id]");
    if (mini) showDetection(mini.dataset.detId);
  });
  // Rules
  document.querySelectorAll("[data-rules-tab]").forEach((b) => b.addEventListener("click", () => setRulesTab(b.dataset.rulesTab)));
  $("#rule-search").addEventListener("input", () => { clearTimeout(state.rulesView.debounce); state.rulesView.debounce = setTimeout(() => { state.rulesView.offset = 0; loadRuleTable(); }, 250); });
  ["#rule-origin", "#rule-kind", "#rule-state", "#rule-support", "#rule-sort"].forEach((id) => $(id).addEventListener("change", () => { state.rulesView.offset = 0; loadRuleTable(); }));
  $("#rule-prev").addEventListener("click", () => { state.rulesView.offset = Math.max(0, state.rulesView.offset - state.rulesView.limit); loadRuleTable(); });
  $("#rule-next").addEventListener("click", () => { if (state.rulesView.offset + state.rulesView.limit < state.rulesView.total) { state.rulesView.offset += state.rulesView.limit; loadRuleTable(); } });
  $("#rules-body").addEventListener("click", (event) => {
    const toggle = event.target.closest("[data-toggle-rule]");
    if (toggle) { toggleRule(toggle); return; }
    const open = event.target.closest("[data-open-rule]");
    if (open) { openRule(open.dataset.openRule); return; }
    const dets = event.target.closest("[data-rule-detections]");
    if (dets) { state.det.scope = "all"; setScopeTabs(); goDetections({ ruleId: dets.dataset.ruleDetections }); }
  });
  $("#rules-tab-suppressions").addEventListener("click", async (event) => {
    const revoke = event.target.closest("[data-revoke]");
    if (!revoke) return;
    try { await apiSend("DELETE", `/api/suppressions/${encodeURIComponent(revoke.dataset.revoke)}`); toast("Suppression revoked; matching detections are active again."); loadSuppressions(); } catch (error) { toast(error.message, 6000); }
  });
  $("#close-rule-detail").addEventListener("click", () => $("#rule-detail-dialog").close());
  $("#add-rule").addEventListener("click", () => openRuleBuilder(null));
  $("#close-rule-dialog").addEventListener("click", () => $("#rule-dialog").close());
  $("#cancel-rule").addEventListener("click", () => $("#rule-dialog").close());
  $("#rule-kind-select").addEventListener("change", syncBuilderKind);
  $("#validate-rule").addEventListener("click", validateRule);
  $("#rule-form").addEventListener("submit", saveRule);
  $("#add-source").addEventListener("click", () => $("#rule-sources").insertAdjacentHTML("beforeend", sourceRowHtml()));
  $("#add-step").addEventListener("click", () => $("#rule-steps").insertAdjacentHTML("beforeend", stepHtml()));
  $("#rule-dialog").addEventListener("click", (event) => {
    if (event.target.closest(".cg-add")) { event.target.closest(".cond-builder").querySelector(".cg-rows").insertAdjacentHTML("beforeend", conditionRowHtml()); return; }
    if (event.target.closest(".cr-remove")) { const rows = event.target.closest(".cg-rows"); if (rows.children.length > 1) event.target.closest(".cond-row").remove(); return; }
    if (event.target.closest(".sr-remove")) { const list = $("#rule-sources"); if (list.children.length > 1) event.target.closest(".source-row").remove(); return; }
    if (event.target.closest(".step-remove")) { const list = $("#rule-steps"); if (list.children.length > 2) event.target.closest(".seq-step").remove(); }
  });
  // Timeline
  const scheduleTimeline = () => { clearTimeout(state.tl.debounce); state.tl.debounce = setTimeout(() => loadTimeline("start"), 250); };
  ["#tl-search", "#tl-event-id"].forEach((id) => $(id).addEventListener("input", scheduleTimeline));
  ["#tl-range", "#tl-severity"].forEach((id) => $(id).addEventListener("change", () => loadTimeline("start")));
  $("#tl-oldest").addEventListener("click", () => loadTimeline("start"));
  $("#tl-newest").addEventListener("click", () => loadTimeline("end"));
  $("#tl-earlier").addEventListener("click", () => loadTimelineMore("older"));
  $("#tl-more").addEventListener("click", () => loadTimelineMore("newer"));
  $("#timeline-list").addEventListener("click", (event) => { const entry = event.target.closest("[data-det-id]"); if (entry) showDetection(entry.dataset.detId); });
  $("#timeline-list").addEventListener("keydown", (event) => { if (event.key === "Enter") event.target.closest("[data-det-id]")?.click(); });
}
wireDetections();

// ---------- Live refresh: poll a cheap change marker, refresh only what changed ----------
state.live = { events: null, detections: null, rules: null, interval: 3, timer: null, lastOk: null, engineReady: null, viewRefreshAt: 0, viewLoading: false };

async function livePoll() {
  try {
    const live = await api("/api/live");
    state.live.lastOk = Date.now();
    const engineNowReady = live.engine_ready && state.live.engineReady === false;
    state.live.engineReady = !!live.engine_ready;
    const changed = engineNowReady || (state.live.events !== null && (live.events_seq !== state.live.events || live.detections_seq !== state.live.detections || live.rules_version !== state.live.rules));
    state.live.events = live.events_seq; state.live.detections = live.detections_seq; state.live.rules = live.rules_version;
    if (live.refresh_seconds && live.refresh_seconds !== state.live.interval) state.live.interval = live.refresh_seconds;
    const heartbeat = live.last_collector_heartbeat ? ` · collector ${ago(live.last_collector_heartbeat)}` : "";
    const engineNote = !live.engine_ready ? " · detection engine starting" : live.engine_replaying ? " · rebuilding correlation state" : (live.detection_backlog > 2000 ? ` · detecting (${number(live.detection_backlog)} queued)` : "");
    setConnection("connected", `Live · ${state.live.interval}s${heartbeat}${engineNote}`);
    $("#connection-state").title = `Polling every ${state.live.interval}s. Newest event ${live.newest_event_time || "—"}. Detection engine: ${live.engine_phase || "—"}, backlog ${number(live.detection_backlog || 0)} event(s).`;
    // While history is being collected the data changes on every poll; redrawing a whole page every
    // 3 s made the dashboard feel stuck.  Views refresh at most every 10 s unless the engine just became ready.
    const due = engineNowReady || Date.now() - (state.live.viewRefreshAt || 0) >= 10000;
    if (changed && !document.hidden && due && !state.live.viewLoading) {
      state.live.viewRefreshAt = Date.now();
      state.metrics.lastLiveRefresh = Date.now();
      // The Detections list refreshes on its own 60-second timer (rows stay still while being read).
      let pending = null;
      if (engineNowReady) pending = reloadCurrentView();      // pages that showed "engine starting" fill in
      else if (state.view === "overview") pending = loadOverview();
      else if (state.view === "timeline") pending = timelineLiveUpdate();
      else if (state.view === "events" && state.offset === 0) pending = loadEvents();
      else if (state.view === "endpoints") pending = renderEndpoint();
      if (state.view !== "detections") refreshDetectionBadge(engineNowReady);
      if (pending && pending.finally) { state.live.viewLoading = true; pending.finally(() => { state.live.viewLoading = false; }); }
    }
  } catch (error) {
    setConnection("offline", "API unavailable");
  } finally {
    clearTimeout(state.live.timer);
    state.live.timer = setTimeout(livePoll, state.live.interval * 1000);
  }
}

// ---------- Start-up ----------
api("/api/health").then(() => setConnection("connected", "API connected")).catch(() => setConnection("offline", "API unavailable"));
loadOverview();
api("/api/config").then((config) => {
  state.live.interval = config.refresh_seconds || 3;
  state.det.refreshSeconds = config.anomaly_refresh_seconds || 60;
  if (state.view === "detections") startDetectionTimer();
  updateDetectionRefreshNote();
}).catch(() => {}).finally(livePoll);
