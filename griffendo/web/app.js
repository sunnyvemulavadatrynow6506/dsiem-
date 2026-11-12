const viewInfo = {
  overview: { title: "Overview", heading: "Signal, at a glance.", description: "A live view of collected Windows event activity." },
  detections: { title: "Detections", heading: "What needs attention.", description: "Rule matches, correlated event chains and behaviour anomalies on this host, scored and explained." },
  rules: { title: "Rules", heading: "Decide what is detected.", description: "Imported, built-in and custom detection rules, the behaviour model, suppressions and collection health." },
  events: { title: "Event explorer", heading: "Every event, in context.", description: "Search normalized fields and inspect the original event XML." },
  processes: { title: "Processes", heading: "Execution, connected.", description: "Review process activity and available parent-child relationships." },
  timeline: { title: "Timeline", heading: "Sequence tells the story.", description: "Active detections over the last seven days, oldest first, updating live." },
  endpoints: { title: "Endpoint", heading: "This host, monitored.", description: "Host identity, monitoring and collection status, and the detections raised on it." }
};

const state = { view: "overview", offset: 0, limit: 50, total: 0, debounce: null, overview: null, quick: null, host: null };
const $ = (selector, root = document) => root.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character]);
const number = (value) => new Intl.NumberFormat().format(value || 0);

const hex = (value) => (value === null || value === undefined || value === "" ? "—" : value);
const pidText = (value) => (value === null || value === undefined || value === "" ? "" : `PID ${value}`);

function processCell(event) {
  if (!event.process_name) return `<span class="proc-none">—</span>`;
  return `<span class="proc-name" title="${escapeHtml(event.process_path || event.process_name)}">${escapeHtml(event.process_name)}</span>${event.pid != null ? `<span class="proc-sub">${pidText(event.pid)}</span>` : ""}`;
}

function parentCell(event) {
  if (event.parent_process_name) return `<span class="parent-name">${escapeHtml(event.parent_process_name)}</span>${event.parent_pid != null ? `<span class="proc-sub">${pidText(event.parent_pid)}</span>` : ""}`;
  if (event.parent_pid != null) return `<span class="proc-none">${pidText(event.parent_pid)} (name not logged)</span>`;
  return `<span class="proc-none">—</span>`;
}

// A thin progress bar at the top while any request has taken longer than 300 ms (v5.1), so a slow
// page shows that it is working instead of looking frozen.
const requestState = { count: 0, timer: null };
function requestStarted() {
  requestState.count += 1;
  if (!requestState.timer) requestState.timer = setTimeout(() => document.body.classList.add("is-loading"), 300);
}
function requestFinished() {
  requestState.count = Math.max(0, requestState.count - 1);
  if (!requestState.count) { clearTimeout(requestState.timer); requestState.timer = null; document.body.classList.remove("is-loading"); }
}

async function api(path) {
  const quiet = path.startsWith("/api/live");          // the background poll never shows the bar
  if (!quiet) requestStarted();
  try {
    const response = await fetch(path, { headers: { Accept: "application/json" } });
    if (!response.ok) {
      const detail = await response.json().catch(() => ({}));
      throw new Error(detail.detail || `Request failed (${response.status})`);
    }
    return await response.json();
  } finally {
    if (!quiet) requestFinished();
  }
}

function setConnection(status, label) {
  const element = $("#connection-state");
  element.className = `connection-state ${status}`;
  element.lastElementChild.textContent = label;
}

function toast(message, ms = 2600) {
  const element = $("#toast");
  element.textContent = message;
  element.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.remove("show"), ms);
}

function emptyState(message) {
  return `<div class="empty-state">${escapeHtml(message)}</div>`;
}

function eventTime(value) {
  if (!value) return "Time unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? escapeHtml(value) : date.toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
}

function renderMetrics(totals = {}) {
  const metrics = [
    ["Events collected", totals.events, "RAW RECORDS PRESERVED"],
    ["Reporting hosts", totals.hosts, "DISTINCT ENDPOINTS"],
    ["Observed processes", totals.processes, "NORMALIZED PROCESS NAMES"],
    ["Event IDs", totals.event_ids, "DISTINCT IDS SEEN"]
  ];
  $("#metric-grid").innerHTML = metrics.map(([label, value, foot], index) => `
    <article class="metric-card"><div class="metric-top"><span>${label}</span><span class="metric-index">0${index + 1}</span></div>
    <div class="metric-value">${number(value)}</div><div class="metric-foot">${foot}</div></article>`).join("");
}

// ---------- 24-hour activity graph (v4): stacked by event category, rolling window, local hours ----------
// Category -> colour is fixed (never by rank), validated for colour-vision deficiency; every colour also has
// a text label (legend with counts, tooltip and table view), so nothing relies on colour alone.
const CATEGORY_COLORS = { security: "#2a78d6", system: "#eb6834", application: "#1baf7a", defender: "#eda100", other: "#e87ba4", unknown: "#008300" };
const localClock = (value, withMinutes = true) => { const d = new Date(value); return Number.isNaN(d.getTime()) ? "—" : d.toLocaleTimeString([], { hour: "2-digit", minute: withMinutes ? "2-digit" : undefined, hour12: false }); };

function bucketLabel(bucket) {
  return `${localClock(bucket.start)}–${localClock(bucket.end)}${bucket.partial ? " (partial hour)" : ""}`;
}

function renderActivityChart(activity) {
  const chart = $("#trend-chart"), legend = $("#trend-legend"), note = $("#trend-note");
  state.activity = activity;
  if (!activity) { chart.innerHTML = `<div class="chart-empty">Activity data unavailable.</div>`; return; }
  const categories = activity.categories;
  legend.innerHTML = categories.map((c) => `<span class="legend-chip${c.total ? "" : " is-zero"}" title="${escapeHtml(Object.keys(c.channels).join(", ") || "No events")}"><span class="legend-swatch" style="background:${CATEGORY_COLORS[c.key]}"></span>${escapeHtml(c.label)} <b>${number(c.total)}</b></span>`).join("");
  const others = categories.find((c) => c.key === "other");
  note.textContent = `${number(activity.total)} events from ${dayTime(activity.window_start)} to ${dayTime(activity.window_end)} (event time)${others && others.total ? ` · Other channels: ${Object.keys(others.channels).join(", ")}` : ""}`;
  renderActivityTable(activity);
  if (!activity.total) {
    chart.innerHTML = `<div class="chart-empty">No events were recorded in the last 24 hours (${escapeHtml(dayTime(activity.window_start))} – ${escapeHtml(dayTime(activity.window_end))}). If collection is not running, this is missing data, not a quiet system.</div>`;
    return;
  }
  const buckets = activity.buckets;
  // Drawn in real pixels (no stretching), so labels keep their size at every window width.
  const W = Math.max(280, Math.round(chart.clientWidth || 700)), H = 200, left = 40, right = 6, top = 10, base = 166;
  const maxTotal = Math.max(...buckets.map((b) => b.total), 1);
  const step = Math.pow(10, Math.floor(Math.log10(maxTotal)));
  const nice = [1, 2, 2.5, 5, 10].map((m) => m * step).find((v) => v >= maxTotal / 2) || maxTotal;
  const yMax = Math.max(nice * 2, maxTotal);
  const y = (value) => base - (value / yMax) * (base - top);
  const slot = (W - left - right) / buckets.length;
  const barWidth = Math.max(6, Math.min(22, slot * 0.66));
  const grid = [0, yMax / 2, yMax].map((v) => `<line class="chart-gridline" x1="${left}" y1="${y(v)}" x2="${W - right}" y2="${y(v)}"/><text class="chart-axis" x="${left - 6}" y="${y(v) + 4}" text-anchor="end">${number(Math.round(v))}</text>`).join("");
  const every = Math.max(1, Math.ceil(buckets.length / Math.max(3, Math.floor((W - left) / 64))));
  const bars = buckets.map((bucket, index) => {
    const x = left + index * slot + (slot - barWidth) / 2;
    let cursor = base, parts = "";
    const present = categories.filter((c) => bucket.counts[c.key]);
    present.forEach((c, n) => {
      const height = Math.max(1, base - y(bucket.counts[c.key]));
      const gap = n > 0 ? 2 : 0;                        // 2px surface gap between stacked segments
      const segTop = cursor - height;
      const h = Math.max(1, height - gap);
      const isTop = n === present.length - 1;
      const r = isTop ? Math.min(4, h / 2, barWidth / 2) : 0;
      parts += isTop && r > 0
        ? `<path class="chart-seg" fill="${CATEGORY_COLORS[c.key]}" d="M${x},${segTop + h} V${segTop + r} Q${x},${segTop} ${x + r},${segTop} H${x + barWidth - r} Q${x + barWidth},${segTop} ${x + barWidth},${segTop + r} V${segTop + h} Z"/>`
        : `<rect class="chart-seg" fill="${CATEGORY_COLORS[c.key]}" x="${x}" y="${segTop}" width="${barWidth}" height="${h}"/>`;
      cursor = segTop;
    });
    const label = index % every === 0 || index === buckets.length - 1 ? `<text class="chart-label" x="${x + barWidth / 2}" y="${base + 16}" text-anchor="middle">${escapeHtml(localClock(bucket.start))}</text>` : "";
    return `<g class="chart-col">${parts}<rect class="chart-hit" data-bucket="${index}" x="${left + index * slot}" y="${top}" width="${slot}" height="${base - top}" tabindex="0" aria-label="${escapeHtml(bucketLabel(bucket))}: ${bucket.total} events"/>${label}</g>`;
  }).join("");
  chart.innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Events per hour over the last 24 hours, stacked by category. A table view is available below the chart.">${grid}${bars}</svg><div class="chart-tip" id="chart-tip" hidden></div>`;
}

function showActivityTip(target) {
  const tip = $("#chart-tip");
  const activity = state.activity;
  if (!tip || !activity || !target || !target.dataset.bucket) return;
  const bucket = activity.buckets[Number(target.dataset.bucket)];
  const rows = activity.categories.filter((c) => bucket.counts[c.key]).map((c) => `<div class="tip-row"><span class="legend-swatch" style="background:${CATEGORY_COLORS[c.key]}"></span><span>${escapeHtml(c.label)}</span><b>${number(bucket.counts[c.key])}</b></div>`).join("");
  tip.innerHTML = `<div class="tip-head">${escapeHtml(bucketLabel(bucket))}</div>${rows || `<div class="tip-row"><span>No events</span></div>`}<div class="tip-row tip-total"><span>Total</span><b>${number(bucket.total)}</b></div>`;
  tip.hidden = false;
  const box = $("#trend-chart").getBoundingClientRect(), rect = target.getBoundingClientRect();
  const leftPos = Math.min(Math.max(0, rect.left - box.left + rect.width / 2 - 90), box.width - 180);
  tip.style.left = `${leftPos}px`;
  tip.style.top = "0px";
  document.querySelectorAll(".chart-col.hover").forEach((col) => col.classList.remove("hover"));
  target.parentNode.classList.add("hover");
}

function hideActivityTip() {
  const tip = $("#chart-tip");
  if (tip) tip.hidden = true;
  document.querySelectorAll(".chart-col.hover").forEach((col) => col.classList.remove("hover"));
}

function renderActivityTable(activity) {
  const table = $("#trend-table");
  const cats = activity.categories;
  table.innerHTML = `<div class="table-scroll"><table class="data-table compact-table"><thead><tr><th>HOUR (LOCAL)</th>${cats.map((c) => `<th>${escapeHtml(c.label.toUpperCase())}</th>`).join("")}<th>TOTAL</th></tr></thead><tbody>${activity.buckets.map((b) => `<tr><td>${escapeHtml(bucketLabel(b))}</td>${cats.map((c) => `<td class="mono-cell">${number(b.counts[c.key] || 0)}</td>`).join("")}<td class="mono-cell"><b>${number(b.total)}</b></td></tr>`).join("")}</tbody></table></div>`;
}

function renderEventIds(rows) {
  const root = $("#event-id-list");
  if (!rows.length) { root.innerHTML = emptyState("No event IDs yet. New endpoint events will be ranked here."); return; }
  const maximum = Math.max(...rows.map((row) => row.count), 1);
  root.innerHTML = rows.map((row) => `<div class="rank-row" role="button" tabindex="0" data-event-id="${row.event_id}" title="Filter explorer to event ${row.event_id}">
    <span class="rank-id">${row.event_id}</span><span class="rank-label">${escapeHtml(row.label)}</span><span class="rank-track"><span class="rank-fill" style="width:${Math.max(3, row.count / maximum * 100)}%"></span></span><span class="rank-count">${number(row.count)}</span></div>`).join("");
}

function renderProcessesPreview(rows) {
  const root = $("#process-preview");
  if (!rows.length) { root.innerHTML = emptyState("Process activity appears when process-creation audit events are collected."); return; }
  root.innerHTML = rows.slice(0, 5).map((row) => `<div class="process-row" data-process="${escapeHtml(row.process_name)}"><span class="process-name">${escapeHtml(row.process_name)}</span><span class="process-host">${escapeHtml(row.hostname || "Multiple hosts")}</span><span class="process-count">${number(row.count)}</span></div>`).join("");
}

function renderChannels(rows) {
  const root = $("#channel-list");
  if (!rows.length) { root.innerHTML = emptyState("No channel data received yet."); return; }
  const maximum = Math.max(...rows.map((row) => row.count), 1);
  root.innerHTML = rows.map((row) => `<div class="channel-row"><span title="${escapeHtml(row.channel)}">${escapeHtml(row.channel)}</span><span class="channel-track"><span class="channel-fill" style="display:block;width:${Math.max(3, row.count / maximum * 100)}%"></span></span><span class="channel-count">${number(row.count)}</span></div>`).join("");
}

async function loadOverview() {
  try {
    const data = await api(`/api/overview?tz_offset=${-new Date().getTimezoneOffset()}`);
    state.overview = data;
    renderMetrics(data.totals);
    renderActivityChart(data.activity_24h);
    renderEventIds(data.event_ids);
    renderProcessesPreview(data.processes);
    renderChannels(data.channels);
    syncChannelFilter(data.channels);
    loadDetectionOverview();
    setConnection("connected", "API connected");
    return true;
  } catch (error) {
    setConnection("offline", "API unavailable");
    toast(error.message);
    return false;
  }
}

// Channels beyond the original four (added for anomaly rules) become filterable too.
function syncChannelFilter(rows) {
  const select = $("#channel-filter");
  const known = new Set(Array.from(select.options).map((option) => option.value));
  rows.forEach((row) => { if (row.channel && !known.has(row.channel)) { select.add(new Option(row.channel, row.channel)); known.add(row.channel); } });
}

function currentEventFilters() {
  const params = new URLSearchParams({ limit: state.limit, offset: state.offset });
  const search = $("#event-search").value.trim();
  const host = $("#host-filter").value.trim();
  const channel = $("#channel-filter").value;
  const eventId = $("#event-id-filter").value.trim();
  if (search) params.set("q", search);
  if (host) params.set("host", host);
  if (channel) params.set("channel", channel);
  if (eventId && /^\d+$/.test(eventId)) params.set("event_id", eventId);
  timeFilterParams("#event-time").forEach(([key, value]) => params.set(key, value));
  return params;
}

async function loadEvents() {
  const body = $("#events-body");
  try {
    const data = await api(`/api/events?${currentEventFilters()}`);
    state.total = data.total;
    $("#event-result-count").textContent = `${number(data.total)} matching event${data.total === 1 ? "" : "s"}`;
    const start = data.total ? state.offset + 1 : 0;
    const end = Math.min(state.offset + data.items.length, data.total);
    $("#event-page-label").textContent = `${start}-${end} of ${number(data.total)}`;
    $("#previous-page").disabled = state.offset === 0;
    $("#next-page").disabled = state.offset + state.limit >= data.total;
    if (!data.items.length) {
      body.innerHTML = `<tr><td colspan="8">${emptyState("No events match this view. Check the filters or connect an agent to begin ingestion.")}</td></tr>`;
      return;
    }
    body.innerHTML = data.items.map((event) => `<tr data-event-id="${escapeHtml(event.id)}">
      <td>${eventTime(event.timestamp)}</td>
      <td><span class="event-badge"><b>${event.event_id ?? "—"}</b><span>${escapeHtml(event.event_label || event.provider || "Windows event")}</span></span></td>
      <td>${escapeHtml(event.channel)}</td><td>${escapeHtml(event.hostname)}</td>
      <td>${escapeHtml(event.username || "—")}</td>
      <td class="proc-cell">${processCell(event)}</td>
      <td class="proc-cell">${parentCell(event)}</td>
      <td><span class="level-pill ${escapeHtml((event.severity || "").toLowerCase())}">${escapeHtml(event.severity || "Unknown")}</span></td>
      </tr>`).join("");
  } catch (error) { body.innerHTML = `<tr><td colspan="8">${emptyState(error.message)}</td></tr>`; }
}

async function showEvent(eventId) {
  try {
    const event = await api(`/api/events/${encodeURIComponent(eventId)}`);
    $("#event-dialog .dialog-head .section-kicker").textContent = "EVENT RECORD";
    $("#dialog-title").textContent = `Event ${event.event_id ?? "record"} · ${event.event_label} · ${event.hostname}`;
    const f = event.fields || {};
    const parentPath = f.ParentProcessName || f.ParentImage || f.CreatorProcessName || null;
    const details = [
      ["EVENT", "__group__"],
      ["Timestamp", event.timestamp], ["Host", event.hostname], ["Channel", event.channel],
      ["Provider", event.provider], ["Severity", event.severity], ["User", event.username],
      ["PROCESS (CHILD)", "__group__"],
      ["Process name", event.process_name], ["Process path", event.process_path], ["PID", event.pid],
      ["PARENT PROCESS", "__group__"],
      ["Parent process name", event.parent_process_name], ["Parent process path", parentPath], ["Parent PID", event.parent_pid],
      ["COMMAND", "__group__"],
      ["Command line", event.command_line]
    ];
    const fields = Object.entries(event.fields || {}).map(([key, value]) => `<div class="detail-item"><span>${escapeHtml(key)}</span><b>${escapeHtml(value)}</b></div>`).join("");
    $("#dialog-body").innerHTML = `<div class="detail-grid">${details.map(([label, value]) => value === "__group__" ? `<div class="detail-group">${escapeHtml(label)}</div>` : `<div class="detail-item"><span>${escapeHtml(label)}</span><b>${escapeHtml(value ?? "—")}</b></div>`).join("")}</div>
      ${fields ? `<div class="detail-section"><h3>Event data</h3><div class="detail-grid">${fields}</div></div>` : ""}
      <div class="detail-section"><h3>Original event XML</h3><pre class="raw-event">${escapeHtml(event.raw_xml)}</pre></div>`;
    $("#event-dialog").showModal();
  } catch (error) { toast(error.message); }
}

async function loadProcesses() {
  const body = $("#processes-body");
  loadLineage();
  try {
    const rows = await api("/api/processes?limit=250");
    if (!rows.length) {
      body.innerHTML = `<tr><td colspan="7">${emptyState("No process records found. Enable process-creation auditing to populate this view.")}</td></tr>`;
      $("#process-tree").innerHTML = "";
      return;
    }
    // Resolve a missing parent name from another observed process with the same host + PID.
    const byPid = new Map();
    rows.forEach((row) => { if (row.pid != null) byPid.set(`${row.hostname}|${row.pid}`, row); });
    const parentName = (row) => row.parent_process_name || (row.parent_pid != null && byPid.get(`${row.hostname}|${row.parent_pid}`)?.process_name) || "";
    body.innerHTML = rows.map((row) => {
      const parent = parentName(row);
      const resolved = !row.parent_process_name && parent ? " (matched by PID)" : "";
      return `<tr data-process="${escapeHtml(row.process_name)}">
        <td class="proc-cell"><span class="proc-name" title="${escapeHtml(row.process_path || row.process_name)}">${escapeHtml(row.process_name)}</span></td>
        <td>${hex(row.pid)}</td>
        <td class="proc-cell">${parent ? `<span class="parent-name">${escapeHtml(parent)}</span>${resolved ? `<span class="proc-sub">${resolved.trim()}</span>` : ""}` : `<span class="proc-none">${row.parent_pid != null ? "name not logged" : "—"}</span>`}</td>
        <td>${hex(row.parent_pid)}</td>
        <td>${escapeHtml(row.hostname)}</td><td>${number(row.events)}</td><td>${eventTime(row.first_seen)}</td></tr>`;
    }).join("");

    const branches = new Map();
    const loose = [];
    rows.forEach((row) => {
      const parent = parentName(row);
      if (!parent && row.parent_pid == null) { loose.push(row); return; }
      const key = `${row.hostname}|${parent || "?"}|${row.parent_pid ?? ""}`;
      if (!branches.has(key)) branches.set(key, { parent: parent || "Unknown process", pid: row.parent_pid, host: row.hostname, children: [] });
      branches.get(key).children.push(row);
    });
    const html = Array.from(branches.values()).slice(0, 60).map((branch) => `<div class="tree-branch">
      <div class="tree-node parent"><span class="role-tag parent">PARENT</span><span class="tree-name">${escapeHtml(branch.parent)}</span><span class="tree-pid">${pidText(branch.pid)}</span><span class="tree-host">${escapeHtml(branch.host)}</span></div>
      <div class="tree-children">${branch.children.map((row) => `<div class="tree-node child"><span class="role-tag child">CHILD</span><span class="tree-name">${escapeHtml(row.process_name)}</span><span class="tree-pid">${pidText(row.pid)}</span></div>`).join("")}</div>
    </div>`);
    if (loose.length) html.push(`<div class="tree-branch"><div class="tree-node parent"><span class="role-tag parent">NO PARENT LOGGED</span><span class="tree-host">${loose.length} process${loose.length === 1 ? "" : "es"}</span></div><div class="tree-children">${loose.slice(0, 40).map((row) => `<div class="tree-node child"><span class="role-tag child">PROCESS</span><span class="tree-name">${escapeHtml(row.process_name)}</span><span class="tree-pid">${pidText(row.pid)}</span></div>`).join("")}</div></div>`);
    $("#process-tree").innerHTML = html.join("");
  } catch (error) { body.innerHTML = `<tr><td colspan="7">${emptyState(error.message)}</td></tr>`; }
}

// loadTimeline (v3) is defined with the timeline code below.

const ACTIVITY_GROUPS = [
  ["Logon / authentication", [4624, 4625, 4634, 4647, 4648, 4768, 4769, 4771, 4776]],
  ["Process execution", [4688, 4689, 1, 5]],
  ["Services", [7034, 7035, 7036, 7040, 7045, 4697]],
  ["Privilege use", [4672, 4673, 4674]],
  ["Account / group management", [4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4738, 4740, 4756]],
  ["Policy / audit changes", [4719, 4739, 4902, 4904, 1102]],
  ["Network / firewall", [5156, 5157, 5158, 3]]
];

function tally(items, pick) {
  const counts = new Map();
  items.forEach((item) => { const key = pick(item); if (key) counts.set(key, (counts.get(key) || 0) + 1); });
  return Array.from(counts, ([key, count]) => ({ key, count })).sort((x, y) => y.count - x.count);
}
const miniList = (title, rows, limit = 8) => `<div><h4>${escapeHtml(title)}</h4>${rows.length ? rows.slice(0, limit).map((r) => `<div class="mini-row"><span>${escapeHtml(r.key)}</span><b>${number(r.count)}</b></div>`).join("") : `<div class="mini-row"><span>None observed</span></div>`}</div>`;

async function showHostOverview(host) {
  const panel = $("#host-overview");
  state.host = host.hostname;
  document.querySelectorAll(".endpoint-row.selectable").forEach((row) => row.classList.toggle("selected", row.dataset.host === host.hostname));
  panel.hidden = false;
  panel.innerHTML = emptyState("Loading host overview…");
  try {
    const data = await api(`/api/events?${new URLSearchParams({ host: host.hostname, limit: 200 })}`);
    const items = data.items || [];
    const groupRows = ACTIVITY_GROUPS.map(([label, ids]) => ({ key: label, count: items.filter((e) => ids.includes(Number(e.event_id))).length })).filter((r) => r.count).sort((x, y) => y.count - x.count);
    const topProcesses = tally(items, (e) => e.process_name);
    const topUsers = tally(items, (e) => e.username);
    const topIds = tally(items, (e) => (e.event_id != null ? `${e.event_id} · ${e.event_label || e.provider || "Windows event"}` : null));
    const channels = tally(items, (e) => e.channel);
    const providers = tally(items, (e) => e.provider);
    const times = items.map((e) => new Date(e.timestamp).getTime()).filter((t) => !Number.isNaN(t));
    const range = times.length ? `${eventTime(new Date(Math.min(...times)).toISOString())} → ${eventTime(new Date(Math.max(...times)).toISOString())}` : "—";
    const summaryParts = [];
    if (groupRows.length) summaryParts.push(`Mostly ${groupRows.slice(0, 2).map((r) => r.key.toLowerCase()).join(" and ")} activity`);
    if (topProcesses.length) summaryParts.push(`most active process is ${topProcesses[0].key}`);
    if (topUsers.length) summaryParts.push(`most active account is ${topUsers[0].key}`);
    const summary = summaryParts.length ? summaryParts.join("; ") + "." : "No normalized activity has been received from this host yet.";
    panel.innerHTML = `<h3>${escapeHtml(host.hostname)}</h3>
      <div class="host-summary"><b>What this host is doing:</b> ${escapeHtml(summary)} <i>(based on its latest ${number(items.length)} events)</i></div>
      <div class="host-stat-grid">
        <div class="host-stat"><span>OPERATING SYSTEM</span><b>${escapeHtml(host.os_name || "—")}</b></div>
        <div class="host-stat"><span>AGENT ID</span><b>${escapeHtml(host.agent_id)}</b></div>
        <div class="host-stat"><span>TOTAL EVENTS STORED</span><b>${number(host.events)}</b></div>
        <div class="host-stat"><span>LAST CHECK-IN</span><b>${eventTime(host.last_seen)}</b></div>
        <div class="host-stat"><span>SAMPLE TIME RANGE</span><b>${range}</b></div>
        <div class="host-stat"><span>DISTINCT PROCESSES / USERS</span><b>${topProcesses.length} / ${topUsers.length}</b></div>
      </div>
      <div class="host-columns">
        ${miniList("ACTIVITY TYPE", groupRows)}${miniList("TOP PROCESSES", topProcesses)}${miniList("TOP ACCOUNTS", topUsers)}
        ${miniList("TOP EVENT IDS", topIds)}${miniList("CHANNELS", channels)}${miniList("TOP PROVIDERS", providers)}
      </div>
      <div style="margin-top:14px"><button class="quick-button" id="host-open-events">Open this host in Event explorer →</button></div>`;
    $("#host-open-events").addEventListener("click", () => { $("#host-filter").value = host.hostname; state.offset = 0; setView("events"); });
  } catch (error) { panel.innerHTML = emptyState(error.message); }
}

async function loadEndpoints() {
  // v5: single-host Endpoint page (identity, monitoring, collection, detections) - see renderEndpoint in detections.js.
  await renderEndpoint();
  try {
    const rows = await api("/api/hosts");
    state.hosts = rows;
    const wanted = rows.find((host) => host.hostname === state.host) || rows[0];
    if (wanted) showHostOverview(wanted); else { $("#host-overview").hidden = false; $("#host-overview").innerHTML = emptyState("No events received yet."); }
  } catch (error) { $("#host-overview").hidden = false; $("#host-overview").innerHTML = emptyState(error.message); }
}

// ---------- Home quick-list buttons ----------
async function renderQuick(kind) {
  const panel = $("#quick-panel");
  panel.innerHTML = emptyState("Loading…");
  try {
    let html = "";
    const head = (a, b, c, d) => `<div class="q-row q-head"><span>${a}</span><span>${b}</span><span>${c}</span><span>${d}</span></div>`;
    if (kind === "hosts") {
      const rows = await api("/api/hosts");
      html = rows.length ? head("HOST", "OS", "LAST SEEN", "EVENTS") + rows.map((h) => `<div class="q-row" data-go-host="${escapeHtml(h.hostname)}"><b>${escapeHtml(h.hostname)}</b><span>${escapeHtml(h.os_name)}</span><span>${eventTime(h.last_seen)}</span><span>${number(h.events)}</span></div>`).join("") : emptyState("No hosts have reported yet.");
    } else if (kind === "processes") {
      const rows = await api("/api/processes?limit=15");
      html = rows.length ? head("PROCESS", "PARENT", "HOST", "EVENTS") + rows.map((r) => `<div class="q-row" data-process="${escapeHtml(r.process_name)}"><b>${escapeHtml(r.process_name)}</b><span>${escapeHtml(r.parent_process_name || (r.parent_pid != null ? pidText(r.parent_pid) : "—"))}</span><span>${escapeHtml(r.hostname)}</span><span>${number(r.events)}</span></div>`).join("") : emptyState("No process activity yet.");
    } else if (kind === "eventids") {
      const rows = (state.overview && state.overview.event_ids) || [];
      html = rows.length ? head("EVENT ID", "DESCRIPTION", "CHANNEL", "COUNT") + rows.map((r) => `<div class="q-row" data-event-id-filter="${r.event_id}"><b>${r.event_id}</b><span>${escapeHtml(r.label)}</span><span>${escapeHtml(r.channel || "")}</span><span>${number(r.count)}</span></div>`).join("") : emptyState("No event IDs yet.");
    } else if (kind === "channels") {
      const rows = (state.overview && state.overview.channels) || [];
      html = rows.length ? head("CHANNEL", "", "", "EVENTS") + rows.map((r) => `<div class="q-row" data-channel="${escapeHtml(r.channel)}"><b>${escapeHtml(r.channel)}</b><span></span><span></span><span>${number(r.count)}</span></div>`).join("") : emptyState("No channel data yet.");
    } else if (kind === "recent") {
      const rows = await api("/api/timeline?limit=10");
      html = rows.length ? head("EVENT", "HOST", "PROCESS / USER", "TIME") + rows.map((e) => `<div class="q-row" data-event-id="${escapeHtml(e.id)}"><b>${e.event_id ?? ""} ${escapeHtml(e.label || "")}</b><span>${escapeHtml(e.hostname)}</span><span>${escapeHtml(e.process_name || "—")} / ${escapeHtml(e.username || "—")}</span><span>${eventTime(e.timestamp)}</span></div>`).join("") : emptyState("No events yet.");
    }
    panel.innerHTML = html;
  } catch (error) { panel.innerHTML = emptyState(error.message); }
}

function toggleQuick(kind) {
  const panel = $("#quick-panel");
  const same = state.quick === kind && !panel.hidden;
  document.querySelectorAll(".quick-button[data-quick]").forEach((b) => b.setAttribute("aria-expanded", String(!same && b.dataset.quick === kind)));
  if (same) { panel.hidden = true; state.quick = null; return; }
  state.quick = kind;
  panel.hidden = false;
  renderQuick(kind);
}

function setView(view) {
  if (!viewInfo[view]) return;
  state.view = view;
  document.querySelectorAll(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  document.querySelectorAll(".view-panel").forEach((panel) => panel.classList.toggle("active", panel.id === `view-${view}`));
  $("#crumb-title").textContent = viewInfo[view].title;
  $("#page-title").textContent = viewInfo[view].heading;
  $("#page-description").textContent = viewInfo[view].description;
  $("#range-text").textContent = view === "detections" ? "DETECTION TIME · SELECTED RANGE" : view === "timeline" ? "DETECTIONS · OLDEST FIRST" : view === "overview" ? "COUNTS · ALL RETAINED · GRAPH LAST 24 H · DETECTIONS 7 D" : view === "rules" ? "RULES · SIGNALS STORED" : "COUNTS · ALL RETAINED";
  // View-specific timers run only while their view is open (the collector is never affected).
  if (view === "detections") startDetectionTimer(); else stopDetectionTimer();
  window.scrollTo({ top: 0 });
  return VIEW_LOADERS[view]();
}

async function loadLineage() {
  /* Exact process trees from Sysmon GUIDs, with Security 4688 parent links clearly marked as
     probable (PID reuse). A lineage the telemetry cannot prove is never drawn. */
  const root = $("#process-lineage");
  if (!root) return;
  try {
    const data = await api("/api/process-lineage?limit=400");
    const totals = $("#lineage-totals"), note = $("#lineage-note");
    if (totals) totals.textContent = `${number(data.totals.processes)} PROCESSES · ${number(data.totals.exact_edges)} EXACT · ${number(data.totals.probable_edges)} PROBABLE`;
    if (note) note.textContent = data.note;
    if (!data.nodes.length) {
      root.innerHTML = emptyState("No process-creation events in the window. Install Sysmon or enable Audit Process Creation (4688) for process lineage.");
      return;
    }
    // Group children by their parent so a tree reads top-down.
    const byParent = new Map();
    const roots = [];
    data.nodes.forEach((node) => {
      const parentId = node.parent && node.parent.id;
      if (!parentId || !data.nodes.some((n) => n.id === parentId)) { roots.push(node); return; }
      if (!byParent.has(parentId)) byParent.set(parentId, []);
      byParent.get(parentId).push(node);
    });
    const renderNode = (node, depth) => {
      const children = byParent.get(node.id) || [];
      const link = node.parent ? (node.parent.exact
        ? `<span class="lineage-edge exact" title="Exact link from Sysmon process GUIDs">exact</span>`
        : `<span class="lineage-edge probable" title="Parent matched by Security 4688 PID only; a reused PID can make this uncertain">probable</span>`) : "";
      const suspicious = (node.command_line || "").length > 200;
      return `<div class="lineage-node depth-${Math.min(depth, 4)}">
        <div class="lineage-node-head"><span class="tree-name">${escapeHtml(node.name)}</span>${link}
          <span class="tree-host">${escapeHtml(node.host || "")}</span>
          <span class="tree-pid">${escapeHtml(node.source === "sysmon" ? "GUID" : "PID")}</span></div>
        ${node.command_line ? `<div class="lineage-cmd mono-cell${suspicious ? " long" : ""}" title="${escapeHtml(node.command_line)}">${escapeHtml(node.command_line.slice(0, 160))}${node.command_line.length > 160 ? "…" : ""}</div>` : ""}
        ${children.length ? `<div class="lineage-children">${children.map((child) => renderNode(child, depth + 1)).join("")}</div>` : ""}
      </div>`;
    };
    root.innerHTML = roots.map((node) => `<div class="lineage-root">${renderNode(node, 0)}</div>`).join("");
  } catch (error) {
    root.innerHTML = emptyState(`Process lineage is unavailable: ${error.message}`);
  }
}

const VIEW_LOADERS = { overview: () => loadOverview(), detections: () => loadDetections(), rules: () => loadRulesView(), events: () => loadEvents(), processes: () => loadProcesses(), timeline: () => loadTimeline("start"), endpoints: () => loadEndpoints() };

// ---------- Manual refresh (v4): collect now, then reload what is on screen ----------
state.refresh = { running: false, lastOk: null };

async function reloadCurrentView() {
  if (state.view === "detections") return loadDetections({ preserve: true });
  if (state.view === "timeline") return loadTimeline("start");
  return VIEW_LOADERS[state.view]();
}

function setRefreshStatus(text, kind = "", title = "") {
  const status = $("#refresh-status");
  status.textContent = text;
  status.className = `refresh-status ${kind}`;
  status.title = title || text;
}

async function manualRefresh() {
  if (state.refresh.running) return;            // one refresh at a time (the server also serialises them)
  state.refresh.running = true;
  const button = $("#refresh-button");
  button.disabled = true;
  button.classList.add("busy");
  button.setAttribute("aria-busy", "true");
  $(".refresh-label", button).textContent = "Refreshing…";
  setRefreshStatus("Collecting new events…", "working");
  try {
    const result = await apiSend("POST", "/api/refresh");
    await reloadCurrentView();
    refreshDetectionBadge(true);
    const counts = `${number(result.new_events)} new event${result.new_events === 1 ? "" : "s"}, ${number(result.new_detections)} new detection${result.new_detections === 1 ? "" : "s"}`;
    if (result.ok) {
      state.refresh.lastOk = result.refreshed_at;
      const partial = result.collection.state === "partial";
      setRefreshStatus(`Refreshed ${localClock(result.refreshed_at)} · ${counts}${partial ? " · some channels failed" : ""}`, partial ? "warn" : "ok", result.collection.message);
      toast(`${partial ? "Refreshed with problems" : "Refreshed"}: ${counts}. ${result.collection.message}`, partial ? 7000 : 3500);
    } else {
      // Collection did not succeed: say so, keep the previous "last refreshed" time.
      const last = state.refresh.lastOk ? ` · last successful ${localClock(state.refresh.lastOk)}` : "";
      const label = { unavailable: "No collector running", timeout: "Collection timed out", failed: "Collection failed" }[result.collection.state] || "Collection failed";
      setRefreshStatus(`${label} - showing stored data${last}`, "error", result.collection.message);
      const failedCount = (result.collection.channels_failed || []).length;
      toast(`${label}${failedCount ? ` for ${failedCount} channel(s)` : ""}: ${String(result.collection.message || "").replace(/^Collection failed:\s*/, "")} Details: Rules → Coverage & collection.`, 9000);
    }
  } catch (error) {
    const last = state.refresh.lastOk ? ` · last successful ${localClock(state.refresh.lastOk)}` : "";
    setRefreshStatus(`Refresh failed${last}`, "error", error.message);
    toast(`Refresh failed: ${error.message}`, 9000);
  } finally {
    state.refresh.running = false;
    button.disabled = false;
    button.classList.remove("busy");
    button.removeAttribute("aria-busy");
    $(".refresh-label", button).textContent = "Refresh";
  }
}

function wireNewHandlers() {
  document.querySelectorAll(".quick-button[data-quick]").forEach((b) => b.addEventListener("click", () => toggleQuick(b.dataset.quick)));
  $("#quick-panel").addEventListener("click", (event) => {
    const row = event.target.closest(".q-row:not(.q-head)");
    if (!row) return;
    if (row.dataset.goHost) { state.host = row.dataset.goHost; setView("endpoints"); }
    else if (row.dataset.process) { $("#event-search").value = row.dataset.process; setView("events"); scheduleEventSearch(); }
    else if (row.dataset.eventIdFilter) { $("#event-id-filter").value = row.dataset.eventIdFilter; state.offset = 0; setView("events"); }
    else if (row.dataset.channel) { $("#channel-filter").value = row.dataset.channel; state.offset = 0; setView("events"); }
    else if (row.dataset.eventId) showEvent(row.dataset.eventId);
  });
  $("#endpoints-list").addEventListener("click", (event) => {
    const row = event.target.closest(".endpoint-row.selectable");
    if (row && state.hosts) showHostOverview(state.hosts[Number(row.dataset.index)]);
  });
  $("#endpoints-list").addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") event.target.closest(".endpoint-row.selectable")?.click(); });
}
wireNewHandlers();

function scheduleEventSearch() {
  clearTimeout(state.debounce);
  state.debounce = setTimeout(() => { state.offset = 0; loadEvents(); }, 220);
}

document.querySelectorAll(".nav-item").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
document.querySelectorAll("[data-go]").forEach((button) => button.addEventListener("click", () => setView(button.dataset.go)));
$("#refresh-button").addEventListener("click", manualRefresh);
$("#trend-chart").addEventListener("mouseover", (event) => { const hit = event.target.closest(".chart-hit"); if (hit) showActivityTip(hit); });
$("#trend-chart").addEventListener("focusin", (event) => { const hit = event.target.closest(".chart-hit"); if (hit) showActivityTip(hit); });
$("#trend-chart").addEventListener("mouseleave", hideActivityTip);
window.addEventListener("resize", () => {
  clearTimeout(state.resizeTimer);
  state.resizeTimer = setTimeout(() => { if (state.view === "overview" && state.activity) renderActivityChart(state.activity); }, 150);
});
$("#trend-chart").addEventListener("focusout", hideActivityTip);
$("#trend-table-toggle").addEventListener("click", () => {
  const table = $("#trend-table"), button = $("#trend-table-toggle");
  table.hidden = !table.hidden;
  button.setAttribute("aria-expanded", String(!table.hidden));
  button.textContent = table.hidden ? "Show as table" : "Hide table";
});
$("#event-search").addEventListener("input", scheduleEventSearch);
$("#host-filter").addEventListener("input", scheduleEventSearch);
$("#channel-filter").addEventListener("change", scheduleEventSearch);
$("#event-id-filter").addEventListener("input", scheduleEventSearch);
$("#previous-page").addEventListener("click", () => { state.offset = Math.max(0, state.offset - state.limit); loadEvents(); });
$("#next-page").addEventListener("click", () => { if (state.offset + state.limit < state.total) { state.offset += state.limit; loadEvents(); } });
$("#close-dialog").addEventListener("click", () => $("#event-dialog").close());
$("#event-dialog").addEventListener("click", (event) => { if (event.target === $("#event-dialog")) $("#event-dialog").close(); });
$("#events-body").addEventListener("click", (event) => { const row = event.target.closest("[data-event-id]"); if (row) showEvent(row.dataset.eventId); });
$("#processes-body").addEventListener("click", (event) => { const row = event.target.closest("[data-process]"); if (row) { $("#event-search").value = row.dataset.process; setView("events"); scheduleEventSearch(); } });
$("#process-preview").addEventListener("click", (event) => { const row = event.target.closest("[data-process]"); if (row) { $("#event-search").value = row.dataset.process; setView("events"); scheduleEventSearch(); } });
$("#event-id-list").addEventListener("click", (event) => { const row = event.target.closest("[data-event-id]"); if (row) { $("#event-id-filter").value = row.dataset.eventId; setView("events"); } });
$("#event-id-list").addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") event.target.closest("[data-event-id]")?.click(); });

// Start-up (first data load, live polling) runs at the end of detections.js, after every view's code is loaded.
setInterval(() => { if (state.view === "overview" && !document.hidden && state.quick && !$("#quick-panel").hidden) renderQuick(state.quick); }, 30000);

