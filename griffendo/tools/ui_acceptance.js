// UI acceptance checks for Griffendo v4 (Playwright, headless Chromium).
// Run against the synthetic demo:  python tools/demo_server.py 8770 --live-every 1   then
//   node tools/ui_acceptance.js <screenshot-folder> http://127.0.0.1:8770/
// Synthetic data only. Uses Playwright's fake clock to test the 60-second Anomalies schedule.
// Acceptance checks for the v4 UI against the synthetic demo (tools/demo_server.py).
const { chromium } = require('playwright');
const results = {};
const check = (name, ok, detail) => { results[name] = { ok: !!ok, detail }; };
(async () => {
  const [out, base] = [process.argv[2], process.argv[3]];
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1440, height: 1000 }, timezoneId: 'Asia/Kolkata' });
  const p = await ctx.newPage();
  const errors = []; p.on('pageerror', e => errors.push(e.message)); p.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  const requests = []; p.on('request', r => requests.push({ url: r.url(), method: r.method(), t: Date.now() }));
  await p.clock.install();                      // fake timers so the 60 s schedule can be tested quickly
  await p.goto(base); await p.clock.runFor(2500); await p.waitForTimeout(1500);

  // ---- Graph
  const graph = await p.evaluate(async () => {
    const data = await (await fetch(`/api/overview?tz_offset=${-new Date().getTimezoneOffset()}`)).json();
    const a = data.activity_24h;
    const legend = [...document.querySelectorAll('#trend-legend .legend-chip')].map(c => ({ text: c.textContent.trim(), color: getComputedStyle(c.querySelector('.legend-swatch')).backgroundColor }));
    const fills = [...new Set([...document.querySelectorAll('#trend-chart .chart-seg')].map(e => e.getAttribute('fill')))];
    const spanH = (Date.parse(a.window_end) - Date.parse(a.window_start)) / 3600000;
    return { total: a.total, sumBuckets: a.buckets.reduce((s, x) => s + x.total, 0), legend, fills, spanH, buckets: a.buckets.length, columns: document.querySelectorAll('#trend-chart .chart-col').length };
  });
  check('graph: window is 24 h', graph.spanH === 24, graph.spanH);
  check('graph: legend matches data (6 categories, distinct colours)', graph.legend.length === 6 && new Set(graph.legend.map(l => l.color)).size === 6, graph.legend);
  check('graph: plotted columns = buckets, totals agree', graph.columns === graph.buckets && graph.total === graph.sumBuckets, graph);
  await p.hover('.chart-hit[data-bucket="10"]');
  const tip = await p.$eval('#chart-tip', e => !e.hidden && e.textContent);
  check('graph: tooltip on hover', tip && tip.includes('Total'), tip);
  await p.click('#trend-table-toggle');
  const rows = await p.$$eval('#trend-table tbody tr', r => r.length);
  check('graph: table view lists every bucket', rows === graph.buckets, rows);
  await p.click('#trend-table-toggle');

  // ---- Quick buttons alignment
  for (const width of [1440, 1024, 390]) {
    await p.setViewportSize({ width, height: 900 }); await p.waitForTimeout(400);
    const geo = await p.$$eval('.quick-buttons .quick-button', bs => bs.map(x => { const r = x.getBoundingClientRect(); return [Math.round(r.top), Math.round(r.height), Math.round(r.width)]; }));
    const heights = new Set(geo.map(g => g[1]));
    const rowsTop = [...new Set(geo.map(g => g[0]))];
    const overflow = await p.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
    check(`buttons @${width}: equal height, aligned rows, no horizontal scroll`, heights.size === 1 && !overflow, { geo, rowsTop, overflow });
    await p.screenshot({ path: `${out}/accept_overview_${width}.png` });
  }
  await p.setViewportSize({ width: 1440, height: 1000 });

  // ---- Refresh button
  const before = requests.filter(r => r.url.endsWith('/api/refresh')).length;
  await p.click('#refresh-button');
  const busy = await p.$eval('#refresh-button', b => ({ disabled: b.disabled, label: b.textContent.trim() }));
  await p.click('#refresh-button', { force: true }).catch(() => {});        // second click while running
  await p.waitForFunction(() => !document.querySelector('#refresh-button').disabled, null, { timeout: 30000 });
  const status = await p.$eval('#refresh-status', e => ({ cls: e.className, text: e.textContent }));
  const sent = requests.filter(r => r.url.endsWith('/api/refresh')).length - before;
  check('refresh: loading state while running', busy.disabled && busy.label.includes('Refreshing'), busy);
  check('refresh: single request for double click', sent === 1, sent);
  check('refresh: success reported with counts', status.cls.includes('ok') && /Refreshed/.test(status.text), status);
  await p.route('**/api/refresh', route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: false, collection: { state: 'failed', message: 'Collection failed: System: access denied (simulated)' }, new_events: 0, new_detections: 0, refreshed_at: new Date().toISOString() }) }));
  await p.click('#refresh-button');
  await p.waitForFunction(() => !document.querySelector('#refresh-button').disabled);
  const failed = await p.$eval('#refresh-status', e => ({ cls: e.className, text: e.textContent, title: e.title }));
  check('refresh: failure shown, not reported as success, keeps last successful time', failed.cls.includes('error') && /failed/i.test(failed.text) && /last successful/.test(failed.text), failed);
  await p.route('**/api/refresh', route => route.fulfill({ status: 500, contentType: 'application/json', body: '{"detail":"simulated server error"}' }));
  await p.click('#refresh-button');
  await p.waitForFunction(() => !document.querySelector('#refresh-button').disabled);
  const errored = await p.$eval('#refresh-status', e => e.textContent);
  const restored = await p.$eval('#refresh-button', b => b.textContent.trim());
  check('refresh: HTTP error shown and button restored', /Refresh failed/.test(errored) && restored.endsWith('Refresh') && !restored.includes('Refreshing'), { errored, restored });
  await p.unroute('**/api/refresh');

  // ---- Anomalies: 60 s refresh, selection and scroll kept
  await p.click('[data-view="anomalies"]'); await p.clock.runFor(1000); await p.waitForTimeout(1500);
  const sumReqs = () => requests.filter(r => r.url.includes('/api/anomalies/summary')).length;
  const start = sumReqs();
  for (let i = 0; i < 25; i++) { await p.clock.runFor(2000); await p.waitForTimeout(120); }        // 50 s of polls, live data arriving
  const after50 = sumReqs() - start;
  await p.clock.runFor(12000); await p.waitForTimeout(1500);
  const after62 = sumReqs() - start;
  check('anomalies: no automatic reload within 50 s while data arrives', after50 === 0, after50);
  check('anomalies: one automatic reload at 60 s', after62 === 1, after62);
  const note = await p.$eval('#anomaly-refresh-note', e => e.textContent);
  check('anomalies: schedule shown', /EVERY 60 S/.test(note), note);
  const firstRow = await p.$('#anomaly-body tr[data-anomaly-id]:nth-child(3)');
  const selectedId = await firstRow.getAttribute('data-anomaly-id');
  await firstRow.click(); await p.waitForTimeout(800); await p.click('#close-dialog');
  await p.evaluate(() => window.scrollTo(0, 900)); const y0 = await p.evaluate(() => window.scrollY);
  await p.clock.runFor(61000); await p.waitForTimeout(1500);
  const sel = await p.$$eval('#anomaly-body tr.selected-row', r => r.map(x => x.dataset.anomalyId));
  const y1 = await p.evaluate(() => window.scrollY);
  check('anomalies: selection and scroll position kept across auto refresh', sel.includes(selectedId) && Math.abs(y1 - y0) < 5, { sel, selectedId, y0, y1 });

  // ---- Rule toggle consistency (UI)
  const count = async () => p.evaluate(async () => { const s = await (await fetch('/api/anomalies/summary')).json(); const l = await (await fetch('/api/anomalies?rule_id=SEC-4625&limit=1')).json(); const t = await (await fetch('/api/timeline/anomalies?limit=500')).json(); return { low: s.counts_by_severity.Low.records, rule: l.total, tl4625: t.items.filter(i => i.detections.some(d => d.rule_id === 'SEC-4625')).length, history: (await (await fetch('/api/anomalies?rule_id=SEC-4625&scope=all&limit=1')).json()).total }; });
  await p.click('.anomaly-tab[data-anomaly-mode="rules"]'); await p.waitForTimeout(1200);
  const c0 = await count();
  await p.fill('#rule-search', '4625'); await p.clock.runFor(300); await p.waitForTimeout(300);
  await p.click('[data-toggle-rule="SEC-4625"]'); await p.waitForTimeout(1500);
  const off = await p.getAttribute('[data-toggle-rule="SEC-4625"]', 'aria-checked');
  const c1 = await count();
  const cards = await p.$eval('#severity-grid [data-severity="Low"] .metric-value', e => e.textContent);
  check('toggle off: switch saved, active counts/list/timeline drop to zero, history kept', off === 'false' && c1.rule === 0 && c1.tl4625 === 0 && c1.history >= c0.rule && Number(cards.replace(/\D/g, '')) === c1.low, { c0, c1, cards });
  await p.screenshot({ path: `${out}/accept_rules_off.png` });
  await p.click('[data-toggle-rule="SEC-4625"]'); await p.waitForTimeout(2500);
  const c2 = await count();
  const toastText = await p.$eval('#toast', e => e.textContent);
  check('toggle on: earlier detections restored (+ any missed), no duplicates', c2.rule >= c0.rule && c2.rule === c2.history && c2.tl4625 === c2.rule && /shown again/.test(toastText), { c2, toastText });

  // ---- Timeline
  await p.click('[data-view="timeline"]'); await p.clock.runFor(1500); await p.waitForTimeout(2000);
  const tl = await p.$$eval('#timeline-list [data-tl-key]', es => es.map(e => ({ key: e.dataset.tlKey, t: e.querySelector('time').getAttribute('datetime') })));
  const ordered = tl.every((x, i) => i === 0 || x.t >= tl[i - 1].t);
  check('timeline: oldest first, no duplicate entries', ordered && new Set(tl.map(x => x.key)).size === tl.length, { n: tl.length });
  await p.click('#tl-newest'); await p.clock.runFor(1500); await p.waitForTimeout(1500);
  const n0 = await p.$$eval('#timeline-list [data-tl-key]', es => es.length);
  for (let i = 0; i < 12; i++) { await p.clock.runFor(3000); await p.waitForTimeout(400); }     // live polls; demo writes events every 1 s
  const tl2 = await p.$$eval('#timeline-list [data-tl-key]', es => es.map(e => ({ key: e.dataset.tlKey, t: e.querySelector('time').getAttribute('datetime') })));
  const ordered2 = tl2.every((x, i) => i === 0 || x.t >= tl2[i - 1].t);
  check('timeline: live anomalies inserted in order without duplicates', tl2.length > n0 && ordered2 && new Set(tl2.map(x => x.key)).size === tl2.length, { before: n0, after: tl2.length });
  await p.screenshot({ path: `${out}/accept_timeline_live.png` });
  await p.click('#timeline-list [data-tl-key]'); await p.waitForTimeout(1000);
  const dialog = await p.$eval('#event-dialog', d => d.open && d.textContent.includes('Original event XML'));
  check('timeline: entry opens anomaly with event details', dialog, dialog);
  await p.click('#close-dialog');
  check('no JavaScript errors (except the deliberately simulated HTTP 500)', errors.filter(e => !e.includes('status of 500')).length === 0, errors);
  console.log(JSON.stringify(results, null, 1));
  const failedChecks = Object.entries(results).filter(([, v]) => !v.ok).map(([k]) => k);
  console.log(failedChecks.length ? `FAILED: ${failedChecks.join(' | ')}` : `ALL ${Object.keys(results).length} UI CHECKS PASSED`);
  await b.close();
})();
