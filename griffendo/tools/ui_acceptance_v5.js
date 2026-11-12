// UI acceptance checks for Griffendo v5 (Playwright, headless Chromium), synthetic demo data only.
//   python3.12 tools/demo_server.py 8771 --live-every 2      then
//   node tools/ui_acceptance_v5.js <screenshot-folder> http://127.0.0.1:8771/
const { chromium } = require('playwright');
const results = {};
const check = (name, ok, detail) => { results[name] = { ok: !!ok, detail }; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  const [out, base] = [process.argv[2], process.argv[3]];
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 }, timezoneId: 'Asia/Kolkata' });
  const p = await ctx.newPage();
  const errors = [];
  p.on('pageerror', (e) => errors.push(e.message));
  // Browsers log every 4xx response as a console error; those are judged by URL instead (the builder's
  // validation call is expected to answer 422 for an invalid rule).
  p.on('console', (m) => { if (m.type() === 'error' && !/status of 4\d\d/.test(m.text())) errors.push(m.text()); });
  p.on('response', (r) => { if (r.status() >= 400 && !r.url().includes('/rules/validate')) errors.push(`${r.status()} ${r.url()}`); });
  await p.goto(base);
  // Wait for the engine to process the demo backlog.
  for (let i = 0; i < 120; i++) {
    const s = await p.evaluate(async () => (await (await fetch('/api/detections/status')).json()).processing.backlog_events);
    if (s === 0) break;
    await sleep(1000);
  }
  await p.reload(); await sleep(2500);

  // ---- Overview: three detection columns
  const cols = await p.$$eval('#det-columns .det-column', (c) => c.map((x) => x.querySelector('h3').textContent));
  check('overview: three detection columns', cols.length === 3 && cols[0].includes('Critical') && cols[1] === 'Medium', cols);
  const api = await p.evaluate(async () => (await fetch('/api/detections/summary?range=7d&recent=4')).json());
  const shown = await p.$$eval('#det-columns .det-count b', (b) => b.map((x) => Number(x.textContent.replace(/\D/g, ''))));
  const expected = [api.counts.Critical, api.counts.High, api.counts.Medium, api.counts.Low, api.counts.Informational];
  check('overview: column counts equal the shared summary', JSON.stringify(shown) === JSON.stringify(expected), { shown, expected });
  check('overview: recent detections listed', (await p.$$('#det-columns .det-mini')).length > 0);
  check('overview: status row shows latest detection and engine state', (await p.textContent('#det-status-row')).includes('LATEST DETECTION'));
  await p.screenshot({ path: `${out}/v5_overview_detection_columns.png`, fullPage: false });
  await p.click('#det-columns .det-count.sev-high');
  await sleep(1500);
  const highRows = await p.$$eval('#det-body tr .sev-pill', (s) => s.map((x) => x.textContent));
  check('overview -> detections: clicking High opens a High-filtered list', p.url() && highRows.length > 0 && highRows.every((s) => s === 'High'), highRows.slice(0, 5));

  // ---- Detections page
  await p.selectOption('#det-severity', '');
  await sleep(1200);
  const allCount = await p.textContent('#det-count');
  check('detections: list loads with count and range', /detection/.test(allCount) && /7 days/.test(allCount), allCount);
  const firstRow = await p.$('#det-body tr[data-det-id]');
  check('detections: rows present', !!firstRow);
  // Time presets
  await p.selectOption('#det-time .tf-preset', '1h');
  await sleep(1200);
  const hourCount = Number((await p.textContent('#det-count')).split(' ')[0].replace(/\D/g, ''));
  await p.selectOption('#det-time .tf-preset', '7d');
  await sleep(1200);
  const weekCount = Number((await p.textContent('#det-count')).split(' ')[0].replace(/\D/g, ''));
  check('detections: time presets narrow the list', hourCount <= weekCount && weekCount > 0, { hourCount, weekCount });
  await p.selectOption('#det-time .tf-preset', 'custom');
  await p.fill('#det-time .tf-start-date', '2026-10-30'); await p.fill('#det-time .tf-start-time', '10:00:00');
  await p.fill('#det-time .tf-end-date', '2026-10-29'); await p.fill('#det-time .tf-end-time', '10:00:00');
  await p.click('#det-time .tf-apply');
  check('detections: custom range rejects start after end', (await p.textContent('#det-time .tf-error')).includes('later'));
  await p.click('#det-time .tf-clear');
  await sleep(1200);
  // Detail dialog
  await p.click('#det-body tr[data-det-id]');
  await p.waitForSelector('#det-dialog .det-section');
  const sections = await p.$$eval('#det-dialog .det-section h3', (h) => h.map((x) => x.textContent));
  check('detail: summary, why, risk, conditions, sequence/events, investigation, verdict sections', sections.length === 7 && sections[0].startsWith('1') && sections[6].startsWith('9'), sections);
  await p.screenshot({ path: `${out}/v5_detection_detail.png` });
  await p.check('#verdict-form input[value="needs_investigation"]');
  await p.selectOption('#verdict-form select[name=status]', 'Investigating');
  await p.click('#verdict-form button[type=submit]');
  await sleep(1200);
  const history = await p.textContent('#det-dialog-body');
  check('detail: verdict and status saved and shown in history', history.includes('Needs investigation'));
  await p.click('#close-det-dialog');
  // Correlation detection detail
  await p.fill('#det-search', 'Office application');
  await sleep(1200);
  const chainRow = await p.$('#det-body tr[data-det-id]');
  if (chainRow) {
    await chainRow.click();
    await p.waitForSelector('#det-dialog .chain-link');
    const links = await p.$$eval('#det-dialog .chain-link', (l) => l.map((x) => x.textContent));
    check('detail: chain detection shows the correlation path', links.some((l) => l.includes('WINWORD')) && links.some((l) => l.includes('child process')), links.slice(0, 4));
    await p.screenshot({ path: `${out}/v5_chain_detection.png` });
    await p.click('#close-det-dialog');
  } else check('detail: chain detection shows the correlation path', false, 'no chain detection');
  await p.fill('#det-search', '');
  await sleep(800);

  // ---- 60-second refresh preserves the list
  const note = await p.textContent('#det-refresh-note');
  check('detections: refresh schedule shown (60 s)', note.includes('60'), note);

  // ---- Rules page
  await p.click('button.nav-item[data-view="rules"]');
  await sleep(2000);
  const ruleCount = await p.textContent('#rule-count');
  check('rules: list with counts', /rules/.test(ruleCount) && /on/.test(ruleCount), ruleCount);
  await p.fill('#rule-search', 'SEC-4720');
  await sleep(1200);
  const sw = await p.$('#rules-body button.switch[data-toggle-rule="SEC-4720"]');
  await sw.click();
  await sleep(2500);
  const off = await p.$eval('#rules-body button.switch[data-toggle-rule="SEC-4720"]', (b) => b.getAttribute('aria-checked'));
  check('rules: switch saves off', off === 'false', off);
  await p.click('#rules-body button.switch[data-toggle-rule="SEC-4720"]');
  await sleep(2500);
  const on = await p.$eval('#rules-body button.switch[data-toggle-rule="SEC-4720"]', (b) => b.getAttribute('aria-checked'));
  check('rules: switch back on (look-back runs)', on === 'true', on);
  await p.fill('#rule-search', 'Multiple Logon Failure');
  await sleep(1200);
  await p.click('#rules-body [data-open-rule]');
  await p.waitForSelector('#rule-detail-body h4');
  const ruleText = await p.textContent('#rule-detail-body');
  check('rules: detail shows provenance, licence and original query', ruleText.includes('Elastic License') && ruleText.includes('Original query'), ruleText.slice(0, 120));
  await p.screenshot({ path: `${out}/v5_rule_detail.png` });
  await p.click('#close-rule-detail');
  // Builder
  await p.click('#add-rule');
  await p.fill('#rule-form input[name=name]', 'UI synthetic rule');
  await p.selectOption('#rule-form select[name=severity]', 'Medium');
  await p.fill('#rule-form input[name=category]', 'Execution');
  await p.fill('#rule-form textarea[name=description]', 'Synthetic test rule');
  await p.fill('#rule-form textarea[name=explanation]', 'Synthetic');
  await p.fill('#rule-form textarea[name=investigation]', 'Synthetic');
  await p.fill('#rule-sources .sr-channel', 'Security');
  await p.fill('#rule-sources .sr-ids', '4624');
  await p.fill('#rule-condition .cr-field', 'registry.path');
  await p.fill('#rule-condition .cr-values', 'HKLM\\x');
  await p.click('#validate-rule');
  await sleep(800);
  const err = await p.textContent('#rule-form-error');
  check('builder: refuses a field the selected source never has', err.includes('never present') && err.includes('Sysmon'), err.slice(0, 160));
  await p.fill('#rule-condition .cr-field', 'winlog.logon.type');
  await p.fill('#rule-condition .cr-values', 'RemoteInteractive');
  await p.click('#validate-rule');
  await sleep(800);
  check('builder: valid rule accepted', (await p.textContent('#rule-validate-note')).includes('valid'));
  await p.screenshot({ path: `${out}/v5_rule_builder.png` });
  await p.click('#save-rule');
  await sleep(2500);
  check('builder: custom rule saved', !(await p.$eval('#rule-dialog', (d) => d.open)));
  // Model tab
  await p.click('[data-rules-tab="model"]');
  await sleep(1200);
  const model = await p.textContent('#rules-tab-model');
  check('model: lifecycle stage and progress shown', model.includes('LEARN') && model.includes('Learning progress'), model.slice(0, 120));
  await p.screenshot({ path: `${out}/v5_behaviour_model.png` });
  await p.click('[data-rules-tab="rules"]');

  // ---- Timeline
  await p.click('button.nav-item[data-view="timeline"]');
  await sleep(2000);
  const times = await p.$$eval('#timeline-list .timeline-entry time', (t) => t.map((x) => x.getAttribute('datetime')));
  check('timeline: detections oldest first', times.length > 0 && times.every((t, i) => i === 0 || times[i - 1] <= t), times.length);
  await p.screenshot({ path: `${out}/v5_timeline.png` });

  // ---- Endpoint
  await p.click('button.nav-item[data-view="endpoints"]');
  await sleep(2500);
  const ep = await p.textContent('#endpoint-root');
  check('endpoint: identity, monitoring, detections, collection, optional sources', ep.includes('SYNTHETIC-WS01') && ep.includes('DETECTIONS ON THIS HOST') && ep.includes('Optional sources') && ep.includes('Sysmon'), ep.slice(0, 160));
  await p.screenshot({ path: `${out}/v5_endpoint.png`, fullPage: true });

  // ---- Event explorer time filter
  await p.click('button.nav-item[data-view="events"]');
  await sleep(1500);
  const totalAll = Number((await p.textContent('#event-result-count')).replace(/\D/g, ''));
  await p.selectOption('#event-time .tf-preset', '1h');
  await sleep(1200);
  const totalHour = Number((await p.textContent('#event-result-count')).replace(/\D/g, ''));
  const applied = await p.textContent('#event-time .tf-applied');
  check('events: time filter narrows results and shows the applied range', totalHour < totalAll && applied.includes('Last hour'), { totalAll, totalHour, applied });

  // ---- Layout at phone width
  for (const width of [1024, 390]) {
    await p.setViewportSize({ width, height: 900 });
    await p.click('button.nav-item[data-view="overview"]');
    await sleep(1200);
    const overflow = await p.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    check(`layout: no horizontal page scroll at ${width}px`, overflow <= 1, overflow);
  }
  await p.setViewportSize({ width: 1440, height: 1000 });
  check('no JavaScript errors', errors.length === 0, errors.slice(0, 5));
  const failed = Object.entries(results).filter(([, v]) => !v.ok);
  console.log(JSON.stringify(results, null, 1));
  console.log(failed.length ? `FAILED: ${failed.map(([k]) => k).join(' | ')}` : `ALL ${Object.keys(results).length} UI CHECKS PASSED`);
  await browser.close();
  process.exit(failed.length ? 1 : 0);
})();
