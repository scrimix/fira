// Measure revision-list rendering in a production frontend bundle. Snapshot
// entities come from the local fixture; only revision metadata is synthetic.
// Mocked responses exclude backend replay and remote network latency. Timings
// include local JSON delivery, React/DOM work and Playwright orchestration.
// PLAN_PERF_URL=http://localhost:5180 pnpm plan-history:perf
import { chromium } from 'playwright';
import { writeFileSync } from 'node:fs';

const url = process.env.PLAN_PERF_URL ?? 'http://localhost:5180';
const counts = (process.env.PLAN_PERF_REVISIONS ?? '1000,10000,50000').split(',').map(Number);
const out = process.env.PLAN_PERF_OUT ?? '/tmp/fira-plan-history-browser-perf.json';
const browser = await chromium.launch({ headless: true });
const results = [];
try {
  for (const count of counts) {
    const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, timezoneId: 'Europe/Riga' });
    const page = await context.newPage();
    page.setDefaultTimeout(120_000);
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    const login = await context.request.get(`${url}/api/auth/dev-login?email=maya%40fira.dev`, { maxRedirects: 0 });
    if (![302, 303].includes(login.status())) throw new Error(`Local fixture login failed: ${login.status()}`);
    const workspaces = await (await context.request.get(`${url}/api/workspaces`)).json();
    const workspace = workspaces.find((ws) => !ws.is_personal);
    if (!workspace) throw new Error('Requires the standard local team fixture');
    const headers = { 'x-workspace-id': workspace.id };
    const bootstrap = await (await context.request.get(`${url}/api/bootstrap`, { headers })).json();
    const project = bootstrap.projects.find((p) => p.title === 'Atlas');
    const snapshot = await (await context.request.get(`${url}/api/plan/at?project_id=${project.id}`, { headers })).json();
    const first = Date.parse(snapshot.genesis);
    const last = Date.now();
    const changes = Array.from({ length: count }, (_, i) => ({
      seq: 100_000 + i, kind: 'task.set_title', count: 1,
      at: new Date(first + (last - first) * i / count).toISOString(),
    }));
    const metadataBytes = Buffer.byteLength(JSON.stringify(changes));
    let requests = 0;
    let metadataRequests = 0;
    await page.route('**/api/plan/history?**', async (route) => {
      metadataRequests++;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ genesis: snapshot.genesis, changes }) });
    });
    await page.route('**/api/plan/at?**', async (route) => {
      requests++;
      const query = new URL(route.request().url()).searchParams;
      const seq = query.has('seq') ? Number(query.get('seq')) : changes.at(-1).seq;
      const at = query.get('t') ?? changes.find((c) => c.seq === seq)?.at ?? snapshot.at;
      await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ ...snapshot, at, revision: seq }) });
    });
    await page.addInitScript((ws) => localStorage.setItem('fira:activeWorkspace', ws), workspace.id);
    await page.goto(url);
    await page.waitForSelector('.avatar');
    const entry = page.getByRole('button', { name: 'Plan (P)', exact: true });
    if (await entry.count() !== 1) throw new Error('Production Plan entry is missing');
    await entry.click();
    await page.locator('.nav-proj[title="Atlas"]').first().click();
    const cdp = await context.newCDPSession(page);
    await cdp.send('Performance.enable');
    const heap = async () => (await cdp.send('Performance.getMetrics')).metrics.find((m) => m.name === 'JSHeapUsedSize').value;
    const baselineHeap = await heap();
    const openStart = performance.now();
    await page.getByRole('button', { name: 'Past', exact: true }).click();
    await page.waitForSelector('.plan-wrap[aria-busy="false"] .plan-revision-axis');
    await page.waitForFunction((n) => document.querySelectorAll('.plan-revision-marker').length === n, count);
    const openMs = performance.now() - openStart;
    const fullHeap = await heap();
    const picker = page.getByLabel('Revision', { exact: true });
    const selectStart = performance.now();
    const middle = changes[Math.floor(count / 2)];
    await picker.selectOption(String(middle.seq));
    await page.waitForSelector(`.plan-wrap[data-revision="${middle.seq}"][aria-busy="false"]`);
    const selectMs = performance.now() - selectStart;
    const zoomStart = performance.now();
    const before = await page.getByRole('slider').getAttribute('data-start');
    await page.getByRole('button', { name: 'Zoom in history', exact: true }).click();
    await page.waitForFunction((old) => document.querySelector('.plan-revision-axis').dataset.start !== old, before);
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    const zoomMs = performance.now() - zoomStart;
    if (metadataRequests !== 1) throw new Error(`Revision list fetched ${metadataRequests} times while scrubbing`);
    if (errors.length) throw new Error(errors.join('\n'));
    const result = {
      revisions: count, metadata_bytes: metadataBytes, open_ms: openMs,
      select_ms: selectMs, zoom_ms: zoomMs, requests, metadata_requests: metadataRequests,
      full_history_heap_delta_mb: (fullHeap - baselineHeap) / 1024 / 1024,
      options: await picker.locator('option').count(),
      visible_markers_after_zoom: await page.locator('.plan-revision-marker').count(),
    };
    results.push(result);
    console.log('PLAN_HISTORY_BROWSER_PERF', JSON.stringify(result));
    await context.close();
  }
  writeFileSync(out, JSON.stringify({ url, note: 'Production frontend; synthetic revision metadata, fixture snapshot, mocked history responses', results }, null, 2));
  console.log(`Report written to ${out}`);
} finally {
  await browser.close();
}
