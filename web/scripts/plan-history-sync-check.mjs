// Integration regression for revision-list invalidation, using the local dev
// frontend and fixture API. Feed and WS messages are mocked; no DB writes.
import { chromium } from 'playwright';
const url = process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173';
const browser = await chromium.launch({ args: ['--no-sandbox'] });
const assert = (condition, message) => { if (!condition) throw new Error(message); };
try {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const login = await context.request.get(`${url}/api/auth/dev-login?email=maya%40fira.dev`, { maxRedirects: 0 });
  assert([302, 303].includes(login.status()), 'Fixture login failed');
  const workspaces = await (await context.request.get(`${url}/api/workspaces`)).json();
  const ws = workspaces.find((w) => !w.is_personal);
  const headers = { 'x-workspace-id': ws.id };
  const bootstrap = await (await context.request.get(`${url}/api/bootstrap`, { headers })).json();
  const project = bootstrap.projects.find((p) => p.title === 'Atlas');
  const task = bootstrap.tasks.find((t) => t.project_id === project.id);
  const otherTask = bootstrap.tasks.find((t) => t.project_id !== project.id);
  const source = await (await context.request.get(`${url}/api/plan/history?project_id=${project.id}`, { headers })).json();
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  let socket;
  await page.routeWebSocket('**/api/ws?**', (ws) => { socket = ws; });
  let feed = [];
  let additions = [];
  let revisionRequests = [];
  let snapshotRequests = 0;
  page.on('request', (request) => {
    if (new URL(request.url()).pathname === '/api/plan/at') snapshotRequests++;
  });
  await page.route('**/api/changes?**', async (route) => {
    const since = Number(new URL(route.request().url()).searchParams.get('since'));
    const ops = feed.filter((op) => op.seq > since);
    feed = [];
    await route.fulfill({ json: { ops, cursor: ops.at(-1)?.seq ?? since } });
  });
  await page.route('**/api/plan/history?**', async (route) => {
    const since = Number(new URL(route.request().url()).searchParams.get('since'));
    revisionRequests.push(since);
    await route.fulfill({ json: { genesis: source.genesis, changes: [...source.changes, ...additions].filter((c) => c.seq > since) } });
  });
  await page.addInitScript((id) => localStorage.setItem('fira:activeWorkspace', id), ws.id);
  await page.goto(url);
  await page.waitForSelector('.avatar');
  await page.keyboard.press('p');
  await page.locator('.nav-proj[title="Atlas"]').first().click();
  await page.getByRole('button', { name: 'Past', exact: true }).click();
  await page.waitForSelector('.plan-wrap[aria-busy="false"] .plan-revision-axis');
  const initialRequests = revisionRequests.length;
  assert(initialRequests > 0, 'Revision list did not load');
  assert(snapshotRequests === 0, 'Opening live history fetched an unused snapshot');
  const picker = page.getByLabel('Revision', { exact: true });
  for (const change of source.changes.slice(0, 3)) {
    await picker.selectOption(String(change.seq));
    await page.waitForSelector(`.plan-wrap[data-revision="${change.seq}"][aria-busy="false"]`);
  }
  assert(revisionRequests.length === initialRequests, 'Scrubbing refetched revisions');
  const historicalRequests = snapshotRequests;
  let seq = bootstrap.cursor + 1000;
  const nudge = async (projectId, payload, ownEcho = false) => {
    const entry = { seq: ++seq, op_id: `history-test-${seq}`, kind: payload.kind, payload, project_id: projectId, applied_at: new Date().toISOString() };
    if (ownEcho) {
      // Exercise the real echo-dedup path without writing to the database.
      await page.evaluate(async (id) => {
        const { useFira } = await import('/src/store/index.ts');
        const applied = new Map(useFira.getState().appliedOpIds);
        applied.set(id, Date.now());
        useFira.setState({ appliedOpIds: applied });
      }, entry.op_id);
    }
    feed.push(entry);
    socket.send(JSON.stringify({ new_cursor: entry.seq }));
    await page.waitForFunction(async (target) => {
      const { useFira } = await import('/src/store/index.ts');
      return useFira.getState().cursor >= target;
    }, entry.seq);
    await page.waitForTimeout(200);
    return entry;
  };
  await nudge(otherTask.project_id, { kind: 'task.set_title', task_id: otherTask.id, title: otherTask.title });
  await nudge(project.id, { kind: 'task.set_description', task_id: task.id, description_md: 'Synthetic feed only' });
  assert(revisionRequests.length === initialRequests, 'Unrelated operations refreshed revision metadata');
  const next = { seq: seq + 1, kind: 'task.set_title', count: 1, at: new Date().toISOString() };
  additions.push(next);
  await nudge(project.id, { kind: next.kind, task_id: task.id, title: 'This echoed title must be skipped' }, true);
  await picker.locator(`option[value="${next.seq}"]`).waitFor({ state: 'attached' });
  assert(revisionRequests.length === initialRequests + 1, 'Own acknowledged edit did not refresh exactly once');
  assert(revisionRequests.at(-1) === source.changes.at(-1).seq, 'Refresh did not request only new revisions');
  assert(snapshotRequests === historicalRequests, 'Feed update refetched an immutable historical snapshot');
  const title = await page.evaluate(async (id) => {
    const { useFira } = await import('/src/store/index.ts');
    return useFira.getState().tasks.find((task) => task.id === id).title;
  }, task.id);
  assert(title === task.title, 'Own echo was applied twice');
  await page.getByRole('button', { name: 'Past', exact: true }).click();
  await page.getByRole('button', { name: 'Past', exact: true }).click();
  await picker.waitFor();
  assert(revisionRequests.length === initialRequests + 1, 'Reopening fetched unchanged revisions');
  assert(errors.length === 0, errors.join('\n'));
  console.log('PASS: scrub/reopen reuse metadata; WS ignores unrelated ops; own echoes fetch only a delta; snapshots stay unchanged.');
  await context.close();
} finally { await browser.close(); }
