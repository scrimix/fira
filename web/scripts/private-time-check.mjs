import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const browser = await chromium.launch({ args: ['--no-sandbox'] });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(() => localStorage.setItem('fira:playground', '1'));
  await page.goto(process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173');
  await page.locator('.avatar').waitFor();
  const target = await page.evaluate(async () => {
    const moduleUrl = (part) => performance.getEntriesByType('resource').find((entry) => entry.name.includes(part)).name;
    const { useFira } = await import(moduleUrl('/src/store/index.ts'));
    const { taskTimeLeft } = await import(moduleUrl('/src/time.ts'));
    const s = useFira.getState();
    const project = s.projects.find((p) => p.title === 'Atlas');
    const teammateTasks = new Set(s.blocks.filter((b) => b.user_id !== s.meId).map((b) => b.task_id));
    const task = s.tasks.find((t) => t.project_id === project.id && t.sprint_id && t.estimate_min != null && teammateTasks.has(t.id));
    const normalLeft = taskTimeLeft(task, s.blocks);
    await s.setProjectMembers(project.id, project.members.map((m) => m.user_id === s.meId ? { ...m, role: 'dev' } : m));
    const next = useFira.getState();
    const restricted = next.tasks.find((t) => t.id === task.id);
    if (!restricted.has_private_time || taskTimeLeft(restricted, next.blocks) !== null) throw new Error('Private time must make remaining time unavailable');
    next.setPlanProject(project.id);
    next.setView('plan');
    return { taskId: task.id, sprintId: task.sprint_id, normalLeft };
  });
  assert.equal(typeof target.normalLeft, 'number');
  await page.locator('.plan-rows').waitFor();
  const cards = page.locator('.plan-card:not(.plan-card-retro)');
  let tested = false;
  for (let i = 0; i < await cards.count(); i++) {
    const info = cards.nth(i).getByRole('button', { name: 'Sprint information' });
    await info.click();
    if (await page.getByText('Private time excluded; full sprint time is unavailable.', { exact: false }).count()) {
      tested = true;
      assert.ok(await page.getByText(/visible time|visible time blocks/).count());
      await page.keyboard.press('Escape');
      break;
    }
    await page.keyboard.press('Escape');
  }
  assert.ok(tested, 'Sprint information must indicate private time');
  await page.evaluate(async (id) => {
    const { useFira } = await import(performance.getEntriesByType('resource').find((entry) => entry.name.includes('/src/store/index.ts')).name);
    useFira.getState().openTask(id);
  }, target.taskId);
  await page.getByText('Private time excluded', { exact: true }).first().waitFor();
  const leftField = page.locator('.field').filter({ has: page.locator('h5', { hasText: 'Time left' }) });
  assert.ok((await leftField.textContent()).includes('Private time excluded'));
  assert.equal(await page.locator('.est-bar:visible').count(), 0, 'Partial time must not draw a complete budget bar');
  assert.ok(await page.getByText(/visible done/).count());
  const pure = await page.evaluate(async () => {
    const { buildRetroBuckets, sprintInformation } = await import(performance.getEntriesByType('resource').find((entry) => entry.name.includes('/src/plan.ts')).name);
    const task = { id: 'task', project_id: 'project', sprint_id: null, track_id: null, title: 'Done', sort_key: 'M', section: 'done', status: 'done', estimate_min: 120, has_private_time: true, finished_at: '2026-10-12T12:00:00Z' };
    const blocks = [{ id: 'block', task_id: task.id, user_id: 'me', state: 'completed', start_at: '2026-09-07T08:00:00Z', end_at: '2026-09-07T09:00:00Z' }];
    const input = { projectId: 'project', tracks: [], sprints: [], tasks: [task], blocks, weekStartMs: new Date('2026-09-07T00:00:00').getTime(), weekCount: 10, ownTimeOnly: true };
    const buckets = buildRetroBuckets(input);
    const completion = buildRetroBuckets({ ...input, blocks: [] });
    const info = sprintInformation({ id: 'sprint', project_id: 'project', track_id: null, title: 'Sprint', starts_on: '2026-10-12', ends_on: '2026-10-19', sort_key: 'M' }, [task], [], true);
    return { dates: buckets.map((b) => b.startsOn), completion: completion.map((b) => b.startsOn), info };
  });
  assert.deepEqual(pure.dates, pure.completion, 'Restricted retro must use completion dates even when own blocks exist');
  assert.equal(pure.info.hasPrivateTime, true);
  assert.equal(pure.info.ownTimeOnly, true);
  assert.equal(pure.info.estimatedMinutes, 120);
  assert.equal(pure.info.capacityMinutes, 2400);
  const restored = await page.evaluate(async (id) => {
    const { useFira } = await import(performance.getEntriesByType('resource').find((entry) => entry.name.includes('/src/store/index.ts')).name);
    const { taskTimeLeft } = await import(performance.getEntriesByType('resource').find((entry) => entry.name.includes('/src/time.ts')).name);
    const s = useFira.getState();
    const task = s.tasks.find((task) => task.id === id);
    s.applyRemoteOp({ op_id: 'private-time-cleared', seq: 10, kind: 'project.time_visibility', project_id: task.project_id,
      payload: { kind: 'project.time_visibility', project_id: task.project_id, private_task_ids: [] }, applied_at: new Date().toISOString() });
    return taskTimeLeft(useFira.getState().tasks.find((task) => task.id === id), useFira.getState().blocks);
  }, target.taskId);
  assert.equal(typeof restored, 'number', 'Removing the last private block restores numeric Time Left live');
  assert.deepEqual(errors, []);
  console.log('Passed: private task remaining time, sprint partial-time warning, hidden budget bars, and completion-date retro grouping.');
} finally {
  await browser.close();
}
