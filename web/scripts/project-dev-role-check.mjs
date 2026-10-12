import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const browser = await chromium.launch({ args: ['--no-sandbox'] });
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(() => localStorage.setItem('fira:playground', '1'));
  await page.goto(process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173');
  await page.locator('.avatar').waitFor();
  const result = await page.evaluate(async () => {
    const { useFira } = await import(performance.getEntriesByType('resource').find((entry) => entry.name.includes('/src/store/index.ts')).name);
    const initial = useFira.getState();
    const [privateProject, normalProject] = initial.projects;
    const privateTask = initial.tasks.find((task) => task.project_id === privateProject.id);
    const normalTask = initial.tasks.find((task) => task.project_id === normalProject.id);
    const teammate = initial.users.find((user) => user.id !== initial.meId);
    const block = (id, task, owner) => ({ id, task_id: task.id, user_id: owner,
      start_at: '2026-10-12T08:00:00Z', end_at: '2026-10-12T09:00:00Z', state: 'planned',
      jira_worklog_id: null, jira_sync_error: null });
    const own = block('own', privateTask, initial.meId);
    const hidden = block('hidden', privateTask, teammate.id);
    const visible = block('visible', normalTask, teammate.id);
    useFira.setState({ blocks: [own, hidden, visible], linkedBlocks: [hidden, visible] });
    const members = privateProject.members.map((member) => member.user_id === initial.meId ? { ...member, role: 'dev' } : member);
    if (!members.some((member) => member.user_id === initial.meId)) members.push({ user_id: initial.meId, role: 'dev' });
    await useFira.getState().setProjectMembers(privateProject.id, members);
    const after = useFira.getState();
    const cached = after.blocks.map((b) => b.id);
    const linked = after.linkedBlocks.map((b) => b.id);
    after.setTaskTitle(privateTask.id, 'Developer edited task');
    const track = after.addTrack(privateProject.id, 'Developer track');
    const sprint = after.addSprint(privateProject.id, track, 'Developer sprint', '2026-10-12', '2026-10-19');
    after.upsertBlock({ ...hidden, id: 'forbidden' });
    after.upsertBlock({ ...own, id: 'new-own' });
    const now = useFira.getState();
    // Stub network refreshes only for this isolated store test.
    useFira.setState({ hydrate: async () => {}, loadLinkedCalendar: async () => {} });
    now.applyRemoteOp({ op_id: 'late-block', seq: 1, project_id: privateProject.id, kind: 'block.create',
      payload: { kind: 'block.create', block: { ...hidden, id: 'late-hidden' } }, applied_at: new Date().toISOString() });
    now.applyRemoteOp({ op_id: 'move', seq: 2, project_id: normalProject.id, kind: 'task.move_project',
      payload: { kind: 'task.move_project', from_project_id: normalProject.id, to_project_id: privateProject.id,
        task: { ...normalTask, project_id: privateProject.id }, blocks: [visible, block('moved-own', normalTask, initial.meId)] },
      applied_at: new Date().toISOString() });
    const final = useFira.getState();
    return { cached, linked, blocks: final.blocks.map((b) => b.id),
      taskTitle: final.tasks.find((task) => task.id === privateTask.id).title,
      track: !!final.tracks.find((t) => t.id === track), sprint: !!final.sprints.find((s) => s.id === sprint) };
  });
  assert.deepEqual(result.cached, ['own', 'visible']);
  assert.deepEqual(result.linked, ['visible']);
  assert.deepEqual(result.blocks, ['own', 'new-own', 'moved-own']);
  assert.equal(result.taskTitle, 'Developer edited task');
  assert.ok(result.track && result.sprint);
  await page.evaluate(async () => {
    const { useFira } = await import(performance.getEntriesByType('resource').find((entry) => entry.name.includes('/src/store/index.ts')).name);
    useFira.getState().openEditProject(useFira.getState().projects[0].id);
  });
  await page.waitForTimeout(300);
  await page.locator('.np-members .select-trigger').first().click({ timeout: 3000 });
  assert.ok(await page.getByRole('option').filter({ hasText: 'works tasks; sees only own time blocks' }).count());
  assert.deepEqual(errors, []);
  console.log('Passed: dev downgrade clears cached and linked teammate blocks, owns new blocks, edits tasks/plans, guards live updates and task moves.');
} finally {
  await browser.close();
}
