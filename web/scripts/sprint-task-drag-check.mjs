import assert from 'node:assert/strict';
import { chromium } from 'playwright';
const browser = await chromium.launch({ args: ['--no-sandbox'] });
try {
 const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
 const errors = []; page.on('pageerror', e => errors.push(e.message));
 await page.addInitScript(() => localStorage.setItem('fira:playground', '1'));
 await page.goto(process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173');
 await page.locator('.sidebar').waitFor();
 await page.evaluate(async () => {
  const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
  const s = useFira.getState(), sprint = s.sprints[0];
  const tasks = s.tasks.slice(0, 4).map((t, i) => ({ ...t, project_id: sprint.project_id,
   sprint_id: sprint.id, track_id: sprint.track_id, title: `Sprint drag ${i}`,
   section: 'later', status: 'todo', sort_key: ['a0', 'a1', 'a2', 'a3'][i] }));
  const start = new Date(); start.setDate(start.getDate() - (start.getDay() + 6) % 7);
  const end = new Date(start); end.setDate(end.getDate() + 14);
  useFira.setState({ tasks, sprints: [{ ...sprint, title: 'Source sprint', starts_on: start.toISOString().slice(0, 10), ends_on: end.toISOString().slice(0, 10) }], blocks: [], planShowTasks: true });
  s.setView('plan', sprint.project_id);
 });
 const card = page.locator('.plan-card').filter({ hasText: 'Source sprint' });
 await card.scrollIntoViewIfNeeded();
 const rows = card.locator('.plan-task');
 const row = i => rows.filter({ hasText: `Sprint drag ${i}` });
 const order = () => rows.locator('.plan-task-title').allTextContents();
 const transfer = await page.evaluateHandle(() => new DataTransfer());
 const hover = async (i, offset) => {
  const box = await row(i).boundingBox();
  await row(i).dispatchEvent('dragover', { dataTransfer: transfer, clientY: box.y + offset * box.height });
 };
 await row(0).dispatchEvent('dragstart', { dataTransfer: transfer });
 await hover(2, 0.9);
 const marks = () => rows.evaluateAll(nodes => nodes.filter(n => n.dataset.drop).map(n => [n.textContent, n.dataset.drop]));
 const firstMark = await marks();
 await hover(3, 0.1);
 assert.deepEqual(await marks(), firstMark, 'Both sides of a gap must resolve to one insertion marker');
 await row(3).dispatchEvent('drop', { dataTransfer: transfer, clientY: 0 });
 await row(0).dispatchEvent('dragend', { dataTransfer: transfer });
 assert.deepEqual(await order(), ['Sprint drag 1', 'Sprint drag 2', 'Sprint drag 0', 'Sprint drag 3'], 'Drop must match the marker');
 const source = await row(0).locator('.plan-task-title').boundingBox();
 const target = await row(1).boundingBox();
 await page.mouse.move(source.x + 20, source.y + source.height / 2);
 await page.mouse.down();
 await page.mouse.move(target.x + 40, target.y + 2, { steps: 10 });
 await page.mouse.move(target.x + 41, target.y + 2);
 await page.mouse.up();
 assert.deepEqual(await order(), ['Sprint drag 0', 'Sprint drag 1', 'Sprint drag 2', 'Sprint drag 3'], 'Native drag must update task position');
 assert.equal(await card.locator('[data-drop]').count(), 0, 'Drop clears the indicator');
 // Self drops have no insertion marker, and canceling clears every marker.
 await row(0).dispatchEvent('dragstart', { dataTransfer: transfer });
 await hover(0, 0.5);
 assert.deepEqual(await marks(), [], 'Original slot must not advertise a move');
 await hover(3, 0.9);
 assert.equal((await marks()).length, 1);
 await row(0).dispatchEvent('dragend', { dataTransfer: transfer });
 assert.deepEqual(await marks(), [], 'Cancel clears the marker');

 // A gap at the archive boundary has one legal anchor on its active side.
 await page.evaluate(async () => {
  const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
  useFira.setState(s => ({ tasks: s.tasks.map((t, i) => ({ ...t,
   section: i < 2 ? 'now' : i === 2 ? 'later' : 'done',
   status: i === 3 ? 'done' : 'todo', sort_key: ['A', 'a', 'b', 'c'][i] })) }));
 });
 await row(0).dispatchEvent('dragstart', { dataTransfer: transfer });
 await hover(2, 0.9);
 const archiveMark = await marks();
 assert.equal(archiveMark.length, 1);
 await hover(3, 0.1);
 assert.deepEqual(await marks(), archiveMark, 'Archive boundary uses the same legal slot from both sides');
 const archiveBox = await row(3).boundingBox();
 await row(3).dispatchEvent('drop', { dataTransfer: transfer, clientY: archiveBox.y + 2 });
 await row(0).dispatchEvent('dragend', { dataTransfer: transfer });
 assert.deepEqual(await order(), ['Sprint drag 1', 'Sprint drag 2', 'Sprint drag 0', 'Sprint drag 3']);
 assert.equal(await row(0).getAttribute('data-section'), 'later', 'Boundary drop must take the active section');
 // Mixed-case keys must use the same ordering in the move handler and snapshot.
 await page.evaluate(async () => {
  const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
  useFira.setState(s => ({ tasks: s.tasks.map((t, i) => ({ ...t, section: 'later', sort_key: ['A', 'a', 'b', 'c'][i] })) }));
 });
 await row(2).dispatchEvent('dragstart', { dataTransfer: transfer });
 await hover(0, 0.9);
 const topBox = await row(1).boundingBox();
 await row(1).dispatchEvent('drop', { dataTransfer: transfer, clientY: topBox.y + 2 });
 await row(2).dispatchEvent('dragend', { dataTransfer: transfer });
 assert.deepEqual(await order(), ['Sprint drag 0', 'Sprint drag 2', 'Sprint drag 1', 'Sprint drag 3']);
 // Moving between cards must update both sprint membership and position.
 await page.evaluate(async () => {
  const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
  useFira.setState(s => {
   const sprint = { ...s.sprints[0], id: crypto.randomUUID(), title: 'Destination sprint' };
   const task = { ...s.tasks[0], id: crypto.randomUUID(), title: 'Destination task', sprint_id: sprint.id };
   return { sprints: [...s.sprints, sprint], tasks: [...s.tasks, task] };
  });
 });
 const destination = page.locator('.plan-card').filter({ hasText: 'Destination sprint' });
 const destinationRow = destination.locator('.plan-task');
 await row(0).dispatchEvent('dragstart', { dataTransfer: transfer });
 const destinationBox = await destinationRow.boundingBox();
 await destinationRow.dispatchEvent('dragover', { dataTransfer: transfer, clientY: destinationBox.y + 1 });
 assert.equal(await destinationRow.getAttribute('data-drop'), 'before');
 await destinationRow.dispatchEvent('drop', { dataTransfer: transfer });
 await destination.locator('.plan-task').first().dispatchEvent('dragend', { dataTransfer: transfer });
 assert.deepEqual(await destination.locator('.plan-task-title').allTextContents(), ['Sprint drag 0', 'Destination task']);
 assert.equal(await row(0).count(), 0, 'Cross-card drop removes the source from its old sprint');
 // An empty checklist still accepts a plain sprint assignment.
 await page.evaluate(async () => {
  const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
  useFira.setState(s => ({ tasks: s.tasks.filter(t => t.title !== 'Destination task')
   .map(t => t.title === 'Sprint drag 0' ? { ...t, sprint_id: s.sprints[0].id } : t) }));
 });
 await row(0).dispatchEvent('dragstart', { dataTransfer: transfer });
 await destination.locator('.plan-card-tasks').dispatchEvent('dragover', { dataTransfer: transfer });
 await destination.locator('.plan-card-tasks').dispatchEvent('drop', { dataTransfer: transfer });
 await destination.locator('.plan-task').first().dispatchEvent('dragend', { dataTransfer: transfer });
 assert.deepEqual(await destination.locator('.plan-task-title').allTextContents(), ['Sprint drag 0']);
 assert.deepEqual(errors, []);
 console.log('Passed: canonical gap marker, matching drop order, native dragging, self drops, cancellation, archive boundaries, mixed-case sort keys, cross-card and empty-card drops.');
} finally { await browser.close(); }
