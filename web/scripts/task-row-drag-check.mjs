import assert from 'node:assert/strict';
import { chromium } from 'playwright';
const browser = await chromium.launch({ args: ['--no-sandbox'] });
try {
 for (const mode of ['mouse', 'touch']) {
  const page = await browser.newPage({ viewport: { width: mode === 'touch' ? 820 : 1440, height: 1180 }, hasTouch: true });
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await page.addInitScript(() => localStorage.setItem('fira:playground', '1'));
  await page.goto(process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173');
  await page.locator('.sidebar').waitFor();
  const ids = await page.evaluate(async () => {
   const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
   const s = useFira.getState();
   const p = s.projects[0];
   const tasks = s.tasks.filter(t => t.project_id === p.id).slice(0, 3).map((t, i) => ({ ...t, title: 'Drag fixture ' + i, section: 'now', status: 'open', assignee_id: s.meId, subtasks: [], sort_key: ['a0', 'a1', 'a2'][i] }));
   useFira.setState({ tasks, blocks: [], listFilter: { ...s.listFilter, project_id: p.id, tag_ids: [], sections: [], assignee_id: null } });
   s.setView('list', p.id);
   return tasks.map(t => t.id);
  });
  const rows = page.locator('.task-row'); await rows.first().waitFor();
  const source = page.locator(`[data-task-id="${ids[0]}"]`);
  const target = page.locator(`[data-task-id="${ids[1]}"]`);
  const sb = await source.locator('.task-title').boundingBox(); const tb = await target.boundingBox();
  const x = sb.x + 10, y = sb.y + sb.height / 2, endY = tb.y + tb.height - 3;
  const cdp = await page.context().newCDPSession(page);
  if (mode === 'mouse') { await page.mouse.move(x,y); await page.mouse.down(); }
  else await cdp.send('Input.dispatchTouchEvent', { type: 'touchStart', touchPoints: [{ x,y }] });
  await page.waitForTimeout(300);
  assert.equal(await source.getAttribute('data-pressing'), 'true', mode + ' hold activates drag');
  if (mode === 'mouse') await page.mouse.move(x,endY,{steps:5});
  else await cdp.send('Input.dispatchTouchEvent', { type: 'touchMove', touchPoints: [{ x,y:endY }] });
  await page.waitForTimeout(50);
  assert.equal(await target.getAttribute('data-drop-mark'), 'after', mode + ' drop indicator');
  if (mode === 'mouse') await page.mouse.up();
  else await cdp.send('Input.dispatchTouchEvent', { type: 'touchEnd', touchPoints: [] });
  await page.waitForTimeout(100);
  assert.deepEqual(await rows.evaluateAll(nodes => nodes.map(n => n.dataset.taskId)), [ids[1],ids[0],ids[2]], mode + ' reorder');
  assert.equal(await page.locator('.list-title-input').count(),0,'drag must not edit title');
  assert.equal(await page.locator('.modal-backdrop').count(),0,'drag must not open modal');
  await page.waitForTimeout(400);
  const originalOrder = await rows.evaluateAll(nodes => nodes.map(n => n.dataset.taskId));
  const cancelBox = await source.locator('.task-title').boundingBox();
  const cx = cancelBox.x + 10, cy = cancelBox.y + cancelBox.height / 2;
  if (mode === 'mouse') {
    await page.mouse.move(cx,cy); await page.mouse.down();
    await page.mouse.move(cx,cy+12);
  } else {
    await cdp.send('Input.dispatchTouchEvent', { type:'touchStart', touchPoints:[{x:cx,y:cy}] });
    await cdp.send('Input.dispatchTouchEvent', { type:'touchMove', touchPoints:[{x:cx,y:cy+12}] });
  }
  await page.waitForTimeout(300);
  assert.notEqual(await source.getAttribute('data-pressing'), 'true', 'Moving before hold must cancel drag');
  if (mode === 'mouse') await page.mouse.up();
  else await cdp.send('Input.dispatchTouchEvent', { type:'touchCancel', touchPoints:[] });
  assert.deepEqual(await rows.evaluateAll(nodes => nodes.map(n => n.dataset.taskId)), originalOrder);
  assert.equal(await page.locator('.modal-backdrop').count(), 0, 'Cancelled movement must not open modal');
  await page.waitForTimeout(400);
  if (mode === 'mouse') {
    const grip = await source.locator('.task-grip').boundingBox();
    const next = await page.locator(`[data-task-id="${ids[2]}"]`).boundingBox();
    await page.mouse.move(grip.x+grip.width/2,grip.y+grip.height/2);
    await page.mouse.down();
    await page.waitForTimeout(30);
    assert.equal(await source.getAttribute('draggable'), 'true');
    await page.mouse.move(grip.x+grip.width/2,next.y+next.height-3,{steps:8});
    await page.mouse.move(next.x+100,next.y+next.height-3);
    await page.mouse.move(next.x+101,next.y+next.height-3);
    await page.mouse.up();
    await page.waitForTimeout(100);
    assert.deepEqual(await rows.evaluateAll(nodes => nodes.map(n => n.dataset.taskId)), [ids[1],ids[2],ids[0]], 'Immediate grip drag still works');
    await source.locator('.task-title').click();
    await source.locator('.list-title-input').waitFor();
    await page.keyboard.press('Escape');
  }
  assert.deepEqual(errors, []);
  console.log('Passed ' + mode + ': whole-row hold, drop indicator, reorder, no accidental edit/modal.');
  await page.close();
 }
} finally { await browser.close(); }
