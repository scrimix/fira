import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const longTitle = 'Review the requirements and capture all the details before moving on to the next step. '.repeat(12).trim();
const browser = await chromium.launch({ args: ['--no-sandbox'] });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => localStorage.setItem('fira:playground', '1'));
  await page.goto(process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173');
  await page.locator('.sidebar').waitFor();
  const ids = await page.evaluate(async title => {
    const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
    const s = useFira.getState();
    const project = s.projects[0];
    const task = s.tasks.find(t => t.project_id === project.id);
    const subId = s.addSubtask(task.id, title);
    s.setView('list', project.id);
    return { taskId: task.id, subId };
  }, longTitle);
  async function visibleText(editor) {
    await editor.waitFor();
    await page.waitForFunction(el => el.clientHeight >= el.scrollHeight && el.clientWidth >= el.scrollWidth, await editor.elementHandle());
    assert.equal(await editor.inputValue(), longTitle);
  }
  // Existing text, growth and shrinkage in the task dialog.
  await page.evaluate(async taskId => {
    const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
    useFira.getState().openTask(taskId);
  }, ids.taskId);
  await page.locator(`[data-subtask-id="${ids.subId}"] .sname`).click();
  const editor = page.locator('.modal-subtasks .subtask-edit-input');
  await visibleText(editor);
  const tall = await editor.evaluate(el => el.clientHeight);
  await editor.fill('Short title');
  assert.ok(await editor.evaluate(el => el.clientHeight) < tall);
  await editor.fill(longTitle);
  await visibleText(editor);
  // A width change while editing must remeasure wrapping.
  await page.setViewportSize({ width: 600, height: 1100 });
  await visibleText(editor);
  await page.keyboard.press('Escape');
  const add = page.locator('.modal-subtasks .subtask-add-input');
  await add.fill(longTitle);
  await visibleText(add);
  await page.keyboard.press('Escape');
  assert.deepEqual(errors, []);
  console.log('Passed: long subtask editing, growth, shrinkage, resize, cancel, and add field.');
} finally {
  await browser.close();
}
