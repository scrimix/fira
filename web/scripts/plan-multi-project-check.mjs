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
  await page.locator('.sidebar button[title="Plan (P)"]').click();
  await page.locator('.plan-rows').waitFor();
  const scope = () => page.locator('.plan-row[data-project]').evaluateAll((rows) => [...new Set(rows.map((row) => row.dataset.project))]);
  const all = await scope();
  assert.ok(all.length > 1, 'Default Plan must show tracks from multiple projects');
  assert.ok((await page.locator('.topbar').textContent()).includes('All projects'));
  const total = await page.locator('.plan-card:not(.plan-card-retro)').count();
  assert.equal(await page.locator('.sidebar [data-proj-active="true"]').count(), 0);
  const title = await page.locator('.plan-row[data-project] .plan-row-sub').first().textContent();
  const selected = page.locator(`.sidebar .nav-proj[title=${JSON.stringify(title)}]`);
  await selected.click();
  assert.equal((await scope()).length, 1, 'Selecting a project must scope its tracks');
  assert.equal(await page.locator('.sidebar [data-proj-active="true"]').count(), 1);
  assert.ok(await page.locator('.plan-card:not(.plan-card-retro)').count() < total);
  await selected.click();
  assert.deepEqual(await scope(), all, 'Clicking the selected project must restore every track');
  assert.equal(await page.locator('.plan-card:not(.plan-card-retro)').count(), total);
  assert.equal(await page.locator('.sidebar [data-proj-active="true"]').count(), 0);
  const source = page.locator('.plan-row[data-project]').filter({ has: page.locator('.plan-card:not(.plan-card-retro)') }).first();
  const sourceProject = await source.getAttribute('data-project');
  const sourceTrack = await source.getAttribute('data-track');
  const target = page.locator(`.plan-row[data-project]:not([data-project="${sourceProject}"])`).first();
  const header = source.locator('.plan-card-head').first();
  const box = await header.boundingBox();
  const destination = await target.locator('.plan-row-grid').boundingBox();
  const label = await source.locator('.plan-card-head').first().textContent();
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width / 2 + 5, destination.y + 20, { steps: 5 });
  await page.mouse.up();
  assert.ok((await page.locator(`.plan-row[data-project="${sourceProject}"][data-track="${sourceTrack}"] .plan-card-head`).allTextContents()).includes(label), 'Dragging across projects must retain the sprint in its original project');
  assert.deepEqual(errors, [], 'No uncaught browser errors');
  await page.screenshot({ path: '/tmp/plan-multi-project.png' });
  console.log(`Passed: ${all.length} projects, ${total} sprint cards, sidebar solo/reset, cross-project drag guard.`);
} finally {
  await browser.close();
}
