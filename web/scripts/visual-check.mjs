// Headless-browser smoke check for visual/styling changes (themes, CSS
// tokens, layout). Logs into playground mode (no backend/DB needed),
// drives a few representative screens, and writes screenshots + console
// errors to disk so a change can be eyeballed without a real browser.
//
// Usage:
//   pnpm dev                      # in one terminal, leave running
//   node scripts/visual-check.mjs # in another
//
// First run needs a Chromium binary: `pnpm exec playwright install chromium`
// (and, on a bare Linux box, `sudo pnpm exec playwright install-deps chromium`).
//
// Appearance is two independent axes — theme (palette) and style
// (shape/density) — so the sweep below walks the combinations that
// matter rather than a single "dark" pass. Extend it for a new styling
// task by adding another `await page...` block + `shot()` call, or
// another entry in COMBOS; it's a plain Playwright script, not a
// framework.

import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';

const URL = process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173';
const OUT_DIR = process.env.VISUAL_CHECK_OUT ?? 'scripts/visual-check-out';

mkdirSync(OUT_DIR, { recursive: true });
const shot = (name) => `${OUT_DIR}/${name}.png`;

// [theme, style] pairs. classic/classic is the untouched baseline — worth
// shooting so a regression there is as visible as one in a new combo.
const COMBOS = [
  ['classic', 'classic'],
  ['classic', 'modern'],
  ['dark', 'modern'],
];

const browser = await chromium.launch({ args: ['--no-sandbox'] });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
// `plan.selfcheck.ts` throws in dev when one of its assertions fails, so
// this script is the only automation that can see it. Uncaught exceptions
// fail the sweep; console errors are logged but don't, because the
// pre-login `/api/me` probe legitimately 401s and the browser reports
// that as a console error. Gate on the signal, not on the noise.
const thrown = [];
page.on('console', (msg) => {
  if (msg.type() === 'error') console.log('CONSOLE ERROR:', msg.text());
});
page.on('pageerror', (err) => {
  console.log('PAGE ERROR:', err.message);
  thrown.push(err.message);
});

await page.goto(URL);
await page.waitForSelector('button.login-playground', { timeout: 15000 });
await page.click('button.login-playground');
await page.waitForSelector('.avatar', { timeout: 15000 });

// The two segmented pickers live side by side in the account modal's
// Appearance section and share their option labels ("classic"), so scope
// each click to its own group by aria-label.
async function setAppearance(theme, style) {
  await page.click('button[aria-label="Account settings"]');
  await page.waitForSelector('text=Appearance', { timeout: 10000 });
  await page.click(`[aria-label="Theme"] button:has-text("${theme}")`);
  await page.click(`[aria-label="Style"] button:has-text("${style}")`);
  await page.waitForTimeout(200);
  await page.screenshot({ path: shot(`account-modal-${theme}-${style}`) });
  await page.click('button[aria-label="Close"]');
  await page.waitForTimeout(300);
}

for (const [theme, style] of COMBOS) {
  const tag = `${theme}-${style}`;
  await setAppearance(theme, style);

  // Calendar first — it's the default view after login.
  await page.click('.sidebar .nav-btn', { timeout: 5000 }).catch(() => {});
  await page.waitForTimeout(300);
  await page.screenshot({ path: shot(`app-${tag}`) });

  // Zoom into the time-block area for a close look at the block corners,
  // resting shadow and left-stripe accent.
  const grid = page.locator('.cal-grid-wrap, .cal-grid').first();
  if (await grid.count()) {
    await grid.screenshot({ path: shot(`calendar-blocks-${tag}`) }).catch(() => {});
  }

  // A project's list view: task-row density plus the tag filter chips.
  await page.click('.sidebar .nav-proj', { timeout: 5000 }).catch(() => {});
  await page.waitForTimeout(500);
  await page.screenshot({ path: shot(`list-view-${tag}`) });
  const tagFilter = page.locator('.list-tag-filter').first();
  if (await tagFilter.count()) {
    await tagFilter.screenshot({ path: shot(`list-tag-filter-${tag}`) }).catch(() => {});
  }

  // Task modal — the densest surface in the app, and the one where the
  // modal radius / shadow / pane padding all show at once.
  const row = page.locator('.task-row').first();
  if (await row.count()) {
    await row.click();
    await page.waitForTimeout(400);
    await page.screenshot({ path: shot(`task-modal-${tag}`) });
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);
  }

  // Plan board. Reached by the `p` shortcut rather than the sidebar
  // button, which is gated out of production builds.
  await page.keyboard.press('p');
  await page.waitForTimeout(500);
  await page.screenshot({ path: shot(`plan-view-${tag}`) });
  // Tight crop of the rows: card corners, the track rail, the badge and
  // the dashed retro band all read at this zoom and nowhere else.
  const board = page.locator('.plan-rows').first();
  if (await board.count()) {
    await board.screenshot({ path: shot(`plan-board-${tag}`) }).catch(() => {});
  }
}

// Authenticated scrubber sweep against the local seeded API. Opt in because
// the ordinary playground snapshot has current entities but no op history.
// VISUAL_CHECK_HISTORY=1 VISUAL_CHECK_URL=http://localhost:5173 pnpm visual-check
if (process.env.VISUAL_CHECK_HISTORY === '1') {
  const historyContext = await browser.newContext({ viewport: { width: 1280, height: 900 }, timezoneId: 'Europe/Riga' });
  const historyPage = await historyContext.newPage();
  historyPage.on('pageerror', (error) => thrown.push(error.message));
  let revisionRequests = 0;
  historyPage.on('request', (request) => {
    if (new globalThis.URL(request.url()).pathname === '/api/plan/history') revisionRequests++;
  });
  const login = await historyContext.request.get(`${URL}/api/auth/dev-login?email=maya%40fira.dev`, { maxRedirects: 0 });
  if (![302, 303].includes(login.status()) && !login.ok()) throw new Error(`Fixture login failed: ${login.status()}`);
  const workspaces = await (await historyContext.request.get(`${URL}/api/workspaces`)).json();
  const team = workspaces.find((ws) => !ws.is_personal);
  if (!team) throw new Error('History sweep needs the seeded team workspace');
  await historyPage.addInitScript((ws) => localStorage.setItem('fira:activeWorkspace', ws), team.id);
  await historyPage.goto(URL);
  await historyPage.waitForSelector('.avatar');
  await historyPage.keyboard.press('p');
  await historyPage.locator('.nav-proj[title="Atlas"]').first().click();
  if (await historyPage.locator('.plan-timeline').count()) throw new Error('History panel should start hidden');
  const unplanned = historyPage.getByRole('button', { name: 'Unplanned', exact: true });
  await historyPage.locator('.plan-row-retro .plan-row-title').filter({ hasText: 'Unplanned' }).waitFor();
  await unplanned.click();
  if (await historyPage.locator('.plan-row-retro').count()) throw new Error('Unplanned toggle did not hide its band');
  await unplanned.click();
  await historyPage.getByRole('button', { name: 'Past', exact: true }).click();
  // Bring the metrics task's original sprint into the visible window.
  await historyPage.getByTitle('Back one week', { exact: true }).click();
  await historyPage.getByTitle('Back one week', { exact: true }).click();
  const panel = historyPage.locator('.plan-timeline');
  await panel.waitFor();
  const must = (condition, message) => { if (!condition) throw new Error(message); };
  must(await historyPage.locator('.plan-scroll .plan-timeline').count() === 0,
    'Revision timeline is still inside the roadmap scroll container');
  const bootstrap = await (await historyContext.request.get(`${URL}/api/bootstrap`, { headers: { 'x-workspace-id': team.id } })).json();
  const atlas = bootstrap.projects.find((project) => project.title === 'Atlas');
  const metadata = await (await historyContext.request.get(`${URL}/api/plan/history?project_id=${atlas.id}`, { headers: { 'x-workspace-id': team.id } })).json();
  const deletionIndex = metadata.changes.findIndex((change) => change.kind === 'task.delete');
  must(deletionIndex > 0, 'Fixture has no deleted-task revision to inspect');
  const revision = metadata.changes[deletionIndex - 1];
  const picker = historyPage.getByLabel('Revision', { exact: true });
  const waitRevision = (seq) => historyPage.waitForSelector(`.plan-wrap[data-history][data-revision="${seq}"][aria-busy="false"]`);
  await historyPage.waitForSelector('.plan-wrap[aria-busy="false"]');
  const initialRevisionRequests = revisionRequests;
  const fullAxis = historyPage.getByRole('slider', { name: 'Scrub plan history', exact: true });
  const fullRange = async () => ({
    start: await fullAxis.getAttribute('data-start'), end: await fullAxis.getAttribute('data-end'),
    live: await fullAxis.getAttribute('aria-valuenow'),
  });
  const fullBeforeWheel = await fullRange();
  await fullAxis.hover();
  for (let i = 0; i < 3; i++) {
    await historyPage.mouse.wheel(0, 300);
    await historyPage.waitForTimeout(60);
    must(JSON.stringify(await fullRange()) === JSON.stringify(fullBeforeWheel),
      'Scrolling out at Fit advanced the live timestamp or history bounds');
  }
  must(await historyPage.getByRole('button', { name: 'Zoom out history', exact: true }).isDisabled(),
    'Zoom out did not stop at the full history range');

  await picker.selectOption(String(revision.seq));
  await waitRevision(revision.seq);
  must(await historyPage.locator('.plan-card[data-ghost], .plan-card-drift, .plan-history-legend').count() === 0,
    'Historical plan displayed a live comparison overlay');
  must(await historyPage.locator('.plan-task-title').filter({ hasText: 'Retire the v1 metrics pipeline' }).count() > 0,
    'Deleted task was not resurrected at its exact historical revision');
  must(await historyPage.locator('.plan-card-grip, .plan-card-del, .plan-card-add-btn, .plan-task-x').count() === 0,
    'Historical cards exposed mutation controls');
  must(await historyPage.locator('.plan-task-tick:not(:disabled)').count() === 0, 'Historical checklist can still be ticked');
  const mutations = [];
  historyPage.on('request', (request) => {
    if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method())) mutations.push(request.url());
  });
  must(await unplanned.isEnabled(), 'Historical Unplanned toggle is disabled');
  const historicalUnplanned = historyPage.locator('.plan-row-retro');
  await historicalUnplanned.waitFor();
  must(await historicalUnplanned.locator('.plan-task-title').count() > 0, 'Historical unplanned tasks are missing');
  must(await historicalUnplanned.locator('.plan-card-promote, [draggable="true"]').count() === 0,
    'Historical unplanned work exposes promotion or dragging');
  await historicalUnplanned.locator('.plan-task').first().click();
  must(await historyPage.locator('.modal-backdrop').count() === 0, 'Historical unplanned row opened the live editor');
  await unplanned.click();
  must(await historicalUnplanned.count() === 0, 'Historical Unplanned toggle does not hide the band');
  await unplanned.click();
  await historicalUnplanned.waitFor();
  await picker.selectOption(String(metadata.changes[0].seq));
  await waitRevision(metadata.changes[0].seq);
  must(await historicalUnplanned.count() === 0, 'Unplanned work appeared before it was recorded');
  must(await unplanned.isEnabled(), 'Unplanned toggle was disabled for an empty historical band');
  await picker.selectOption(String(revision.seq));
  await waitRevision(revision.seq);
  await historicalUnplanned.waitFor();
  const roadmapBefore = await historyPage.locator('.plan-scroll').evaluate((el) => ({
    scrollLeft: el.scrollLeft, labels: [...el.querySelectorAll('.plan-week')].map((week) => week.textContent).join(','),
  }));
  const scaleBefore = await historyPage.locator('.plan-revision-zoom .week-nav-count').innerText();
  await historyPage.getByRole('button', { name: 'Zoom in history', exact: true }).click();
  const scaleAfter = await historyPage.locator('.plan-revision-zoom .week-nav-count').innerText();
  must(scaleBefore !== scaleAfter, 'History zoom did not change its time scale');
  const roadmapAfter = await historyPage.locator('.plan-scroll').evaluate((el) => ({
    scrollLeft: el.scrollLeft, labels: [...el.querySelectorAll('.plan-week')].map((week) => week.textContent).join(','),
  }));
  must(JSON.stringify(roadmapBefore) === JSON.stringify(roadmapAfter), 'History zoom moved or rescaled the roadmap');
  must(await picker.inputValue() === String(revision.seq), 'Zoom changed the selected revision');
  // Selecting a revision leaves focus in the newest-first picker.
  // Left/right must follow time rather than native option order.
  await picker.focus();
  await picker.press('ArrowLeft');
  must(await picker.inputValue() === String(metadata.changes[deletionIndex - 2].seq), 'Focused picker Left stepped forward in time');
  await waitRevision(metadata.changes[deletionIndex - 2].seq);
  await picker.press('ArrowRight');
  must(await picker.inputValue() === String(revision.seq), 'Focused picker Right stepped backward in time');
  await waitRevision(revision.seq);
  must(await picker.evaluate((el) => document.activeElement === el), 'Revision stepping unexpectedly moved focus');
  const keyboardAxis = historyPage.getByRole('slider', { name: 'Scrub plan history', exact: true });
  await keyboardAxis.focus();
  await keyboardAxis.press('ArrowLeft');
  must(await picker.inputValue() === String(metadata.changes[deletionIndex - 2].seq), 'Timeline Left disagrees with picker Left');
  await waitRevision(metadata.changes[deletionIndex - 2].seq);
  await keyboardAxis.press('ArrowRight');
  must(await picker.inputValue() === String(revision.seq), 'Timeline Right disagrees with picker Right');
  await waitRevision(revision.seq);

  await historyPage.getByRole('button', { name: 'Previous revision', exact: true }).click();
  must(await picker.inputValue() === String(metadata.changes[deletionIndex - 2].seq), 'Previous change did not select the exact revision');
  await historyPage.getByRole('button', { name: 'Next revision', exact: true }).click();
  must(await picker.inputValue() === String(revision.seq), 'Next change did not restore the exact revision');
  await waitRevision(revision.seq);
  for (const [theme, style] of COMBOS) {
    await historyPage.evaluate(({ theme, style }) => {
      document.documentElement.dataset.theme = theme;
      document.documentElement.dataset.style = style;
    }, { theme, style });
    await historyPage.screenshot({ path: shot(`plan-history-${theme}-${style}`) });
  }
  const axis = historyPage.getByRole('slider', { name: 'Scrub plan history', exact: true });
  const box = await axis.boundingBox();
  must(!!box, 'Revision axis has no pointer target');
  must(await historyPage.locator('.plan-wrap > .plan-history-status').count() === 0,
    'History status still occupies the top of the board');
  const timeBeforeClick = await axis.getAttribute('aria-valuenow');
  await historyPage.mouse.click(box.x + box.width * .35, box.y + 65);
  must(await axis.getAttribute('aria-valuenow') !== timeBeforeClick, 'Clicking the timeline did not select a time');
  await historyPage.waitForSelector('.plan-wrap[data-history][aria-busy="false"]');
  const playhead = await historyPage.locator('.plan-revision-playhead span').boundingBox();
  must(!!playhead, 'Playhead has no drag target');
  await historyPage.mouse.move(playhead.x + playhead.width / 2, playhead.y + playhead.height / 2);
  await historyPage.mouse.down();
  const dragTimes = [];
  for (const fraction of [.4, .45, .5, .55, .6]) {
    await historyPage.mouse.move(box.x + box.width * fraction, box.y + 65);
    dragTimes.push(await axis.getAttribute('aria-valuenow'));
  }
  await historyPage.mouse.up();
  must(new Set(dragTimes).size === dragTimes.length, 'Dragging the playhead did not update the timestamp continuously');
  await historyPage.waitForSelector('.plan-wrap[data-history][aria-busy="false"]');
  const selectedBeforePan = await axis.getAttribute('aria-valuenow');
  const startBeforePan = await axis.getAttribute('data-start');
  await historyPage.mouse.move(box.x + box.width * .5, box.y + 65);
  await historyPage.mouse.down();
  await historyPage.mouse.move(box.x + box.width * .65, box.y + 65);
  await historyPage.mouse.up();
  must(await axis.getAttribute('aria-valuenow') === selectedBeforePan, 'Panning changed the revision time');
  must(await axis.getAttribute('data-start') !== startBeforePan, 'Dragging did not pan the timeline');
  const spanBeforeWheel = Number(await axis.getAttribute('data-end')) - Number(await axis.getAttribute('data-start'));
  await historyPage.mouse.move(box.x + box.width * .5, box.y + 65);
  await historyPage.mouse.wheel(0, -300);
  await historyPage.waitForFunction((previous) => {
    const el = document.querySelector('.plan-revision-axis');
    return el && Number(el.dataset.end) - Number(el.dataset.start) < previous;
  }, spanBeforeWheel);
  must(await axis.getAttribute('aria-valuenow') === selectedBeforePan, 'Wheel zoom changed the revision time');
  await historyPage.getByRole('button', { name: 'Fit all history', exact: true }).click();
  const layout = () => historyPage.evaluate(() => {
    const body = document.querySelector('.plan-body').getBoundingClientRect();
    const panel = document.querySelector('.plan-history-panel').getBoundingClientRect();
    return { bodyHeight: body.height, panelTop: panel.top, panelHeight: panel.height };
  });
  const restingLayout = await layout();
  await historyPage.route('**/api/plan/at?**', async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 500));
    await route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'History test error' }) });
  }, { times: 1 });
  await picker.selectOption(String(metadata.changes[deletionIndex - 2].seq));
  await historyPage.locator('.plan-revision-caption .plan-history-status').filter({ hasText: 'Loading…' }).waitFor();
  must(JSON.stringify(await layout()) === JSON.stringify(restingLayout), 'Loading status shifted the board or footer');
  await historyPage.getByRole('button', { name: 'Retry', exact: true }).waitFor();
  must(JSON.stringify(await layout()) === JSON.stringify(restingLayout), 'Error status shifted the board or footer');
  must(await historyPage.locator('.plan-history-panel .plan-history-status').count() === 1, 'Retry status is not in the bottom panel');
  must(await historyPage.locator('.plan-card').count() === 0, 'Failed history request displayed a stale board');
  await historyPage.getByRole('button', { name: 'Retry', exact: true }).click();
  await waitRevision(metadata.changes[deletionIndex - 2].seq);
  must(JSON.stringify(await layout()) === JSON.stringify(restingLayout), 'Finishing the read shifted the board or footer');
  must(mutations.length === 0, `History interactions wrote data: ${mutations.join(', ')}`);
  await historyPage.getByRole('button', { name: 'Past', exact: true }).click();
  await historyPage.waitForSelector('.plan-wrap:not([data-history])');
  must(await historyPage.locator('.plan-timeline, .plan-history-status').count() === 0, 'Past toggle did not hide the revision panel');
  await historyPage.getByRole('button', { name: 'Past', exact: true }).click();
  await picker.waitFor();
  await picker.selectOption(String(revision.seq));
  await waitRevision(revision.seq);
  await picker.selectOption('live');
  await historyPage.waitForSelector('.plan-wrap:not([data-history])');
  must(await historyPage.locator('.plan-card[data-ghost]').count() === 0, 'Live plan retained replay ghosts');
  must(await historyPage.locator('.plan-card-grip').count() > 0, 'Live plan did not restore editing');
  must(revisionRequests === initialRevisionRequests, 'Scrubbing or reopening fetched the unchanged revision list');
  await historyPage.screenshot({ path: shot('plan-history-return-live') });
  await historyContext.close();
}

await browser.close();
console.log(`Screenshots written to ${OUT_DIR}/`);
if (thrown.length) {
  console.log(`\n${thrown.length} uncaught page error(s) — failing the sweep:`);
  for (const e of thrown) console.log(`  - ${e}`);
  process.exit(1);
}
