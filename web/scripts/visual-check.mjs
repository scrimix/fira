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
page.on('console', (msg) => { if (msg.type() === 'error') console.log('CONSOLE ERROR:', msg.text()); });
page.on('pageerror', (err) => console.log('PAGE ERROR:', err.message));

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
}

await browser.close();
console.log(`Screenshots written to ${OUT_DIR}/`);
