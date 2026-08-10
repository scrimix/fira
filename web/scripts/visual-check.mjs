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
// Extend this for a new styling task by adding another `await page...`
// block + `shot('name')` call — it's a plain Playwright script, not a
// framework.

import { chromium } from 'playwright';
import { mkdirSync } from 'node:fs';

const URL = process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173';
const OUT_DIR = process.env.VISUAL_CHECK_OUT ?? 'scripts/visual-check-out';

mkdirSync(OUT_DIR, { recursive: true });
const shot = (name) => `${OUT_DIR}/${name}.png`;

const browser = await chromium.launch({ args: ['--no-sandbox'] });
const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
page.on('console', (msg) => { if (msg.type() === 'error') console.log('CONSOLE ERROR:', msg.text()); });
page.on('pageerror', (err) => console.log('PAGE ERROR:', err.message));

await page.goto(URL);
await page.waitForSelector('button.login-playground', { timeout: 15000 });
await page.click('button.login-playground');
await page.waitForSelector('.avatar', { timeout: 15000 });
await page.screenshot({ path: shot('app-classic') });

await page.click('button[aria-label="Account settings"]');
await page.waitForSelector('text=Appearance', { timeout: 10000 });
await page.screenshot({ path: shot('account-modal-classic') });

await page.click('button:has-text("dark")');
await page.waitForTimeout(300);
await page.screenshot({ path: shot('account-modal-dark') });

await page.click('button[aria-label="Close"]');
await page.waitForTimeout(300);
await page.screenshot({ path: shot('app-dark') });

// Zoom into the calendar time-block area for a close look at the
// outline/fill relationship (the thing most recently fixed).
const grid = page.locator('.cal-grid-wrap, .cal-grid').first();
if (await grid.count()) {
  await grid.screenshot({ path: shot('calendar-blocks-dark') }).catch(() => {});
}

// List view: project icon + tag chip colors. Open a project from the
// sidebar's project list (clicking its title navigates to the doc-style
// list view for that project).
await page.click('text=Atlas').catch(() => {});
await page.waitForTimeout(500);
await page.screenshot({ path: shot('list-view-dark') });

// Open a task to see the tag-chip / project-dot colors in the modal.
await page.click('text=OAuth refresh token rotation').catch(() => {});
await page.waitForTimeout(500);
await page.screenshot({ path: shot('task-modal-dark') });

await browser.close();
console.log(`Screenshots written to ${OUT_DIR}/`);
