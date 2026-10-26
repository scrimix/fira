import assert from 'node:assert/strict';
import { chromium } from 'playwright';
const browser = await chromium.launch({ args: ['--no-sandbox'] });
try {
 for (const touch of [false, true]) {
  const page = await browser.newPage({ viewport: { width: 1200, height: 900 }, hasTouch: touch });
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await page.addInitScript(() => localStorage.setItem('fira:playground', '1'));
  await page.goto(process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173');
  await page.locator('.topbar').waitFor();
  await page.keyboard.press('p');
  const triggers = page.getByRole('button', { name: 'Sprint actions', exact: true });
  const visibleIndex = await triggers.evaluateAll(buttons => buttons.findIndex(button => {
   const r = button.getBoundingClientRect();
   return r.left > 300 && r.right < innerWidth - 320 && r.top > 100 && r.bottom < innerHeight;
  }));
  assert.ok(visibleIndex >= 0, 'Fixture has a sprint action visible without scrolling');
  const trigger = triggers.nth(visibleIndex);
  const activate = locator => touch ? locator.tap() : locator.click();
  await activate(trigger);
  const edit = page.getByRole('menuitem', { name: 'Edit sprint' });
  await edit.waitFor();
  if (touch) {
   // Safari can drop focus before the synthetic click without focusing
   // another element. Reproduce that order without a Safari dependency.
   await page.evaluate(() => document.addEventListener('mousedown', event => {
    if (event.target.closest('.plan-sprint-menu')) document.activeElement?.blur();
   }, { capture: true, once: true }));
  }
  await activate(edit);
  const dialog = page.getByRole('dialog', { name: 'Edit sprint' });
  await dialog.waitFor({ timeout: 3000 });
  const name = dialog.getByRole('textbox', { name: 'Sprint name' });
  const updated = `${await name.inputValue()} edited`;
  await name.fill(updated);
  await activate(dialog.getByRole('button', { name: 'Save', exact: true }));
  await dialog.waitFor({ state: 'detached' });
  assert.ok(await page.locator('.plan-card-title').filter({ hasText: updated }).count(), 'Save updates sprint');
  await activate(trigger);
  await page.keyboard.press('Escape');
  assert.equal(await page.getByRole('menu', { name: 'Sprint actions' }).count(), 0, 'Escape dismisses');
  await activate(trigger);
  await page.locator('.topbar').click({ position: { x: 5, y: 5 } });
  assert.equal(await page.getByRole('menu', { name: 'Sprint actions' }).count(), 0, 'Outside press dismisses');
  await activate(trigger);
  await page.locator('.ws-trigger').focus();
  assert.equal(await page.getByRole('menu', { name: 'Sprint actions' }).count(), 0, 'Focus outside dismisses');
  await activate(trigger);
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('ArrowUp');
  await page.keyboard.press('Enter');
  await dialog.waitFor();
  await activate(dialog.getByRole('button', { name: 'Cancel', exact: true }));
  assert.deepEqual(errors, []);
  console.log(`${touch ? 'Touch with Safari blur sequence' : 'Mouse'}: edit opens, saves, and menu dismisses`);
  await page.close();
 }
} finally { await browser.close(); }
