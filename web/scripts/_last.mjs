import { chromium } from 'playwright';
const OUT = '/tmp/claude-1000/-workspace/10436eb1-9c47-4f3b-a122-ca1c7d16cc5b/scratchpad';
const b = await chromium.launch({ args: ['--no-sandbox'] });
const p = await b.newPage({ viewport: { width: 1750, height: 1018 }, deviceScaleFactor: 2 });
const errs = []; p.on('pageerror', (e) => { console.log('PAGE ERROR:', e.message); errs.push(e.message); });
await p.goto('http://localhost:5199');
await p.waitForSelector('button.login-playground', { timeout: 20000 });
await p.click('button.login-playground');
await p.waitForSelector('.avatar', { timeout: 20000 });
await p.keyboard.press('p');
await p.waitForSelector('.plan-rows', { timeout: 20000 });
await p.waitForTimeout(500);

// ticking must not reorder
const card = p.locator('.plan-card:not(.plan-card-retro)').nth(1);
const before = await card.locator('.plan-task-title').allTextContents();
await card.locator('.plan-task').nth(1).locator('.plan-task-tick').click();
await p.waitForTimeout(500);
const after = await card.locator('.plan-task-title').allTextContents();
console.log('tick keeps order:', JSON.stringify(before) === JSON.stringify(after));
console.log('  ', JSON.stringify(after.map(t => t.slice(0, 12))));
await card.locator('.plan-task').nth(1).locator('.plan-task-tick').click();
await p.waitForTimeout(400);

// month labels float
await p.evaluate(() => { document.querySelector('.plan-scroll').scrollLeft += 260; });
await p.waitForTimeout(300);
console.log('visible month labels after scroll:', await p.evaluate(() => {
  const sl = document.querySelector('.plan-scroll').getBoundingClientRect();
  return [...document.querySelectorAll('.plan-month > span')]
    .filter((e) => { const r = e.getBoundingClientRect(); return r.left >= sl.left && r.right <= sl.right; })
    .map((e) => e.textContent.trim());
}));
await p.screenshot({ path: `${OUT}/last-axis.png`, clip: { x: 250, y: 74, width: 560, height: 60 } });
await p.locator('.plan-row').first().hover();
await p.waitForTimeout(250);
await p.screenshot({ path: `${OUT}/last-head.png`, clip: { x: 276, y: 126, width: 220, height: 200 } });
await p.locator('.plan-rail').screenshot({ path: `${OUT}/last-rail.png` });
await b.close();
console.log('page errors:', errs.length);
