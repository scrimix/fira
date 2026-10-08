import { chromium } from 'playwright';
const OUT = '/tmp/claude-1000/-workspace/10436eb1-9c47-4f3b-a122-ca1c7d16cc5b/scratchpad';
const b = await chromium.launch({ args: ['--no-sandbox'] });
const p = await b.newPage({ viewport: { width: 1750, height: 1018 }, deviceScaleFactor: 2 });
p.on('pageerror', (e) => console.log('PAGE ERROR:', e.message));
await p.goto('http://localhost:5199');
await p.waitForSelector('button.login-playground', { timeout: 20000 });
await p.click('button.login-playground');
await p.waitForSelector('.avatar', { timeout: 20000 });
await p.keyboard.press('p');
await p.waitForSelector('.plan-rows', { timeout: 20000 });
await p.waitForTimeout(500);
console.log(await p.evaluate(() => {
  const R = (s) => { const e = document.querySelector(s); if (!e) return null;
    const r = e.getBoundingClientRect();
    return { t: +r.top.toFixed(1), b: +r.bottom.toFixed(1), l: +r.left.toFixed(1), r: +r.right.toFixed(1) }; };
  const months = [...document.querySelectorAll('.plan-month')].map((e) => {
    const c = getComputedStyle(e); const r = e.getBoundingClientRect();
    return { txt: e.textContent.trim(), l: Math.round(r.left), t: +r.top.toFixed(1), b: +r.bottom.toFixed(1),
             bl: c.borderLeftWidth + ' ' + c.borderLeftColor };
  });
  return JSON.stringify({
    toolbar: R('.plan-toolbar'), body: R('.plan-body'), scroll: R('.plan-scroll'),
    axis: R('.plan-axis'), monthsRow: R('.plan-axis-months'), weeksRow: R('.plan-axis-weeks'),
    pad: R('.plan-axis-pad'), rail: R('.plan-rail'), railHead: R('.rail-head'),
    rows: R('.plan-rows'), lastRow: R('.plan-row:last-child'),
    months: months.slice(0, 5),
  }, null, 1);
}));
await p.screenshot({ path: `${OUT}/geo-axis.png`, clip: { x: 250, y: 74, width: 520, height: 64 } });
await p.screenshot({ path: `${OUT}/geo-seam.png`, clip: { x: 150, y: 120, width: 220, height: 440 } });
await b.close();
