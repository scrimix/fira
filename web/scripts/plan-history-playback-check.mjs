// Isolated timeline check with delayed snapshot responses; no backend writes.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';
const browser = await chromium.launch({ args: ['--no-sandbox'] });
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => localStorage.setItem('fira:playground', '1'));
  await page.goto(process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173');
  await page.locator('.sidebar').waitFor();
  await page.evaluate(async () => {
    const resources = performance.getEntriesByType('resource');
    const React = (await import(resources.find(e => e.name.includes('/deps/react.js')).name)).default;
    const { createRoot } = (await import(resources.find(e => e.name.includes('/deps/react-dom_client.js')).name)).default;
    const { PlanTimeline } = await import('/src/components/PlanTimeline.tsx');
    const history = { genesis: '2026-01-01T00:00:00Z', changes: [1, 2, 3].map(seq => ({
      at: `2026-01-0${seq}T00:00:00Z`, seq, count: 1, kind: 'sprint.set_dates',
    })) };
    window.playbackSelections = [];
    window.snapshotDelay = 200;
    function Harness() {
      const [selection, setSelection] = React.useState({ at: null, seq: null });
      const [loaded, setLoaded] = React.useState(null);
      const [error, setError] = React.useState(false);
      window.failPlayback = setError;
      React.useEffect(() => {
        if (selection.seq === null) return;
        const timer = setTimeout(() => setLoaded(selection.seq), window.snapshotDelay);
        return () => clearTimeout(timer);
      }, [selection.seq]);
      return React.createElement('div', { 'data-selected': selection.seq ?? 'live', 'data-loaded': loaded, id: 'playback-harness' },
        React.createElement(PlanTimeline, {
          history, selectedAt: selection.at, selectedSeq: selection.seq,
          onSelect: (at, seq = null) => { window.playbackSelections.push(seq); setSelection({ at, seq }); },
          playbackReady: selection.seq === null || selection.seq === loaded,
          playbackError: error, status: null,
        }));
    }
    const host = document.createElement('div');
    host.style.cssText = 'position:fixed;inset:0;z-index:900;background:var(--paper);padding:24px';
    document.body.append(host);
    createRoot(host).render(React.createElement(Harness));
  });
  const harness = page.locator('#playback-harness');
  const play = () => page.getByRole('button', { name: 'Play history', exact: true });
  const pause = () => page.getByRole('button', { name: 'Pause history', exact: true });
  const selected = seq => page.waitForFunction(seq => document.querySelector('#playback-harness').dataset.selected === String(seq), seq);
  async function chooseSpeed(value, target = page) {
    await target.getByRole('button', { name: 'Playback speed', exact: true }).click();
    await target.getByRole('option', { name: `${value}×`, exact: true }).click();
  }
  const dimensions = await page.locator('.plan-revision-toolbar').evaluate(toolbar => {
    const controls = toolbar.querySelectorAll('.week-nav, .plan-revision-picker .select-trigger');
    const button = toolbar.querySelector('.plan-revision-play');
    const icon = button.querySelector('svg').getBoundingClientRect();
    const label = button.querySelector('span').getBoundingClientRect();
    return { heights: [...controls].map(el => el.getBoundingClientRect().height), icon, label };
  });
  assert.equal(new Set(dimensions.heights).size, 1, 'History controls have a consistent height');
  assert.ok(dimensions.label.x >= dimensions.icon.right, 'Play icon and text stay on one line');
  await chooseSpeed('4');
  await play().click();
  await selected(1);
  await pause().click();
  await page.waitForTimeout(700);
  assert.equal(await harness.getAttribute('data-selected'), '1', 'Pause cancels advancement');
  await play().click();
  await selected(2);
  await page.getByRole('button', { name: 'Previous revision' }).click();
  await selected(1);
  assert.equal(await play().count(), 1, 'Manual navigation pauses playback');
  // A long snapshot request must never be skipped by the timer.
  await page.evaluate(() => { window.snapshotDelay = 1400; });
  await play().click();
  await selected(2);
  await page.waitForTimeout(800);
  assert.equal(await harness.getAttribute('data-selected'), '2', 'Playback waits for the snapshot');
  assert.equal(await harness.getAttribute('data-loaded'), '1');
  await pause().click();
  await page.waitForFunction(() => document.querySelector('#playback-harness').dataset.loaded === '2');
  // Changing speed during playback updates the viewing interval.
  await play().click();
  await chooseSpeed('0.5');
  await page.waitForTimeout(600);
  assert.equal(await harness.getAttribute('data-selected'), '2', 'Half speed gives a longer viewing interval');
  await chooseSpeed('4');
  await selected(3);
  await play().waitFor();
  assert.equal(await harness.getAttribute('data-selected'), '3', 'Playback stops at the final historical snapshot');
  await play().click();
  await selected(1);
  await page.evaluate(() => window.failPlayback(true));
  await play().waitFor();
  assert.equal(await play().isDisabled(), true, 'Snapshot errors stop playback');
  await page.evaluate(() => window.failPlayback(false));
  await play().click();
  await page.getByRole('button', { name: 'Revision', exact: true }).click();
  await page.getByRole('option', { name: 'Live plan', exact: true }).click();
  assert.equal(await play().count(), 1, 'Selecting Live stops playback');
  await play().click();
  await selected(1);
  await pause().click();
  assert.deepEqual(errors, []);
  // Exercise the real board's loading/ready handshake as well as the
  // isolated controls. Mock reads only; historical snapshots never write.
  const board = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const boardErrors = [];
  board.on('pageerror', error => boardErrors.push(error.message));
  await board.addInitScript(() => localStorage.setItem('fira:playground', '1'));
  await board.goto(process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173');
  await board.locator('.sidebar').waitFor();
  const fixture = await board.evaluate(async () => {
    const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
    const s = useFira.getState();
    const projectId = s.projects[0].id;
    return {
      projectId,
      tracks: s.tracks.filter(t => t.project_id === projectId),
      sprints: s.sprints.filter(t => t.project_id === projectId),
      tasks: s.tasks.filter(t => t.project_id === projectId),
    };
  });
  const revisions = [1, 2, 3].map(seq => ({ at: `2026-01-0${seq}T00:00:00Z`, seq, count: 1, kind: 'sprint.set_dates' }));
  const requested = [];
  await board.route('**/api/plan/history?**', route => route.fulfill({ json: { genesis: revisions[0].at, changes: revisions } }));
  await board.route('**/api/plan/at?**', async route => {
    const seq = Number(new URL(route.request().url()).searchParams.get('seq'));
    requested.push(seq);
    await new Promise(resolve => setTimeout(resolve, 400));
    await route.fulfill({ json: { ...fixture, at: revisions[seq - 1].at, genesis: revisions[0].at, revision: seq } });
  });
  await board.evaluate(async projectId => {
    const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
    useFira.getState().setProjectScope(projectId);
    // Keep account/sync effects isolated; only the board's history reads
    // are under test, using the mocked endpoints above.
    const idle = async () => {};
    useFira.setState({
      playgroundMode: false, view: 'plan', planShowHistory: true,
      rehydrate: idle, reloadWorkspaces: idle, reloadLinks: idle,
      reloadWorkspaceInvites: idle, checkBuildVersion: idle,
      loadPersonalCalendar: idle, loadWorkCalendar: idle, loadLinkedCalendar: idle,
      syncOutbox: idle, pollChanges: idle,
    });
  }, fixture.projectId);
  await board.getByRole('button', { name: 'Play history', exact: true }).waitFor({ timeout: 5000 });
  await chooseSpeed('4', board);
  await board.getByRole('button', { name: 'Play history', exact: true }).click();
  await board.locator('.plan-wrap[data-revision="3"][aria-busy="false"]').waitFor();
  await board.getByRole('button', { name: 'Play history', exact: true }).waitFor();
  assert.deepEqual(requested, [1, 2, 3], 'The real board loads every revision in order');
  assert.deepEqual(boardErrors, []);
  await board.screenshot({ path: '/tmp/plan-history-toolbar.png' });
  await board.evaluate(() => document.documentElement.dataset.style = 'modern');
  await board.screenshot({ path: '/tmp/plan-history-toolbar-modern.png' });
  await board.close();
  console.log('Passed: play from Live, pause/resume, speed changes, slow snapshots, manual navigation, replay, errors, and stopping at the end.');
} finally { await browser.close(); }
