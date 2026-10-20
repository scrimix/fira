import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const browser = await chromium.launch({ args: ['--no-sandbox'] });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => localStorage.setItem('fira:playground', '1'));
  await page.goto(process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173');
  await page.locator('.sidebar').waitFor();
  const projects = await page.evaluate(async () => {
    const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
    window.scopeStore = useFira;
    return useFira.getState().projects.map(({ id, title }) => ({ id, title }));
  });
  assert.ok(projects.length > 1, 'Fixture needs multiple projects');
  const picker = page.locator('.project-scope .select-trigger');
  const nav = view => page.locator(`.sidebar .nav-btn[title="${view}"]`);
  async function pick(label) {
    await picker.click();
    await page.getByRole('option', { name: label, exact: true }).click();
    await page.waitForTimeout(50);
  }
  async function expectScope(project) {
    assert.equal(await picker.innerText(), project?.title ?? 'All projects');
    assert.equal(await page.evaluate(() => window.scopeStore.getState().projectScopeId), project?.id ?? null);
  }
  await nav('Calendar (G)').click();
  await pick(projects[1].title);
  const allProjects = page.locator('.sidebar .nav-proj[title="All projects"]');
  const allProjectsBox = await allProjects.boundingBox();
  const scopeBox = await page.locator('.project-scope').boundingBox();
  for (const view of ['Plan (P)', 'Dashboard (D)', 'Calendar (G)', 'List (I)']) {
    await nav(view).click();
    await expectScope(projects[1]);
    assert.equal(await allProjects.isVisible(), true, 'All projects icon stays visible');
    assert.equal(await allProjects.isDisabled(), view === 'List (I)', 'All projects is disabled only in List');
    const iconBox = await allProjects.boundingBox();
    assert.equal(iconBox.y, allProjectsBox.y, 'Sidebar project icons do not jump between views');
    const box = await page.locator('.project-scope').boundingBox();
    assert.equal(box.x, scopeBox.x, 'Scope stays in the same position');
    assert.equal(box.width, scopeBox.width, 'Scope width stays stable across views');
    if (view === 'Plan (P)') {
      const rowProjects = await page.locator('.plan-row').evaluateAll(rows => [...new Set(rows.map(r => r.dataset.project))]);
      assert.deepEqual(rowProjects, [projects[1].id], 'Plan content follows the shared project');
    }
    if (view === 'Calendar (G)') {
      const railProjects = await page.locator('.rail-group-head .pname').allTextContents();
      assert.ok(railProjects.every(title => title === projects[1].title), 'Calendar rail follows scope');
    }
  }
  assert.equal(await page.locator('.list-proj-head h1').innerText(), projects[1].title);
  assert.equal(await page.locator('.list-proj-head').count(), 1, 'List stays single-project');
  assert.equal(await picker.isDisabled(), true, 'List displays scope without allowing selection');
  await picker.click({ force: true });
  assert.equal(await page.getByRole('listbox').count(), 0, 'Read-only scope does not open a menu');
  await allProjects.click({ force: true });
  await expectScope(projects[1]);
  assert.equal(await page.locator('.list-proj-head').count(), 1, 'Disabled All icon cannot change List');
  await nav('Plan (P)').click();
  await allProjects.click();
  await expectScope(null);
  for (const view of ['Dashboard (D)', 'Calendar (G)', 'Plan (P)']) {
    await nav(view).click();
    await expectScope(null);
  }
  await nav('List (I)').click();
  assert.equal(await picker.innerText(), projects[1].title, 'All retains the last individual List project');
  assert.equal(await page.locator('.list-proj-head').count(), 1);
  await nav('Plan (P)').click();
  await expectScope(null);
  // Sidebar picking is consistent and never toggles off on a second click.
  const target = page.locator(`.sidebar .nav-proj[title="${projects[0].title}"]`);
  await target.click();
  await target.click();
  await expectScope(projects[0]);
  assert.equal(await target.getAttribute('aria-pressed'), 'true');
  await page.screenshot({ path: '/tmp/project-scope-plan.png' });
  // Refresh restores both All and individual scopes.
  for (const project of [projects[1], null]) {
    await pick(project?.title ?? 'All projects');
    await page.reload();
    await page.locator('.sidebar').waitFor();
    await page.evaluate(async () => {
      const { useFira } = await import(performance.getEntriesByType('resource').find(e => e.name.includes('/src/store/index.ts')).name);
      window.scopeStore = useFira;
    });
    await expectScope(project);
  }
  // The picker and account remain on screen on a small phone.
  await nav('Calendar (G)').click();
  await page.setViewportSize({ width: 390, height: 844 });
  for (const locator of [picker, page.getByRole('button', { name: 'Account settings' })]) {
    const box = await locator.boundingBox();
    assert.ok(box.x >= 0 && box.x + box.width <= 390, 'Header control fits on phone');
  }
  await pick(projects[1].title);
  await expectScope(projects[1]);
  await page.screenshot({ path: '/tmp/project-scope-mobile.png' });
  // Removing the selected project returns shared views to All, while
  // List falls back to another individual project.
  await page.evaluate(id => {
    window.scopeStore.getState().applyRemoteOp({
      op_id: crypto.randomUUID(), payload: { kind: 'project.delete', project_id: id },
    });
  }, projects[1].id);
  await expectScope(null);
  assert.notEqual(await page.evaluate(() => window.scopeStore.getState().listFilter.project_id), projects[1].id);
  assert.deepEqual(errors, []);
  console.log('Passed: shared scope across views, List exception, explicit All, repeated sidebar picks, refresh, phone header, and project removal.');
} finally {
  await browser.close();
}
