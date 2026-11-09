// Run against `pnpm dev`: node scripts/project-members-check.mjs
// Uses fixture data and mocked HTTP; never writes to a backend.
import assert from 'node:assert/strict';
import { chromium } from 'playwright';

const browser = await chromium.launch({ args: ['--no-sandbox'] });
try {
  const page = await browser.newPage();
  page.setDefaultTimeout(10000);
  const errors = [];
  const requests = [];
  let fixture;
  let serverMembers;
  let failNext = false;
  page.on('pageerror', (error) => errors.push(error.message));
  await page.routeWebSocket('**/api/ws?**', () => {});
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (fixture && path.startsWith(`/api/projects/${fixture.projectId}/members`)) {
      requests.push({ method: request.method(), path, body: request.postData() });
      assert.equal(path, `/api/projects/${fixture.projectId}/members/${fixture.targetId}`);
      if (failNext) {
        failNext = false;
        return route.fulfill({ status: 403, json: { error: 'Removal denied' } });
      }
      if (request.method() === 'DELETE') {
        assert.equal(request.postData(), null, 'Removal sent a body');
        // Another editor added an unrelated member. The target command must
        // preserve that user even though this dialog has never seen them.
        serverMembers = [...serverMembers.filter((m) => m.user_id !== fixture.targetId), { user_id: fixture.extraId, role: 'member' }];
      } else if (request.method() === 'PUT') {
        assert.equal(request.postData(), null, 'Add sent a membership list');
        serverMembers.push({ user_id: fixture.targetId, role: 'member' });
      } else if (request.method() === 'PATCH') {
        assert.deepEqual(request.postDataJSON(), { role: 'dev' });
        serverMembers = serverMembers.map((m) => m.user_id === fixture.targetId ? { ...m, role: 'dev' } : m);
      } else {
        throw new Error(`Unexpected membership method: ${request.method()}`);
      }
      return route.fulfill({ json: serverMembers });
    }
    await route.fulfill({ status: 401, json: {} });
  });
  await page.goto(process.env.VISUAL_CHECK_URL ?? 'http://localhost:5173');
  await page.locator('button.login-playground').click();
  await page.waitForSelector('.avatar');
  fixture = await page.evaluate(async () => {
    const { useFira } = await import('/src/store/index.ts');
    const state = useFira.getState();
    const project = state.projects.find((p) => p.members.some((m) => m.role === 'lead') && p.members.length > 1);
    const lead = project.members.find((m) => m.role === 'lead');
    const target = project.members.find((m) => m.user_id !== lead.user_id);
    const extra = state.users.find((u) => !project.members.some((m) => m.user_id === u.id));
    // Keep unrelated wake/overlay fetches out of this HTTP fixture. Member
    // commands below still use the real store and API client.
    const background = Object.fromEntries([
      'rehydrate', 'reloadWorkspaces', 'reloadLinks', 'reloadWorkspaceInvites',
      'loadLinkedCalendar', 'loadPersonalCalendar', 'loadWorkCalendar',
      'checkBuildVersion', 'syncOutbox', 'pollChanges', 'loadAllUsers',
    ].map((key) => [key, async () => {}]));
    useFira.setState({ ...background, meId: lead.user_id, myWorkspaceRole: 'member', playgroundMode: false });
    useFira.getState().openEditProject(project.id);
    return { projectId: project.id, leadId: lead.user_id, targetId: target.user_id, extraId: extra.id,
      targetName: state.users.find((u) => u.id === target.user_id).name, members: project.members };
  });
  serverMembers = structuredClone(fixture.members);
  await page.waitForFunction(async () => {
    const { useFira } = await import('/src/store/index.ts');
    return useFira.getState().projectModal?.kind === 'edit';
  });
  assert.match(await page.locator('.np-member-owner').innerText(), /lead \(you\)/i);
  assert.equal(await page.locator(`.np-member[data-armed="${fixture.leadId}"]`).count(), 0);
  // A failed command must leave the displayed/store membership intact.
  failNext = true;
  const removeTarget = async () => {
    await page.getByRole('button', { name: `Remove ${fixture.targetName}`, exact: true }).click();
    await page.getByRole('button', { name: 'Remove', exact: true }).click();
    await page.waitForSelector('fieldset:not([disabled])');
  };
  await removeTarget();
  assert.equal(await page.getByRole('button', { name: `Remove ${fixture.targetName}`, exact: true }).count(), 1);
  await removeTarget();
  await page.waitForFunction(async ({ projectId, targetId, extraId }) => {
    const { useFira } = await import('/src/store/index.ts');
    const project = useFira.getState().projects.find((p) => p.id === projectId);
    return project && !project.members.some((m) => m.user_id === targetId) && project.members.some((m) => m.user_id === extraId);
  }, fixture);
  assert.match(await page.locator('.np-member-owner').innerText(), /lead \(you\)/i);
  await page.getByRole('button', { name: 'Add member', exact: true }).click();
  await page.locator('.np-members-candidates .user-row').filter({ hasText: fixture.targetName }).click();
  await page.waitForFunction(async ({ projectId, targetId }) => {
    const { useFira } = await import('/src/store/index.ts');
    return useFira.getState().projects.find((p) => p.id === projectId)?.members.some((m) => m.user_id === targetId);
  }, fixture);
  // Workspace-owner access also survives an implicit/missing self row.
  serverMembers = serverMembers.filter((m) => m.user_id !== fixture.leadId);
  await page.evaluate(async ({ projectId, targetId }) => {
    const { useFira } = await import('/src/store/index.ts');
    useFira.setState({ myWorkspaceRole: 'owner' });
    await useFira.getState().setProjectMemberRole(projectId, targetId, 'dev');
    if (!useFira.getState().projects.some((p) => p.id === projectId)) throw new Error('Workspace owner lost implicit project access');
  }, fixture);
  assert.deepEqual(requests.map((r) => r.method), ['DELETE', 'DELETE', 'PUT', 'PATCH']);
  assert(requests.slice(0, 3).every((r) => r.body === null));
  assert.deepEqual(errors, []);
  console.log('PASS: targeted DELETE/PUT/PATCH, no list bodies, failed removal preserves state, concurrent addition survives, lead retains access');
} finally {
  await browser.close();
}
