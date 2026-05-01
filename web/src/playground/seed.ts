// Playground fixture data, browser-only.
//
// Mirrors the shape of a real /api/bootstrap response so the rest of the app
// can't tell the difference between "real workspace" and "playground." A
// trimmed-down port of `api/src/seed.rs` — same characters and projects, fewer
// tasks because we don't need the full benchmark surface here.
//
// IDs are minted with `crypto.randomUUID()` at first-enter and persisted via
// the zustand persist middleware. We don't need cross-session-stable IDs; the
// localStorage snapshot is the source of truth once the playground starts.
//
// All time block timestamps anchor to Monday 00:00 in the user's *local*
// timezone — same convention the calendar grid uses (web/src/time.ts) so the
// blocks land on the visible week.

import type {
  Bootstrap, Project, Epic, Sprint, Task, TimeBlock, GcalEvent, Subtask, User,
  WorkspaceRole,
} from '../types';

export interface PlaygroundSeed {
  bootstrap: Bootstrap;
  me: User;
  workspace: {
    id: string;
    title: string;
    is_personal: boolean;
    members: { user_id: string; role: WorkspaceRole }[];
  };
}

function localWeekStart(): number {
  const now = new Date();
  const dayFromMon = (now.getDay() + 6) % 7;
  return new Date(now.getFullYear(), now.getMonth(), now.getDate() - dayFromMon).getTime();
}

function ts(weekStartMs: number, day: number, startMin: number): string {
  return new Date(weekStartMs + day * 86_400_000 + startMin * 60_000).toISOString();
}

export function buildPlaygroundSeed(): PlaygroundSeed {
  const uid = () => crypto.randomUUID();

  // ---- Users ----
  const maya: User = { id: uid(), email: 'maya@fira.dev', name: 'Maya Chen',  initials: 'MC' };
  const anna: User = { id: uid(), email: 'anna@fira.dev', name: 'Anna Park',  initials: 'AP' };
  const bob:  User = { id: uid(), email: 'bob@fira.dev',  name: 'Bob Reyes',  initials: 'BR' };
  const jin:  User = { id: uid(), email: 'jin@fira.dev',  name: 'Jin Okafor', initials: 'JO' };
  const users = [maya, anna, bob, jin];

  // ---- Workspace (single team workspace, Maya as owner) ----
  const workspaceId = uid();
  const workspace = {
    id: workspaceId,
    title: 'Playground',
    is_personal: false,
    members: [
      { user_id: maya.id, role: 'owner'  as WorkspaceRole },
      { user_id: anna.id, role: 'member' as WorkspaceRole },
      { user_id: bob.id,  role: 'member' as WorkspaceRole },
      { user_id: jin.id,  role: 'member' as WorkspaceRole },
    ],
  };

  // ---- Projects ----
  const atlas: Project = {
    id: uid(), workspace_id: workspaceId,
    title: 'Atlas', icon: 'Compass', color: '#0F766E',
    source: 'jira', description: 'Core platform. Auth, billing, infra.',
    external_url_template: null,
    members: [
      { user_id: maya.id, role: 'lead' },
      { user_id: anna.id, role: 'lead' },
      { user_id: bob.id,  role: 'member' },
    ],
  };
  const relay: Project = {
    id: uid(), workspace_id: workspaceId,
    title: 'Relay', icon: 'Zap', color: '#B45309',
    source: 'notion', description: 'Internal tooling — sync engine.',
    external_url_template: null,
    members: [
      { user_id: maya.id, role: 'lead' },
      { user_id: jin.id,  role: 'member' },
    ],
  };
  const helix: Project = {
    id: uid(), workspace_id: workspaceId,
    title: 'Helix', icon: 'Sparkles', color: '#6D28D9',
    source: 'local', description: 'Personal R&D — embedding experiments.',
    external_url_template: null,
    members: [
      { user_id: maya.id, role: 'lead' },
    ],
  };
  const projects = [atlas, relay, helix];

  // ---- Epics ----
  const eAuth:    Epic = { id: uid(), project_id: atlas.id, title: 'Auth v2 (refresh + SSO)' };
  const ePerf:    Epic = { id: uid(), project_id: atlas.id, title: 'Perf + observability' };
  const eSync:    Epic = { id: uid(), project_id: relay.id, title: 'Sync engine v1' };
  const eOnboard: Epic = { id: uid(), project_id: relay.id, title: 'Source onboarding' };
  const eSearch:  Epic = { id: uid(), project_id: helix.id, title: 'Semantic task search' };
  const epics = [eAuth, ePerf, eSync, eOnboard, eSearch];

  // ---- Sprints ----
  const sAtlas:    Sprint = { id: uid(), project_id: atlas.id, title: 'Atlas · current',  dates: 'this week',  active: true };
  const sRelay:    Sprint = { id: uid(), project_id: relay.id, title: 'Relay · Sprint 9', dates: 'this week',  active: true };
  const sHelixQ2:  Sprint = { id: uid(), project_id: helix.id, title: 'Helix · Q2',       dates: 'Q2',         active: true };
  const sprints = [sAtlas, sRelay, sHelixQ2];

  // ---- Tasks ----
  // Subtask helper.
  let subKey = 0;
  const subs = (taskId: string, list: [string, boolean][]): Subtask[] =>
    list.map(([title, done], i) => ({
      id: uid(), task_id: taskId, title, done,
      sort_key: `M${String(i).padStart(3, '0')}`,
    })).map((s) => ({ ...s, sort_key: `M${String(subKey++).padStart(3, '0')}` }));

  const mkTask = (over: Partial<Task> & Pick<Task, 'project_id' | 'title' | 'section' | 'status'>): Task => {
    const id = uid();
    return {
      id,
      project_id: over.project_id,
      epic_id: over.epic_id ?? null,
      sprint_id: over.sprint_id ?? null,
      assignee_id: over.assignee_id ?? null,
      title: over.title,
      description_md: over.description_md ?? '',
      section: over.section,
      status: over.status,
      priority: over.priority ?? null,
      source: over.source ?? 'local',
      external_id: over.external_id ?? null,
      external_url: over.external_url ?? null,
      estimate_min: over.estimate_min ?? null,
      spent_min: over.spent_min ?? 0,
      tags: over.tags ?? [],
      sort_key: over.sort_key ?? `M${String(subKey++).padStart(3, '0')}`,
      subtasks: over.subtasks ?? [],
    };
  };

  const tAtlasOauth = mkTask({
    project_id: atlas.id, epic_id: eAuth.id, sprint_id: sAtlas.id, assignee_id: maya.id,
    title: 'OAuth refresh token rotation',
    description_md: 'Rotate refresh tokens on every use. Invalidate the old token within a 30-second grace window.\n\nFollow RFC 6749 §10.4 + §6 recommendations.',
    section: 'now', status: 'in_progress', priority: 'p1',
    source: 'jira', external_id: 'ATL-412',
    estimate_min: 360, spent_min: 120, tags: ['auth', 'security'],
  });
  tAtlasOauth.subtasks = subs(tAtlasOauth.id, [
    ['Audit current refresh logic', true],
    ['Add rotation endpoint', true],
    ['Migrate existing tokens', false],
    ['Backfill metrics dashboard', false],
  ]);

  const tAtlasReview = mkTask({
    project_id: atlas.id, epic_id: ePerf.id, sprint_id: sAtlas.id, assignee_id: maya.id,
    title: 'Code review: rate-limit middleware',
    description_md: "Bob's PR. Token bucket per IP + per user. Check the redis fallback.",
    section: 'now', status: 'todo', priority: 'p2',
    source: 'jira', external_id: 'ATL-440',
    estimate_min: 60,
  });

  const tAtlasPerf = mkTask({
    project_id: atlas.id, epic_id: ePerf.id, sprint_id: sAtlas.id, assignee_id: bob.id,
    title: 'Investigate p99 spike on /sessions',
    description_md: 'p99 went from 80ms → 320ms after the auth refactor merge. Bisect commits.',
    section: 'now', status: 'in_progress', priority: 'p0',
    source: 'jira', external_id: 'ATL-449',
    estimate_min: 240, spent_min: 60, tags: ['perf'],
  });

  const tRelayJira = mkTask({
    project_id: relay.id, epic_id: eSync.id, sprint_id: sRelay.id, assignee_id: maya.id,
    title: 'Jira webhook → task upsert',
    description_md: 'Receive Jira webhook, debounce 500ms, upsert task by external_id.',
    section: 'now', status: 'in_progress', priority: 'p1',
    source: 'notion', external_id: 'sync-engine/47',
    estimate_min: 300, spent_min: 90, tags: ['sync'],
  });
  tRelayJira.subtasks = subs(tRelayJira.id, [
    ['Webhook signature verification', true],
    ['Debounce queue', false],
    ['Conflict detection', false],
  ]);

  const tRelayNotion = mkTask({
    project_id: relay.id, epic_id: eOnboard.id, sprint_id: sRelay.id, assignee_id: jin.id,
    title: 'Notion column-mapping flow',
    section: 'now', status: 'todo', priority: 'p1',
    source: 'notion', external_id: 'sync-engine/55',
    estimate_min: 360,
  });

  const tHelixEmb = mkTask({
    project_id: helix.id, epic_id: eSearch.id, sprint_id: sHelixQ2.id, assignee_id: maya.id,
    title: 'Sentence embeddings for task search',
    description_md: 'Try bge-small + qdrant, measure recall@10 on held-out set.',
    section: 'now', status: 'in_progress', priority: 'p2',
    source: 'local',
    estimate_min: 240, spent_min: 30, tags: ['research'],
  });
  tHelixEmb.subtasks = subs(tHelixEmb.id, [
    ['Spin up qdrant locally', true],
    ['Index 1k sample tasks', false],
    ['Build held-out eval', false],
  ]);

  // A couple of LATER + DONE tasks so the inbox doesn't look empty in those
  // sections.
  const tAtlasLater = mkTask({
    project_id: atlas.id, epic_id: eAuth.id, assignee_id: maya.id,
    title: 'Magic-link auth fallback',
    section: 'later', status: 'backlog', priority: 'p2',
    source: 'jira', external_id: 'ATL-501',
  });
  const tHelixLater = mkTask({
    project_id: helix.id, assignee_id: maya.id,
    title: 'Try DuckDB for snapshot replay queries',
    section: 'later', status: 'backlog', priority: 'p3',
    source: 'local',
  });
  const tAtlasDone = mkTask({
    project_id: atlas.id, epic_id: eAuth.id, sprint_id: sAtlas.id, assignee_id: maya.id,
    title: 'Migrate session store to Redis 7',
    section: 'done', status: 'done',
    source: 'jira', external_id: 'ATL-401',
    estimate_min: 240, spent_min: 280,
  });

  const tasks = [
    tAtlasOauth, tAtlasReview, tAtlasPerf,
    tRelayJira, tRelayNotion,
    tHelixEmb,
    tAtlasLater, tHelixLater, tAtlasDone,
  ];

  // ---- Time blocks (Maya's calendar this week) ----
  const ws = localWeekStart();
  const now = Date.now();
  const stateFor = (endMs: number) => endMs <= now ? ('completed' as const) : ('planned' as const);
  const block = (day: number, startMin: number, durMin: number, taskId: string): TimeBlock => {
    const start_at = ts(ws, day, startMin);
    const end_at = ts(ws, day, startMin + durMin);
    return {
      id: uid(),
      task_id: taskId,
      user_id: maya.id,
      start_at,
      end_at,
      state: stateFor(Date.parse(end_at)),
    };
  };
  const blocks: TimeBlock[] = [
    // Mon
    block(0, 9 * 60,           90,  tAtlasOauth.id),
    block(0, 10 * 60 + 30,     60,  tAtlasReview.id),
    block(0, 13 * 60,         120,  tRelayJira.id),
    // Tue
    block(1, 9 * 60,          120,  tAtlasOauth.id),
    block(1, 11 * 60 + 30,     90,  tHelixEmb.id),
    block(1, 14 * 60,          90,  tRelayJira.id),
    // Wed
    block(2, 9 * 60,           90,  tAtlasOauth.id),
    block(2, 13 * 60,          90,  tRelayJira.id),
    block(2, 15 * 60,          90,  tHelixEmb.id),
    // Thu
    block(3, 9 * 60,          120,  tAtlasOauth.id),
    block(3, 13 * 60,          90,  tRelayJira.id),
    // Fri
    block(4, 9 * 60,           90,  tAtlasReview.id),
    block(4, 13 * 60,         120,  tHelixEmb.id),
  ];

  // ---- GCal events (background "external" obligations on Maya's calendar) ----
  const gcal: GcalEvent[] = [
    { id: uid(), user_id: maya.id, title: '1:1 with Anna',    start_at: ts(ws, 0, 11 * 60 + 30), end_at: ts(ws, 0, 12 * 60) },
    { id: uid(), user_id: maya.id, title: 'Atlas standup',    start_at: ts(ws, 1, 13 * 60),       end_at: ts(ws, 1, 14 * 60) },
    { id: uid(), user_id: maya.id, title: 'Standup',          start_at: ts(ws, 2, 10 * 60 + 30), end_at: ts(ws, 2, 11 * 60) },
    { id: uid(), user_id: maya.id, title: 'Design review',    start_at: ts(ws, 2, 14 * 60 + 30), end_at: ts(ws, 2, 15 * 60) },
    { id: uid(), user_id: maya.id, title: 'Atlas standup',    start_at: ts(ws, 3, 13 * 60),       end_at: ts(ws, 3, 14 * 60) },
    { id: uid(), user_id: maya.id, title: 'Demo prep',        start_at: ts(ws, 4, 11 * 60 + 30), end_at: ts(ws, 4, 12 * 60) },
  ];

  return {
    bootstrap: {
      users,
      projects,
      epics,
      sprints,
      tasks,
      blocks,
      gcal,
      cursor: 0,
    },
    me: maya,
    workspace,
  };
}
