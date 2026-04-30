// Local-first store. Source of truth for the UI.
//
// Hydrate once on mount via `hydrate()` (calls /bootstrap). Reads are sync
// against this state. Writes mutate state immediately AND append to the outbox.
// Components never await network calls.

import { create } from 'zustand';
import type {
  Bootstrap, Project, User, Epic, Sprint, Task, TimeBlock, GcalEvent, UUID, Section, Subtask, Status,
} from '../types';
import { api, HttpError } from '../api';
import { newOp, type Op, type OpKind, type AnyOpKind, type ChangeEntry } from './outbox';

// Sync state machine. The TopBar pill reads this directly.
//   idle  — nothing queued, last attempt either succeeded or never ran
//   syncing — a request is in flight
//   error — last attempt failed; backoff is active until next retry
//   offline — request failed with a network error (distinguished so we can
//     show a different label and not pile up 'error' counts on transient
//     loss-of-connection)
export type SyncStatus =
  | { kind: 'idle' }
  | { kind: 'syncing' }
  | { kind: 'error'; message: string; failedOpIds: UUID[] }
  | { kind: 'offline'; message: string };

const SYNC_BATCH_SIZE = 50;

interface InboxFilter {
  project_id: UUID | null;
  epic_id: UUID | null;
  sprint_id: UUID | 'active' | 'all' | 'none';
  status: 'open' | 'all' | 'in_progress' | 'todo' | 'done';
  assignee_id: UUID | 'all' | null;
}

interface FiraState {
  // Tri-state: null = haven't checked yet, false = anonymous, true = authed.
  // The login screen renders only when this is exactly false.
  authChecked: boolean;
  loaded: boolean;
  error: string | null;

  users: User[];
  projects: Project[];
  epics: Epic[];
  sprints: Sprint[];
  tasks: Task[];
  blocks: TimeBlock[];
  gcal: GcalEvent[];

  outbox: Op[];
  syncStatus: SyncStatus;
  // Last successful sync wallclock time (ms since epoch), null if none yet.
  lastSyncedAt: number | null;

  // Change-feed state.
  // `cursor` is the highest server-side `seq` we've ingested. Polls send
  // it as `?since=cursor` and the server returns rows strictly after it.
  cursor: number;
  // `appliedOpIds` records op_ids this client already applied locally so
  // when the server echoes them back via /changes we skip re-applying.
  // Value is the wallclock timestamp at insertion — used for GC.
  appliedOpIds: Map<string, number>;

  // session
  meId: UUID | null;
  view: 'calendar' | 'inbox';
  // Pinned set of people the user can flip between, like browser tabs.
  selectedPersonIds: UUID[];
  // The currently-viewed person (must be in selectedPersonIds).
  activePersonId: UUID | null;
  // Offset in weeks from the seeded anchor week (0 = the seeded "this week").
  weekOffset: number;
  projectFilter: Record<UUID, boolean>;
  inboxFilter: InboxFilter;
  openTaskId: UUID | null;
  creatingDraft: { project_id: UUID | null; section: 'now' | 'later'; assignee_id: UUID | null } | null;
  // Discriminated union — one modal serves both create and edit. null = closed.
  projectModal: { kind: 'new' } | { kind: 'edit'; id: UUID } | null;

  hydrate: () => Promise<void>;
  logout: () => Promise<void>;
  // Drain the outbox once. Safe to call concurrently — re-entrant calls
  // bail out while a sync is in flight.
  syncOutbox: () => Promise<void>;
  // Pull change-feed rows since `cursor`, apply each through applyRemoteOp,
  // advance cursor.
  pollChanges: () => Promise<void>;
  // Apply a remote op — upsert-tolerant for create kinds so an echo of an
  // op the local client already created does nothing.
  applyRemoteOp: (entry: ChangeEntry) => void;
  setView: (v: 'calendar' | 'inbox', projectId?: UUID) => void;
  addPerson: (id: UUID) => void;
  removePerson: (id: UUID) => void;
  setActivePerson: (id: UUID) => void;
  setWeekOffset: (offset: number) => void;
  toggleProjectFilter: (id: UUID) => void;
  setInboxFilter: (patch: Partial<InboxFilter>) => void;
  openTask: (id: UUID | null) => void;
  openCreate: (initial?: Partial<{ project_id: UUID | null; section: 'now' | 'later'; assignee_id: UUID | null }>) => void;
  closeCreate: () => void;
  openCreateProject: () => void;
  openEditProject: (id: UUID) => void;
  closeProjectModal: () => void;
  addProject: (input: { title: string; icon: string; color: string }) => Promise<Project>;
  updateProject: (
    id: UUID,
    patch: Partial<{ title: string; icon: string; color: string }>,
  ) => Promise<Project>;
  // Member changes are their own op (`project.set_members`) — separate from
  // visual edits — so the apply path can treat removal-from-project as a
  // dedicated event and drop project state cleanly.
  setProjectMembers: (id: UUID, members: UUID[]) => Promise<Project>;
  // Pulls the full user directory and merges into `users` so the project
  // editor's Members picker can offer teammates the caller hasn't worked
  // with yet (bootstrap only includes co-members of in-scope projects).
  loadAllUsers: () => Promise<void>;

  // mutations — update local state synchronously + emit op
  addTask: (projectId: UUID, section: Section, title: string, assigneeId?: UUID | null) => UUID | null;
  tickTask: (taskId: UUID) => void;
  setTaskStatus: (taskId: UUID, status: Status) => void;
  setTaskSection: (taskId: UUID, section: Section) => void;
  setTaskAssignee: (taskId: UUID, assigneeId: UUID | null) => void;
  reorderTasks: (projectId: UUID, section: Section, orderedIds: UUID[]) => void;
  setTaskTitle: (taskId: UUID, title: string) => void;
  setTaskDescription: (taskId: UUID, description_md: string) => void;
  setTaskEstimate: (taskId: UUID, estimate_min: number | null) => void;
  addSubtask: (taskId: UUID, title: string) => UUID | null;
  tickSubtask: (taskId: UUID, subId: UUID) => void;
  setSubtaskTitle: (taskId: UUID, subId: UUID, title: string) => void;
  deleteSubtask: (taskId: UUID, subId: UUID) => void;
  upsertBlock: (block: TimeBlock) => void;
  updateBlock: (blockId: UUID, patch: Partial<TimeBlock>) => void;
  duplicateBlock: (blockId: UUID) => UUID | null;
  deleteBlock: (blockId: UUID) => void;
}

// Append a new op to the outbox AND record its op_id so when the server
// echoes it back via /changes we know to skip re-applying it.
function pushOp(s: FiraState, payload: OpKind): {
  outbox: Op[];
  appliedOpIds: Map<string, number>;
} {
  const op = newOp(payload);
  const next = new Map(s.appliedOpIds);
  next.set(op.op_id, Date.now());
  return { outbox: [...s.outbox, op], appliedOpIds: next };
}

// Older than this and we drop the entry — the change feed will have
// already passed by, so an echo can't reasonably arrive anymore.
const APPLIED_TTL_MS = 5 * 60 * 1000;

// Pure: produce a state delta from a remote op. Tolerant by design —
// applying the same op twice (echo + local) must be a no-op, and applying
// to deleted resources must not throw. Used by applyRemoteOp.
function applyOpToState(s: FiraState, op: AnyOpKind): Partial<FiraState> {
  switch (op.kind) {
    case 'task.create': {
      if (s.tasks.some((t) => t.id === op.task.id)) return {};
      return { tasks: [...s.tasks, op.task] };
    }
    case 'task.tick': {
      return {
        tasks: s.tasks.map((t) => t.id === op.task_id
          ? { ...t, status: op.done ? 'done' : 'in_progress' }
          : t),
      };
    }
    case 'task.set_status':
      return { tasks: s.tasks.map((t) => t.id === op.task_id ? { ...t, status: op.status } : t) };
    case 'task.set_section':
      return { tasks: s.tasks.map((t) => t.id === op.task_id ? { ...t, section: op.section } : t) };
    case 'task.set_assignee':
      return { tasks: s.tasks.map((t) => t.id === op.task_id ? { ...t, assignee_id: op.assignee_id } : t) };
    case 'task.set_estimate':
      return { tasks: s.tasks.map((t) => t.id === op.task_id ? { ...t, estimate_min: op.estimate_min } : t) };
    case 'task.set_title':
      return { tasks: s.tasks.map((t) => t.id === op.task_id ? { ...t, title: op.title } : t) };
    case 'task.set_description':
      return { tasks: s.tasks.map((t) => t.id === op.task_id ? { ...t, description_md: op.description_md } : t) };
    case 'task.reorder': {
      const newKeyById = new Map<string, string>();
      op.ordered.forEach((id, i) => {
        newKeyById.set(id, String((i + 1) * 1000).padStart(8, '0'));
      });
      return {
        tasks: s.tasks.map((t) => {
          const k = newKeyById.get(t.id);
          return k != null ? { ...t, sort_key: k } : t;
        }),
      };
    }
    case 'subtask.create': {
      const t = s.tasks.find((x) => x.id === op.subtask.task_id);
      if (!t) return {};
      if (t.subtasks.some((st) => st.id === op.subtask.id)) return {};
      return {
        tasks: s.tasks.map((x) => x.id === op.subtask.task_id
          ? { ...x, subtasks: [...x.subtasks, op.subtask] }
          : x),
      };
    }
    case 'subtask.tick':
      return {
        tasks: s.tasks.map((t) => ({
          ...t,
          subtasks: t.subtasks.map((st) => st.id === op.subtask_id ? { ...st, done: op.done } : st),
        })),
      };
    case 'subtask.set_title':
      return {
        tasks: s.tasks.map((t) => ({
          ...t,
          subtasks: t.subtasks.map((st) => st.id === op.subtask_id ? { ...st, title: op.title } : st),
        })),
      };
    case 'subtask.delete':
      return {
        tasks: s.tasks.map((t) => ({
          ...t,
          subtasks: t.subtasks.filter((st) => st.id !== op.subtask_id),
        })),
      };
    case 'block.create': {
      if (s.blocks.some((b) => b.id === op.block.id)) return {};
      return { blocks: [...s.blocks, op.block] };
    }
    case 'block.update':
      return { blocks: s.blocks.map((b) => b.id === op.block_id ? { ...b, ...op.patch } : b) };
    case 'block.delete':
      return { blocks: s.blocks.filter((b) => b.id !== op.block_id) };
    case 'project.create': {
      if (s.projects.some((p) => p.id === op.project.id)) return {};
      return {
        projects: [...s.projects, op.project].sort((a, b) => a.title.localeCompare(b.title)),
        projectFilter: { ...s.projectFilter, [op.project.id]: true },
      };
    }
    case 'project.update': {
      // Visual fields only — membership is handled by project.set_members.
      // Upsert: if the project isn't in our local list yet (e.g., we were
      // just added as a member), insert it. We rely on a follow-up
      // project.set_members op (or the initial bootstrap on next reload)
      // for the authoritative member list.
      const exists = s.projects.some((p) => p.id === op.project.id);
      const next = exists
        ? s.projects.map((p) => p.id === op.project.id ? op.project : p)
        : [...s.projects, op.project];
      return {
        projects: next.sort((a, b) => a.title.localeCompare(b.title)),
        projectFilter: exists
          ? s.projectFilter
          : { ...s.projectFilter, [op.project.id]: true },
      };
    }
    case 'project.set_members': {
      // If we're no longer in the member set, the owner removed us. The
      // change feed will deliver this op once and then fall silent for the
      // project — drop everything we have for it locally so the UI doesn't
      // linger on stale state.
      if (s.meId != null && !op.members.includes(s.meId)) {
        const droppedTaskIds = new Set(
          s.tasks.filter((t) => t.project_id === op.project_id).map((t) => t.id),
        );
        const { [op.project_id]: _drop, ...remainingFilter } = s.projectFilter;
        const nextProjects = s.projects.filter((p) => p.id !== op.project_id);
        const inboxFilter = s.inboxFilter.project_id === op.project_id
          ? { ...s.inboxFilter, project_id: nextProjects[0]?.id ?? null }
          : s.inboxFilter;
        return {
          projects: nextProjects,
          tasks: s.tasks.filter((t) => t.project_id !== op.project_id),
          epics: s.epics.filter((e) => e.project_id !== op.project_id),
          sprints: s.sprints.filter((sp) => sp.project_id !== op.project_id),
          blocks: s.blocks.filter((b) => !droppedTaskIds.has(b.task_id)),
          projectFilter: remainingFilter,
          inboxFilter,
          openTaskId: s.openTaskId && droppedTaskIds.has(s.openTaskId)
            ? null
            : s.openTaskId,
        };
      }
      // Still a member — just sync the member list.
      return {
        projects: s.projects.map((p) =>
          p.id === op.project_id ? { ...p, members: op.members } : p,
        ),
      };
    }
    default:
      return {};
  }
}

export const useFira = create<FiraState>((set, get) => ({
  authChecked: false,
  loaded: false,
  error: null,

  users: [],
  projects: [],
  epics: [],
  sprints: [],
  tasks: [],
  blocks: [],
  gcal: [],

  outbox: [],
  syncStatus: { kind: 'idle' },
  lastSyncedAt: null,
  cursor: 0,
  appliedOpIds: new Map(),

  meId: null,
  view: 'calendar',
  selectedPersonIds: [],
  activePersonId: null,
  weekOffset: 0,
  creatingDraft: null,
  projectModal: null,
  projectFilter: {},
  inboxFilter: {
    project_id: null,
    epic_id: null,
    sprint_id: 'active',
    status: 'open',
    assignee_id: null,
  },
  openTaskId: null,

  hydrate: async () => {
    try {
      const me: User = await api.me();
      const data: Bootstrap = await api.bootstrap();
      const projectFilter: Record<UUID, boolean> = {};
      data.projects.forEach((p) => { projectFilter[p.id] = true; });
      const firstProject = data.projects[0]?.id ?? null;
      set({
        authChecked: true,
        loaded: true,
        error: null,
        users: data.users,
        projects: data.projects,
        epics: data.epics,
        sprints: data.sprints,
        tasks: data.tasks,
        blocks: data.blocks,
        gcal: data.gcal,
        cursor: data.cursor ?? 0,
        meId: me.id,
        selectedPersonIds: [me.id],
        activePersonId: me.id,
        projectFilter,
        inboxFilter: {
          ...get().inboxFilter,
          project_id: firstProject,
          assignee_id: me.id,
        },
      });
    } catch (e) {
      // 401 from /me means "not logged in" — that's a normal state, not an
      // error. Anything else is a real failure.
      if (e instanceof HttpError && e.status === 401) {
        set({ authChecked: true, loaded: false, error: null, meId: null });
        return;
      }
      set({ authChecked: true, error: e instanceof Error ? e.message : String(e) });
    }
  },

  logout: async () => {
    try { await api.logout(); } catch { /* best-effort */ }
    // Hard reload so any in-memory state (outbox, modals) is dropped and the
    // next /me check decides what to render.
    window.location.assign('/');
  },

  syncOutbox: async () => {
    const { outbox, syncStatus } = get();
    if (syncStatus.kind === 'syncing') return;
    // Take the first batch of queued ops. Errored ops also re-enter this
    // pool — the user (or the next interval tick) gets to retry them.
    const batch = outbox.filter((o) => o.status !== 'syncing').slice(0, SYNC_BATCH_SIZE);
    if (batch.length === 0) return;

    const batchIds = new Set(batch.map((o) => o.op_id));
    set((s) => ({
      syncStatus: { kind: 'syncing' },
      outbox: s.outbox.map((o) => batchIds.has(o.op_id) ? { ...o, status: 'syncing' as const } : o),
    }));

    try {
      const { results } = await api.postOps(batch);
      const byId = new Map(results.map((r) => [r.op_id, r]));
      const errored: UUID[] = [];
      let firstError: string | null = null;
      set((s) => ({
        outbox: s.outbox
          // Drop ops the server accepted; keep + flag the ones it rejected.
          // Ops that weren't part of this batch pass through untouched.
          .map((o) => {
            const r = byId.get(o.op_id);
            if (!r) return o;
            if (r.status === 'ok') return null;
            errored.push(o.op_id);
            if (!firstError) firstError = r.error ?? 'unknown error';
            return { ...o, status: 'error' as const };
          })
          .filter((o): o is Op => o !== null),
      }));
      if (errored.length > 0) {
        set({
          syncStatus: { kind: 'error', message: firstError ?? 'sync error', failedOpIds: errored },
        });
      } else {
        set({ syncStatus: { kind: 'idle' }, lastSyncedAt: Date.now() });
      }
    } catch (e) {
      // Network / 5xx — put the batch back to 'queued' for the next tick.
      const msg = e instanceof Error ? e.message : String(e);
      set((s) => ({
        syncStatus: { kind: 'offline', message: msg },
        outbox: s.outbox.map((o) =>
          batchIds.has(o.op_id) ? { ...o, status: 'queued' as const } : o,
        ),
      }));
    }
  },

  pollChanges: async () => {
    const { cursor, appliedOpIds, applyRemoteOp } = get();
    let resp;
    try {
      resp = await api.getChanges(cursor);
    } catch {
      // Pull failures are silent — the existing syncStatus already reflects
      // server reachability through the push side.
      return;
    }
    for (const entry of resp.ops) {
      if (appliedOpIds.has(entry.op_id)) continue;
      applyRemoteOp(entry);
    }
    // GC: drop appliedOpIds entries older than the TTL. After this much
    // wallclock time, any echo that was going to come back already did.
    const now = Date.now();
    const trimmed = new Map(appliedOpIds);
    let didTrim = false;
    for (const [id, ts] of trimmed) {
      if (now - ts > APPLIED_TTL_MS) { trimmed.delete(id); didTrim = true; }
    }
    set({
      cursor: resp.cursor,
      appliedOpIds: didTrim ? trimmed : appliedOpIds,
    });
  },

  applyRemoteOp: (entry) => {
    // Dispatch on payload kind. Create kinds upsert (no-op if id exists),
    // update kinds patch in place, delete kinds tolerate the row being gone.
    const op = entry.payload as AnyOpKind;
    set((s) => applyOpToState(s, op));
    // Track that we now know about this op so a duplicate poll doesn't
    // re-apply it. (The outbox path already adds; this covers remote-origin.)
    set((s) => {
      const next = new Map(s.appliedOpIds);
      next.set(entry.op_id, Date.now());
      return { appliedOpIds: next };
    });
  },

  setView: (v, projectId) => set((s) => ({
    view: v,
    inboxFilter: projectId ? { ...s.inboxFilter, project_id: projectId } : s.inboxFilter,
  })),
  addPerson: (id) => set((s) => ({
    selectedPersonIds: s.selectedPersonIds.includes(id)
      ? s.selectedPersonIds
      : [...s.selectedPersonIds, id],
    activePersonId: id,
  })),
  removePerson: (id) => set((s) => {
    const next = s.selectedPersonIds.filter((x) => x !== id);
    let active = s.activePersonId;
    if (active === id) {
      // Fall back to the closest remaining person, preferring me.
      const idx = s.selectedPersonIds.indexOf(id);
      active = next[Math.min(idx, next.length - 1)]
        ?? (s.meId && next.includes(s.meId) ? s.meId : next[0] ?? null);
    }
    return { selectedPersonIds: next, activePersonId: active };
  }),
  setActivePerson: (id) => set((s) => ({
    activePersonId: id,
    selectedPersonIds: s.selectedPersonIds.includes(id)
      ? s.selectedPersonIds
      : [...s.selectedPersonIds, id],
  })),
  setWeekOffset: (offset) => set({ weekOffset: offset }),
  toggleProjectFilter: (id) => set((s) => ({
    projectFilter: { ...s.projectFilter, [id]: !(s.projectFilter[id] !== false) },
  })),
  setInboxFilter: (patch) => set((s) => ({ inboxFilter: { ...s.inboxFilter, ...patch } })),
  openTask: (id) => set({ openTaskId: id, creatingDraft: id ? null : get().creatingDraft }),
  openCreate: (initial) => set((s) => ({
    creatingDraft: {
      project_id: initial?.project_id ?? s.inboxFilter.project_id ?? s.projects[0]?.id ?? null,
      section: initial?.section ?? 'now',
      assignee_id: initial?.assignee_id ?? s.meId,
    },
    openTaskId: null,
  })),
  closeCreate: () => set({ creatingDraft: null }),
  openCreateProject: () => set({ projectModal: { kind: 'new' } }),
  openEditProject: (id) => set({ projectModal: { kind: 'edit', id } }),
  closeProjectModal: () => set({ projectModal: null }),

  addProject: async (input) => {
    // Project create is rare and deliberate — a synchronous round-trip is
    // fine and avoids the "appears in sidebar then vanishes on error" jank
    // that an outbox-style optimistic insert would cause.
    const project = await api.createProject(input);
    set((s) => ({
      projects: [...s.projects, project].sort((a, b) => a.title.localeCompare(b.title)),
      projectFilter: { ...s.projectFilter, [project.id]: true },
      // Switch into the new project's inbox so the user lands somewhere
      // useful instead of an empty calendar.
      view: 'inbox',
      inboxFilter: { ...s.inboxFilter, project_id: project.id },
      projectModal: null,
    }));
    return project;
  },

  updateProject: async (id, patch) => {
    const updated = await api.updateProject(id, patch);
    set((s) => ({
      projects: s.projects
        .map((p) => p.id === id ? updated : p)
        .sort((a, b) => a.title.localeCompare(b.title)),
    }));
    return updated;
  },

  setProjectMembers: async (id, members) => {
    const updated = await api.setProjectMembers(id, members);
    set((s) => ({
      projects: s.projects.map((p) => p.id === id ? updated : p),
    }));
    return updated;
  },

  loadAllUsers: async () => {
    const all = await api.listAllUsers();
    set((s) => {
      const byId = new Map(s.users.map((u) => [u.id, u]));
      for (const u of all) byId.set(u.id, u);
      return { users: Array.from(byId.values()).sort((a, b) => a.name.localeCompare(b.name)) };
    });
  },

  addTask: (projectId, section, title, assigneeId) => {
    const trimmed = title.trim();
    if (!trimmed) return null;
    const state = get();
    const project = state.projects.find((p) => p.id === projectId);
    if (!project) return null;
    const peers = state.tasks.filter((t) => t.project_id === projectId && t.section === section);
    const maxSort = peers.reduce((m, t) => (t.sort_key > m ? t.sort_key : m), '0');
    const newTask: Task = {
      id: crypto.randomUUID(),
      project_id: projectId,
      epic_id: null,
      sprint_id: null,
      assignee_id: assigneeId !== undefined ? assigneeId : state.meId,
      title: trimmed,
      description_md: '',
      section,
      status: section === 'done' ? 'done' : 'todo',
      priority: null,
      source: project.source,
      external_id: null,
      estimate_min: null,
      spent_min: 0,
      tags: [],
      sort_key: `${maxSort}~`,
      subtasks: [],
    };
    set((s) => ({
      tasks: [...s.tasks, newTask],
      ...pushOp(s, { kind: 'task.create', task: newTask }),
    }));
    return newTask.id;
  },

  tickTask: (taskId) => set((s) => {
    const t = s.tasks.find((x) => x.id === taskId);
    if (!t) return {};
    const nextStatus = t.status === 'done' ? 'in_progress' : 'done';
    const done = nextStatus === 'done';
    return {
      tasks: s.tasks.map((x) => x.id === taskId ? { ...x, status: nextStatus } : x),
      ...pushOp(s, { kind: 'task.tick', task_id: taskId, done }),
    };
  }),

  setTaskStatus: (taskId, status) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, status } : x),
    ...pushOp(s, { kind: 'task.set_status', task_id: taskId, status }),
  })),

  setTaskSection: (taskId, section) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, section } : x),
    ...pushOp(s, { kind: 'task.set_section', task_id: taskId, section }),
  })),

  setTaskAssignee: (taskId, assigneeId) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, assignee_id: assigneeId } : x),
    ...pushOp(s, { kind: 'task.set_assignee', task_id: taskId, assignee_id: assigneeId }),
  })),

  reorderTasks: (projectId, section, orderedIds) => set((s) => {
    // Re-number sort keys with wide spacing so future inserts can be done
    // without another full pass.
    const newKeyById = new Map<string, string>();
    orderedIds.forEach((id, i) => {
      newKeyById.set(id, String((i + 1) * 1000).padStart(8, '0'));
    });
    return {
      tasks: s.tasks.map((t) => {
        const k = newKeyById.get(t.id);
        return k != null ? { ...t, sort_key: k } : t;
      }),
      ...pushOp(s, { kind: 'task.reorder', project_id: projectId, section, ordered: orderedIds }),
    };
  }),

  setTaskTitle: (taskId, title) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, title } : x),
    ...pushOp(s, { kind: 'task.set_title', task_id: taskId, title }),
  })),

  setTaskDescription: (taskId, description_md) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, description_md } : x),
    ...pushOp(s, { kind: 'task.set_description', task_id: taskId, description_md }),
  })),

  setTaskEstimate: (taskId, estimate_min) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, estimate_min } : x),
    ...pushOp(s, { kind: 'task.set_estimate', task_id: taskId, estimate_min }),
  })),

  addSubtask: (taskId, title) => {
    const trimmed = title.trim();
    if (!trimmed) return null;
    const state = get();
    const task = state.tasks.find((t) => t.id === taskId);
    if (!task) return null;
    const maxSort = task.subtasks.reduce((m, s) => (s.sort_key > m ? s.sort_key : m), '0');
    const sub: Subtask = {
      id: crypto.randomUUID(),
      task_id: taskId,
      title: trimmed,
      done: false,
      sort_key: `${maxSort}~`,
    };
    set((s) => ({
      tasks: s.tasks.map((t) => t.id === taskId ? { ...t, subtasks: [...t.subtasks, sub] } : t),
      ...pushOp(s, { kind: 'subtask.create', subtask: sub }),
    }));
    return sub.id;
  },

  setSubtaskTitle: (taskId, subId, title) => set((s) => ({
    tasks: s.tasks.map((t) => t.id !== taskId ? t : {
      ...t,
      subtasks: t.subtasks.map((st) => st.id === subId ? { ...st, title } : st),
    }),
    ...pushOp(s, { kind: 'subtask.set_title', subtask_id: subId, title }),
  })),

  deleteSubtask: (taskId, subId) => set((s) => ({
    tasks: s.tasks.map((t) => t.id !== taskId ? t : {
      ...t,
      subtasks: t.subtasks.filter((st) => st.id !== subId),
    }),
    ...pushOp(s, { kind: 'subtask.delete', subtask_id: subId }),
  })),

  tickSubtask: (taskId, subId) => set((s) => {
    let nextDone = false;
    const tasks = s.tasks.map((t) => {
      if (t.id !== taskId) return t;
      return {
        ...t,
        subtasks: t.subtasks.map((st) => {
          if (st.id !== subId) return st;
          nextDone = !st.done;
          return { ...st, done: nextDone };
        }),
      };
    });
    return { tasks, ...pushOp(s, { kind: 'subtask.tick', subtask_id: subId, done: nextDone }) };
  }),

  upsertBlock: (block) => set((s) => {
    const exists = s.blocks.some((b) => b.id === block.id);
    return {
      blocks: exists ? s.blocks.map((b) => b.id === block.id ? block : b) : [...s.blocks, block],
      ...pushOp(s, { kind: 'block.create', block }),
    };
  }),

  updateBlock: (blockId, patch) => set((s) => ({
    blocks: s.blocks.map((b) => b.id === blockId ? { ...b, ...patch } : b),
    ...pushOp(s, { kind: 'block.update', block_id: blockId, patch }),
  })),

  duplicateBlock: (blockId) => {
    const orig = get().blocks.find((b) => b.id === blockId);
    if (!orig) return null;
    const startMs = Date.parse(orig.start_at);
    const endMs = Date.parse(orig.end_at);
    const dur = endMs - startMs;
    // Place duplicate immediately after the original. Clamp to end-of-day so
    // dragging across midnight doesn't blow past day 6.
    const dayMs = 24 * 60 * 60 * 1000;
    const dayStart = Math.floor(startMs / dayMs) * dayMs;
    const newStart = Math.min(startMs, dayStart + dayMs - dur);
    const newBlock: TimeBlock = {
      ...orig,
      id: crypto.randomUUID(),
      start_at: new Date(newStart).toISOString(),
      end_at: new Date(newStart + dur).toISOString(),
      state: 'planned',
    };
    set((s) => ({
      blocks: [...s.blocks, newBlock],
      ...pushOp(s, { kind: 'block.create', block: newBlock }),
    }));
    return newBlock.id;
  },

  deleteBlock: (blockId) => set((s) => ({
    blocks: s.blocks.filter((b) => b.id !== blockId),
    ...pushOp(s, { kind: 'block.delete', block_id: blockId }),
  })),
}));

// Selectors that components subscribe to. Putting these here keeps the
// component code uncluttered with `useFira((s) => ...)` boilerplate.
export const selectMe = (s: FiraState): User | null =>
  s.users.find((u) => u.id === s.meId) ?? null;
export const selectProject = (id: UUID | null) => (s: FiraState): Project | null =>
  id ? s.projects.find((p) => p.id === id) ?? null : null;
export const selectTasksForProject = (id: UUID | null) => (s: FiraState): Task[] =>
  id ? s.tasks.filter((t) => t.project_id === id) : [];
