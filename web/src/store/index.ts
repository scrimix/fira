// Local-first store. Source of truth for the UI.
//
// Hydrate once on mount via `hydrate()` (calls /bootstrap). Reads are sync
// against this state. Writes mutate state immediately AND append to the outbox.
// Components never await network calls.

import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import type {
  Bootstrap, Project, User, Epic, Sprint, Task, TimeBlock, GcalEvent, UUID, Section, Subtask, Status,
  Workspace, WorkspaceRole, UserLink, LinkedTask,
} from '../types';
import { api, HttpError, setActiveWorkspaceId } from '../api';
import { newOp, type Op, type OpKind, type AnyOpKind, type ChangeEntry } from './outbox';
import {
  clearPlayground, isPlayground, loadPlaygroundSnapshot, markPlayground,
} from '../playground';
import { setFrozenNow } from '../time';

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

export type ToastKind = 'error' | 'info';
export interface Toast {
  id: string;
  kind: ToastKind;
  message: string;
}

interface FiraState {
  // Tri-state: null = haven't checked yet, false = anonymous, true = authed.
  // The login screen renders only when this is exactly false.
  authChecked: boolean;
  loaded: boolean;
  error: string | null;
  // True when the app is running against the in-memory playground seed
  // instead of a real backend. Gates network calls everywhere.
  playgroundMode: boolean;

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
  workspaces: Workspace[];
  // Active workspace id. Null only briefly between login and bootstrap;
  // every signed-in user always has at least their personal workspace.
  activeWorkspaceId: UUID | null;
  // The caller's role in the active workspace — drives UI gating.
  myWorkspaceRole: WorkspaceRole | null;
  workspaceModal: { kind: 'new' } | { kind: 'edit'; id: UUID } | null;
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
  creatingDraft: {
    project_id: UUID | null;
    section: 'now' | 'later';
    assignee_id: UUID | null;
    // Optional pending time-block — set when the draft was opened by
    // dragging on the calendar. Submit creates the task AND a block; cancel
    // creates neither (the drag rendered a ghost only).
    block?: { start_at: string; end_at: string; user_id: UUID } | null;
  } | null;
  // Account-link state. `links` holds every link involving me (pending
  // sent / received / accepted). The overlay (linkedBlocks/Tasks/Gcal)
  // is the partner's read-only calendar projection — fetched separately
  // because it crosses workspace boundaries that bootstrap doesn't.
  links: UserLink[];
  linkedBlocks: TimeBlock[];
  linkedTasks: LinkedTask[];
  linkedGcal: GcalEvent[];
  // Calendar toggle: render the partner's blocks alongside mine. Off by
  // default — the user opts in once they've linked.
  showLinked: boolean;
  linkModalOpen: boolean;
  // Discriminated union — one modal serves both create and edit. null = closed.
  projectModal: { kind: 'new' } | { kind: 'edit'; id: UUID } | null;
  // Transient notifications. Auto-dismissed after a few seconds; the user
  // can also click to dismiss. Mostly used for surfacing API errors that
  // happen outside the request flow of an open modal.
  toasts: Toast[];

  hydrate: () => Promise<void>;
  enterPlayground: () => void;
  logout: () => Promise<void>;
  switchWorkspace: (id: UUID) => Promise<void>;
  // Pull listMyWorkspaces and reconcile against local state. Called on a
  // user-channel WS nudge after any membership/role/title/delete change.
  reloadWorkspaces: () => Promise<void>;
  createWorkspace: (title: string) => Promise<Workspace>;
  renameWorkspace: (id: UUID, title: string) => Promise<Workspace>;
  setWorkspaceMembers: (
    id: UUID,
    members: { user_id: UUID; role: WorkspaceRole }[],
  ) => Promise<Workspace>;
  setWorkspaceMemberRole: (id: UUID, userId: UUID, role: WorkspaceRole) => Promise<Workspace>;
  deleteWorkspace: (id: UUID) => Promise<void>;
  loadWorkspaceUsers: (id: UUID) => Promise<void>;
  openCreateWorkspace: () => void;
  openEditWorkspace: (id: UUID) => void;
  closeWorkspaceModal: () => void;
  // Drain the outbox once. Safe to call concurrently — re-entrant calls
  // bail out while a sync is in flight.
  syncOutbox: () => Promise<void>;
  // Pull change-feed rows since `cursor`, apply each through applyRemoteOp,
  // advance cursor.
  pollChanges: () => Promise<void>;
  // Move an errored op back to 'queued' so the next syncOutbox tick
  // picks it up. Useful when the server-side validation is fixed (e.g.
  // the user edited the URL template after a malformed value 400'd).
  retryOp: (op_id: UUID) => void;
  // Drop an errored op from the outbox without sending it. The local
  // mutation already happened — the user accepts that the server will
  // never know about it. Used when the server permanently rejects an op.
  discardOp: (op_id: UUID) => void;
  // Bulk retry / discard for the failed-ops popover.
  retryAllFailed: () => void;
  discardAllFailed: () => void;
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
  openCreate: (initial?: Partial<{
    project_id: UUID | null;
    section: 'now' | 'later';
    assignee_id: UUID | null;
    block: { start_at: string; end_at: string; user_id: UUID } | null;
  }>) => void;
  closeCreate: () => void;
  openCreateProject: () => void;
  openEditProject: (id: UUID) => void;
  closeProjectModal: () => void;
  showToast: (message: string, kind?: ToastKind) => void;
  reloadLinks: () => Promise<void>;
  requestLink: (email: string) => Promise<void>;
  acceptLink: (id: UUID) => Promise<void>;
  cancelLink: (id: UUID) => Promise<void>;
  loadLinkedCalendar: () => Promise<void>;
  setShowLinked: (v: boolean) => void;
  openLinkModal: () => void;
  closeLinkModal: () => void;
  dismissToast: (id: string) => void;
  addProject: (input: { title: string; icon: string; color: string }) => Promise<Project>;
  updateProject: (
    id: UUID,
    patch: Partial<{
      title: string;
      icon: string;
      color: string;
      external_url_template: string | null;
    }>,
  ) => Promise<Project>;
  // Member changes are their own op (`project.set_members`) — separate from
  // visual edits — so the apply path can treat removal-from-project as a
  // dedicated event and drop project state cleanly.
  setProjectMembers: (
    id: UUID,
    members: { user_id: UUID; role: import('../types').ProjectRole }[],
  ) => Promise<Project>;
  deleteProject: (id: UUID) => Promise<void>;
  // Pulls the active workspace's directory and merges into `users` so the
  // project editor's Members picker can offer teammates the caller hasn't
  // worked with yet (bootstrap only includes workspace + project members).
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
  setTaskExternalId: (taskId: UUID, external_id: string | null) => void;
  setTaskExternalUrl: (taskId: UUID, external_url: string | null) => void;
  deleteTask: (taskId: UUID) => void;
  addSubtask: (taskId: UUID, title: string) => UUID | null;
  tickSubtask: (taskId: UUID, subId: UUID) => void;
  setSubtaskTitle: (taskId: UUID, subId: UUID, title: string) => void;
  deleteSubtask: (taskId: UUID, subId: UUID) => void;
  reorderSubtasks: (taskId: UUID, orderedIds: UUID[]) => void;
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

// Called after the user resolves a failed op (discard / retry-success). If
// the outbox is now empty, re-bootstrap so the local state matches what's
// actually on the server. Discards leave behind local mutations the server
// never saw — phantom tasks/edits — and a fresh /bootstrap is the cheapest
// way to reset to ground truth.
function resyncIfDrained(get: () => FiraState) {
  if (get().outbox.length === 0) {
    void get().hydrate();
  }
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
    case 'task.set_external_id':
      return { tasks: s.tasks.map((t) => t.id === op.task_id ? { ...t, external_id: op.external_id } : t) };
    case 'task.set_external_url':
      return { tasks: s.tasks.map((t) => t.id === op.task_id ? { ...t, external_url: op.external_url } : t) };
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
    case 'task.delete': {
      return {
        tasks: s.tasks.filter((t) => t.id !== op.task_id),
        blocks: s.blocks.filter((b) => b.task_id !== op.task_id),
        openTaskId: s.openTaskId === op.task_id ? null : s.openTaskId,
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
    case 'subtask.reorder':
      return {
        tasks: s.tasks.map((t) => {
          if (t.id !== op.task_id) return t;
          const byId = new Map(t.subtasks.map((st) => [st.id, st]));
          const reordered = op.ordered
            .map((id, i) => {
              const existing = byId.get(id);
              if (!existing) return null;
              byId.delete(id);
              return { ...existing, sort_key: `M${String(i).padStart(3, '0')}` };
            })
            .filter((x): x is NonNullable<typeof x> => x != null);
          // Append any subtasks the caller didn't include (defensive against
          // a stale ordered list racing with a concurrent subtask.create).
          const tail = Array.from(byId.values());
          return { ...t, subtasks: [...reordered, ...tail] };
        }),
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
      if (s.meId != null && !op.members.some((m) => m.user_id === s.meId)) {
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
    case 'project.delete': {
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
        projectModal: s.projectModal && s.projectModal.kind === 'edit' && s.projectModal.id === op.project_id
          ? null
          : s.projectModal,
      };
    }
    default:
      return {};
  }
}

// JSON can't round-trip a Map (we use one for appliedOpIds), so the
// persisted form tags it and the reviver rebuilds it on load.
const replacer = (_k: string, v: unknown) =>
  v instanceof Map
    ? { __type: 'Map', entries: Array.from(v.entries()) }
    : v;
const reviver = (_k: string, v: unknown) => {
  if (v && typeof v === 'object' && (v as { __type?: string }).__type === 'Map') {
    return new Map((v as { entries: [string, number][] }).entries);
  }
  return v;
};

/// Apply a fresh bootstrap response (real or playground) into the store.
/// Called from both hydrate paths so the bootstrap → state derivation
/// (projectFilter init, inboxFilter defaults, view selection by project
/// count, role lookup) lives in one place.
function applyBootstrap(
  set: (partial: Partial<FiraState>) => void,
  get: () => FiraState,
  data: Bootstrap,
  me: User,
  active: Workspace,
  workspaces: Workspace[],
  playground: boolean,
): void {
  const projectFilter: Record<UUID, boolean> = {};
  data.projects.forEach((p) => { projectFilter[p.id] = true; });
  const firstProject = data.projects[0]?.id ?? null;
  const myMember = active.members.find((m) => m.user_id === me.id);
  set({
    authChecked: true,
    loaded: true,
    error: null,
    playgroundMode: playground,
    users: data.users,
    projects: data.projects,
    epics: data.epics,
    sprints: data.sprints,
    tasks: data.tasks,
    blocks: data.blocks,
    gcal: data.gcal,
    links: data.links ?? [],
    cursor: data.cursor ?? 0,
    appliedOpIds: new Map(),
    outbox: [],
    meId: me.id,
    workspaces,
    activeWorkspaceId: active.id,
    myWorkspaceRole: (myMember?.role ?? 'member') as WorkspaceRole,
    selectedPersonIds: [me.id],
    activePersonId: me.id,
    projectFilter,
    inboxFilter: {
      ...get().inboxFilter,
      project_id: firstProject,
      assignee_id: me.id,
    },
    // Empty workspace lands on inbox: that view's empty state has the
    // owner-aware "Create your first project" / "ask an admin" CTA.
    // Calendar can't usefully render with zero projects.
    view: data.projects.length === 0 ? 'inbox' : 'calendar',
  });
}

export const useFira = create<FiraState>()(persist((set, get) => ({
  authChecked: false,
  loaded: false,
  error: null,
  playgroundMode: false,

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
  workspaces: [],
  activeWorkspaceId: null,
  myWorkspaceRole: null,
  workspaceModal: null,
  links: [],
  linkedBlocks: [],
  linkedTasks: [],
  linkedGcal: [],
  showLinked: false,
  linkModalOpen: false,
  view: 'calendar',
  selectedPersonIds: [],
  activePersonId: null,
  weekOffset: 0,
  creatingDraft: null,
  projectModal: null,
  toasts: [],
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
    // Playground reads its bootstrap from the bundled snapshot JSON; real
    // auth fetches from /api/bootstrap. From there the two flows feed
    // identical state shape into `applyBootstrap`, so every downstream
    // component sees the same kind of data regardless of source.
    if (isPlayground()) {
      markPlayground();
      const snap = loadPlaygroundSnapshot();
      // Freeze "now" to the snapshot timestamp BEFORE applying state, so
      // the calendar's first render aligns with the snapshot's week.
      setFrozenNow(snap.snapshot_at);
      setActiveWorkspaceId(snap.workspace.id);
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('fira:activeWorkspace', snap.workspace.id);
      }
      applyBootstrap(set, get, snap.bootstrap, snap.me, snap.workspace, [snap.workspace], true);
      return;
    }
    setFrozenNow(null);
    try {
      const me: User = await api.me();
      const workspaces = await api.listMyWorkspaces();
      // Last-active workspace is sticky across reloads via localStorage; falls
      // back to personal if the persisted one disappears (rare, e.g. removed).
      const persisted = typeof localStorage !== 'undefined'
        ? localStorage.getItem('fira:activeWorkspace')
        : null;
      const fallback = workspaces.find((w) => w.is_personal) ?? workspaces[0];
      const active = workspaces.find((w) => w.id === persisted) ?? fallback;
      if (!active) {
        // Should never happen — every user has a personal workspace.
        set({ authChecked: true, error: 'No workspace available' });
        return;
      }
      setActiveWorkspaceId(active.id);
      const data: Bootstrap = await api.bootstrap();
      applyBootstrap(set, get, data, me, active, workspaces, false);
    } catch (e) {
      // 401 from /me means the session expired — drop cached data and
      // bounce to login. Anything else (network error, 5xx) is treated as
      // offline: if we have cached state from a previous session we boot
      // into offline mode so the user can keep working until connectivity
      // returns. The 2 s ticker keeps trying syncOutbox() / pollChanges()
      // in the background, so reconnection is automatic.
      if (e instanceof HttpError && e.status === 401) {
        set({
          authChecked: true,
          loaded: false,
          error: null,
          meId: null,
          users: [], projects: [], epics: [], sprints: [], tasks: [], blocks: [], gcal: [],
          workspaces: [], activeWorkspaceId: null, myWorkspaceRole: null,
          outbox: [], cursor: 0, appliedOpIds: new Map(),
        });
        return;
      }
      const cached = get();
      if (cached.meId && cached.activeWorkspaceId && cached.projects.length >= 0) {
        // We have a usable cache. Render the app with whatever was
        // persisted; show the offline state in the sync pill.
        setActiveWorkspaceId(cached.activeWorkspaceId);
        set({
          authChecked: true,
          loaded: true,
          error: null,
          syncStatus: {
            kind: 'offline',
            message: e instanceof Error ? e.message : String(e),
          },
        });
        return;
      }
      set({ authChecked: true, error: e instanceof Error ? e.message : String(e) });
    }
  },

  enterPlayground: () => {
    // The Login button calls this to flip the flag and reload. After
    // reload, hydrate() sees `isPlayground()` and routes through the
    // shared bootstrap apply path. Implemented as flag-then-reload (not
    // an inline state poke) so the playground entry point goes through
    // the exact same code path as a "user already in playground" reload.
    markPlayground();
    window.location.assign('/');
  },

  switchWorkspace: async (id) => {
    const ws = get().workspaces.find((w) => w.id === id);
    if (!ws) return;
    setActiveWorkspaceId(id);
    if (typeof localStorage !== 'undefined') {
      localStorage.setItem('fira:activeWorkspace', id);
    }
    // Re-bootstrap into the new workspace's data. We could try to be clever
    // and merge, but it's simpler and safer to re-fetch — the state shape
    // mirrors a fresh hydrate.
    set({
      loaded: false,
      activeWorkspaceId: id,
      cursor: 0,
      outbox: [],
      appliedOpIds: new Map(),
      // Linked overlay is per-session, not per-workspace — but we drop
      // the cached blocks on switch so the App-level effect refetches
      // them after the new bootstrap lands.
      linkedBlocks: [],
      linkedTasks: [],
      linkedGcal: [],
    });
    const data = await api.bootstrap();
    const projectFilter: Record<UUID, boolean> = {};
    data.projects.forEach((p) => { projectFilter[p.id] = true; });
    const firstProject = data.projects[0]?.id ?? null;
    const meId = get().meId;
    const myMember = ws.members.find((m) => m.user_id === meId);
    set((s) => ({
      loaded: true,
      users: data.users,
      projects: data.projects,
      epics: data.epics,
      sprints: data.sprints,
      tasks: data.tasks,
      blocks: data.blocks,
      gcal: data.gcal,
      links: data.links ?? [],
      cursor: data.cursor ?? 0,
      myWorkspaceRole: (myMember?.role ?? 'member') as WorkspaceRole,
      projectFilter,
      selectedPersonIds: meId ? [meId] : [],
      activePersonId: meId,
      inboxFilter: {
        ...s.inboxFilter,
        project_id: firstProject,
        assignee_id: meId,
      },
      // Same empty-workspace rule as initial hydrate.
      view: data.projects.length === 0 ? 'inbox' : 'calendar',
    }));
  },

  reloadWorkspaces: async () => {
    if (get().playgroundMode) return;
    const fresh = await api.listMyWorkspaces();
    const meId = get().meId;
    const activeId = get().activeWorkspaceId;
    const stillActive = activeId != null && fresh.some((w) => w.id === activeId);
    if (activeId != null && !stillActive) {
      // The active workspace is no longer in our list (deleted or we got
      // removed). Bounce to a fallback before any further reads fail.
      const fallback = fresh.find((w) => w.is_personal) ?? fresh[0];
      if (fallback) {
        // Pre-set workspaces so switchWorkspace can find the fallback row.
        set({ workspaces: fresh });
        await get().switchWorkspace(fallback.id);
        return;
      }
    }
    set((s) => {
      const active = stillActive ? fresh.find((w) => w.id === activeId) ?? null : null;
      const role: WorkspaceRole | null = active && meId
        ? ((active.members.find((m) => m.user_id === meId)?.role ?? 'member') as WorkspaceRole)
        : s.myWorkspaceRole;
      return { workspaces: fresh, myWorkspaceRole: role };
    });
  },

  createWorkspace: async (title) => {
    const playground = get().playgroundMode;
    const meId = get().meId;
    const ws: Workspace = playground
      ? {
          id: crypto.randomUUID(),
          title,
          is_personal: false,
          members: meId ? [{ user_id: meId, role: 'owner' }] : [],
        }
      : await api.createWorkspace(title);
    set((s) => ({ workspaces: [...s.workspaces, ws] }));
    await get().switchWorkspace(ws.id);
    return ws;
  },

  renameWorkspace: async (id, title) => {
    const playground = get().playgroundMode;
    const existing = get().workspaces.find((w) => w.id === id);
    const ws: Workspace = playground && existing
      ? { ...existing, title }
      : await api.renameWorkspace(id, title);
    set((s) => ({ workspaces: s.workspaces.map((w) => w.id === id ? ws : w) }));
    return ws;
  },

  setWorkspaceMembers: async (id, members) => {
    const playground = get().playgroundMode;
    const existing = get().workspaces.find((w) => w.id === id);
    const ws: Workspace = playground && existing
      ? { ...existing, members }
      : await api.setWorkspaceMembers(id, members);
    const meId = get().meId;
    set((s) => ({
      workspaces: s.workspaces.map((w) => w.id === id ? ws : w),
      myWorkspaceRole: id === s.activeWorkspaceId
        ? ((ws.members.find((m) => m.user_id === meId)?.role ?? 'member') as WorkspaceRole)
        : s.myWorkspaceRole,
    }));
    return ws;
  },

  deleteWorkspace: async (id) => {
    const { playgroundMode, workspaces, activeWorkspaceId } = get();
    const target = workspaces.find((w) => w.id === id);
    if (!target) return;
    if (target.is_personal) {
      throw new Error("Personal workspaces can't be deleted.");
    }
    // Pick the fallback up front so we know we have somewhere to land, but
    // do NOT switch yet — switchWorkspace flips the x-workspace-id header,
    // and the server's delete handler requires that header to match the
    // workspace being deleted (owner-of-this-workspace check).
    const needsSwitch = activeWorkspaceId === id;
    const fallback = needsSwitch
      ? (workspaces.find((w) => w.id !== id && w.is_personal)
        ?? workspaces.find((w) => w.id !== id))
      : null;
    if (needsSwitch && !fallback) {
      throw new Error('No other workspace to switch to.');
    }
    if (!playgroundMode) await api.deleteWorkspace(id);
    if (needsSwitch && fallback) {
      await get().switchWorkspace(fallback.id);
    }
    // Local cleanup. Other clients learn about this through the user-channel
    // WS nudge (see workspaces::delete on the server) and reconcile via
    // reloadWorkspaces — there is no workspace-scoped op for this event.
    set((s) => ({
      workspaces: s.workspaces.filter((w) => w.id !== id),
      workspaceModal: s.workspaceModal && s.workspaceModal.kind === 'edit' && s.workspaceModal.id === id
        ? null
        : s.workspaceModal,
    }));
  },

  setWorkspaceMemberRole: async (id, userId, role) => {
    const playground = get().playgroundMode;
    const existing = get().workspaces.find((w) => w.id === id);
    const ws: Workspace = playground && existing
      ? {
          ...existing,
          members: existing.members.map((m) => m.user_id === userId ? { ...m, role } : m),
        }
      : await api.setWorkspaceMemberRole(id, userId, role);
    const meId = get().meId;
    set((s) => ({
      workspaces: s.workspaces.map((w) => w.id === id ? ws : w),
      myWorkspaceRole: id === s.activeWorkspaceId && userId === meId
        ? role
        : s.myWorkspaceRole,
    }));
    return ws;
  },

  loadWorkspaceUsers: async (id) => {
    if (get().playgroundMode) return;
    const all = await api.listWorkspaceUsers(id);
    set((s) => {
      const byId = new Map(s.users.map((u) => [u.id, u]));
      for (const u of all) byId.set(u.id, u);
      return { users: Array.from(byId.values()).sort((a, b) => a.name.localeCompare(b.name)) };
    });
  },

  openCreateWorkspace: () => set({ workspaceModal: { kind: 'new' } }),
  openEditWorkspace: (id) => set({ workspaceModal: { kind: 'edit', id } }),
  closeWorkspaceModal: () => set({ workspaceModal: null }),

  logout: async () => {
    // Playground "logout" is just an exit — there's no session to invalidate
    // server-side. Clear the flag so the next visit starts fresh on the
    // login screen.
    if (get().playgroundMode) {
      clearPlayground();
    } else {
      try { await api.logout(); } catch { /* best-effort */ }
    }
    // Drop the persisted snapshot so the next user's reload doesn't see
    // the previous session's projects/tasks. Hard reload after.
    try { localStorage.removeItem('fira:store-v1'); } catch { /* private mode */ }
    window.location.assign('/');
  },

  syncOutbox: async () => {
    const { outbox, syncStatus, playgroundMode } = get();
    if (syncStatus.kind === 'syncing') return;
    // Playground: there's no server. Mutations have already been applied
    // locally via pushOp; just clear the queue so the sync pill stays clean.
    if (playgroundMode) {
      if (outbox.length > 0) {
        set({ outbox: [], syncStatus: { kind: 'idle' }, lastSyncedAt: Date.now() });
      }
      return;
    }
    // Server-rejected ops block the queue: auto-sync stops until the user
    // resolves them via the SyncPill (Retry / Discard). Network failures
    // are different — that path puts ops back to 'queued' and keeps trying.
    if (outbox.some((o) => o.status === 'error')) return;
    const batch = outbox.filter((o) => o.status === 'queued').slice(0, SYNC_BATCH_SIZE);
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
        // Surface the actual server message — the SyncPill counter alone
        // doesn't tell the user *why* the op was rejected.
        const fe: string = firstError ?? 'sync error';
        const summary = errored.length > 1
          ? `${errored.length} ops failed: ${fe}`
          : `Sync failed: ${fe}`;
        get().showToast(summary);
      } else {
        set({ syncStatus: { kind: 'idle' }, lastSyncedAt: Date.now() });
        // If the user retried failed ops and they just succeeded, the
        // queue is finally clean — same drain trigger as the discard path.
        if (syncStatus.kind === 'error') resyncIfDrained(get);
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

  retryOp: (op_id) => set((s) => {
    const remaining = s.outbox.map((o) =>
      o.op_id === op_id && o.status === 'error' ? { ...o, status: 'queued' as const } : o,
    );
    const stillFailed = (s.syncStatus.kind === 'error'
      ? s.syncStatus.failedOpIds.filter((x) => x !== op_id)
      : []);
    return {
      outbox: remaining,
      syncStatus: stillFailed.length > 0
        ? { ...s.syncStatus as Extract<SyncStatus, { kind: 'error' }>, failedOpIds: stillFailed }
        : { kind: 'idle' as const },
    };
  }),

  discardOp: (op_id) => {
    set((s) => {
      const remaining = s.outbox.filter((o) => o.op_id !== op_id);
      const stillFailed = (s.syncStatus.kind === 'error'
        ? s.syncStatus.failedOpIds.filter((x) => x !== op_id)
        : []);
      return {
        outbox: remaining,
        syncStatus: stillFailed.length > 0
          ? { ...s.syncStatus as Extract<SyncStatus, { kind: 'error' }>, failedOpIds: stillFailed }
          : { kind: 'idle' as const },
      };
    });
    resyncIfDrained(get);
  },

  retryAllFailed: () => set((s) => ({
    outbox: s.outbox.map((o) => o.status === 'error' ? { ...o, status: 'queued' as const } : o),
    syncStatus: { kind: 'idle' as const },
  })),

  discardAllFailed: () => {
    set((s) => ({
      outbox: s.outbox.filter((o) => o.status !== 'error'),
      syncStatus: { kind: 'idle' as const },
    }));
    resyncIfDrained(get);
  },

  pollChanges: async () => {
    if (get().playgroundMode) return;
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
      block: initial?.block ?? null,
    },
    openTaskId: null,
  })),
  closeCreate: () => set({ creatingDraft: null }),
  openCreateProject: () => set({ projectModal: { kind: 'new' } }),
  openEditProject: (id) => set({ projectModal: { kind: 'edit', id } }),
  closeProjectModal: () => set({ projectModal: null }),

  showToast: (message, kind = 'error') => {
    const id = crypto.randomUUID();
    set((s) => ({ toasts: [...s.toasts, { id, kind, message }] }));
    // Auto-dismiss errors after 6s, info after 3s. Keep them clickable for
    // immediate dismissal in the meantime (handled by the Toasts component).
    const ttl = kind === 'error' ? 6000 : 3000;
    window.setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    }, ttl);
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),

  reloadLinks: async () => {
    if (get().playgroundMode) return;
    try {
      const fresh = await api.listLinks();
      const accepted = fresh.find((l) => l.status === 'accepted');
      const hadAccepted = get().links.some((l) => l.status === 'accepted');
      set({ links: fresh });
      // Refresh the partner overlay if we became linked or stayed
      // linked. If the link disappeared, drop the cached overlay so a
      // stale partner snapshot can't leak after unlink.
      if (accepted) {
        await get().loadLinkedCalendar();
      } else if (hadAccepted) {
        set({ linkedBlocks: [], linkedTasks: [], linkedGcal: [], showLinked: false });
      }
    } catch {
      // Silent — same posture as pollChanges. The next user-channel
      // nudge or a manual modal-open will retry.
    }
  },

  requestLink: async (email) => {
    const link = await api.createLink(email);
    set((s) => ({ links: [...s.links.filter((l) => l.id !== link.id), link] }));
  },

  acceptLink: async (id) => {
    const link = await api.acceptLink(id);
    set((s) => ({ links: s.links.map((l) => l.id === id ? link : l) }));
    await get().loadLinkedCalendar();
  },

  cancelLink: async (id) => {
    await api.deleteLink(id);
    set((s) => ({
      links: s.links.filter((l) => l.id !== id),
      linkedBlocks: [],
      linkedTasks: [],
      linkedGcal: [],
      showLinked: false,
    }));
  },

  loadLinkedCalendar: async () => {
    if (get().playgroundMode) return;
    try {
      const data = await api.linkedCalendar();
      set({
        linkedBlocks: data.blocks,
        linkedTasks: data.tasks,
        linkedGcal: data.gcal,
      });
    } catch {
      // No-op — most likely "no accepted link", which can happen if a
      // partner unlinked between our state read and the request. The
      // overlay gets cleared when reloadLinks notices the change.
    }
  },

  setShowLinked: (v) => set({ showLinked: v }),
  openLinkModal: () => set({ linkModalOpen: true }),
  closeLinkModal: () => set({ linkModalOpen: false }),

  addProject: async (input) => {
    // Project create is rare and deliberate — a synchronous round-trip is
    // fine and avoids the "appears in sidebar then vanishes on error" jank
    // that an outbox-style optimistic insert would cause.
    const { playgroundMode, activeWorkspaceId, meId } = get();
    const project: Project = playgroundMode
      ? {
          id: crypto.randomUUID(),
          workspace_id: activeWorkspaceId ?? '',
          title: input.title,
          icon: input.icon,
          color: input.color,
          source: 'local',
          description: null,
          external_url_template: null,
          members: meId ? [{ user_id: meId, role: 'lead' }] : [],
        }
      : await api.createProject(input);
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
    const playground = get().playgroundMode;
    const existing = get().projects.find((p) => p.id === id);
    const updated: Project = playground && existing
      ? {
          ...existing,
          ...(patch.title !== undefined ? { title: patch.title } : {}),
          ...(patch.icon !== undefined ? { icon: patch.icon } : {}),
          ...(patch.color !== undefined ? { color: patch.color } : {}),
          ...(patch.external_url_template !== undefined
            ? { external_url_template: patch.external_url_template }
            : {}),
        }
      : await api.updateProject(id, patch);
    set((s) => ({
      projects: s.projects
        .map((p) => p.id === id ? updated : p)
        .sort((a, b) => a.title.localeCompare(b.title)),
    }));
    return updated;
  },

  setProjectMembers: async (id, members) => {
    const playground = get().playgroundMode;
    const existing = get().projects.find((p) => p.id === id);
    const updated: Project = playground && existing
      ? { ...existing, members }
      : await api.setProjectMembers(id, members);
    set((s) => ({
      projects: s.projects.map((p) => p.id === id ? updated : p),
    }));
    return updated;
  },

  deleteProject: async (id) => {
    if (!get().playgroundMode) await api.deleteProject(id);
    // applyOpToState handles the local cleanup symmetrically with the
    // change-feed echo; we share the path so a remote delete does the
    // same thing. projectModal close is handled in there too.
    set((s) => applyOpToState(s, { kind: 'project.delete', project_id: id }));
  },

  loadAllUsers: async () => {
    if (get().playgroundMode) return; // user list is fixed by the seed
    const ws = get().activeWorkspaceId;
    if (!ws) return;
    const all = await api.listWorkspaceUsers(ws);
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
      external_url: null,
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

  setTaskExternalId: (taskId, external_id) => {
    // Empty string and null both mean "clear" — collapse to null on the wire.
    const trimmed = external_id?.trim() ?? '';
    const next = trimmed === '' ? null : trimmed;
    set((s) => ({
      tasks: s.tasks.map((x) => x.id === taskId ? { ...x, external_id: next } : x),
      ...pushOp(s, { kind: 'task.set_external_id', task_id: taskId, external_id: next }),
    }));
  },

  setTaskExternalUrl: (taskId, external_url) => {
    const trimmed = external_url?.trim() ?? '';
    const next = trimmed === '' ? null : trimmed;
    set((s) => ({
      tasks: s.tasks.map((x) => x.id === taskId ? { ...x, external_url: next } : x),
      ...pushOp(s, { kind: 'task.set_external_url', task_id: taskId, external_url: next }),
    }));
  },

  deleteTask: (taskId) => set((s) => ({
    tasks: s.tasks.filter((t) => t.id !== taskId),
    blocks: s.blocks.filter((b) => b.task_id !== taskId),
    openTaskId: s.openTaskId === taskId ? null : s.openTaskId,
    ...pushOp(s, { kind: 'task.delete', task_id: taskId }),
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

  reorderSubtasks: (taskId, orderedIds) => set((s) => {
    const tasks = s.tasks.map((t) => {
      if (t.id !== taskId) return t;
      const byId = new Map(t.subtasks.map((st) => [st.id, st]));
      const reordered = orderedIds
        .map((id, i) => {
          const existing = byId.get(id);
          if (!existing) return null;
          byId.delete(id);
          return { ...existing, sort_key: `M${String(i).padStart(3, '0')}` };
        })
        .filter((x): x is NonNullable<typeof x> => x != null);
      return { ...t, subtasks: [...reordered, ...Array.from(byId.values())] };
    });
    return {
      tasks,
      ...pushOp(s, { kind: 'subtask.reorder', task_id: taskId, ordered: orderedIds }),
    };
  }),

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
}), {
  name: 'fira:store-v1',
  storage: createJSONStorage(() => localStorage, { replacer, reviver }),
  // Persist only data we want to recover offline. Skip transient UI state
  // (modals, view, drag draft) and ephemeral flags (authChecked, loaded,
  // error, syncStatus). Re-bootstrap will overwrite the data fields when
  // the network is back.
  partialize: (s) => ({
    users: s.users,
    projects: s.projects,
    epics: s.epics,
    sprints: s.sprints,
    tasks: s.tasks,
    blocks: s.blocks,
    gcal: s.gcal,
    outbox: s.outbox,
    cursor: s.cursor,
    appliedOpIds: s.appliedOpIds,
    lastSyncedAt: s.lastSyncedAt,
    meId: s.meId,
    workspaces: s.workspaces,
    activeWorkspaceId: s.activeWorkspaceId,
    myWorkspaceRole: s.myWorkspaceRole,
    selectedPersonIds: s.selectedPersonIds,
    activePersonId: s.activePersonId,
    playgroundMode: s.playgroundMode,
    links: s.links,
    showLinked: s.showLinked,
  // partialize is loosely typed — zustand expects S but we're returning a
  // subset of fields. Cast through unknown is the canonical workaround.
  }) as unknown as FiraState,
  onRehydrateStorage: () => (state) => {
    // After hydration, re-arm the api wrapper with the persisted active
    // workspace so the very first request after reload carries the
    // X-Workspace-Id header even before /me runs.
    if (state?.activeWorkspaceId) setActiveWorkspaceId(state.activeWorkspaceId);
  },
}));

// Selectors that components subscribe to. Putting these here keeps the
// component code uncluttered with `useFira((s) => ...)` boilerplate.
export const selectMe = (s: FiraState): User | null =>
  s.users.find((u) => u.id === s.meId) ?? null;
export const selectProject = (id: UUID | null) => (s: FiraState): Project | null =>
  id ? s.projects.find((p) => p.id === id) ?? null : null;
export const selectTasksForProject = (id: UUID | null) => (s: FiraState): Task[] =>
  id ? s.tasks.filter((t) => t.project_id === id) : [];
