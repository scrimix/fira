// Local-first store. Source of truth for the UI.
//
// Hydrate once on mount via `hydrate()` (calls /bootstrap). Reads are sync
// against this state. Writes mutate state immediately AND append to the outbox.
// Components never await network calls.

import { create } from 'zustand';
import type {
  Bootstrap, Project, User, Epic, Sprint, Task, TimeBlock, GcalEvent, UUID, Section, Subtask, Status,
} from '../types';
import { api } from '../api';
import { newOp, type Op, type OpKind } from './outbox';

interface InboxFilter {
  project_id: UUID | null;
  epic_id: UUID | null;
  sprint_id: UUID | 'active' | 'all' | 'none';
  status: 'open' | 'all' | 'in_progress' | 'todo' | 'done';
  assignee_id: UUID | 'all' | null;
}

interface FiraState {
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

  hydrate: () => Promise<void>;
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

const enqueue = (s: FiraState, payload: OpKind): Op[] => [...s.outbox, newOp(payload)];

export const useFira = create<FiraState>((set, get) => ({
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

  meId: null,
  view: 'calendar',
  selectedPersonIds: [],
  activePersonId: null,
  weekOffset: 0,
  creatingDraft: null,
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
      const data: Bootstrap = await api.bootstrap();
      const me = data.users.find((u) => u.email === 'maya@fira.dev') ?? data.users[0] ?? null;
      const projectFilter: Record<UUID, boolean> = {};
      data.projects.forEach((p) => { projectFilter[p.id] = true; });
      const firstProject = data.projects[0]?.id ?? null;
      set({
        loaded: true,
        error: null,
        users: data.users,
        projects: data.projects,
        epics: data.epics,
        sprints: data.sprints,
        tasks: data.tasks,
        blocks: data.blocks,
        gcal: data.gcal,
        meId: me?.id ?? null,
        selectedPersonIds: me ? [me.id] : [],
        activePersonId: me?.id ?? null,
        projectFilter,
        inboxFilter: {
          ...get().inboxFilter,
          project_id: firstProject,
          assignee_id: me?.id ?? null,
        },
      });
    } catch (e) {
      set({ error: e instanceof Error ? e.message : String(e) });
    }
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
      outbox: enqueue(s, { kind: 'task.create', task: newTask }),
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
      outbox: enqueue(s, { kind: 'task.tick', task_id: taskId, done }),
    };
  }),

  setTaskStatus: (taskId, status) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, status } : x),
    outbox: enqueue(s, { kind: 'task.set_status', task_id: taskId, status }),
  })),

  setTaskSection: (taskId, section) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, section } : x),
    outbox: enqueue(s, { kind: 'task.set_section', task_id: taskId, section }),
  })),

  setTaskAssignee: (taskId, assigneeId) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, assignee_id: assigneeId } : x),
    outbox: enqueue(s, { kind: 'task.set_assignee', task_id: taskId, assignee_id: assigneeId }),
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
      outbox: enqueue(s, { kind: 'task.reorder', project_id: projectId, section, ordered: orderedIds }),
    };
  }),

  setTaskTitle: (taskId, title) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, title } : x),
    outbox: enqueue(s, { kind: 'task.set_title', task_id: taskId, title }),
  })),

  setTaskDescription: (taskId, description_md) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, description_md } : x),
    outbox: enqueue(s, { kind: 'task.set_description', task_id: taskId, description_md }),
  })),

  setTaskEstimate: (taskId, estimate_min) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, estimate_min } : x),
    outbox: enqueue(s, { kind: 'task.set_estimate', task_id: taskId, estimate_min }),
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
      outbox: enqueue(s, { kind: 'subtask.create', subtask: sub }),
    }));
    return sub.id;
  },

  setSubtaskTitle: (taskId, subId, title) => set((s) => ({
    tasks: s.tasks.map((t) => t.id !== taskId ? t : {
      ...t,
      subtasks: t.subtasks.map((st) => st.id === subId ? { ...st, title } : st),
    }),
    outbox: enqueue(s, { kind: 'subtask.set_title', subtask_id: subId, title }),
  })),

  deleteSubtask: (taskId, subId) => set((s) => ({
    tasks: s.tasks.map((t) => t.id !== taskId ? t : {
      ...t,
      subtasks: t.subtasks.filter((st) => st.id !== subId),
    }),
    outbox: enqueue(s, { kind: 'subtask.delete', subtask_id: subId }),
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
    return { tasks, outbox: enqueue(s, { kind: 'subtask.tick', subtask_id: subId, done: nextDone }) };
  }),

  upsertBlock: (block) => set((s) => {
    const exists = s.blocks.some((b) => b.id === block.id);
    return {
      blocks: exists ? s.blocks.map((b) => b.id === block.id ? block : b) : [...s.blocks, block],
      outbox: enqueue(s, { kind: 'block.create', block }),
    };
  }),

  updateBlock: (blockId, patch) => set((s) => ({
    blocks: s.blocks.map((b) => b.id === blockId ? { ...b, ...patch } : b),
    outbox: enqueue(s, { kind: 'block.update', block_id: blockId, patch }),
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
      outbox: enqueue(s, { kind: 'block.create', block: newBlock }),
    }));
    return newBlock.id;
  },

  deleteBlock: (blockId) => set((s) => ({
    blocks: s.blocks.filter((b) => b.id !== blockId),
    outbox: enqueue(s, { kind: 'block.delete', block_id: blockId }),
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
