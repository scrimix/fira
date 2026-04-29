// Local-first store. Source of truth for the UI.
//
// Hydrate once on mount via `hydrate()` (calls /bootstrap). Reads are sync
// against this state. Writes mutate state immediately AND append to the outbox.
// Components never await network calls.

import { create } from 'zustand';
import type {
  Bootstrap, Project, User, Epic, Sprint, Task, TimeBlock, GcalEvent, UUID, Section,
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
  selectedPersonId: UUID | null;
  projectFilter: Record<UUID, boolean>;
  inboxFilter: InboxFilter;
  openTaskId: UUID | null;

  hydrate: () => Promise<void>;
  setView: (v: 'calendar' | 'inbox', projectId?: UUID) => void;
  setPerson: (id: UUID) => void;
  toggleProjectFilter: (id: UUID) => void;
  setInboxFilter: (patch: Partial<InboxFilter>) => void;
  openTask: (id: UUID | null) => void;

  // mutations — update local state synchronously + emit op
  tickTask: (taskId: UUID) => void;
  setTaskSection: (taskId: UUID, section: Section) => void;
  setTaskTitle: (taskId: UUID, title: string) => void;
  setTaskDescription: (taskId: UUID, description_md: string) => void;
  tickSubtask: (taskId: UUID, subId: UUID) => void;
  upsertBlock: (block: TimeBlock) => void;
  updateBlock: (blockId: UUID, patch: Partial<TimeBlock>) => void;
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
  selectedPersonId: null,
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
        selectedPersonId: me?.id ?? null,
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
  setPerson: (id) => set({ selectedPersonId: id }),
  toggleProjectFilter: (id) => set((s) => ({
    projectFilter: { ...s.projectFilter, [id]: !(s.projectFilter[id] !== false) },
  })),
  setInboxFilter: (patch) => set((s) => ({ inboxFilter: { ...s.inboxFilter, ...patch } })),
  openTask: (id) => set({ openTaskId: id }),

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

  setTaskSection: (taskId, section) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, section } : x),
    outbox: enqueue(s, { kind: 'task.set_section', task_id: taskId, section }),
  })),

  setTaskTitle: (taskId, title) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, title } : x),
    outbox: enqueue(s, { kind: 'task.set_title', task_id: taskId, title }),
  })),

  setTaskDescription: (taskId, description_md) => set((s) => ({
    tasks: s.tasks.map((x) => x.id === taskId ? { ...x, description_md } : x),
    outbox: enqueue(s, { kind: 'task.set_description', task_id: taskId, description_md }),
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
