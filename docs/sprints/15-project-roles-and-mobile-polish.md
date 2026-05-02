# Sprint 15 — Per-project roles, inbox visibility, and mobile/UI polish

**Status:** shipped
**Date:** 2026-05-02

## Goal

Two themes ran together this sprint:

1. **The workspace owner showed up everywhere.** In the inbox, every
   project rendered an empty assignee group for the workspace owner —
   they're an implicit project lead, so they appeared in `project.members`
   even on projects they had nothing to do with. The fix needed to be
   semantic, not cosmetic: a real per-project role that lets the owner
   say "I'm not actively in this project" while still keeping cross-
   workspace authority.
2. **Mobile + small UI debts.** The Select popover didn't open on phones
   (Project picker, Assignee role, Status — none of them). Description
   field showed a 1–2 px ghost scrollbar. Glyphs (`✓` / `×`) were
   inconsistent with the codebase's Lucide-icon convention. Section
   headings in the task modal had drift between the three sections. The
   draft modal pre-selected a project, so a half-attentive tap landed
   tasks in the wrong project. The calendar rail diverged from the inbox
   ordering, and the "All" button hid Later tasks.

Most of these were independent fixes; they ride together because they
all surfaced while looking at the same screens.

## 1. Project roles — `owner`, `lead`, `member`, `inactive`

### Data model — migrations 0012 and 0013

```sql
-- 0012: add 'owner' to project_members.role + backfill workspace owners
ALTER TABLE project_members DROP CONSTRAINT project_members_role_check;
ALTER TABLE project_members
    ADD CONSTRAINT project_members_role_check
    CHECK (role IN ('owner','lead','member'));

INSERT INTO project_members (project_id, user_id, role)
SELECT p.id, wm.user_id, 'owner'
FROM projects p
JOIN workspace_members wm ON wm.workspace_id = p.workspace_id
WHERE wm.role = 'owner' AND wm.removed_at IS NULL
ON CONFLICT (project_id, user_id) DO UPDATE
    SET role = 'owner', removed_at = NULL;

-- 0013: add 'inactive' (no data backfill)
ALTER TABLE project_members
    ADD CONSTRAINT project_members_role_check
    CHECK (role IN ('owner','lead','member','inactive'));
```

The role axis grew from {`lead`, `member`} to {`owner`, `lead`, `member`,
`inactive`}. Two of those are "passive" — `owner` and `inactive` —
meaning the user stays in the project for history/data purposes but
doesn't render as an assignee group in the inbox unless they have a
Now task assigned to them.

| role       | inbox visibility (Now)         | edit power | who sets it
|------------|--------------------------------|------------|-------------
| `owner`    | hidden unless assigned tasks   | yes        | auto-assigned to workspace owner; WS owner can change their own
| `lead`     | always visible                 | yes        | WS owner promotes
| `member`   | always visible                 | no         | default for added members
| `inactive` | hidden unless assigned tasks   | no         | WS owner can mark anyone

`owner` is the workspace owner's per-project default; `inactive` is the
mirror for regular members.

### Backend (api/src/db.rs, api/src/main.rs)

- `create_project_tx` now inserts the creator (always the workspace
  owner — project creation is owner-gated) with role `'owner'` rather
  than `'lead'`. Their assignee group stays hidden in the inbox by
  default.
- `set_project_members_tx` lost its `project_owner_id` parameter. The
  "force-include" anchor moved from `projects.owner_id` (the historical
  creator) to the **current workspace owner**, looked up inside the same
  transaction. If they're in `desired`, honor the role; otherwise add
  them with role `'owner'`. This lets the WS owner change their own
  role freely while preventing accidental self-removal.
- `has_project_lead_authority` accepts both `'lead'` and `'owner'`
  rows. Workspace ownership remains the wildcard (`is_workspace_owner`
  short-circuits before the role lookup) so cross-project authority
  doesn't depend on the per-project role.
- Validation in `set_project_members` accepts the four-role set.

### Frontend (web/src/components/InboxView.tsx, ProjectModal.tsx)

`InboxView` filters `assigneeIds`:

```ts
const nowAssignees = new Set(nowTasks.map((t) => t.assignee_id).filter(...));
const visibleMembers = project.members.filter(
  (m) => (m.role !== 'owner' && m.role !== 'inactive')
       || nowAssignees.has(m.user_id),
);
```

The header counter (`{project.members.length} members`) still reflects
total membership — the visibility filter is for assignee groups only,
not for "who's in this project".

`ProjectModal` was rebuilt around the new role axis:

- The "you" row stops being filtered out of the editable list when the
  caller is the workspace owner — they need to see and change their own
  role inline. Non-WS-owners still see themselves as a read-only header
  row, but it now renders their actual role rather than a hardcoded
  `lead (you)` label.
- The role `Select` got two new options: `owner` and `inactive`, with
  hint lines that spell out "hidden from inbox unless tasks assigned"
  so the visibility behavior isn't a surprise.
- Self-row has no remove button (backend force-include backstops the UI
  guard).

### Decisions

- **Owner role over a separate `is_active` flag.** Considered putting
  the visibility hint on a sibling column. Rejected because the use
  cases for "passive but present" are role-shaped: workspace owner =
  passive by default, member = active by default, opt-in either way.
  One axis with four values reads cleaner than two axes with two each.
- **Anchor force-include on workspace ownership, not creator.** The
  old code anchored the "can't be removed from project_members" rule on
  `projects.owner_id` (the creator). That's brittle once you imagine
  ownership transfers. Anchoring on `workspace_members.role = 'owner'`
  ties the rule to who actually has cross-project authority *now*.
- **No bulk migration of explicit `lead` rows.** Existing `lead` rows
  for non-WS-owners stay as-is. Only WS-owner rows get rewritten to
  `owner`. The migration is idempotent (`INSERT … ON CONFLICT DO
  UPDATE`) and safe to rerun.
- **No "self-toggle inactive" endpoint yet.** A regular member can't
  flip themselves to `inactive` today — only the WS owner can. We held
  off on the dedicated `/api/projects/:id/members/me` endpoint because
  the visible benefit was small relative to the surface area; the WS
  owner is one ping away. If patterns of "I parked myself" emerge,
  add the self-service endpoint then.

## 2. Inbox — Unassigned bucket and auto-Later on unassign

Before this sprint, a Now task whose `assignee_id` was `null` rendered
nowhere when the inbox grouped by assignee. The user had to know which
section the task lived in to find it.

Two coupled changes:

- **Unassigned bucket.** The Now section gets an "Unassigned" assignee
  group (`?` avatar, "Unassigned" label) when there are unassigned now-
  tasks. Renders only when non-empty, so projects where every Now task
  is owned don't pick up an extra row.
- **Auto-flip to Later on unassign.** `setTaskAssignee(id, null)` for a
  task currently in `now` also pushes a `task.set_section` op moving it
  to `later`. Without an owner, a Now task has no group to render under
  — the parking lot is exactly where ownerless work belongs. Both ops
  are emitted in one store update so remote echoes apply atomically.

The Unassigned bucket exists for legacy data and for the rare explicit
"ownerless Now task" case. With the auto-flip rule, it normally stays
empty.

## 3. Calendar rail — sort + scope

Two small bugs:

- **All button skipped Later tasks.** The rail's section filter was
  hardcoded to `t.section === 'now'`. With "All" enabled, the toggle
  now widens to `(now || later)` so users can drag Later tasks onto the
  calendar to log time without a round-trip to the inbox. "My" stays
  Now-only — that's the focus list.
- **Rail order didn't match the inbox.** The rail filtered without
  sorting, so the visual order drifted from what users curate in the
  inbox. Sort is now Now-first, then `sort_key` within each section —
  same key the inbox uses.

## 4. Draft modal — no default project

`openCreate` used to default `project_id` to the active inbox filter or
the first project. Tapping the Draft button while viewing project
"Atlas" pre-filled "Atlas", and a half-attentive tap-through created
the task in Atlas without the user noticing. Now `creatingDraft.project_id`
defaults to `null`; the draft modal's Create button stays disabled
until the user picks explicitly. Caller-provided initial values (e.g.
the calendar's drag-to-create flow) still propagate.

## 5. Mobile fix — Select popover on touch devices

The `Select` component is the codebase-wide replacement for native
dropdowns. On mobile, none of its instances opened. Two fixes:

- **`mousedown` → `pointerdown` for the outside-click document
  listener.** `mousedown` is synthesized late on iOS and absent
  entirely on touch-only hardware. `pointerdown` covers mouse + touch
  in one event and fires reliably on iOS Safari.
- **`touch-action: manipulation` on `.select-trigger` and
  `.select-option`.** Suppresses iOS's 300 ms double-tap-zoom delay,
  which was occasionally swallowing the click that would have opened
  the popover.

This fix applies to every Select instance — Project picker, Assignee
role, Status, the workspace-modal role chips, etc. There are still
mobile gaps elsewhere in the app, but at least the dropdowns work.

## 6. Icon and typography consistency

- **Glyphs → Lucide.** Every `×` close/remove button across modals
  (TaskModal, TaskModalDraft, ProjectModal, WorkspaceModal,
  LinkAccountModal, CalendarView user pills) and every subtask `✓`
  check (TaskModalDraft was the last holdout) now uses Lucide icons.
  The single exception is the inbox task-rail done-checkmark — it stays
  as a glyph because its rendering is visually different from a checkbox
  (a green tick, not a check inside a square).
- **Section heading helper in TaskModal.** Description / Subtasks /
  Time blocks were three slightly-different inline-styled `<h5>`s. They
  collapsed into one `SectionHeading` component (title + optional hint
  + optional trailing slot) and a single CSS rule shared with the side
  panel. The "· N" subtitle moved into a separate span with `--ink-4`
  so it reads as metadata rather than part of the heading. Empty-state
  text ("No blocks yet.") was harmonized with the description's empty
  state — same `--fs-sm`, sans-serif, vertical rhythm.
- **Description scrollbar.** The autosize logic on the description
  textarea grows it to `scrollHeight`, but line-height rounding showed
  a 1–2 px ghost scrollbar on multi-line content. `overflow: hidden`
  on `.desc-md.desc-md-edit` settles it; the modal already scrolls.

## Migration safety

Both 0012 and 0013 are forward-only safe:

- Each does `DROP CONSTRAINT` + `ADD CONSTRAINT` on `project_members`
  — brief `ACCESS EXCLUSIVE` lock, full-table revalidation, fine on a
  table this size.
- 0012's backfill is idempotent (`ON CONFLICT DO UPDATE`) and only
  touches workspace-owner rows.
- 0013 has no data changes.
- Mixed-version tolerance: workspace ownership is still the wildcard
  for project-edit authority, so old API instances still serving
  traffic during a rollout don't lose authority on rows that flipped
  from `lead` to `owner`. Old clients sending `lead`/`member` continue
  to validate.

Side effect worth knowing: every existing workspace owner who was an
explicit project member with role `'lead'` (typical, since project
creators get auto-rowed) gets rewritten to `'owner'`. They will
visibly disappear from the inbox assignee groups in projects where
they have no Now tasks. That's the fix shipping — not a bug.

## What we noticed but didn't fix

- **Self-toggle for `inactive`.** Regular members can't mark themselves
  inactive without going through the WS owner. Add a small
  `POST /api/projects/:id/members/me/active` endpoint when the friction
  shows up.
- **Per-project member count display.** The project header in the
  inbox still shows `{project.members.length} members`, which counts
  all rows including hidden owners/inactive. Considered narrowing this
  to "visible members" but kept it accurate; users opening the project
  modal expect the same number of rows the count promised.
- **Drag onto Unassigned.** The new Unassigned bucket renders but
  doesn't accept drops to set `assignee_id = null`. With the
  auto-flip-to-Later rule, dropping there would also flip the section,
  which is non-obvious; left for a future pass.
- **Mobile beyond the Select fix.** Dropdowns work, but the modal
  layout (220 px sidebar at all viewport widths), draggable-to-
  calendar gestures, and the calendar grid itself are still
  desktop-shaped. Out of scope for this sprint — the user explicitly
  scoped to "fix the Select".
