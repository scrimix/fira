# Sprint 30 — Move a task to another project

**Status:** built
**Date:** 2026-08-30

## Goal

Let a task change its `project_id` — from the task modal, one picker,
with an explicit confirm step that names **who loses access** before
anything is written.

The feature is small in the UI and awkward in the model, because
`project_id` isn't just a label on a task: it is the *scope key* for
authorization, for the change feed, for calendar visibility, and for
four things the task points at (tags, epic, sprint, Jira project).
Moving a task moves all of those out from under it.

## 1. What `project_id` actually controls

Every one of these reads the task's project, so every one of them
changes meaning the moment the task moves:

| consumer | how it uses `tasks.project_id` |
|---|---|
| `ensure_scope.rs` (all six helpers) | the predicate for *every* task / subtask / block / tag / attachment write |
| `db::list_blocks_in_scope` | `time_blocks JOIN tasks WHERE t.project_id = ANY(scope)` — **blocks are visible via the task's project, not via the block's owner** |
| `get_changes` | `processed_ops.project_id` decides who receives an op |
| `tags` / `task_tags` | tags are per-project (`tags.project_id`, unique on `(project_id, lower(title))`) |
| `epics`, `sprints` | both are `project_id NOT NULL`; `tasks.epic_id` / `sprint_id` FK into them |
| `projects.external_url_template`, `jira_project_key` | resolve the task's issue link and its worklog target |
| `goals.project_id` | a personal goal filtered to a project silently gains/loses this task's blocks |

The second row is the one that produces the user-visible harm, and it's
the reason the warning has to exist. `list_blocks_in_scope` has no
`user_id` predicate — a block is delivered to a client because the
client can see the block's *task's project*. So when a task moves into a
project Bob isn't in, **every block Bob has on that task vanishes from
Bob's calendar**, with no tombstone and no explanation. His hours are
still in the database; he just can't see them, and neither can anyone
else who lost the project.

That is the thing to warn about, and it should be stated in those terms
in the dialog — not as a vague "some users might lose access".

### Visibility loss is recoverable; nothing is destroyed

Worth being precise, because it changes how hard the dialog has to
push: **the blocks are not deleted, and adding the user to the target
project brings them all back.** `db::project_scope` is recomputed from
live membership on every `/api/bootstrap`, and `list_blocks_in_scope`
filters on that scope — so a `project_members` insert restores every
block on the next hydrate, with no repair step.

The recovery is even live rather than reload-gated: the
`project.set_members` arm in `store/index.ts:803` notices "we're in a
member set for a project we don't have locally" and the `applyRemoteOp`
wrapper schedules a `hydrate()`. Bob gets his calendar back without
touching anything.

So the honest framing for the dialog is **"disappears from their
calendar until you add them to <target>"**, not "loses their work".
Warn clearly, don't threaten. The genuinely irreversible losses are in
§6 — tags and epic/sprint — and those are about the task, not about
people.

## 2. Who to check

Exactly the set the feature request names, and no more:

- `tasks.assignee_id`
- `SELECT DISTINCT user_id FROM time_blocks WHERE task_id = $1`

`tasks.created_by` is deliberately **not** checked. It's an attribution
field for a past event; the creator has no ongoing need for the row.

"Has access to the target project" must use the same predicate as
`require_project_access`, or the dialog will disagree with the server:

```
p.owner_id = u
OR EXISTS (project_members WHERE project_id = target AND user_id = u AND removed_at IS NULL)
OR EXISTS (workspace_members WHERE workspace_id = ws AND user_id = u
             AND removed_at IS NULL AND role = 'owner')
```

Note `project_members.role = 'inactive'` still counts as access —
`inactive` is a *display* state (hidden from inbox assignee groups), not
an authorization state. Don't add a role filter here.

Two distinct buckets, because they read differently to the user:

1. **Blocks go dark.** `N blocks by <names>` disappear from those
   people's calendars.
2. **Assignee is orphaned.** The task stays assigned to someone who
   can't open it. The list's assignee grouping renders a name that
   can't act on the row.

## 3. Cross-workspace is out of scope

Reject `from.workspace_id != to.workspace_id` with a 400. Tags,
members, invites and the entire scope model are per-workspace; a
cross-workspace move is a different and much larger feature. The picker
only offers projects in the active workspace, so this is a guard, not a
UI path.

## 4. Why REST, not an outbox op

Every other task mutation is an outbox op. This one shouldn't be:

- It needs a **confirm gate** whose result the user sees *before* the
  write commits. The outbox is fire-and-forget by construction.
- It spans **two project scopes**. `apply_payload` returns a single
  `out_project_id`; the op envelope has nowhere to put the second one.
- It's rare and deliberate, not a per-keystroke mutation — the same
  reason attachments and project-member edits went REST (see README,
  "with introduction of attachments the architecture changed a bit").

```
POST /api/tasks/:id/move   { to_project_id, acknowledge_access_loss: bool }
```

The client computes the impact report **locally** — it already has
`projects[].members`, `blocks`, and `assignee_id` in the store, all
scoped correctly — so the dialog renders with no round trip. The server
recomputes the same set as the authority and returns **409** when the
impact set is non-empty and `acknowledge_access_loss` isn't set.

The client sets that flag to *what the dialog actually showed*, never a
blanket `true` — see §8. That's what makes the 409 reachable: it fires
exactly when client and server disagree about who's stranded, which is a
membership change that raced the dialog.

Authorization: `require_project_access` on **both** source and target,
for the caller, in the header's workspace.

## 5. The change-feed fan-out (the actually-hard part)

`processed_ops.project_id` is one column and `get_changes` filters on
it. A move has **two audiences with opposite needs**:

- source-project members must *drop* the task and its blocks
- target-project members must *gain* them

One log row can only reach one of them. A row scoped to the source
leaves target-only members without the task until their next hydrate; a
row scoped to the target leaves source-only members holding a ghost.

**Write two rows in the same transaction**, same synthesized kind,
different `project_id`:

```rust
let payload = json!({
  "kind": "task.move_project",
  "from_project_id": from, "to_project_id": to,
  "task": &moved_task,   // full row, post-move (tag_ids now empty)
  "blocks": &blocks,     // see §8 — a target-only member has never seen these
});
record_synthesized_op(&mut tx, user, ws, kind, payload.clone(), Some(from)).await?;
record_synthesized_op(&mut tx, user, ws, kind, payload,         Some(to)).await?;
```

`record_synthesized_op` generates its own `op_id` per call, so the two
rows don't collide on the `processed_ops` PK.

Client apply is a single idempotent branch keyed on *visibility*, not on
which row arrived:

```ts
case 'task.move_project': {
  const visible = s.projects.some((p) => p.id === op.to_project_id);
  if (!visible) return {                       // same shape as task.delete
    tasks:  s.tasks.filter((t) => t.id !== op.task.id),
    blocks: s.blocks.filter((b) => b.task_id !== op.task.id),
    openTaskId: s.openTaskId === op.task.id ? null : s.openTaskId,
  };
  const t = normalizeTask(op.task);            // upsert, not push
  return { tasks: s.tasks.some((x) => x.id === t.id)
    ? s.tasks.map((x) => (x.id === t.id ? t : x))
    : [...s.tasks, t] };
}
```

A client in *both* projects receives both rows and applies the same
upsert twice — a no-op the second time. A client in neither receives
nothing. Add `task.move_project` to `RemoteOnlyOpKind` in
`store/outbox.ts`; clients never enqueue it.

The WS nudge is already workspace-scoped, so both audiences get poked
without further work.

## 6. What the move must rewrite

Ordered, all inside the one transaction:

- **`project_id`** — the point of the exercise.
- **Tags** — **dropped.** `DELETE FROM task_tags WHERE task_id = $1`.
  `task_tags` rows point at tags owned by the *source* project, and a
  tag is an identity-bearing row (migration 0015), not a string — it
  doesn't travel. Remapping by title into the target project was the
  alternative; rejected because auto-creating rows in the target
  project as a side effect of moving one task is a surprise, and it
  quietly pollutes that project's tag vocabulary. Dropping is legible,
  and the dialog names every tag going away, so it isn't silent.

  The source project's `tags` rows are **not** touched — other tasks
  still use them, and moving the task back leaves them available to
  re-attach by hand.
- **`epic_id`, `sprint_id`** — set `NULL`. Both FK into project-scoped
  rows and there's no sane remap.

**Tags, epic and sprint are the irreversible part of the move.** Moving
the task back does not restore any of the three. This is what the
confirm dialog is really for — the access warnings in §2 undo
themselves the moment someone is added to the project (see §1), these
don't.
- **`sort_key`** — recompute to the tail of the target project's same
  section, or the task lands in an arbitrary slot in a list it's never
  been in.
- **`external_url`** — if the source project had an
  `external_url_template` (or `jira_project_key`) and the target's
  differs, materialize the *currently resolved* URL into
  `tasks.external_url` before the move. Per-task `external_url` already
  wins over the project template (`TaskModal.tsx:155`), so the link keeps
  resolving instead of being silently re-pointed at the target project's
  template. Leave `external_id` alone.

Rides along with no work:

- **Attachments** — FK is `task_id` only. The stored `storage_path` is
  `{project_id}/{task_id}/{name}` and lives in the DB, so reads still
  resolve; the S3 key just keeps the old project prefix. Not worth
  copying objects to fix.
- **Blocks** — `time_blocks.task_id` is untouched. Their *visibility*
  changes, which is §2's whole subject.
- **Subtasks** — task-scoped.

Left alone knowingly:

- **`time_blocks.jira_worklog_id`** — worklogs already pushed live on
  the old project's issue. Nothing sensible to do about that here.
- **`goals`** — a project-scoped personal goal silently re-scores. Goals
  are recomputed from blocks every render by design (migration 0033), so
  this is consistent with how goals already behave when a project's
  contents change.

## 7. UI

`TaskModal.tsx` already renders a project dot + title in the meta grid
as static text. Keep exactly that, and add a pencil `icon-btn` beside
it (`ProjectEditor`) — hidden in a one-project workspace, where there's
nowhere to move to. The pencil opens `MoveTaskModal`; the sidebar
itself never becomes an editor.

**The target picker belongs inside the dialog, not in the sidebar.**
Two reasons, one of them learned the hard way:

- The impact is what makes the choice, so it should update as you try
  targets — compare "Atlas strands Dana" against "Orion costs nothing"
  without closing anything.
- `<Select>` portals its menu to `document.body`. A sidebar editor that
  swaps in a `<Select>` needs its own click-away handler to revert, and
  that handler can't see the portaled menu: `wrapRef.contains(target)`
  is false for it, so `mousedown` on an option tore down the `<Select>`
  before the `click` could fire `onChange`. The picker looked
  completely dead. Inside a modal there's no competing click-away, and
  `.select-menu` (z-index 1200) already clears the backdrop (60).

One thing the dialog must do that `ConfirmDelete` doesn't: let an open
`<Select>` swallow the first Escape. The house Escape handler captures
on `window`, so without a `document.querySelector('.select-menu')`
check it closes the whole dialog when the user only meant to dismiss
the dropdown.

On change, a confirm dialog in the `ConfirmDelete` house style
(`MoveTaskModal`, styled off the existing confirm classes).
No type-to-confirm guard: everything here is either recoverable or
re-attachable by hand, and the dialog itself carries the weight.

**The dialog is always shown, and it is exhaustive.** Not just the
access warnings — every consequence of the move, including the ones
that are merely surprising rather than harmful. The user asked for
"full info about what can or will be dropped", and the reason it's
worth building that way is that this dialog is the *only* place these
consequences are ever visible: tags vanish, the epic clears, and
someone's calendar empties, all with no other notification anywhere in
the product. If a consequence isn't in this dialog, it happens
invisibly.

Two sections, because "people" and "data" are different kinds of
worry and the first is recoverable while the second isn't:

> **Move "Refactor auth" from Orion to Atlas?**
>
> **People who can't see Atlas**
> - **Dana** — 5 time blocks disappear from her calendar
> - **Sam** — 2 time blocks, and he's the assignee: the task stays
>   assigned to someone who can't open it
>
> Their blocks aren't deleted. Add them to Atlas and everything
> comes back.
>
> **Dropped from the task — permanently**
> - Tags `auth`, `backend`
> - Epic **Q3 hardening**
> - Sprint **Sprint 14**
>
> Moving the task back to Orion won't restore these.
>
> *Attachments, subtasks and time blocks move with the task.*
>
> [Cancel] [Move to Atlas]

Rules for building the body:

- **Render only the sections and rows that apply.** A move with no
  affected users drops the whole first section (and its reassuring
  line with it); a task with no tags/epic/sprint drops the second.
- **When neither section has content, still show the dialog** — a
  short "Move X from Orion to Atlas? Nothing will be lost." That's the
  cheap confirm that makes the loud version trustworthy, and it's one
  key to dismiss.
- **Name every item.** Every affected person, every tag, the epic, the
  sprint — by name, not by count. "3 tags will be dropped" makes the
  user go look; listing them doesn't.
- **Per-person block counts**, since one lost block and forty are very
  different decisions.
- **Flag the assignee inline** on their row rather than as a separate
  bullet, so a person who is both assignee and block-owner appears once.
- The trailing italic line states what *survives*. It's there because
  the two lists above prime the user to assume everything is at risk.

All of it comes from local state — `projects[].members`, `blocks`,
`tags`, `task.tag_ids`, `epics`, `sprints` — so the dialog renders
instantly on picker change, with no preflight round trip.

After the POST resolves, call `pollChanges()` and let the
`task.move_project` row apply. No optimistic local write: same posture
as attachments, and it keeps the two-row fan-out as the single source
of the state transition.

## 8. What implementation changed

Two things the design missed, both found while wiring it up:

- **Blocks have to ride in the payload.** Blocks are reached through
  `task → project`, so a target-project member who wasn't in the source
  has *never* seen this task's blocks — the task would arrive with none
  of its history until their next hydrate. The payload carries
  `blocks` alongside `task`, and receivers upsert by block id so a
  client that already had them is unaffected.
- **The ack flag has to be honest to be worth anything.** The first cut
  had the client always send `acknowledge_access_loss: true`, which
  makes the server's 409 unreachable from our own UI. It now sends what
  the dialog actually showed (`stranded.length > 0`), so the 409 fires
  exactly when client and server disagree — a membership change racing
  the dialog. The modal treats that as "our state is stale", re-hydrates,
  and shows the corrected list rather than closing.

## 9. Test cases worth writing

- Move with a block owner outside the target → server 409 without the
  ack flag; succeeds with it; that owner's `/api/bootstrap` no longer
  returns the blocks.
- A client in both projects applies both log rows and ends with exactly
  one copy of the task.
- A client in the source only ends with the task **and its blocks** gone.
- Adding the block owner to the target project restores every block on
  their next hydrate — the recovery path the dialog promises.
- Tags drop: `task_tags` for the task is empty afterwards, and the
  source project's `tags` rows still exist for its other tasks.
- `from.workspace_id != to.workspace_id` → 400.
- Caller is a member of the source but not the target → 403.
