# Sprint 07 — Collaboration polish + issue links

**Status:** done
**Date:** 2026-04-30

## Goal

Two unrelated tracks bundled because they fell in the same sitting.
First, the collaboration story shipped in sprint 03 had several rough
edges that only surfaced once a second human (real or seeded) was in
the picture: project membership wasn't editable from the UI, "me" was
hardcoded to Maya in the inbox, time blocks for teammates didn't ride
the bootstrap, and the calendar rail filtered other people's tasks out
entirely — making `time_blocks.user_id` a column nobody could
meaningfully use. Second, no manual hook existed for marking a task
with a Jira / Linear / GitHub issue id, so daily-use was incomplete:
you could plan and log time but you couldn't link out to the system
the work actually lives in.

## What shipped

### Project membership in the editor

- **`time_blocks` aside, `project_members` got a soft-delete column.**
  Migration `0005_member_soft_delete.sql` adds `removed_at TIMESTAMPTZ`.
  Hard-deleting a member would orphan task `assignee_id` history; soft
  removal preserves the row, hides the project from the user, and
  re-adding the same person is just `removed_at = NULL`.
- **Two endpoints, two ops, one PATCH was wrong.** First pass folded
  `members` into `PATCH /projects/:id` next to `title/icon/color`.
  That conflated visual edits with access control and made the
  apply-on-the-client logic ugly. Split:
  - `PATCH /projects/:id` — title / icon / color / external URL
    template only. Emits `project.update`.
  - `PUT /projects/:id/members` — full desired member set. Emits
    `project.set_members { project_id, members }`.
  - The owner is force-added to `want` server-side so an owner can't
    accidentally lock themselves out of their own project.
- **`GET /users`.** Auth-required directory listing so the editor's
  picker can offer teammates the caller hasn't shared a project with
  yet. Bootstrap's `list_users_in_scope` only returns co-members, so
  without this you couldn't invite anyone new.
- **`/changes` scope had to broaden.** A user just removed from a
  project no longer has the project in their normal scope, so the
  removal op would never reach them — the stale project would linger
  in their UI until reload. Fixed by including soft-removed rows in
  the scope query and capping with `applied_at <= removed_at`. They
  receive exactly one terminal `project.set_members` op and nothing
  after — no read-leak of ongoing project activity.
- **Frontend apply path drops state on removal.** When a
  `project.set_members` op arrives where `meId ∉ members`, we drop
  the project + its tasks, epics, sprints, blocks, the project filter
  entry, and reset `inboxFilter.project_id` if it was the removed one.
- **ProjectModal: Members section.** Adding is one click — search popover, click row, closes. **Removing requires two steps**: click the `×` chip to arm a red `Remove` button, click that to commit. Asymmetric on purpose — losing access is heavier than gaining it. Originally rendered as a `position: absolute` popover that overflowed the modal; switched to an inline picker inside the same bordered container with `max-height: 180px; overflow: auto` on candidates so it never escapes the modal.

### Calendar / inbox correctness

- **Time blocks for everyone in scope.** `bootstrap` was calling
  `list_blocks_for_user(user.id)` so every client only ever loaded
  their own blocks. Switched to `list_blocks_in_scope(scope)` joining
  through `tasks` so any block on a project the caller can see comes
  back. The frontend already filtered by `b.user_id === activePersonId`,
  so switching to a teammate in the calendar now actually shows their
  week.
- **`block.user_id` is now correct on drop.** The old code set
  `block.user_id = task.assignee_id ?? activePersonId ?? meId`, which
  meant dragging a teammate-owned task onto your own calendar
  silently routed the block to their calendar. Replaced with
  `activePersonId ?? meId`. The block lives on whoever's calendar it
  was dropped on, full stop.
- **Rail Mine/All toggle.** Without the toggle, the rail filtered
  tasks by `t.assignee_id === activePersonId`, so logging time on a
  task someone else owned was literally impossible from the UI —
  `time_blocks.user_id` was a vestigial column. Now: `Mine` (default)
  shows your tasks; `All` shows every task in the project, with
  non-yours dimmed to 0.55 opacity and prefixed with `↗` so they
  don't outshout your own. Hover restores full opacity. Right-aligned
  in the rail head; filter input fills the middle.
- **Title filter in the rail.** `Filter…` input matches against
  `title` or `external_id` (case-insensitive). Composes with the
  Mine/All toggle. Esc clears.
- **Inbox: stop hardcoding Maya as "me".** `email === 'maya@fira.dev'`
  was leaking through from sprint 02. Replaced with `id === meId` in
  the assignee headers and avatars. Also, `meId` floats to the top of
  the assignee groups when the caller is a project member —
  alphabetical wasn't right: people read their own tasks first.
- **Time-block list shows the owner avatar.** Once blocks belong to
  arbitrary users (not just the assignee), the task modal's Time
  blocks section needed to show *whose* block. Added a 20px avatar
  column at the start of each row; `data-me` highlights yours.

### Issue links

- **`projects.external_url_template`.** Migration
  `0006_external_url_template.sql`. Free-form string, `{key}`
  placeholder. NULL means no tracker — task external_ids still display
  but as plain text, not a link. Edited from the project modal
  ("Issue URL template" field, hint flips when `{key}` is missing).
  Validated server-side: must start with `http://` or `https://`,
  ≤ 512 chars.
- **`task.external_id` is now editable.** New op
  `task.set_external_id { task_id, external_id }`. Empty / whitespace
  on the wire = NULL in the DB. Side panel of `TaskModal` got an
  "Issue link" field — empty state shows "Click to add an issue id";
  set state shows `[BDS-345]` either as a clickable link (project has
  template) or muted text with a tooltip nudging the owner to add one.
  Pencil icon arms the editor.
- **Draft modal got the same field.** Following the Estimate
  pattern: read mode shows "Click to set" or `[BDS-345]`, click flips
  into the input. On submit, if non-empty, fires `setTaskExternalId`
  after `addTask` so the create flow doesn't bypass the new op.
- **TaskModalDraft footer.** Pulled the Create button out of
  `modal-main` into a real `.modal-footer` with a top border, sticky
  to the bottom of the modal. Added a Cancel button next to it for
  symmetry. Old layout had the button float wherever the
  description/subtasks ran out — felt detached from the modal.

### Three-state PATCH for nullable fields

The `external_url_template` PATCH brought the absent / null / set
distinction up properly: a missing key leaves the column alone, a
JSON `null` clears it, a string sets it. Implemented with a
`deserialize_explicit_option` helper (`Option<Option<String>>`) since
we don't carry `serde_with`. Applied this convention to the frontend
too — the modal sends `null` to clear, omits the key to leave alone.

## Decisions worth keeping

- **Soft-delete over hard-delete on `project_members`.** Hard delete
  via FK CASCADE would unwind cleanly for the membership row but
  leaves the door open for stale `task.assignee_id` rows that point
  at a user no longer associated with the project. Soft-delete keeps
  the audit trail intact and makes "Anna used to be on this project"
  expressible later without another migration.
- **Owner is implicit in `set_project_members_tx`.** The handler
  doesn't trust the client to include the owner in the desired set —
  if the caller is the owner and the wire payload omits them, we
  add them anyway. Treats owner-membership as an invariant of the
  schema, not a UI contract.
- **Two ops, not one super-op.** Splitting `project.update` from
  `project.set_members` paid off when writing the apply path: the
  removal-from-project case is its own clearly-bounded code path
  ("if I'm not in members, drop this and everything tied to it")
  rather than an `if (members.changed)` branch tucked inside a
  visual-update handler.
- **Change-feed scope cap by `applied_at <= removed_at`.** Without
  the cap, a former member would see all the project's ongoing
  activity forever via `/changes` even though they're no longer in
  the bootstrap scope. With the cap, they get exactly the terminal
  removal op and nothing after — minimal read leak, single dispatch.
- **`{key}` over `{}` or `%s`.** Reads as a placeholder to a human
  glancing at the template field; fewer questions in support.
- **Friction on remove, none on add.** Two-step remove (× → Remove)
  came directly from "removing someone is a heavier action than
  adding them." Add is one click and auto-closes; if you want to
  add another, click "Add member" again — no batched mode, no
  "Done" button.
- **`block.user_id` follows the calendar, not the task.** Multiple
  people working on the same task is a real case (pair programming,
  a senior reviewing a junior's PR). Tying the block to the task's
  assignee at drop-time would have collapsed that distinction.
- **Caller floats to top in pickers.** `meId` first, then alphabetical.
  Assigning to yourself is the common case; you shouldn't have to
  scan past teammates to reach your own avatar.

## Things that bit us

- **The inbox "(you)" hardcode.** Easy fix once spotted, but
  conceptually it had been wrong since sprint 02 — nobody noticed
  because nobody had logged in as anyone but Maya. Real teammates +
  dev-login swap exposed it instantly.
- **`fmtMin` on negative minutes.** `Math.floor(-255 / 60) = -5` and
  `-255 % 60 = -15` made `fmtMin(-255)` render `-5h-15`. The "Time
  left" column is the only place that exercises negatives, and the
  bug had been latent since sprint 02. Sign-aware split (extract sign,
  format the magnitude) drops it back to `-4h15`.
- **Bootstrap binary stamp lag.** During testing the user reported
  that time blocks for teammates still weren't loading after the fix.
  Cause: `cargo check` compiles but doesn't update `target/debug/fira-api`,
  so the running binary was the pre-fix one. Worth remembering when
  diagnosing "I changed the code, it doesn't work" — the binary's
  mtime is the truth.
- **Popover overflow inside modals.** First Members editor used
  `position: absolute; top: calc(100% + 4px)`, which the parent
  `.modal { overflow: hidden }` clipped at the bottom. Inline
  expansion (the picker becomes part of the bordered container)
  sidesteps the overflow constraint entirely.
- **`.map()`-based apply for `project.update` no-op'd on first sight.**
  When a user gets newly added to a project, the `project.update` op
  hits their client first — and `s.projects.map(p => p.id === op.project.id ? ...)` returns
  unchanged when the project doesn't exist locally. Switched to upsert
  so the project shows up immediately rather than waiting for the next
  bootstrap.

## Verification

```
$ cd api && cargo check                # clean (2 pre-existing warnings)
$ cd web && pnpm exec tsc --noEmit     # clean
```

Manual (logged in as Anna in one tab, Maya in another):

| scenario                                                          | result |
|-------------------------------------------------------------------|--------|
| Maya adds Anna to a new project via Members editor                | Anna's tab gets the project on next /changes poll, with sidebar entry + project filter on |
| Maya removes Anna from a project                                  | Anna's tab drops the project, its tasks, blocks, and inbox-filter target |
| Anna pins Maya, switches active person                            | Maya's blocks render on Anna's calendar week |
| Anna toggles "All" in the rail, drags Maya's task onto her week   | Block created with `user_id = Anna`, shows on Anna's calendar |
| Anna sets task `external_id = "BDS-345"` with project template    | Side panel shows `[BDS-345]` linking to `https://acme.atlassian.net/browse/BDS-345` |
| Same task, no project template                                    | `[BDS-345]` shown as muted text, tooltip nudges to set template |
| Time-left column on overdue task                                  | reads `-4h15` instead of `-4h-15` |
| Inbox while logged in as Anna                                     | Anna's group floats to top, marked "(you)"; Maya's group below not marked |

## What's deferred

- **Inviting a brand-new email.** The Members picker can only add
  people already in the `users` table. A magic-link / dev-only "create
  user" flow could plug the gap for genuine onboarding; nobody has
  asked yet.
- **Re-add a removed user via `/changes`.** Right now the
  `project.set_members` op that re-adds a member only works because
  the broadened scope query looks up active membership freshly each
  request. We don't track "user was re-added at seq X" cleanly — fine
  for now, would need rethinking if we ever want a UI surface for
  membership history.
- **Automated issue sync.** Issue links are manual entry only. Pulling
  status, summary, or due date from Jira is the natural next step but
  a sprint of its own.
- **Per-template URL helpers.** Some trackers don't have a stable URL
  pattern (e.g., GitHub orgs vs. repos). Right now the user types the
  full template; offering "Jira", "Linear", "GitHub" presets would
  be friendlier.

## Next sprint candidates

1. **Deployment** — carried over from sprints 05 + 06.
2. **Real-time push (SSE)** — drop the 2s poll once the company-mode
   collab use case warrants it.
3. **Issue sync v1** — pull status / summary from Jira given the
   project's URL template + an API token.
4. **Per-tracker URL presets** — small UX win on top of the manual
   template field; one dropdown saves four URLs of typing.
