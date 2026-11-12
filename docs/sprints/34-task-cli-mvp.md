# Sprint 34 — task-cli MVP: repository documents ↔ Fira

**Status:** built; dogfooding pending
**Date:** 2026-11-11

## Goal

Maintain human-writable sprint and task documents in a repository and sync
them with Fira through `task-cli`, with a mandatory field-level diff before
any write. This sprint delivers the document format, the canonical model,
the diff engine, and the Fira target. Attachments and the release pipeline
follow in [sprint 35](35-task-cli-attachments.md), write-only Notion in
[sprint 36](36-task-cli-notion.md); both build on the design below.
Later references to "sprint 35" below predate that split.

## Prerequisite

Sprint 33's database backups and restore verification must be working before
production CLI writes are enabled.

## Architecture

One CLI, `task-cli`, with Fira as its target in this sprint and Notion added
in sprint 35. The repository is the only bridge between services; there is no
direct Fira ↔ Notion sync.

```text
Repository documents -> task-cli publish fira -> Fira
Fira                 -> task-cli import fira  -> repository documents
```

**The repository owns identity.** Every sprint and task gets a UUID generated
locally by the CLI and committed with the document. Fira uses that same UUID
as its own ID (the web client already creates IDs client-side, so the server
accepts them). No service IDs or mapping files are stored in the repository.

**Canonical model, two-way diff.** The Markdown and Fira sides each have a
converter to one canonical sprint/task model. Every import and publication
converts both sides and shows a field-by-field diff:

```text
task "Application shell"
  status    fira: todo          local: in_progress
  tags      fira: frontend      local: frontend, layout
  subtasks  fira: [ ] Sidebar   local: [x] Sidebar
```

**Nothing is written anywhere, local or remote, until the user accepts the
diff.** Publish and import run the same procedure: fetch the other side,
convert both to canonical, diff. For every differing field the user picks
local or remote, or aborts. The chosen values are written to *both* sides,
so after any accepted run the file and Fira agree. That is the merge
procedure.

No last-synced state is stored, so the CLI cannot tell which side changed a
field and pre-selects nothing. The two commands differ only in scope:
`publish` takes a local file and may create remote objects; `import` takes a
remote object and may create local text.

Fira stays fully editable.

### Completion

- Subtasks: `[ ]` / `[x]` → not done / done.
- Tasks: ⬜ / 🚧 / ✅ → `todo` / `in_progress` / `done` (typed `[ ]` /
  `[~]` / `[x]` are accepted and normalised to the emoji).
  `backlog` is deprecated: it imports as `[ ]` and the CLI never writes it.
  The CLI does not move tasks between list sections.

### Intake

New bugs and features may originate in Fira without a sprint. Intake is an
explicit import with a preview, landing in `tasks/single/`.

## Repository layout

```text
tasks/
  config.toml
  sprints/
    001-initial-scaffolding.md
    002-cli-publishing.md
  single/
    login-redirect-bug.md
  assets/
    <task-id>/
      layout.png
      llm_ctx.md
```

- A sprint is one file; a single (unscheduled) task is one file.
- `assets/<task-id>/` holds files belonging to that task; only tasks have
  assets. In this sprint they are local only: links work in the repository
  and are not synced (see sprint 35).
- File names are for people only. Renaming a file or retitling a task changes
  nothing in sync. Imports name files after a slug of the title, adding a
  suffix on clashes.
- Sprint membership is the file a task is in. Moving a task is cut and paste
  of its block; its ID and assets stay the same.
- Everything under `tasks/` is committed. Credentials never are.
- `tasks/` may be a plain directory or a git submodule. The tasks root is the
  directory containing `config.toml`, found by walking up from the current
  directory, not the git top level.

### Sprint file

```md
---
sprint_id: <automatically inserted UUID>
starts_on: 2026-11-09
ends_on: 2026-11-23
track: Platform
tags: [frontend]
assignee: rihard.g
---

# Initial scaffolding

Sprint description: any prose, including plain headings.

## ⬜ Application shell
<!-- task: id=<automatically inserted UUID> tags=frontend,layout estimate=4h -->

Build the application shell.

![Layout](../assets/<task-id>/layout.png)

### Subtasks

- [x] Navigation
- [ ] Sidebar

## 🚧 Routing
<!-- task: id=<automatically inserted UUID> -->
```

- The top `#` heading is the sprint title. A heading that starts with a
  status marker (⬜ 🚧 ✅, or a typed `[ ]`/`[~]`/`[x]`) is a task. Everything between the title and
  the first task is the sprint description.
- A task's body runs to the next task heading. A `Subtasks` heading directly
  under the task holds its checklist.
- Dates follow Fira's Monday-aligned, end-exclusive range. An unscheduled
  sprint may omit dates; validate date pairs and ranges before publication.
- Fira sprints have no description field yet, so in this sprint the sprint
  description is local only and not compared. (Synced since
  [sprint 37](37-sprint-description-and-task-order.md).)

### Single task file

The same task format, one task per file, with the title as the top heading:

```md
# ⬜ Login redirects to the wrong page
<!-- task: id=<automatically inserted UUID> tags=bug,authentication assignee=rihard.g -->

After signing in, the user lands on an empty screen.

## Subtasks

- [ ] Reproduce the redirect
- [ ] Fix callback handling
```

### Task metadata comment

Each task has one `<!-- task: … -->` comment, canonically on the line
directly under its heading, holding space-separated `key=value` pairs: `id`,
`tags` (comma-separated), `assignee`, `estimate`. Values containing spaces are
quoted, e.g. `tags="needs review",bug`. All keys are optional; a hand-written
task can omit the comment entirely and the CLI adds it with a new ID. Unknown
keys are an error, not silently dropped.

### Tolerant parsing, strict `fmt`

WYSIWYG Markdown editors (e.g. VS Code's Office Viewer) move comments with
their block but may leave blank lines between heading and comment, and people
type checkbox variants like `[ x ]` by hand. So:

- **Parsing is lenient.** A task's comment is the single `task:` comment
  anywhere in its body (up to the next task heading), not only the line
  under the heading. Two `task:` comments in one task is an error (likely a
  copy-paste). Heading checkboxes accept `[x]`, `[X]`, `[ x ]`, `[~]`,
  `[ ~ ]`, `[ ]`. `publish`, `import` and `diff` work on such files without
  running `fmt` first.
- **`task-cli fmt` normalises structure only:** moves each `task:` comment
  directly under its heading, rewrites status markers to ⬜ / 🚧 / ✅,
  inserts missing IDs, and orders comment keys (`id` first). It never
  changes prose, blank lines inside descriptions, or wrapping, and follows
  the local file safety rules.
- `publish` and `import` do not reformat; their local writes stay surgical.
  `fmt --check` exits 1 if anything would change, for a pre-commit hook.

### Inheritance

Sprint frontmatter `tags` and `assignee` apply to every task in the file that
omits that key. Inheritance is live: changing the sprint's `tags` changes the
canonical tags of every inheriting task, and the next publication diff shows
it. A key on the task replaces the sprint value rather than adding to it
(`tags=bug` means only `bug`). Single tasks inherit nothing.

The sprint's `tags` / `assignee` are also published as its Fira sprint
defaults, so tasks created in the Fira UI pick them up too. On import, task
keys equal to the sprint's values are omitted to keep the file clean.

## Identity and structured fields

- [x] Generate sprint/task UUIDs locally and insert them on first publish or
      on an explicit `task-cli fmt`. Reject duplicate IDs across `tasks/`
      (e.g. a copy-pasted task block).
- [x] Fira API: create sprints and tasks with client-supplied UUIDs from the
      CLI, as the web client already does.
- [x] Fira API: report whether a task/sprint ID exists, was deleted, or never
      existed. Deletes are hard, but `task.delete` ops remain in
      `processed_ops`, which is never pruned.
- [x] Parse Markdown with a real parser; headings, checklists and `task:`
      comments inside fenced code blocks are content.
- [x] Implement tolerant parsing and `fmt` as described above; test against
      files saved by a WYSIWYG editor (blank lines around comments) and
      hand-typed checkbox variants (`[ x ]`).
- [x] Treat subtasks as an ordered value list of title and completion.
      Publish additions, edits, order, and removals to match it. Subtasks have
      no user-visible IDs.
- [x] Support task title, description, completion, sprint membership, tags,
      assignee, and estimate; sprint title, dates, track, and default
      tags/assignee.
- [x] Resolve users explicitly and tags/tracks within project scope. Never
      silently pick an ambiguous display name or create memberships.
- [x] Unsupported Fira fields, including list section, remain unmanaged;
      spent time and audit history are never overwritten.

## CLI

Distinct verbs rather than push/pull. The target is always explicit, so
sprint 35 can add `notion` without changing existing commands.

```sh
task-cli init                              # create tasks/config.toml
task-cli login fira
task-cli fmt [file] [--check]              # insert missing IDs, normalise structure lines
task-cli publish fira <sprint-or-task-file>
task-cli import  fira <url-or-id> [--into <file>]
task-cli diff    [file...]                 # read-only: working copy vs Fira
```

A task import need not select a sprint; without `--into` it lands in
`tasks/single/`.

- [x] Fetch current remote state, validate scope, and show the field-level
      diff before every import and publication; ask before writing.
      `--dry-run` never mutates. Without a TTY the CLI fails unless
      `--prefer local|remote` is given, which answers every differing field
      in that direction for unattended runs.
- [x] Show subtask list changes in the diff.
- [x] Refuse writes when remote state changed between preview and write, using
      server-side revision preconditions.
- [x] Make retries safe. Because IDs are assigned locally, creates are
      idempotent; an interrupted run is resumed by publishing again.

### Diff mode

`task-cli diff` is read-only: it converts the working copy (including
uncommitted edits) and Fira to canonical, matches by ID, and shows the
differences. It never prompts and never writes. Sprint 35 adds remote HEAD
and Notion columns.

```text
sprint "Onboarding"  (tasks/sprints/001-onboarding.md)
  task "Welcome screen"
    title     current: Welcome flow   fira: Welcome screen
    subtasks  current: [ ] Copy       fira: [x] Copy
  task "Email verification"           in sync
  only in fira:  "Password reset" (in this sprint, in no file)
  deleted:       "Old banner" (deleted in Fira, still in repo)
```

- Without arguments it covers everything under `tasks/`; with files, only
  those.
- Fields that agree everywhere are hidden; `--all` shows them.
- Exit code 0 when in sync, 1 on differences, 2 on errors, so it can run in
  CI or a pre-commit hook. `--json` emits the same comparison for scripts.

### Diff presentation (provisional)

A starting point modelled on git, to be revised after real use:

- `task-cli diff` prints coloured text through `$PAGER` (default `less -R`).
  Piped or with `--no-pager` it prints plain text.
- `publish` / `import` first show the full diff in the pager, then ask per
  differing field, like `git add -p`:

  ```text
  task "Welcome screen"  (tasks/sprints/001-onboarding.md:12)
    title   local: Welcome flow
            fira:  Welcome screen
  [l]ocal [r]emote  [t] task: all local  [T] task: all remote
  [L] everything local  [R] everything remote  [s]kip  [q]uit  [?]
  ```

- Long text fields (descriptions) show a unified line diff inside the field.
- After the last answer, a summary ("Fira: 3 updates, 1 create; local: 2
  files") and a final `[y/N]`. `q` at any point writes nothing.

Later options, only if real use asks for them: `--edit` (a `git rebase -i`
style plan file in `$EDITOR`) and a full-screen TUI on the same diff data.

- [ ] Dogfood the CLI on this repository's own sprints for at least a week
      before calling the interaction design done; record what was annoying
      and adjust prompts, defaults, and shortcuts.

### Removal and deletion

**Absence is never a signal, in either direction.** A task can be missing
because it was deleted, moved, accidentally cut, never imported, or the file
comes from an old branch; the CLI cannot tell these apart, so it never acts
on absence alone.

- Publishing a file only touches the tasks in that file. A Fira task that is
  in the sprint but in no local file is listed as "only in Fira, not
  touched": not deleted, not removed from the sprint.
- Import never deletes or moves local text because something is missing
  remotely.
- The only implicit move is presence elsewhere: the same ID in a different
  file means the task moved, and membership follows the file.
- A local task deleted in Fira (per the existence check) is resolved by
  asking: recreate (same ID), delete locally, or skip. There is no default;
  with `--prefer` the answer is always skip.
- The CLI never deletes remotely in this sprint. Deleting a task in the file
  and publishing does not delete it in Fira; delete it in the Fira UI.
  An explicit `task-cli delete` follows in sprint 35.

### Sprint import

- A sprint import writes `tasks/sprints/<slug>.md` with frontmatter, title,
  and all of the sprint's tasks. If a file with that `sprint_id` exists, it
  is updated in place through the normal diff. `--into` does not apply.
- Tasks that already exist in another local file are moved into the sprint
  file; the move is shown in the diff.
- Tasks in the local file that are no longer in the remote sprint follow the
  removal rules: listed, never moved or deleted by default.
- Task order is taken from Fira on first import and is not managed after that.
  (Compared and synced since [sprint 37](37-sprint-description-and-task-order.md).)
- The sprint's frontmatter `tags`/`assignee` come from the Fira sprint
  defaults; task keys equal to them are omitted.

### Local file safety

Users will often have unstaged edits in `tasks/` while running the CLI. The
CLI must never lose them:

- **No clean-tree requirement.** The CLI works on the working copy as it is,
  unstaged edits included.
- **Surgical edits.** Local writes change only the lines the accepted diff
  names (an inserted comment, a heading checkbox, a field value, a moved task
  block). Everything else stays byte-for-byte identical.
- **No lost updates.** The CLI hashes each file when it reads it and checks
  again just before writing. If the file changed in between (e.g. saved in
  an editor while the prompt was open), that file is skipped with a message.
- **Atomic writes.** Write to a temporary file and rename.
- **Backup before touching dirty files.** Before writing a file with
  uncommitted changes, copy it to `<git-dir>/task-cli/backups/<timestamp>/`
  (inside `.git`, so never committed; works for submodules too).
- **Read-only git.** The CLI never runs git commands that touch the working
  copy, index, or branches (`checkout`, `stash`, `reset`, `commit`, `add`).

### Help

Help is built into the binary, so it always matches the installed version.
The same text serves humans and LLM agents; there is no separate skill.

```sh
task-cli --help                 # commands, one line each
task-cli <command> --help       # flags, examples, exit codes
task-cli help format            # file format reference
task-cli help workflow          # the common loop: write, fmt, diff, publish
task-cli help agents            # everything an LLM agent needs, in one page
```

- `help format` is complete enough to write valid files without reading this
  document, with one full example per file type.
- `help agents` prints one self-contained Markdown page: the format, the
  rules that matter most (never edit or invent `id=`; deleting a block does
  not delete the task), and the safe non-interactive commands: `fmt`,
  `diff --json`, `publish --dry-run`. Agents must not run `publish`/`import`
  with `--prefer` unless the user explicitly asked, since that skips the
  human diff review.
- Commands detect a missing TTY and point to `--dry-run`, `diff --json` or
  `--prefer` instead of hanging on a prompt.
- Errors name the file and line, say what is wrong, and what to do next
  (e.g. `tasks/sprints/001-onboarding.md:14: unknown key "tag" in task
  comment; did you mean "tags"?`).
- A repository using `task-cli` needs one line in its agent instructions
  (e.g. `CLAUDE.md`): "Run `task-cli help agents` before editing `tasks/`."

## Authentication and installation

- [x] Add scoped, revocable Fira automation tokens, storing token hashes on the
      server and enforcing existing workspace/project authorization. Do not
      reuse browser cookies.
- [x] Keep credentials outside the repo, each developer using their own.
      Support a permission-restricted config directory mounted as a
      persistent dev-container volume. `tasks/config.toml` contains only
      non-secret connection and project data.
- [x] Build `task-cli` as a separate Rust crate `cli/`, not a bin in `api/`,
      so the server's dependencies stay out of it. It talks to Fira over HTTP
      with an automation token like any other client.
- [x] Install with `cargo install --git … --tag cli-v…`. Prebuilt releases
      follow in sprint 35.

## Test scenario: basic workflow

Run end to end against a dev Fira instance, never production.

1. **Set up.** `task-cli init`, `task-cli login fira`.
   → `tasks/config.toml` exists; the credential is stored outside the repo.

2. **Write a sprint by hand.** Create `tasks/sprints/001-onboarding.md` with
   dates, `tags: [frontend]`, and two tasks without comments: "Welcome
   screen" (two subtasks) and "Email verification" (with
   `<!-- task: tags=backend -->`). Create `tasks/single/login-redirect-bug.md`.

3. **Format.** `task-cli fmt`.
   → Every task has `<!-- task: id=… -->`, the sprint has `sprint_id`. No
   other text changed. Nothing is sent anywhere.

4. **First publish.** `task-cli publish fira tasks/sprints/001-onboarding.md`.
   → The diff lists the sprint and both tasks as new. "Welcome screen" shows
   inherited tag `frontend`, "Email verification" only `backend`. Accept.
   → In Fira: the sprint has the dates, the tasks have the same UUIDs as the
   file, the subtasks are in order.

5. **Republish without changes.** → Empty diff, nothing written.

6. **Edit on both sides.** In Fira, tick one "Welcome screen" subtask and set
   "Email verification" to in progress. In the file, change the "Welcome
   screen" description, without committing.

7. **Publish.**
   → Exactly three differing fields, none pre-selected. Pick remote for the
   subtask and status, local for the description.
   → Fira has the new description; the file has `[x]` and `[~]`. `git diff`
   shows only those lines plus the earlier description edit. Republishing is
   an empty diff.

8. **Same field on both sides.** Change the "Welcome screen" title in Fira
   and in the file, then publish.
   → The diff shows both titles. Pick Fira's. → Both sides have it.

9. **Import.** Change a task's estimate in Fira, then
   `task-cli import fira <sprint>`.
   → The estimate is the only difference; after accepting, the file has it.

10. **Plan the bug into the sprint.** Publish the single bug, then cut its
    block into the sprint file (changing the heading level) and delete
    `single/login-redirect-bug.md`. Publish the sprint.
    → The diff shows the bug joining the sprint and inheriting `frontend`.

11. **Remove a task locally.** Delete the "Email verification" block and
    publish. → Listed as "only in Fira, not touched"; it stays in Fira.

12. **Delete a task in Fira.** Delete "Welcome screen" in the Fira UI, then
    publish. → The CLI asks: recreate / delete locally / skip. Skip changes
    nothing.

13. **Overview.** Change a title in Fira only, then `task-cli diff`.
    → The title difference plus the notices from steps 11–12. Exit code 1.
    Nothing written.

14. **Fresh clone.** Clone the repo elsewhere, log in, publish.
    → No field differences; only the notices from steps 11–12.

## Acceptance criteria

- [x] Handwrite a sprint file and a single task without IDs, preview, confirm
      publication, and see the same UUIDs in the files and in Fira.
- [x] Repeated publication has an empty diff. Renaming a file, retitling a
      task, or moving a task between files keeps its identity.
- [x] Changing sprint `tags` shows the change on every inheriting task; a task
      with its own `tags=` is unaffected.
- [x] Subtask edits/reorder/removal round-trip as an ordered checklist.
- [x] ⬜ / 🚧 / ✅ (or typed `[ ]` / `[~]` / `[x]`) round-trip as `todo` / `in_progress` / `done`; a
      `backlog` task imports as `[ ]`; list sections are never changed.
- [x] Import existing Fira work, edit it locally and publish; no duplicates,
      and a field also edited in Fira shows up in the diff for a decision.
- [x] Removing a task block locally and publishing leaves it untouched in Fira
      and lists it as "only in Fira". Deleting a task in Fira makes the next
      publish ask what to do. The CLI never deletes remotely.
- [x] Import a Fira sprint into a new file, then again after remote edits;
      the second import updates the same file and moves nothing silently.
- [x] With unstaged edits in a sprint file, `fmt`, `import` and `publish`
      change only the lines named in the accepted diff. Saving the file in an
      editor while the prompt is open makes the CLI skip that file.
- [x] `task-cli diff` writes nothing and exits 0 only when in sync.
- [ ] An LLM agent given only "run `task-cli help agents`" can create a valid
      sprint file, run `fmt` and `diff --json`, and stops before publishing
      without explicit permission.
- [x] The scenario passes with `tasks/` as a plain directory and as a
      submodule.
- [x] Cancellation, stale state, missing permissions, interrupted requests, and
      partial API failures preserve data and give actionable recovery steps.
- [x] Parser, authorization, idempotency, and end-to-end tests, including
      fenced Markdown, duplicate IDs, and inheritance.

## Out of scope

Everything in sprint 35 (Notion, attachments, sprint descriptions in Fira,
remote-HEAD diff, `delete`, release pipeline). Also: calendar, time logging,
automatic merging beyond an explicit `--prefer`, stored sync state,
background sync, LLM-driven interpretation, and automatic task
splitting/merging.

## Built

**Server** ([`api/src/cli_api.rs`](../../api/src/cli_api.rs), migration
[`0037_task_cli.sql`](../../api/migrations/0037_task_cli.sql)):

- `automation_tokens`: per (user, workspace), sha256 hash only, read-only or
  write, revocable. Membership is re-checked on every request. Tokens are
  accepted *only* by `/api/cli/*` (the `CliCtx` extractor); every other
  route still requires a browser session, so a token cannot bootstrap,
  change settings or mint tokens. Managed in Account settings →
  Automation tokens (`GET/POST /api/automation-tokens`,
  `DELETE /api/automation-tokens/:id`, session only).
- `revision` on `tasks` and `sprints`, from one sequence, bumped by
  triggers when a field the CLI manages changes. Child rows (subtasks,
  task tags, sprint default tags) bump their parent. `sort_key` and
  `updated_at` churn does not, so dragging in the UI causes no false
  conflicts.
- `GET /api/cli/whoami`; `POST /api/cli/fetch` returns the project's
  members (with `active`), tags, tracks, the requested sprints and tasks
  with revisions, and `missing` for each requested id: `deleted` (a delete
  op is in the project's `processed_ops`), `other_project`, or `never`.
  Only projects in the caller's scope are consulted.
- `POST /api/cli/apply`: preconditions plus ops in **one transaction**.
  Revisions are locked `FOR UPDATE` and checked (409 lists the conflicts);
  every op goes through the same `ops::apply_payload` as the web outbox and
  is logged to `processed_ops` with `pg_notify`, so open browsers update
  live. An allow-list rejects deletes of tasks/sprints, blocks and goals.
  A retried `op_id` is skipped. The `processed_ops` insert was factored
  out of `apply_one` into `ops::log_op` so both paths share it.

**CLI** ([`cli/`](../../cli/), a standalone crate with no dependency on
`fira-api`): `doc.rs` (pulldown-cmark structure, tolerant parsing with
byte ranges), `write.rs` (fmt, surgical task/frontmatter edits,
inheritance-aware comments, block moves, rendering), `sync.rs` (canonical
model on both sides, comparison, allowed choices per field, plan of ops and
local edits), `ui.rs` (text/JSON diff, pager, per-field prompts),
`safety.rs` (hash check, `.git/task-cli/backups`, atomic writes, read-only
git). Help pages are compiled in (`help format|workflow|agents`).

Decisions made while building:

- Login pastes a token created in the web UI (or pipes it in for CI;
  `TASK_CLI_FIRA_TOKEN` also works). Credentials live in
  `~/.config/task-cli/credentials.toml` (0600). The dev container bind-mounts the
  host's directory, so one login serves every project's container. Login also fills `workspace_id`/`project_id` in
  `config.toml`.
- Tags and tracks are project structure, managed only by project leads
  and workspace owners. The server now enforces that for every `tag.*` and
  `track.*` op (`ensure_scope::require_project_lead`), which closes a hole
  where any member could create them. The web pickers no longer offer
  "create" (tags live in project settings), and plan-view track controls
  show only for editors. The CLI never creates them: a tag or track named
  in a file that isn't in Fira stops the run before the diff, listing the
  existing ones. A name differing only in case is the same error with the
  right spelling. The `dev` role no longer creates tracks either.
- Assignees are written as handles, never emails: first name, dot, and
  the shortest surname prefix that is unique among the project's
  *members* (`maya.c`; `maya.ch`/`maya.co` when two collide; `-2` for
  identical names). Reading is exact: no prefix matching, so a handle
  that stops fitting (rename, someone leaving, a newcomer lengthening it)
  matches nobody and the error suggests the likely member. Former members
  referenced by old tasks never shift members' handles. A full email is
  also accepted. Only active members can be newly assigned.
- Task headings carry an emoji status (⬜ 🚧 ✅) instead of `[ ]`/`[~]`/`[x]`:
  a checkbox only renders inside a list item, so in a heading it showed
  as literal brackets in every viewer. Typed brackets are still accepted;
  `fmt` (and any status change by publish/import) writes the emoji.
  Subtasks stay a standard `- [ ]` task list (VS Code's built-in preview
  needs the `bierner.markdown-checkbox` extension to draw those).
- Choices that can't be applied are refused with a reason. Two cases:
  clearing sprint dates (no op exists for it), and moving a task to a
  sprint that has no local file (import the sprint first).
- When a sprint's tags or assignee change, tasks that inherited the old
  value get it written explicitly, so they don't change silently.
- A Subtasks section must be last in its task, and subtasks are one line
  each. Text after the list is an error rather than being dropped.
- A remote write happens before local writes. If a file changed on disk
  while the prompt was open, nothing is written at all. If it changes in
  the tiny window after the remote write, that file is skipped with a
  message, and a rerun brings it in line.

Verified: 66 existing API tests plus 8 new ones (revisions, all-or-nothing
apply, stale preconditions, idempotent retry, rejected kinds, existence,
token hashing/revocation/membership); 32 CLI unit tests (parser, fmt
idempotence, surgical edits, inheritance, subtask op planning). The
14-step test scenario was run end to end against a local API on a scratch
database. Also checked: a Fira edit while the prompt is open gives a 409
and nothing is written; an editor save while the prompt is open aborts
the run; no-TTY publish fails with the hint; sprint import into a new
file; task import by link; a remote sprint move relocating a block and
removing its single file; a sprint-defaults change pinning tasks; `tasks/`
as a submodule (backups land in `.git/modules/tasks/`).

Still open: dogfooding on this repository for a week, the LLM-agent
acceptance check, and enabling write tokens against production.

