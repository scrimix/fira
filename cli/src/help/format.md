# task-cli file format

Task documents live under the tasks root, the directory holding
`config.toml` (usually `tasks/`):

```text
tasks/
  config.toml           # Fira URL and project; committed, no secrets
  sprints/*.md          # one file per sprint
  single/*.md           # one file per unscheduled task
  assets/<task-id>/     # files belonging to a task (local only for now)
```

File names are for people. Renaming a file or retitling a task changes
nothing in sync: identity is the `id=` / `sprint_id` UUID, which the CLI
generates. Never edit or invent one.

## Sprint file

```md
---
sprint_id: 9a1d2c3e-0000-4000-8000-000000000001
starts_on: 2026-11-09
ends_on: 2026-11-23
track: Platform
tags: [frontend]
assignee: rihard.g
---

# Initial scaffolding

Sprint description: any prose, including plain headings. Local only.

## ⬜ Application shell
<!-- task: id=9a1d2c3e-0000-4000-8000-000000000002 tags=frontend,layout estimate=4h -->

Build the application shell.

### Subtasks

- [x] Navigation
- [ ] Sidebar

## 🚧 Routing
<!-- task: id=9a1d2c3e-0000-4000-8000-000000000003 -->
```

- The first `#` heading is the sprint title. Everything between it and the
  first task is the sprint description.
- A heading that starts with a status marker is a task:
  ⬜ todo, 🚧 in progress, ✅ done. You may type `[ ]`, `[~]` or `[x]`
  instead; `task-cli fmt` turns them into the emoji (brackets in a heading
  render as plain text, emoji render everywhere).
- A task's body runs to the next task heading. Its description is the body
  without the `task:` comment and the Subtasks section.
- A `Subtasks` heading under the task holds its checklist (`- [ ]` /
  `- [x]`, one line each). It must come last in the task.
- Frontmatter keys, all optional: `sprint_id`, `starts_on`, `ends_on`,
  `track`, `tags` (a `[a, b]` list), `assignee`.
- Dates are Mondays and the range is end-exclusive (a two-week sprint
  starting 2026-11-09 has `ends_on: 2026-11-23`). Give both or neither.
- Sprint `tags` and `assignee` apply to every task in the file that doesn't
  set that key. A task's own `tags=` replaces the sprint's (`tags=bug`
  means only `bug`; `tags=""` means none); `assignee=""` means nobody.

## Single task file

```md
# ⬜ Login redirects to the wrong page
<!-- task: id=9a1d2c3e-0000-4000-8000-000000000004 tags=bug,authentication assignee=rihard.g -->

After signing in, the user lands on an empty screen.

## Subtasks

- [ ] Reproduce the redirect
- [ ] Fix callback handling
```

One task per file, its heading is the title. Single tasks inherit nothing.

## The task comment

One `<!-- task: … -->` per task, canonically on the line under the heading,
holding `key=value` pairs:

| key | value |
|---|---|
| `id` | UUID, inserted by `task-cli fmt` or the first publish |
| `tags` | comma-separated: `tags=bug,"needs review"`; each must already exist in the Fira project (leads create tags there) |
| `assignee` | a handle: first name, dot, surname initial (`maya.c` for Maya Chen); see below |
| `estimate` | `4h`, `30m`, `1h30m` |

Assignee handles are derived from Fira display names. When two members
would share one, the surname grows until they differ (`maya.ch`,
`maya.co`). A full email also works. A handle that matches nobody (a
rename, someone left, a longer handle after someone joined) is an error
that suggests the likely member; `task-cli diff` shows it before anything
is written.

Every key is optional; a hand-written task can leave out the comment
entirely and the CLI adds one. Unknown keys are an error.

Parsing is lenient: the comment may sit anywhere in the task body (some
editors move it), and typed markers like `[ x ]`, `[X]`, `[ ~ ]` are
accepted. `task-cli fmt`
normalises these. Headings, checklists and comments inside fenced code
blocks are content.

## Moving and removing

- Sprint membership is the file a task is in. To move a task, cut its block
  and paste it into another file (adjusting the heading level); its id
  stays the same.
- Deleting a block does not delete the task in Fira. Delete it in Fira.
