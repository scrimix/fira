# task-cli for LLM agents

This page is everything you need to edit task documents in this repository.

## Rules that matter most

1. **Never edit or invent `id=` or `sprint_id`.** Leave them out of new
   tasks; `task-cli fmt` generates them. Changing one breaks the link to
   Fira; a copied one is a duplicate-id error.
2. **Deleting a task block does not delete the task in Fira.** It is only
   listed as "only in Fira". Tell the user if a task should be deleted.
3. **Do not publish or import unless the user explicitly asked you to.**
   Even then, never pass `--prefer`: it skips the human review of the diff.
   Run `publish … --dry-run` and show the user what would change instead.
4. Keep prose as the user wrote it. Change only what you were asked to.

## Safe commands (never write to Fira, never prompt)

```sh
task-cli fmt                      # add ids, normalise structure; prose untouched
task-cli fmt --check              # exit 1 if fmt would change something
task-cli diff --json              # working copy vs Fira, machine-readable
task-cli publish fira <file> --dry-run
```

`diff` exits 0 in sync, 1 on differences, 2 on errors.

## Where things go

- `tasks/sprints/<name>.md`: one sprint per file.
- `tasks/single/<name>.md`: one unscheduled task per file.
- `tasks/assets/<task-id>/`: files belonging to a task.
- A task's sprint is the file it is in. Moving a task = moving its block
  (heading `##` in sprint files, `#` in single files).

## Sprint file

```md
---
starts_on: 2026-11-09
ends_on: 2026-11-23
tags: [frontend]
---

# Onboarding

Optional sprint description.

## ⬜ Welcome screen

What to build, in Markdown.

### Subtasks

- [ ] Copy
- [ ] Illustration

## ⬜ Email verification
<!-- task: tags=backend estimate=4h -->
```

## Single task file

```md
# ⬜ Login redirects to the wrong page
<!-- task: tags=bug assignee=rihard.g -->

After signing in, the user lands on an empty screen.

## Subtasks

- [ ] Reproduce the redirect
```

## Format details

- Task heading: a heading starting with ⬜ (todo), 🚧 (in progress) or
  ✅ (done). `[ ]` / `[~]` / `[x]` also work; `task-cli fmt` converts them.
  Subtasks stay a normal `- [ ]` / `- [x]` checklist.
- Task comment `<!-- task: … -->`, optional, under the heading:
  `tags=a,b` (quote values with spaces: `tags="needs review",bug`; only
  tags that already exist in Fira, never invent one),
  `assignee=<handle>` (`maya.c` = Maya Chen; take it from an existing file or the error message, never guess), `estimate=4h|30m|1h30m`. No other keys.
- Sprint frontmatter keys: `starts_on`, `ends_on` (Mondays, end-exclusive,
  both or neither), `track`, `tags: [a, b]`, `assignee`.
- Sprint `tags`/`assignee` apply to tasks that don't set them; a task's
  `tags=` replaces them, `tags=""` means none.
- The Subtasks section is a one-line-per-item checklist and comes last in
  its task.

## Typical agent task

"Plan a sprint for X": write `tasks/sprints/<slug>.md` in the format above
without ids, run `task-cli fmt`, run `task-cli diff --json` (new tasks show
`"state": "new"`), then stop and tell the user to review and run
`task-cli publish fira <file>`.
