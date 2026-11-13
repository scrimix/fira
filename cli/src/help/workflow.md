# task-cli workflow

Once per repository:

```sh
task-cli init --url https://usefira.app   # creates tasks/config.toml
task-cli login fira                       # per developer; token stays outside the repo
```

The loop:

1. **Write.** Edit `tasks/sprints/*.md` or `tasks/single/*.md` in any
   editor (see `task-cli help format`). Leave out ids; the CLI adds them.
2. **Format.** `task-cli fmt` inserts missing ids and tidies structure
   lines. It never touches prose and sends nothing anywhere.
3. **Look.** `task-cli diff` compares your working copy (uncommitted edits
   included) with Fira. Exit code 0 means in sync.
4. **Publish.** `task-cli publish fira tasks/sprints/<file>.md` shows the
   field-by-field diff, asks local or Fira for each differing field, shows
   a summary, and writes only after you confirm. The chosen values go to
   both sides, so afterwards the file and Fira agree.
   `publish` also creates in Fira whatever the file has that Fira doesn't.
   To merge edits on both sides without creating anything, use
   `task-cli sync fira` (all files, or the ones you name).
5. **Commit** the files as usual. The CLI never runs git commands that
   change anything.

Pulling work from Fira:

```sh
task-cli sprints                          # Fira's sprints, with ids and local files
task-cli import fira "Sprint title"       # whole sprint into tasks/sprints/
task-cli import fira <task-link>          # one task into tasks/single/
```

A task's link comes from "Copy link" in its Fira modal. On the Plan board,
a sprint's menu has "Copy import command".

Import uses the same diff and the same per-field choice.

Things to know:

- Nothing is pre-selected: the CLI stores no sync state, so it can't know
  which side changed a field. You decide.
- Task order counts: the order of task blocks in a sprint file is compared
  with the sprint's checklist order in Fira, and shows up in the diff as
  `order`. Choosing local reorders Fira; choosing Fira moves the blocks.
- Absence never acts. A task missing from a file is not deleted or removed
  from its sprint in Fira, and an import never deletes local text.
- A task deleted in Fira makes the next publish ask: recreate (same id),
  delete locally, or skip.
- If Fira changes between the diff and the write, nothing is written;
  run the command again.
- A file saved while a prompt is open is skipped, and files with
  uncommitted changes are backed up under `.git/task-cli/backups/` before
  being written.
- `--dry-run` shows what would happen. `--prefer local|remote` answers
  every field in one direction for unattended runs.

## Notion

PMs can follow and edit a sprint on their own Notion page. Once per
developer, `task-cli login notion` (an internal integration's secret; share
each page with the integration: page menu ••• → Connections). Then:

```sh
task-cli link notion tasks/sprints/<file>.md <page link>   # once per file
task-cli publish notion tasks/sprints/<file>.md
task-cli sync notion                                       # every linked file
```

The CLI owns the part of the page from a `Tasks` heading to its gray
footer line; the PM's text above and below is never touched. That part
mirrors the file: the sprint description, then every task with its heading,
description and subtasks. Tags, assignee and estimate stay in the
repository. Attachment lists are not published; images and files embedded
in descriptions travel both ways (a file a PM uploads is stored with its
task).

Edits made in Notion come back the same way as Fira's: the footer records
what was last published, so if only one side changed it simply wins; if
both did, you choose per field. Tasks are matched by title, so
a task renamed in Notion shows up as one that disappeared (publishing puts
it back) and one that appeared (added to the file); titles within a file
must differ. When only the file changed, deleted tasks go from the page;
otherwise each task on only one side is a choice: put it back or delete
it from the file, add it to the file or remove it from the page. A new section a PM adds needs a status emoji (⬜ 🚧 ✅) in its
heading to count as a task. With `task_ids = true` under `[notion]`, each
task also shows its `<!-- task: … -->` line (short id, tags, assignee,
estimate), so renames keep their identity. Only changed blocks are rewritten; Notion
comments on a block are lost when that block changes.
