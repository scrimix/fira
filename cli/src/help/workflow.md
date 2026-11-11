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
