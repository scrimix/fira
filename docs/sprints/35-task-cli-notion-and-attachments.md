# Sprint 35 — task-cli: Notion, attachments, and releases

**Status:** planned
**Date:** 2026-11-11

## Goal

Extend the [sprint 34](34-task-cli-mvp.md) MVP: publish PM-facing
pages to Notion, sync task attachments with Fira and Notion, sync sprint
descriptions, add remote-HEAD comparison and explicit deletion, and ship
prebuilt releases. Everything here reuses sprint 34's canonical model, diff
procedure, removal rules, and local file safety unchanged.

## Prerequisite

Sprint 34 shipped and dogfooded; its interaction design adjusted from real use.

## Notion

```text
Repository documents -> task-cli publish notion -> Notion
Notion               -> task-cli import notion  -> repository documents
```

Notion is a third converter to the canonical model. There is no direct
Fira ↔ Notion sync; the repository is the bridge.

### Identity and link

Notion pages carry the repository UUID in a `Repo ID` text property. After a
task is first published to or imported from Notion, the CLI adds a second
comment line with the page ID:

```md
## [ ] Application shell
<!-- task: id=<uuid> tags=frontend -->
<!-- notion: id=<notion page id> -->
```

Sprints record it as `notion_page_id` in the frontmatter. This is how the CLI
knows a task was *ever* linked: Notion cannot tell "never published" apart
from "deleted", and a `Repo ID` query does not return trashed pages. Without
the line, `publish notion` creates a page; with it, the CLI fetches that page
directly. Writing the line is part of the accepted diff.

### Representation

A Notion page represents a sprint or a task. A sprint is a parent ticket; its
tasks are sub-tickets, with subtasks as task-body checklists. Single tasks
are standalone tickets. Titles and page placement can change without breaking
identity.

- [ ] Before every Notion publish/import, check that the configured database
      has the `Repo ID` property and the mapped properties, and that
      permissions are sufficient. Fail with a clear message before the diff.
- [ ] Map sprint dates/track and task assignee, tags, estimate, description,
      and membership explicitly. Status is not managed; PMs adjust it in
      Notion, and it is not compared.
- [ ] Local sprint membership controls the published hierarchy; moving pages
      in Notion is not a planning command.
- [ ] Preserve unrelated PM content by defining the properties and body
      regions the publisher owns.
- [ ] Use the `notion:` line / `notion_page_id` to fetch linked pages
      directly, and `Repo ID` for reverse lookup and duplicate detection.
- [ ] Inspect Notion's concurrency capabilities for the preview/write check
      and document any residual race.

### Intake and import

- New bugs and features may originate in Notion. Import lands in
  `tasks/single/`; the user states explicitly whether a page is a task or a
  sprint, never inferred from nesting.
- Importing a Notion-first page generates a new UUID and writes it into the
  page's `Repo ID` property; that write is part of the import diff.
- A Notion sprint import turns the sprint page's sub-tickets into its tasks.
  Pages without a `Repo ID` get new IDs, written back as part of the diff.

### Removal

Sprint 34's rules apply. Additionally: a task with a `notion:` line whose page
is trashed or returns 404 (deleted, or access lost — the prompt says it cannot
tell which) is resolved by asking: recreate (new page, line rewritten),
unlink (drop the line), or skip.

## Attachments

Attachments belong to tasks only; sprints get a description but no
attachments. Files for a task live in `tasks/assets/<task-id>/`. Only files
linked from a published description are uploaded, so `llm_ctx.md` and other
notes in the same folder stay local unless deliberately linked.

### Canonical form and Fira

Descriptions reference attachments by filename with an `attachment:` link:

```md
local:  ![Layout](../assets/<task-id>/layout.png)
fira:   ![Layout](attachment:layout.png)
```

The canonical model uses `attachment:<filename>`; the Markdown converter maps
it to and from the local path, so diffs contain no URLs or IDs.

- [ ] Fira UI: render `attachment:<name>` in descriptions by resolving it to
      the task's attachment with that filename and loading it through the
      existing `getAttachmentUrl(id)`. People can use the same syntax to embed
      files uploaded in the UI. A missing name renders as a broken link.
- [ ] A remote attachment is identified by task ID and filename, matching
      `attachments(task_id, filename)`. A reference to a filename that is
      ambiguous in Fira is an error.
- [ ] Add a `sha256` column to `attachments` so changed files are detected and
      unchanged uploads skipped.
- [ ] A link to a file outside `assets/<task-id>/` is moved there on publish
      and the link rewritten; the move is part of the diff. Moves never
      overwrite a different existing file.
- [ ] Support screenshots and standalone HTML as downloadable attachments.
      HTML with local dependencies must be packaged explicitly, such as ZIP.
      In-app execution/preview of uploaded HTML is out of scope.
- [ ] Import downloads linked attachments into `assets/<task-id>/` and writes
      local links. Removing a link or local file never deletes a remote
      attachment.

### Notion

Notion files are separate blocks uploaded through its file upload API; their
URLs expire after about an hour and no content hash is exposed.

| Canonical | Notion |
|---|---|
| `![Layout](attachment:layout.png)` on its own line | image block at that position |
| `[spec](attachment:spec.pdf)` on its own line | file block at that position |
| inline `see [spec](attachment:spec.pdf)` | text kept; file block added after the paragraph |

- [ ] Import maps image/file blocks back to `attachment:` links and downloads
      the files. Inline links come back as standalone links; the diff shows it.
- [ ] Identify a Notion file by its name within the page. Detect changes by
      downloading and hashing; cache hashes in `.git/task-cli/cache/` keyed by
      block ID and `last_edited_time`. Losing the cache only costs downloads.
- [ ] Only add/remove blocks inside publisher-owned regions; PM-added images
      elsewhere on the page are never touched.
- [ ] Verify upload size limits and allowed file types for the workspace plan.
      Unsupported files show in the diff as "not publishable to Notion" and
      are skipped, not fatal.

## Sprint descriptions in Fira

- [ ] Add a Markdown `description` to Fira sprints: model, op, history, and
      the sprint editor. The CLI then syncs the sprint file's description.
- [ ] A sprint description linking a local file is a validation error;
      sprint-level material goes on a task (e.g. a "Plan" task) instead.

## CLI additions

```sh
task-cli login notion
task-cli publish notion <sprint-or-task-file>
task-cli import  notion <url-or-id> [--into <file>]
task-cli delete  fira|notion <task-or-sprint-id>
task-cli diff    [file...] [--fetch]   # working copy vs remote HEAD vs Fira vs Notion
```

### Explicit deletion

- [ ] `task-cli delete fira|notion <id>` is the only thing that deletes
      remotely, with its own diff and confirmation. Update `help agents`
      accordingly.

### Diff mode: remote HEAD and Notion

`task-cli diff` gains two columns:

- **remote HEAD**: `tasks/` at the current branch's upstream (falling back to
  the default branch), read with `git show`, so changes teammates pushed but
  you haven't pulled show up;
- **Notion**, when configured.

```text
sprint "Onboarding"  (tasks/sprints/001-onboarding.md)
  task "Welcome screen"
    title     current: Welcome flow   remote: Welcome screen  fira: Welcome screen  notion: Welcome screen
  only in remote:  "Rate limits" (pushed by someone else, not pulled)
  not linked:      "Routing" (never published to Notion)

remote HEAD: origin/master, fetched 3 hours ago
```

- By default the remote ref is used as last fetched, and its age is printed.
  `--fetch` runs `git fetch` first; that only updates remote-tracking refs
  and is the CLI's only git write.
- With `tasks/` as a submodule, git operations run inside the submodule. On a
  detached HEAD, remote HEAD falls back to the `branch` in `.gitmodules`, then
  the submodule remote's default branch; the superproject's pinned commit is
  not a comparison source. An uninitialised submodule fails with a pointer to
  `git submodule update --init`, and `diff` warns about local edits on a
  detached HEAD. Committing and bumping the pointer stay manual.

## Distribution

- [ ] Release on `cli-v*` tags: GitHub Actions builds Linux x86_64, Linux
      aarch64 (the dev container on an Apple Silicon host), and macOS arm64,
      and attaches the binaries to a GitHub Release.
- [ ] The dev container's `post-create.sh` installs a pinned release with
      `gh release download` (works for a private repo).
- [ ] The CLI sends its version; the API rejects versions below a minimum
      supported version with an upgrade message.
- [ ] Notion credentials follow sprint 34's credential rules; CI gets them as
      secrets.
- [ ] No package registry (crates.io, Homebrew).

## Test scenario

Continue sprint 34's scenario against a dev Fira instance and a test Notion
database.

1. **Attachments.** Link `shot.png` from anywhere in the repo in the bug's
   description and publish to Fira.
   → The file moves to `assets/<bug-id>/`, the link is rewritten, Fira shows
   the image inline via `attachment:shot.png`. Republish uploads nothing.
   Edit the image and republish → one re-upload.

2. **Sprint description.** Edit the sprint description and publish.
   → It appears in Fira's sprint editor; republishing is an empty diff.

3. **Notion publish.** `task-cli login notion`,
   `task-cli publish notion tasks/sprints/001-onboarding.md`.
   → Sprint and task pages are created with `Repo ID` set, the bug's image
   as an image block. The file gains `notion_page_id` and `notion:` lines.
   Republishing is an empty diff.

4. **Notion removal.** Trash one task page and publish again.
   → The CLI asks recreate / unlink / skip.

5. **Notion intake.** Create a bug page in Notion, import it, plan it into
   the sprint file, publish to Fira and Notion.
   → One Fira task, the original Notion page updated, no duplicates.

6. **Delete.** `task-cli delete fira <id>` on the task left "only in Fira" in
   sprint 34's step 11. → Its own diff and confirmation; gone afterwards.

7. **Overview.** Push a change from another clone, change a title in Notion,
   then `task-cli diff --fetch`.
   → "only in remote" / differing remote column, the Notion title in its
   column. Nothing written outside remote-tracking refs.

8. **Release install.** Fresh dev container installs the pinned release
   binary; the scenario re-runs with it, including `tasks/` as a submodule
   cloned with `--recurse-submodules` on a detached HEAD.

## Acceptance criteria

- [ ] Import an unscheduled Notion bug, plan it into a sprint file, publish to
      Fira, and update its original Notion page without duplicate tickets.
- [ ] Notion pages are found by `notion:` line or `Repo ID`; trashed pages
      prompt instead of being silently recreated.
- [ ] Linked assets upload once, re-upload only when changed, render inline
      in Fira, map to image/file blocks in Notion, and unlinked files such as
      `llm_ctx.md` are never uploaded.
- [ ] Sprint descriptions round-trip with Fira.
- [ ] `task-cli delete` is the only command that deletes remotely.
- [ ] `task-cli diff` shows working copy, remote HEAD, Fira and Notion side by
      side, matched by ID, writes nothing, and exits 0 only when all agree.
- [ ] Release binaries install in the dev container; old CLI versions are
      rejected with an upgrade message.

## Out of scope

Notion status mapping, a server-side Notion integration, in-app HTML preview,
and everything listed out of scope in sprint 34.
