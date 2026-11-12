# Sprint 35 — task-cli: attachments and releases

**Status:** planned
**Date:** 2026-11-12

## Goal

Make attachments part of the [sprint 34](34-task-cli-mvp.md) flow. A task
document lists its attachments the way Fira's task modal does, whether or not
the description embeds them; `publish fira` uploads them, `import fira`
brings them back, and descriptions can embed them inline. Also ship prebuilt
binaries so a project can install the CLI without a Rust toolchain.

Everything reuses sprint 34's canonical model, diff procedure, removal rules
and local file safety unchanged. Notion follows in
[sprint 36](36-task-cli-notion-write-only.md) and reuses this sprint's
attachment model.

## Prerequisite

Sprint 34 running against production, with fixes from early dogfooding
folded in first.

## Decision: the file describes the work, Fira holds the plan

| Concern | Lives in |
|---|---|
| What a task is: title, description, subtasks, attachments, tags, estimate | repository file |
| Order, priority, status, and how they change over time | Fira (plan history, sprint 32) |
| Sprint membership | repository file, for now |

Order is a plan that changes week to week as tasks come and go; a Markdown
file can't represent that history, and syncing it would churn git. So
heading order is never compared or published. The one exception landed
already (`c0027d4`): a task the CLI *creates* in a sprint gets a `sort_key`
after that sprint's last task, in file order, so a fresh publish doesn't
scramble. Revisit membership the same way if it causes friction in use.

## Attachments

Attachments belong to tasks only. Files live in `tasks/assets/<task-id>/`.

### Format

A task's attachments are its `Attachments` section, a sibling of `Subtasks`:

```md
## ⬜ Application shell
<!-- task: id=9a1d… -->

Build the shell. Target layout:

![Layout](../assets/9a1d…/layout.png)

### Attachments

- [layout.png](../assets/9a1d…/layout.png)
- [spec.pdf](../assets/9a1d…/spec.pdf)

### Subtasks

- [ ] Navigation
```

- The section is the task's attachment set, mirroring Fira's attachments
  panel. A file that is in the list is an attachment whether or not the
  description mentions it.
- The description may embed or link any listed attachment. Fira stores the
  description with `attachment:<filename>` links
  (`![Layout](attachment:layout.png)`); the converter maps them to and from
  the local path, so diffs contain no URLs or IDs.
- Files in `assets/<task-id>/` that are not listed stay local (`llm_ctx.md`
  and other notes).
- Canonical position: after the description, before `Subtasks`; both
  sections come last in the task. Either order parses.
- The attachment set is compared as a set of filename + content hash. List
  order is local and not synced, like task order.

Rules:

- [ ] Filenames are restricted to `[A-Za-z0-9._-]` so they need no escaping
      in Markdown and survive the server's `sanitize_filename` unchanged.
      Anything else is a validation error naming the file.
- [ ] A listed or embedded file that doesn't exist locally is a validation
      error.
- [ ] `fmt`:
      - adds a description-embedded file that is missing from the list;
      - moves a linked file from elsewhere in the repository into
        `assets/<task-id>/` and rewrites both links (never overwriting a
        different file of the same name: that is an error);
      - creates the section if needed, sorts nothing.
      Publish only accepts paths already inside the task's folder.
- [ ] Update `help format` and `help agents`.

### Fira API

Today uploads go through `/api/attachments/*`, which needs a browser
session; automation tokens only reach `/api/cli/*`. Uploading twice creates
a duplicate.

- [ ] Migration: `sha256 TEXT` on `attachments`, NULL for existing rows
      ("unknown": the first comparison downloads the file once to hash it,
      and the API stores the hash).
- [ ] `POST /api/cli/fetch` includes each task's attachments:
      `{id, filename, sha256, size, content_type}`.
- [ ] `PUT /api/cli/tasks/:id/attachments/:filename` with the file body and
      `If-Match: <attachment id seen at preview>` (or `If-None-Match: *`
      for a new name). The id, not the hash, is the precondition, so rows
      with a NULL hash still work.
      - same hash as stored → 200, nothing written;
      - precondition fails → 409, reported as a stale preview like any
        other precondition;
      - otherwise replace: insert the new row and file, delete the old row,
        recording the existing `task.add_attachment` / delete ops in one
        transaction so open browsers update through the change feed. The
        old storage file is deleted after commit.
      - two existing attachments with that filename → 409 "ambiguous",
        resolved in the UI.
- [ ] `DELETE /api/cli/tasks/:id/attachments/:filename` with `If-Match`,
      same op and storage handling.
- [ ] `GET /api/cli/attachments/:id` downloads, same scope check as the
      session route.
- [ ] Respect the existing 10 MB body limit; the CLI checks size before the
      diff so an oversized file fails before anything is written.

### Publish and import

- [ ] `attachments` is one field in sprint 34's diff, shown per file:

      ```text
      task "Application shell"
        attachments  + shot.png   (local only, 240 KB)
                     ~ layout.png (differs)
                     - old.png    (only in Fira)
      ```

      Choosing **local** makes Fira match the list: uploads new and changed
      files and deletes `only in Fira` ones. Choosing **Fira** downloads
      Fira's files and rewrites the list. The confirmation spells out every
      remote delete and every local overwrite. This is the same value-list
      rule subtasks follow; it is the only remote delete the CLI performs.
- [ ] Order of writes: `/api/cli/apply` first (the task must exist), then
      uploads and deletes. If one fails, the rest of the publish stands and
      the next diff shows what is left.
- [ ] Content type is inferred from the extension, falling back to
      `application/octet-stream`.
- [ ] `import fira` writes the `Attachments` section with every Fira
      attachment and downloads them into `assets/<task-id>/`. Existing
      local files with a different hash follow the field choice above.

### Fira UI

- [ ] Render `attachment:<name>` in task descriptions by resolving it to the
      task's attachment with that filename and loading it through
      `getAttachmentUrl(id)`. Images (`png`, `jpg`, `gif`, `webp`) render
      inline; everything else is a download link. A missing name renders
      as a visibly broken link. People can use the same syntax for files
      uploaded in the UI.
- [ ] Security: `get_attachment` serves anything that is not an inline image
      type with `Content-Disposition: attachment` and
      `X-Content-Type-Options: nosniff`. Uploaded HTML and SVG must never
      render same-origin. Standalone HTML is a download; in-app preview is
      out of scope.

## Releases

Installing today needs `cargo install --git … --tag cli-vX`, a Rust
toolchain, and a `Cargo.toml` version bumped by hand (v0.1.1 shipped
reporting 0.1.0 because the tag and the manifest disagreed).

- [ ] GitHub Actions on `cli-v*` tags: fail unless the tag equals
      `cli-v<version from cli/Cargo.toml>`, run the CLI tests, build Linux
      x86_64, Linux aarch64 (dev container on Apple Silicon) and macOS
      arm64, attach the binaries and SHA-256 sums to a GitHub Release.
- [ ] Install is one download, no toolchain (the repository is public):

      ```sh
      curl -fsSL -o ~/.local/bin/task-cli \
        https://github.com/scrimix/fira/releases/download/cli-vX.Y.Z/task-cli-<target>
      chmod +x ~/.local/bin/task-cli
      ```

      `cli/README.md` documents it, keeping `cargo install` as the fallback.
- [ ] The CLI sends `X-Task-Cli-Version`; the API rejects versions below a
      configured minimum with "upgrade task-cli to ≥ X". Bump the minimum
      when a change would make an older CLI write wrong data (this sprint's
      attachment rules are one: an old CLI would drop the section).

## Test scenario

Continue sprint 34's scenario against a dev Fira instance.

1. **Embed and move.** Embed `shot.png` from the repository root in a task's
   description, run `fmt`.
   → The file moves to `assets/<task-id>/`, the embed is rewritten, and
   `shot.png` is added to the `Attachments` section.
2. **Unembedded attachment.** Add `spec.pdf` to the section only.
   → Both appear in the diff as `local only`.
3. **Publish.** `publish fira` the sprint file.
   → Fira's attachments panel shows both; the description shows the image
   inline. Republish → empty diff, nothing uploaded.
4. **Change.** Edit the image, republish.
   → `~ shot.png (differs)`, one upload, the old file gone from storage.
5. **Stays local.** Put `llm_ctx.md` in the same folder, unlisted.
   → Never appears in the diff or in Fira.
6. **Remove.** Delete `spec.pdf` from the section, publish, choose local.
   → Confirmation names the remote delete; afterwards it's gone in Fira.
7. **Import.** Upload `notes.png` in the UI, then `import fira` in a fresh
   clone.
   → `notes.png` is listed in the section and downloaded, although the
   description doesn't mention it.
8. **Conflict.** Preview a publish, replace the file in the UI, accept.
   → 409, reported as stale; re-run shows the new state.
9. **HTML.** Attach `report.html`.
   → Fira offers it as a download; opening the URL does not render it.
10. **Release.** Tag `cli-v<version>` → release with three binaries; a
    mismatched tag fails the workflow. A fresh dev container installs with
    `curl`; an older binary is rejected with the upgrade message.

## Acceptance criteria

- [ ] Every Fira attachment appears in the task's `Attachments` section after
      import, embedded or not, and every listed file appears in Fira after
      publish.
- [ ] Unchanged files are never re-uploaded; unlisted files are never
      uploaded.
- [ ] Remote deletes happen only through the attachments field choice and
      are spelled out in the confirmation.
- [ ] Attachment writes are guarded by preconditions like other writes.
- [ ] Uploaded HTML/SVG never renders same-origin.
- [ ] Prebuilt binaries install without Rust; tag/version mismatches fail
      the release; old CLIs get an upgrade message.

## Out of scope

Notion (sprint 36); remote-HEAD comparison in `diff` (dropped); explicit
`task-cli delete`; sprint descriptions in Fira; managing task order;
attachments on sprints; in-app HTML preview; package registries.
