# Sprint 36 — task-cli: Notion as a document

**Status:** planned
**Date:** 2026-11-12

## Goal

Let PMs follow and edit engineering work in Notion, in the same shape
engineers read it. A sprint file is a document with tasks as sections, and
the PM's Notion page shows the same document. The diff works the same way as
with Fira:

- `task-cli publish notion <file>` renders a sprint file, or a single-task
  file, into the PM's own Notion page, below a `Tasks` heading.
- Edits made there come back through the same field-level diff `publish
  fira` uses, and the user chooses per field.

```text
repository document <-> task-cli publish notion <-> Notion page, below "Tasks"
```

This replaces the earlier draft of this sprint, which published each task as
a write-only Notion sub-ticket with properties inside a "From repo" toggle.
Sub-tickets split the document into rows, lose its reading order, and can't
be edited back.

## Prerequisite

[Sprint 35](35-task-cli-attachments.md) for `attachment:` links and file
hashes, and [sprint 37](37-sprint-description-and-task-order.md) for the
sprint description and task order. Both are built.

## Ownership

The PM creates the page (a sprint ticket, or a standalone ticket such as a
bug) and writes their brief at the top. The task content lives in one
**region**: from the `Tasks` anchor heading to the CLI's footer line. Inside
the region, both the repository and the PM may edit, and the diff reconciles
them. Outside it, the page belongs to the PM and is never written; the CLI reads
only the top-level block list there, to find the region.

Never written, on any page: page properties (status, title, dates,
assignees), comments, and any block outside the region. The CLI never
creates or deletes pages.

### The region mirrors the file

The region is the file's body in Notion blocks. The frontmatter, the `#`
title (the page has its own title, and the anchor takes its place) and the
`Attachments` sections are left out. Each task keeps its `<!-- task: … -->`
line as a gray paragraph. That line is what lets the CLI read the region
back: it carries the task's id, so sections are matched by id however a PM
renames or reorders them.

```text
<PM's brief, goals, notes ...>                    PM-owned, never touched
# Tasks                                           anchor
<sprint description, if the file has one>
## 🚧 Stripe webhook idempotency
<!-- task: id=027b9d13-… tags=billing assignee=@Maya Chen estimate=4h -->   (gray)
<description, embedded images rendered in place>
### Subtasks
☑ Create dedup table
☐ Wrap webhook handlers
## ⬜ OAuth refresh token rotation
<!-- task: id=198ad86d-… … -->
…
task-cli · edits here sync with the repository through `task-cli publish notion` · <hash>
<anything below the footer>                       PM-owned again
```

- [ ] **Anchor.** The first top-level heading, at any level, whose text is
      exactly `Tasks` (`[notion] anchor = "…"` changes it). Anyone may
      write it, so a PM puts it where the work should appear. If there is
      none, the CLI appends one at the end of the page; the diff shows
      `create anchor`. If there are several, that file fails with both
      positions named.
- [ ] **Footer.** The paragraph after the anchor that starts `task-cli ·`
      and is written by the integration's bot user (`GET /v1/users/me`).
      It ends the region and carries the hash of what was last published
      (see Diff). If it is missing, the region runs to the next heading at
      the anchor's level or to the end of the page. The diff warns, and
      treats every difference as changed on both sides.
- [ ] **Flat blocks.** The region is top-level siblings of the anchor, with
      no toggle. Task `##` stays H2, `###` stays H3, and `####` or deeper
      becomes a bold paragraph (Notion has three heading levels), which
      reads back as the same heading level.
- [ ] **Task line.** A paragraph whose text is the canonical task comment
      (`doc::format_comment_raw`), styled gray. The assignee is an
      `@mention` when the person matches a Notion user (see Users), and the
      handle in plain text otherwise. Everything else in it is plain text.
- [ ] **Subtasks.** `### Subtasks` (`## Subtasks` in a single-task file)
      followed by `to_do` blocks with their checked state.
- [ ] **Standalone task.** The same anchor and footer. The region has no
      task heading, because the page is the ticket: the task line,
      description and subtasks. The task's title is not compared, since the
      page title is the PM's.

## Linking

- [ ] A sprint file stores `notion: <page id>` in its frontmatter (a new
      `FRONT_KEYS` entry).
- [ ] A single-task file stores `notion=<page id>` in its `task:` comment (a
      new `COMMENT_KEYS` entry). It is a key, not a second HTML comment:
      the parser would read a second comment as description text and sync
      it to Fira. In Notion's copy of the task line, the key is left out.
- [ ] `task-cli link notion <file> <url>` writes the link, shown in the diff
      like any change. Writing it by hand is equally valid. `fmt` orders the
      key like the others.
- [ ] Publishing an unlinked file fails with "link the Notion page first".
- [ ] A linked page that is trashed or returns 404 fails that file and
      points to `link` again. The message says the CLI can't tell whether
      the page was deleted or access was lost.

## Users

Notion has its own users. Fira and Notion are expected to share people, so
the CLI matches them automatically.

- [ ] Assignees are resolved through Fira first: handles such as `maya.c`
      already need the project's members (`Resolver`, `handles.rs`), so
      `publish notion` requires `login fira` as well. That gives each
      assignee's email and name.
- [ ] The CLI fetches the workspace's Notion users (`GET /v1/users`, people
      only, no bots). The integration needs the "read user information
      including email addresses" capability; without it, the CLI matches by
      name only and prints one notice saying so.
- [ ] Fira users and Notion users are matched by email first
      (case-insensitive), then by exact normalised name. The match is used
      both ways: a handle is written as an `@mention`, and an `@mention`
      read back becomes the handle.
- [ ] A unique match renders as an `@mention`. When there is no match, or
      the name matches several people, the handle stays plain text and a
      warning names the person and the reason (`no Notion user` /
      `ambiguous: 2 Notion users named "Maya Chen"`). Warnings never block
      a publish.
- [ ] A PM who mentions someone with no Fira match fails that task's
      assignee field with the person's name, the same way an unknown
      handle fails in a file.

## Reading the region back

- [ ] The CLI reads the region's blocks (top level plus list children) and
      converts them to Markdown, for the block types the CLI writes:
      - headings, paragraphs, bullet and numbered lists, quotes, code;
      - links, bold/italic/code spans, `to_do`;
      - mentions, and images it uploaded.
      The result is parsed with the existing `doc::parse`, as a sprint or
      single-task document. It is never written to disk as is.
- [ ] Any other block a PM adds (a table, callout, toggle, …) becomes its
      plain text plus a notice `unsupported Notion block <type>, read as
      text`. Nothing is dropped silently.
- [ ] Formatting the CLI doesn't render (colours, highlights, underline) is
      ignored when reading and lost on the next rewrite. `help` documents
      this.
- [ ] **Images.** The CLI writes each embedded image with the caption
      `attachment:<name>` and reads it back as `![alt](attachment:<name>)`.
      An image without that caption (pasted by a PM) is listed as
      `Notion-only image, not imported` and is kept only until the region
      is next rewritten.
- [ ] **Parse errors.** A task line the PM broke (an unknown key, a bad
      estimate) fails that file with the parser's message, pointing at the
      section's heading in Notion.
- [ ] A section with no task line (an H2 a PM added) is a new task: "only in
      Notion", offered for adding to the file. `fmt` then gives it an id.
- [ ] A task missing from Notion but in the file is shown as removed in
      Notion and restored on publish. As with Fira, local text is never
      deleted because something is missing remotely.

## Diff

The footer hash is the hash of what the CLI last published. Comparing it
with both sides tells which one changed:

| Local file vs footer | Notion vs footer | Result |
|---|---|---|
| same | same | `unchanged`, no writes |
| changed | same | Notion is updated without asking (still shown; `--dry-run` writes nothing) |
| same | changed | the file is updated without asking |
| changed | changed | field-level diff, choose per field |

- [ ] Hash = SHA-256 of the canonical region model. It covers the sprint
      description, plus each task's id, status, title, tags, assignee,
      estimate, description, subtasks and order, plus the hashes of
      embedded files. Both sides are hashed after the same normalisation,
      so republishing unchanged content compares equal.
- [ ] The diff, choices and summary reuse `publish fira`'s machinery:
      `Comparison`, `FieldDiff`, `ui::choose`, `merge_task`/`merge_sprint`.
      The other side is labelled `notion`. `--prefer local|notion` answers
      every differing field in one direction, for unattended runs.
- [ ] Fields the region has no place for (sprint dates, track, tags and
      assignee defaults) are never compared.
- [ ] The Notion comparison is built from its own projection of the page
      into the canonical model. `sync::build` keeps its local ↔ Fira
      contract, and this module calls the shared field comparison rather
      than adding a third side.
- [ ] After the choices, the file is edited through `write.rs`
      (`task_edits`, `sprint_edits`, `reorder_blocks`), like a Fira
      publish. If the merged region differs from what Notion has, the
      region is rewritten. Fira is not touched; `publish fira` follows as
      usual.

## Writing to Notion

- [ ] A changed region is replaced wholesale. The CLI archives the blocks
      between the anchor and the footer, footer included, then appends the
      new blocks after the anchor (the `after` parameter). Appends go in
      chunks of 100, and lists deeper than two levels need follow-up
      appends. The footer is written last, so an interrupted publish has
      no footer and the next run treats both sides as changed.
- [ ] Before writing, the CLI rereads the region's block list and compares
      it with what the diff saw. If anything changed meanwhile, it stops
      without writing and asks for a rerun. This narrows the window but
      can't close it: Notion has no conditional writes.
- [ ] Client-side pacing at about 3 requests/s; honour `Retry-After` on 429.
      Archiving is one request per block, so a long sprint takes seconds;
      show progress.
- [ ] Known cost, documented in `help`: Notion comments on blocks inside the
      region are lost when the region is rewritten. Replacing only the
      sections that changed is out of scope.

## Files: only what the description renders

Notion shows what the description shows. The task's `Attachments` list is
not published, and attachments are not synced.

| Canonical | Notion |
|---|---|
| `![Layout](attachment:layout.png)` on its own line | image block at that position, caption `attachment:layout.png` (file block for non-images) |
| inline `see [spec](attachment:spec.pdf)` | the label text only; nothing uploaded |
| listed in `Attachments` only | nothing |

- [ ] Upload embedded files through Notion's file upload API and attach
      them within its expiry window. Files are uploaded only when the
      region is replaced.
- [ ] Inline attachment links are compared by label. A PM who leaves the
      label alone keeps the local link; editing the label is a description
      change.
- [ ] Check the size limits and allowed types for the workspace's plan. An
      unsupported file is shown as "not publishable to Notion" and
      rendered as its alt text, never fatal.

## CLI

```sh
task-cli login   notion
task-cli link    notion <file> <url>
task-cli publish notion <sprint-or-task-file> [--dry-run] [--prefer local|notion]
```

`task-cli diff` stays Fira-only; `publish notion --dry-run` is the read-only
Notion diff. Update `help workflow`, `help format` (the `notion` key) and
`help agents`.

## Test scenario

Run against a test Notion workspace that shares at least one user with Fira
by email.

1. **Unlinked.** `publish notion` on a sprint file without `notion:`.
   → Fails with "link the Notion page first".
2. **Link and first publish.** The PM creates a page with a brief, and
   `link notion` stores it; then publish.
   → The diff shows `anchor missing (will create)`. The `Tasks` heading
   appears after the brief, followed by the sprint description and each
   task with its gray task line, description and subtasks, then the
   footer. The brief is unchanged.
3. **Republish.** No edits; publish.
   → `unchanged`, zero writes.
4. **Local edit only.** Change a title and a description; publish.
   → The region is rewritten without a field prompt; the text above the
   anchor and below the footer is untouched.
5. **Notion edit only.** In Notion, the PM ticks a subtask, edits a
   description, changes the status emoji, reorders two sections and
   renames one; publish.
   → The file gets those changes, matched by id; the rename lands on the
   right task. The diff is empty on the next run.
6. **Both edited.** Change the same task's description on both sides and a
   different task's estimate in Notion only.
   → A field prompt for the description only; the estimate is taken from
   Notion.
7. **PM additions.** The PM adds a new H2 section, a table inside a
   description, and a pasted image.
   → A new task offered "only in Notion"; the table read as text with a
   notice; the image listed as `Notion-only image, not imported`.
8. **Broken task line.** The PM edits a task line into `estimat=3h`.
   → That file fails, naming the section and the parser's message.
9. **Users.** One assignee shares an email with a Notion user, one has no
   Notion account, and one name matches two Notion users. The PM then
   reassigns a task to the matched user by mention.
   → One `@mention`, two plain handles and two warnings; the mention
   reads back as that person's handle.
10. **Standalone.** The PM files a bug with a body; link a single-task file
    and publish.
    → The region has no task heading and holds the task line, description
    and subtasks. The PM's body is unchanged.
11. **Files.** One description embeds an image, one links a PDF inline, and
    one task lists a file only under `Attachments`.
    → The image appears in place with its caption; the PDF link is label
    text; nothing else is uploaded; republish is `unchanged`.
12. **Interrupted publish / concurrent edit.** Kill the CLI mid-write and
    publish again → both sides shown as changed, the region rewritten in
    full. Edit the region in Notion while the prompt is open → the write
    stops and asks for a rerun.

## Acceptance criteria

- [ ] No block outside the anchor…footer region is ever written, and no page
      property is. Outside the region, only the top-level block list is
      read, to find the anchor and footer.
- [ ] Republishing unchanged content makes no writes on either side.
- [ ] PM edits inside the region reach the file through the same per-field
      diff as Fira edits, matched to tasks by the id in the task line.
- [ ] The only Notion id stored in the repository is the page link.
- [ ] Notion users are matched to Fira users automatically, in both
      directions. Every missing or ambiguous match is reported, and none of
      them blocks a publish.
- [ ] Only files embedded in descriptions are uploaded.
- [ ] No Notion page is created or deleted, and no local text is deleted
      because it is missing in Notion.

## Out of scope

Sub-tickets and Notion properties; syncing attachment lists or importing
images pasted in Notion; sprint dates and track in Notion; Notion
comments; replacing only the sections that changed; creating pages; a
server-side Notion integration; `diff` against Notion.
