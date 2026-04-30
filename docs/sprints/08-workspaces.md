# Sprint 08 — Workspaces, two-axis roles, and tenant isolation

**Status:** done
**Date:** 2026-04-30

## Goal

The design doc (§4.8) chose "no workspaces — a team is just a project
with members." That works for a single-founder dogfood; it does not
work the moment two unrelated companies use the same instance, because
there's no isolation seam: every user is in the same global directory,
every operator would see everyone's projects, and `GET /users`
returns the whole table.

We're about to deploy for basic external testing, so we want the
tenancy boundary in place before data accumulates against the wrong
shape. This sprint introduces **workspaces** as the company-level
container, a **two-axis role model** (workspace + project), a
personal-workspace-per-user default so signup keeps working as it does
today, and a workspace switcher so the multi-company case is real.

This explicitly reverses the §4.8 "no enforced workspace boundary"
decision; that section is now stale and is on the next-sprint list.

## Model

### Tables

```
workspaces
  id            uuid pk
  title         text not null
  created_by    uuid references users(id) on delete set null
  is_personal   boolean not null default false
  created_at    timestamptz default now()

workspace_members
  workspace_id  uuid references workspaces(id) on delete cascade
  user_id       uuid references users(id) on delete cascade
  role          text check (role in ('owner','member'))
  removed_at    timestamptz                  -- soft delete
  primary key (workspace_id, user_id)

project_members  (existing table; columns added)
  workspace_id  uuid not null   -- mirrored from projects.workspace_id by trigger
  role          text not null default 'member'
                  check (role in ('lead','member'))
  -- composite FK (workspace_id, user_id) → workspace_members
```

`projects` gets a `workspace_id uuid not null references workspaces`.
`project_members` gets a composite FK
`(workspace_id, user_id) → workspace_members(workspace_id, user_id)`
so it is structurally impossible to add a user to a project who is not
a member of the project's workspace. The mirrored `workspace_id` is
filled in by a BEFORE-INSERT trigger on `project_members` so callers
don't have to thread it through.

### Two role axes

**Workspace**: `owner` | `member`
- `owner` — manages workspace title, members, and roles. Creates
  projects in the workspace. Implicit project lead in every project
  (no project_members row needed). Typically a founder / ops admin.
- `member` — sees only projects they're explicitly added to.

**Project**: `lead` | `member` (per project_members row)
- `lead` — edits the project (title, color, issue URL template),
  adds/removes project members. Cannot change member *roles* —
  promoting to `lead` is a workspace-owner action.
- `member` — works tasks, drags blocks. No project-level edits.

A user can be `owner` of one workspace and `member` of another, and
within a workspace can be `lead` on one project and `member` on
another — the two axes are independent. Workspace owner is a wildcard
on the project axis; the system never materializes that as rows.

### Personal workspace invariant

Every user has exactly one workspace where `is_personal = true` and
they are workspace `owner`. Created on signup (Google OAuth callback)
and on the dev fixture. Cannot be deleted, cannot have other members
added. Title defaults to `"<First>'s workspace"`. This keeps the "sign
in, start using the app immediately" flow intact — there is no
empty-state where a user has nowhere to put a project.

A user can additionally be a member of any number of non-personal
workspaces. The active workspace is selected via a switcher; all
scoped reads and writes are filtered by it.

## API

### Routes

| route                                  | method | what                                                    |
|----------------------------------------|--------|---------------------------------------------------------|
| `/workspaces`                          | GET    | the caller's workspaces (incl. personal)                |
| `/workspaces`                          | POST   | create a non-personal workspace; caller becomes owner   |
| `/workspaces/:id`                      | PATCH  | rename (workspace owner only)                           |
| `/workspaces/:id/members`              | PUT    | replace member set + roles (owner only)                 |
| `/workspaces/:id/members/:user_id`     | PATCH  | change a single member's role (owner only)              |
| `/workspaces/:id/users`                | GET    | directory listing scoped to one workspace               |
| `/workspaces/:id/all-users`            | GET    | every user in the system (owner only) — used by the     |
|                                        |        | settings modal so an owner can add a Google user who    |
|                                        |        | isn't in any workspace yet                              |

`GET /users` (no workspace filter) is removed — it was a cross-tenant
read.

### Active workspace header

The client sends an `X-Workspace-Id` header on every scoped request.
`/me` is unscoped (just returns the user); the SPA fetches workspaces
via `/workspaces`, picks one (last-used in `localStorage`, default
personal), and sends the header on `/bootstrap`, `/ops`, `/changes`.
`AuthCtx` validates the header against `workspace_members` per
request — invalid header → 403.

### Op kinds (synthesized server-side, replayed client-side)

`workspace.create`, `workspace.update`, `workspace.set_members`,
`workspace.set_member_role`. Project ops continue to ride the same
`processed_ops` log; both project- and workspace-scoped rows now carry
`workspace_id` so the change feed can deliver workspace-only ops to
every member of the workspace and project ops to anyone with project
access.

### Authorization (per op)

- `workspace.*` → caller must be workspace `owner`.
- `project.create` → caller must be workspace `owner`.
- `project.update` / `project.set_members` → caller must be workspace
  `owner` OR a project `lead`. When a project lead is the caller,
  the server ignores any role changes in the payload (existing roles
  preserved, new rows default to `member`); only the workspace owner
  may promote to `lead`.
- All task / subtask / block ops → caller must be a member of the
  project. Workspace owners can act on any project in the workspace
  (they're treated as implicit leads).

## UI

### Layout

- **Workspace switcher** in the TopBar breadcrumb chain
  (`Fira / <Workspace> ⌄ / <Project> / <Title>`). Click to open a
  popover listing all workspaces the user belongs to + a
  `+ New workspace` action.
- **Sidebar** stays at 56 px icon-rail width. Order: brand →
  Calendar / Inbox toggle → project icons → `+` (owner only) →
  spacer → settings cog (workspace owner only) at the bottom.
- **TopBar right side**: sync pill → user-initials avatar →
  "Log out".
- **Project icon highlight**: when the inbox view is on a project, that
  project's sidebar icon shows a thin underline in the project's color
  (distinct from the accent left-stripe used for Calendar / Inbox).

### Modals

- **Workspace settings** — owner-only. Title field; member table with
  per-row role `<Select>` (`owner` / `member`); same one-click-add /
  two-step-remove pattern as the project modal. Personal workspaces
  hide the member section.
- **Project settings** — workspace owner OR project lead. Title, icon,
  color, issue URL template, members. Each member row has a per-row
  role `<Select>` (`lead` / `member`) — readable by everyone with
  edit access, but only **interactive for the workspace owner**;
  project leads see a static role tag and a hint line: *"Only the
  workspace owner can change project roles."*
- **Empty inbox states** — three flavors, picked by role:
  1. workspace has projects but none picked → "Pick a project from
     the sidebar."
  2. no projects + caller can create → "Create your first project"
     editorial link (dashed underline, accent color, not a heavy
     button).
  3. no projects + plain member → "You're not a member of any
     project. / Ask a workspace admin to add you to one."

### Smaller polish

- **Login screen** — the dev affordance is now **"Sign in as Maya"**.
  It hits `/auth/dev-login?email=maya@fira.dev` instead of the old
  wipe-and-seed endpoint. Reseeding is a separate CLI step
  (`cargo run --bin seed -- --drop`).
- **Task fields trimmed** — `priority` and `source` were removed from
  every UI surface (TaskModal, TaskModalDraft, inbox row, project
  header). The columns still exist in the DB; just not exposed.
- **Calendar rail toggle** — labeled by *action*, not state: button
  reads "All" by default (click to expand to every project task) and
  "My" when expanded.
- **Input padding** — `.np-title` switched from fixed `height: 36px`
  + horizontal-only padding to real `padding: 9px 12px` so the field
  isn't visually cramped at any base font size.
- **Project sidebar highlight** — active project gets a thin
  underline in the project's color, distinct from the accent left-
  stripe used by the Calendar / Inbox toggle.
- **Topbar trailing trio** — sync pill, "Log out" button, and user
  avatar are all `height: 22px` with consistent 1 px outlines so the
  row reads as one set of paired chips. Avatar sits last.
- **Inbox empty states** — three flavors gated by role: "Pick a
  project," editorial "Create your first project" link for owners,
  or "Ask a workspace admin to add you" for plain members.
- **TaskModal assignee** — now click-to-edit, same affordance as the
  issue link: read-only avatar+name with a pencil icon; clicking it
  opens an inline searchable popover.

### Sync pill + offline mode

- **Combined labels** — when the API is unreachable and ops are
  queued, the pill reads `Offline · N pending` (cloud-off icon)
  instead of fighting two states for the same slot.
- **Failed-ops popover** — server-rejected ops (e.g. a malformed
  `external_url` that 400s) used to silently sit in the outbox with
  status `error` and the only signal was the pill's `Error · N`.
  Clicking the pill now opens a list of failed ops with per-op
  **Retry** (re-queue → next tick re-tries) and **Discard** actions,
  plus "Retry all" / "Discard all" header buttons. New store actions
  `retryOp`, `discardOp`, `retryAllFailed`, `discardAllFailed`.
- **Flicker suppression** — the 2 s `syncOutbox()` tick was flipping
  the pill through `Syncing… → Offline · N pending` on every cycle.
  Two protections: (1) a 300 ms grace before the spinner label
  appears, so fast round-trips never surface "Syncing…"; (2) while
  the grace timer is ticking, the pill keeps rendering whatever it
  last *resolved* to, so the "Offline" prefix doesn't briefly drop
  during the in-flight retry.
- **Reload-while-offline** — the store now persists to `localStorage`
  via `zustand/middleware`'s `persist`, with a custom replacer for
  the `Map`-typed `appliedOpIds`. `hydrate()` distinguishes three
  cases on `/me` failure:
    1. **401** → session expired; clear cached state, show login.
    2. **Network / 5xx with cached `meId`** → boot from cache,
       set `syncStatus: { kind: 'offline' }`. The 2 s ticker keeps
       trying; recovery is automatic.
    3. **Network failure with no cache** → error page (still need
       network for the first-ever load).
  `logout()` removes the persisted snapshot so the next user's
  reload doesn't see leftovers.

### Custom `<Select>` revisited

Native `<select>` rendering was breaking the editorial palette and
its popover got clipped by the modal body's `overflow: auto`. Replaced
in [`web/src/components/Select.tsx`](../../web/src/components/Select.tsx):
generic over the value type, `sm`/`md` sizes, optional per-option hint
line, and renders the menu with `position: fixed` (top/left computed
from the trigger's `getBoundingClientRect`) so it escapes any ancestor
scroll container. Flips upward when there isn't enough room below.

Used for: workspace and project member-row role selectors, project
picker in the task draft modal.

## Migration plan + reseed flow

`bin/seed.rs` accepts `--drop` (or `SEED_DROP=1`): enumerates every
table + function in the public schema, drops them with CASCADE, then
re-runs migrations + seed. Use this whenever a migration's
preconditions stop matching the current DB. The binary prints the
list of workspaces it just inserted so you can tell the new code
ran. Restart the api process afterwards so the running binary picks
up any seeder logic changes baked into `seed::seed_all`.

`api/migrations/0008_workspaces.sql`:

1. Create `workspaces` and `workspace_members`.
2. TRUNCATE the legacy fixture tables (we're still in dev — no
   production data, no backfill).
3. Add `projects.workspace_id UUID NOT NULL REFERENCES workspaces(id)
   ON DELETE CASCADE`.
4. Add `project_members.workspace_id UUID NOT NULL`, plus composite FK
   `(workspace_id, user_id) → workspace_members(workspace_id, user_id)`.
5. BEFORE-INSERT trigger fills `project_members.workspace_id` from
   the parent project on every insert/update.
6. Add `processed_ops.workspace_id` so the change feed can scope by
   tenant.

`api/migrations/0009_workspace_project_roles.sql`:

1. Drop the legacy `('owner','lead','member')` CHECK on
   `workspace_members.role`; add a new one with `('owner','member')`.
   Pre-existing `'lead'` rows fold to `'member'`.
2. Add `project_members.role text not null default 'member'
   check (role in ('lead','member'))`.
3. Promote each project's `owner_id` → `lead` on its
   `project_members` row.

Seeder ([`api/src/seed.rs`](../../api/src/seed.rs)): one shared
`Default` workspace (Maya owns it, everyone else is workspace
`member`), plus a personal workspace per seeded user. Atlas has Maya
and Anna as project `lead`s; Bob is `member`. Relay has Maya as
`lead`, Jin as `member`. Helix is Maya solo.

## Out of scope

- Email invites. Adding a user means typing or picking an existing
  one. A "pre-create user by email" flow is the obvious follow-up.
- Per-workspace billing / quotas.
- Cross-workspace task moves.
- Workspace deletion. Personal workspaces never delete; non-personal
  workspaces can be vacated (members removed) but the row stays.
- "Instance superadmin" with cross-tenant visibility. If support / ops
  needs it, `users.is_superadmin` is the obvious one-line addition.

## Notes for the next sprint

- [`docs/spec.md`](../spec.md) §3 (data model) and §4 (API) still
  describe the pre-workspace world — needs an update covering
  `workspaces`, `workspace_members`, the two role axes, the
  `X-Workspace-Id` header, and the new routes.
- [`docs/fira_design_doc.md`](../fira_design_doc.md) §4.8 is now
  superseded — annotate or rewrite.
- The dev-only `/auth/dev-seed` HTTP endpoint is no longer used by the
  login UI but still ships in the binary. Either delete it or leave
  it for the moment.
- Email invites + cross-tenant pre-create-by-email — the natural next
  step now that workspaces exist.
