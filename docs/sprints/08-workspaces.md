# Sprint 08 — Workspaces, roles, and tenant isolation

**Status:** planned
**Date:** 2026-04-30

## Goal

The design doc (§4.8) chose "no workspaces — a team is just a project
with members." That works for a single-founder dogfood; it does not
work the moment two unrelated companies use the same instance, because
there's no isolation seam: every user is in the same global directory,
every superadmin would see everyone's projects, and `GET /users`
returns the whole table.

We're about to deploy for basic external testing, so we want the
tenancy boundary in place before data accumulates against the wrong
shape. This sprint introduces **workspaces** as the company-level
container, a three-tier role model, a personal-workspace-per-user
default so signup keeps working as it does today, and a workspace
switcher so the multi-company case is real.

This explicitly reverses the §4.8 "no enforced workspace boundary"
decision; that section will be updated when this sprint lands.

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
  role          text check (role in ('admin','project_admin','member'))
  removed_at    timestamptz                       -- soft delete, mirrors project_members
  primary key (workspace_id, user_id)
```

`projects` gets a `workspace_id uuid not null references workspaces`.
`project_members` gets a composite FK
`(workspace_id, user_id) → workspace_members(workspace_id, user_id)`
so it is structurally impossible to add a user to a project who is not
a member of the project's workspace. To wire this in we add a
`workspace_id` column to `project_members` (mirrored from the parent
project, enforced via a trigger or write-time guard).

### Roles

Three tiers, per workspace (a user can be `admin` in one workspace and
`member` in another — role lives on the membership row, not the user):

- **`admin`** — workspace admin. Can edit workspace title, add/remove
  members, assign roles, and do everything `project_admin` can.
- **`project_admin`** — can create projects in the workspace, edit any
  project's title/members/settings, but cannot manage workspace
  membership or roles.
- **`member`** — can view projects they're members of, work tasks,
  drag blocks, etc. No create/edit on projects or workspace.

The workspace creator is `admin` of the workspace they created. There
is no separate "superadmin" / instance owner — admin of the personal
workspace is the highest privilege a user has by default. An admin can
promote any other workspace member to admin, so the creator-going-away
case is solvable in-product.

### Personal workspace invariant

Every user has exactly one workspace where `is_personal = true` and
they are `admin`. Created on signup (Google OAuth callback) and on the
dev-seed path. Cannot be deleted, cannot have other members added.
Title defaults to `"<Name>'s workspace"`. This keeps the "sign in,
start using the app immediately" flow intact — there is no empty-state
where a user has nowhere to put a project.

A user can additionally be a member of any number of non-personal
workspaces. The active workspace is selected via a switcher; all
scoped reads and writes are filtered by it.

## API

### New routes

| route                                  | method | what                                                                |
|----------------------------------------|--------|---------------------------------------------------------------------|
| `/workspaces`                          | POST   | create a non-personal workspace; caller becomes admin               |
| `/workspaces/:id`                      | PATCH  | rename (admin only)                                                 |
| `/workspaces/:id/members`              | PUT    | replace member set (admin only); roles per-member                   |
| `/workspaces/:id/members/:user_id`     | PATCH  | change a single member's role (admin only)                          |
| `/users?workspace_id=…`                | GET    | directory listing scoped to one workspace (admin or project_admin)  |

`GET /users` (no workspace filter) is removed — it's a cross-tenant
read. The `ProjectModal` member picker switches to the workspace-scoped
version using the active workspace.

### Active workspace

The client sends an `X-Workspace-Id` header on every request after
bootstrap. `/me` returns the user plus their workspaces and the active
one (defaulting to personal on first load, then last-used by cookie).
`/bootstrap` uses the header to scope everything it returns; without
it, returns only the personal workspace. `/changes` uses the same
header so peers in other workspaces never leak in.

### New op kinds

`workspace.create`, `workspace.update`, `workspace.set_members`,
`workspace.set_member_role`. Same intent-shaped pattern as the project
ops; same processed_ops scoping rules. Project ops gain a
`workspace_id` field for scope filtering on the change feed.

### Authorization checks (per op)

- `workspace.*` → caller must be `admin` of the target workspace.
- `project.create` → caller must be `admin` or `project_admin` of the
  target workspace, and `members ⊆ workspace_members`.
- `project.update` / `project.set_members` → caller must be the
  project's owner, or `admin` / `project_admin` of the workspace.
- All task / subtask / block ops → caller must be a member of the
  project (today's rule); the workspace check is implicit because the
  project lives in a workspace they have membership in.

## UI

- **Workspace switcher** in the sidebar above the project list. Shows
  active workspace title; click to open a popover listing all
  workspaces the user belongs to + a `+ New workspace` action (which
  opens a tiny modal: title only, no icon/color).
- **Workspace settings modal** — admin-only. Title field; member
  table with role dropdown per row; same add/remove pattern as
  `ProjectModal` (one-click add, two-step remove).
- **Project create/edit** is gated: the `+` next to the project list
  is hidden for plain `member` role; in the project modal, member
  picker only offers users from the active workspace.
- **Personal workspace** renders the same way but the settings modal
  hides the member section and the title field is read-only — single
  inhabitant, nothing to manage.
- The TopBar pill is unchanged; no per-workspace sync state.

## Migration plan

We're still in dev mode with no real user data, so the migration is a
drop-and-reseed — no backfill of existing rows.

`0007_workspaces.sql`:

1. Create `workspaces` and `workspace_members`.
2. Add `projects.workspace_id UUID NOT NULL REFERENCES workspaces(id)
   ON DELETE CASCADE`. No backfill — assumes a freshly seeded DB.
3. Add `project_members.workspace_id UUID NOT NULL`, plus composite FK
   `(workspace_id, user_id) → workspace_members(workspace_id, user_id)`.
4. Trigger or write-side guard ensures
   `project_members.workspace_id = projects.workspace_id` on every
   insert/update.

Seeder updates (`api/src/seed.rs`): create one shared "Acme"
workspace for the fixture team, plus a personal workspace per seeded
user. All seeded projects live in Acme; each user's personal
workspace starts empty. Maya (the dev-seed login user) is `admin` of
Acme so role-gated UI renders. Personal-workspace creation also runs
on the Google OAuth callback path so first-real-login still works.

Existing local DBs get reset with the same dev flow (`docker compose
down -v` + reseed); no production data exists yet.

## Out of scope (call out so we don't speculate)

- Email invites. Adding a user is admin-typed-email-or-pick-from-instance.
  We accept that this means the user must already have signed in once
  (so a `users` row exists). A "pre-create user by email" flow is the
  obvious follow-up but not in this sprint.
- Per-workspace billing / quotas.
- Cross-workspace task moves. A task lives where its project lives;
  moving a project between workspaces is not supported.
- Workspace deletion. Personal workspaces never delete; non-personal
  workspaces can be vacated (members removed) but the row stays.
  Hard-delete is a future cleanup story.
- A separate "instance superadmin" who can see all workspaces. If we
  need this for ops/support, it's a `users.is_superadmin` bool added
  later; not blocking deploy.

## Build order

1. Migration + model types + seeder updates. Verify existing fixture
   still loads end-to-end (Maya in personal + Acme).
2. `/me` returns workspaces + active. `X-Workspace-Id` plumbing on
   bootstrap and changes.
3. Workspace ops on `/ops`; authorization checks per op kind.
4. Workspace switcher + new-workspace modal.
5. Workspace settings modal (member + role management).
6. Gate project create/edit by role; switch project member picker to
   workspace-scoped users.
7. Update spec.md §3 (data model) and §4 (API) and supersede §4.8 of
   the design doc.
