-- Workspaces, the company-level tenant boundary.
--
-- Reverses the §4.8 design-doc decision that treated "team = a project with
-- members." That worked for a single-founder dogfood; once two unrelated
-- companies share an instance, every user lands in the same global directory
-- and projects leak across tenants. Workspaces are the seam.
--
-- Roles per workspace_member row (a user can be `owner` in one workspace and
-- `member` in another):
--   - owner: manages workspace title, members, and roles
--   - lead:  creates and edits projects in the workspace
--   - member: works tasks, drags blocks, etc.
--
-- Personal workspace invariant: every user has exactly one workspace where
-- is_personal = true and they are owner. Created on first login or seeder.
-- Cannot be deleted. Cannot have other members added.
--
-- This migration assumes a freshly seeded database (no production data
-- exists). The previous schema's projects/project_members are dropped and
-- re-shaped to require a workspace_id.

CREATE TABLE workspaces (
    id          UUID PRIMARY KEY,
    title       TEXT NOT NULL,
    is_personal BOOLEAN NOT NULL DEFAULT false,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role         TEXT NOT NULL CHECK (role IN ('owner','lead','member')),
    removed_at   TIMESTAMPTZ,
    PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX idx_workspace_members_user ON workspace_members(user_id);

-- "One personal workspace per user" is enforced at the app layer (seeder +
-- OAuth callback are the only paths that create them). PostgreSQL doesn't
-- allow subqueries in partial-index predicates, and denormalizing
-- is_personal into workspace_members would force two rows to update in
-- lock-step — not worth it for an invariant a single helper guards.

-- Drop preexisting fixture data: every project needs a workspace_id and
-- there's no sensible auto-backfill for legacy rows. The seeder reseats
-- everything within seconds. Order: child rows first, then dependents.
TRUNCATE TABLE
    processed_ops,
    gcal_events,
    time_blocks,
    subtasks,
    tasks,
    sprints,
    epics,
    project_members,
    projects
RESTART IDENTITY;

-- Projects belong to a workspace.
ALTER TABLE projects
    ADD COLUMN workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE;

CREATE INDEX idx_projects_workspace ON projects(workspace_id);

-- Composite FK so it's structurally impossible to add a user to a project
-- they're not in the workspace for. project_members.workspace_id is mirrored
-- from the parent project — enforced by trigger so the app layer doesn't
-- have to thread it through.
ALTER TABLE project_members
    ADD COLUMN workspace_id UUID NOT NULL;

ALTER TABLE project_members
    ADD CONSTRAINT project_members_workspace_member_fk
    FOREIGN KEY (workspace_id, user_id)
    REFERENCES workspace_members(workspace_id, user_id)
    ON DELETE CASCADE;

CREATE OR REPLACE FUNCTION project_members_set_workspace_id()
RETURNS TRIGGER AS $$
BEGIN
    SELECT workspace_id INTO NEW.workspace_id FROM projects WHERE id = NEW.project_id;
    IF NEW.workspace_id IS NULL THEN
        RAISE EXCEPTION 'project % has no workspace_id', NEW.project_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER project_members_workspace_id_trigger
    BEFORE INSERT OR UPDATE OF project_id ON project_members
    FOR EACH ROW EXECUTE FUNCTION project_members_set_workspace_id();

-- The change feed needs to deliver workspace.* ops (rename, member changes,
-- role updates) to every workspace member, even ones who aren't in any of
-- the workspace's projects. project_id alone can't carry that signal — add
-- workspace_id alongside. For project-scoped ops, both columns are set.
ALTER TABLE processed_ops
    ADD COLUMN workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE;
CREATE INDEX idx_processed_ops_seq_workspace ON processed_ops(seq, workspace_id);
