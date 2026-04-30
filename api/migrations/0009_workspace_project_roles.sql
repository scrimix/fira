-- Two role axes:
--   workspace_members.role: ('owner','member')      — workspace tenancy
--   project_members.role:   ('lead','member')       — per-project authority
--
-- Workspace owner is implicitly a project lead in every project — we don't
-- materialize that as rows; the auth check in code treats workspace-owner as
-- a wildcard. This keeps the FK shape simple (a workspace owner who isn't
-- explicitly a project member can still administer the project).
--
-- Project lead can add project members (defaulted to 'member'). Only the
-- workspace owner can change a project member's role to 'lead'.

-- 1) Tighten workspace_members.role to two values. Pre-existing 'lead' rows
--    get folded into 'member' — workspace lead was never the right axis for
--    project authority anyway, and any workspace they previously could
--    "lead" through that role had to also have project membership to do
--    anything meaningful.
UPDATE workspace_members SET role = 'member' WHERE role = 'lead';

ALTER TABLE workspace_members DROP CONSTRAINT workspace_members_role_check;
ALTER TABLE workspace_members
    ADD CONSTRAINT workspace_members_role_check
    CHECK (role IN ('owner','member'));

-- 2) project_members gains a per-row role.
ALTER TABLE project_members
    ADD COLUMN role TEXT NOT NULL DEFAULT 'member'
    CHECK (role IN ('lead','member'));

-- The original project owner (projects.owner_id) becomes the implicit
-- starting lead — project ownership isn't going away as a column (it's the
-- "creator" / billing-anchor concept), but the day-to-day administrative
-- power is now expressed via this role.
UPDATE project_members pm
SET role = 'lead'
FROM projects p
WHERE pm.project_id = p.id AND pm.user_id = p.owner_id;
