-- Add 'owner' to project_members.role. Three values now:
--   owner   — workspace owner's per-project row. Hidden from inbox assignee
--             groups unless tasks are assigned to them; up-rank to 'lead' to
--             show always, down-rank to 'member' to drop edit power.
--   lead    — explicit project lead; edits project + members; visible.
--   member  — works tasks; visible.
--
-- The motivation: workspace owners were implicitly project leads everywhere,
-- so they showed up as an empty assignee group in every project's inbox even
-- when they weren't actively participating. The 'owner' role makes that
-- "passive" stance explicit and lets them de-rank or up-rank themselves.

ALTER TABLE project_members DROP CONSTRAINT project_members_role_check;
ALTER TABLE project_members
    ADD CONSTRAINT project_members_role_check
    CHECK (role IN ('owner','lead','member'));

-- Backfill: workspace owners become 'owner' on every project in their
-- workspace. Existing rows for them get their role rewritten; missing rows
-- get inserted. Non-WS-owner leads stay as-is.
INSERT INTO project_members (project_id, user_id, role)
SELECT p.id, wm.user_id, 'owner'
FROM projects p
JOIN workspace_members wm ON wm.workspace_id = p.workspace_id
WHERE wm.role = 'owner' AND wm.removed_at IS NULL
ON CONFLICT (project_id, user_id) DO UPDATE
    SET role = 'owner', removed_at = NULL;
