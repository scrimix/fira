-- Soft-delete for project membership.
--
-- Removing a user from a project must not vaporize their tasks, time blocks,
-- or assignment history (project_members PK + ON DELETE CASCADE would chain
-- nothing here, but task assignee_id and time_blocks remain meaningful).
-- Instead we mark the row as removed and exclude it from scope queries.
-- Re-adding the same user clears the flag so the row stays unique on PK.

ALTER TABLE project_members
    ADD COLUMN removed_at TIMESTAMPTZ;
