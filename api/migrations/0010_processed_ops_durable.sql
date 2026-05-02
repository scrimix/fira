-- Decouple the change log from entity lifecycle.
--
-- Before: processed_ops.project_id and .workspace_id had ON DELETE CASCADE,
-- so deleting a project/workspace silently wiped its history. That broke
-- two things:
--   1. The synthesized `project.delete` / `workspace.delete` op got
--      cascade-deleted by the very delete it was announcing, so other
--      clients in the workspace never saw the change-feed notification.
--   2. The audit/replay value of processed_ops as a durable log.
--
-- After: drop the FK constraints. workspace_id / project_id are now
-- historical pointers — they may reference deleted rows. The /changes
-- query already handles missing parents (the EXISTS checks naturally
-- yield empty for deleted projects), and clients applying e.g.
-- `task.set_title` for a task that no longer exists locally are tolerated
-- by applyOpToState by design.
--
-- Delete handlers are now responsible for explicit cleanup of every
-- dependent row (rather than relying on cascade) — the handler reads as
-- the authoritative "REMOVE EVERYTHING" sequence for the entity.

ALTER TABLE processed_ops
    DROP CONSTRAINT IF EXISTS processed_ops_project_id_fkey;

ALTER TABLE processed_ops
    DROP CONSTRAINT IF EXISTS processed_ops_workspace_id_fkey;
