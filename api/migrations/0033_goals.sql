-- Goals: a named filter over the caller's own time blocks, with a daily
-- or weekly target. Rendered on the month dashboard as a block grid.
--
-- Strictly personal. `user_id` is what makes that true — a goal is never
-- shared, never shown to another member, and never aggregated across
-- people. There is no team-level goal, now or later.
--
-- Workspace-scoped all the same, and deliberately not confined to the
-- user's personal workspace: the goals worth having ("2h/day on Atlas")
-- reference team-workspace projects and tasks, and scoring them from
-- the personal workspace is impossible — the work_calendar overlay
-- returns bare blocks with no project or tag attribution. So the scope
-- refs resolve inside one workspace, and cross-workspace goals wait for
-- the /api/stats/month endpoint.
--
-- project_id / tag_id / task_id are AND-combined; all NULL means "every
-- block in the workspace counts". Note tag_id already implies a project
-- (tags are project-scoped, migration 0015), so project+tag is slightly
-- redundant — harmless, and it keeps the picker uniform.
--
-- `direction` is the comparison against the target. Both halves are
-- worth having and they are not the same feature:
--   at_least — a floor. "1h of drawing a day." Met when total >= target.
--   at_most  — a cap.   "30m of meetings a day." Met when total <= target.
-- A cap inverts the grid's meaning: an empty day trivially *passes* an
-- at_most goal (no meetings is the ideal), and the interesting cell state
-- is overshoot rather than shortfall.
--
-- target_min NULL = "any block counts": a frequency goal, where the
-- period is met if a matching block exists at all. That only makes sense
-- as a floor — "at most, no amount specified" has no meaning — hence the
-- second CHECK.
--
-- No goal *history* table. "Was the target met on Aug 3" is always
-- recomputed from blocks, never stored, so redefining a goal
-- retroactively re-scores its grid — the behaviour you want while
-- still tuning it.

CREATE TABLE goals (
    id           UUID PRIMARY KEY,
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    cadence      TEXT NOT NULL DEFAULT 'daily'
                 CHECK (cadence IN ('daily', 'weekly')),
    direction    TEXT NOT NULL DEFAULT 'at_least'
                 CHECK (direction IN ('at_least', 'at_most')),
    target_min   INT,
    project_id   UUID REFERENCES projects(id) ON DELETE CASCADE,
    tag_id       UUID REFERENCES tags(id)     ON DELETE CASCADE,
    task_id      UUID REFERENCES tasks(id)    ON DELETE CASCADE,
    sort_key     TEXT NOT NULL DEFAULT 'M',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- A cap needs something to cap. Only floors may leave target_min
    -- NULL, where they mean "any block counts".
    CONSTRAINT goals_cap_needs_target
        CHECK (direction = 'at_least' OR target_min IS NOT NULL)
);

-- The only read pattern: bootstrap loading one user's goals for the
-- active workspace.
CREATE INDEX goals_ws_user ON goals (workspace_id, user_id);
