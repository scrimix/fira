-- Per-project tags.
--
-- Tags now have identity — a UUID — so the title can be edited without
-- having to rewrite every task that references the old string. They
-- live under a project (the inbox-level scope users already think in)
-- and are joined to tasks via a M:N table.
--
-- The previous tasks.tags TEXT[] column was never editable from the UI;
-- it only held playground fixtures. We drop it outright rather than
-- backfilling — the seed re-emits tags as proper rows.

CREATE TABLE tags (
    id          uuid primary key default gen_random_uuid(),
    project_id  uuid not null references projects(id) on delete cascade,
    title       text not null,
    color       text not null,
    created_at  timestamptz not null default now()
);

-- Case-insensitive uniqueness within a project. Two tags called "Auth"
-- and "auth" would be indistinguishable to a user.
CREATE UNIQUE INDEX tags_unique_title_per_project
    ON tags (project_id, lower(title));

CREATE INDEX idx_tags_project ON tags (project_id);

CREATE TABLE task_tags (
    task_id  uuid not null references tasks(id) on delete cascade,
    tag_id   uuid not null references tags(id) on delete cascade,
    primary key (task_id, tag_id)
);

CREATE INDEX idx_task_tags_tag ON task_tags (tag_id);

ALTER TABLE tasks DROP COLUMN tags;
