-- Fira initial schema. Trimmed to what the UI actually renders.
-- Add columns when a feature needs them, not in anticipation.

CREATE TABLE users (
    id          UUID PRIMARY KEY,
    email       TEXT NOT NULL,
    name        TEXT NOT NULL,
    initials    TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE projects (
    id          UUID PRIMARY KEY,
    title       TEXT NOT NULL,
    icon        TEXT NOT NULL DEFAULT '',
    color       TEXT NOT NULL,
    source      TEXT NOT NULL CHECK (source IN ('local','jira','notion')),
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE project_members (
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE epics (
    id          UUID PRIMARY KEY,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title       TEXT NOT NULL
);
CREATE INDEX idx_epics_project ON epics(project_id);

CREATE TABLE sprints (
    id          UUID PRIMARY KEY,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    dates       TEXT,
    active      BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX idx_sprints_project ON sprints(project_id);

CREATE TABLE tasks (
    id              UUID PRIMARY KEY,
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    epic_id         UUID REFERENCES epics(id) ON DELETE SET NULL,
    sprint_id       UUID REFERENCES sprints(id) ON DELETE SET NULL,
    assignee_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    title           TEXT NOT NULL,
    description_md  TEXT NOT NULL DEFAULT '',
    section         TEXT NOT NULL CHECK (section IN ('now','later','done')),
    status          TEXT NOT NULL CHECK (status IN ('backlog','todo','in_progress','done')),
    priority        TEXT CHECK (priority IN ('p0','p1','p2','p3')),
    source          TEXT NOT NULL CHECK (source IN ('local','jira','notion')),
    external_id     TEXT,
    estimate_min    INTEGER,
    spent_min       INTEGER NOT NULL DEFAULT 0,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    sort_key        TEXT NOT NULL DEFAULT 'M',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_tasks_project_section ON tasks(project_id, section);
CREATE INDEX idx_tasks_assignee ON tasks(assignee_id);

CREATE TABLE subtasks (
    id          UUID PRIMARY KEY,
    task_id     UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    done        BOOLEAN NOT NULL DEFAULT false,
    sort_key    TEXT NOT NULL DEFAULT 'M'
);
CREATE INDEX idx_subtasks_task ON subtasks(task_id);

CREATE TABLE time_blocks (
    id          UUID PRIMARY KEY,
    task_id     UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    start_at    TIMESTAMPTZ NOT NULL,
    end_at      TIMESTAMPTZ NOT NULL,
    state       TEXT NOT NULL CHECK (state IN ('planned','completed')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_blocks_user_start ON time_blocks(user_id, start_at);
CREATE INDEX idx_blocks_task ON time_blocks(task_id);

CREATE TABLE gcal_events (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    start_at    TIMESTAMPTZ NOT NULL,
    end_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_gcal_user_start ON gcal_events(user_id, start_at);
