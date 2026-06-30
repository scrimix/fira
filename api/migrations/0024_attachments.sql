-- Attachments table
-- Used primarily for task attachments
-- Storage planned to be Tigris S3

CREATE TABLE attachments (
    id          UUID PRIMARY KEY,
    task_id     UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    filename    TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    content_type TEXT NOT NULL,
    size        BIGINT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);