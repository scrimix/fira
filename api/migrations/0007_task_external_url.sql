-- Per-task external URL — overrides the project's URL template.
--
-- The template (`projects.external_url_template`) only fits trackers with
-- a stable `{key}` pattern (Jira, Linear). Notion pages, GitHub issues
-- with arbitrary slugs, design docs, etc. don't fit a template — a
-- per-task URL is the escape hatch.
--
-- Resolution order:
--   1. tasks.external_url   — wins if set; used directly
--   2. tasks.external_id + projects.external_url_template — template fill
--   3. neither               — render external_id as plain text (or empty)

ALTER TABLE tasks
    ADD COLUMN external_url TEXT;
