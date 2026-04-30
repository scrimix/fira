-- Per-project URL template for the manual issue-link feature.
--
-- Stored as a free-form string with `{key}` as the placeholder for the
-- task's external_id. Example: "https://acme.atlassian.net/browse/{key}".
-- NULL means the project has no tracker — task external_ids are still
-- displayed but not rendered as a link.

ALTER TABLE projects
    ADD COLUMN external_url_template TEXT;
