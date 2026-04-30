-- Turn processed_ops into a change log.
--
-- `seq` gives every applied op a monotonic global cursor. Clients pass their
-- last-seen seq to GET /changes and we return everything strictly after it.
-- `payload` stores the original wire op so peers can replay it through the
-- same handlers they use for local mutations. `project_id` scopes delivery:
-- /changes filters by `project_id IN (user's project_scope)` so a member of
-- project A never sees ops from project B.

ALTER TABLE processed_ops
    ADD COLUMN seq BIGSERIAL,
    ADD COLUMN payload JSONB,
    ADD COLUMN project_id UUID REFERENCES projects(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX idx_processed_ops_seq ON processed_ops(seq);
-- Hot path for /changes?since=N — cursor + project scope filter.
CREATE INDEX idx_processed_ops_seq_project ON processed_ops(seq, project_id);
