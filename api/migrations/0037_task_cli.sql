-- Sprint 34: task-cli.
--
-- 1. Automation tokens: scoped, revocable bearer tokens for non-browser
--    clients. Only the sha256 of the token is stored; the plaintext is
--    shown once at creation. A token is pinned to one (user, workspace),
--    and membership is re-checked on every request, so removing the user
--    from the workspace disables the token without touching it.
--
-- 2. Revisions on tasks and sprints, so a client can say "apply this only
--    if nothing changed since I looked" (POST /api/cli/apply
--    preconditions). One shared sequence: values are only compared for
--    equality, never across entities.
--
--    Only fields the CLI manages bump the revision. sort_key/updated_at
--    churn from a drag in the UI must not turn into false conflicts.
--    Child rows (subtasks, tags, sprint default tags) bump their parent.
--
-- 3. Indexes for the existence check: deletes are hard, but the
--    task.delete / sprint.delete op stays in processed_ops forever, which
--    is how the CLI tells "deleted" apart from "never existed".

CREATE TABLE automation_tokens (
    id            UUID PRIMARY KEY,
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    workspace_id  UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    -- First characters of the plaintext, for recognising a token in the
    -- list. Not enough to authenticate with.
    token_prefix  TEXT NOT NULL,
    can_write     BOOLEAN NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ
);
CREATE INDEX idx_automation_tokens_user ON automation_tokens (user_id, workspace_id);

CREATE SEQUENCE entity_revision_seq;

ALTER TABLE tasks   ADD COLUMN revision BIGINT NOT NULL DEFAULT nextval('entity_revision_seq');
ALTER TABLE sprints ADD COLUMN revision BIGINT NOT NULL DEFAULT nextval('entity_revision_seq');

CREATE FUNCTION bump_revision() RETURNS trigger AS $$
BEGIN
    NEW.revision := nextval('entity_revision_seq');
    RETURN NEW;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER tasks_bump_revision
    BEFORE UPDATE ON tasks
    FOR EACH ROW
    WHEN ((OLD.title, OLD.description_md, OLD.status, OLD.sprint_id,
           OLD.assignee_id, OLD.estimate_min, OLD.project_id)
          IS DISTINCT FROM
          (NEW.title, NEW.description_md, NEW.status, NEW.sprint_id,
           NEW.assignee_id, NEW.estimate_min, NEW.project_id))
    EXECUTE FUNCTION bump_revision();

CREATE TRIGGER sprints_bump_revision
    BEFORE UPDATE ON sprints
    FOR EACH ROW
    WHEN ((OLD.title, OLD.starts_on, OLD.ends_on, OLD.track_id,
           OLD.default_assignee_id, OLD.project_id)
          IS DISTINCT FROM
          (NEW.title, NEW.starts_on, NEW.ends_on, NEW.track_id,
           NEW.default_assignee_id, NEW.project_id))
    EXECUTE FUNCTION bump_revision();

-- Child tables set the parent's revision directly. The parent's own
-- trigger sees no managed field change and leaves that value alone. When
-- the parent itself is being deleted (cascade), the UPDATE finds no row.
CREATE FUNCTION bump_task_revision_from_child() RETURNS trigger AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        UPDATE tasks SET revision = nextval('entity_revision_seq') WHERE id = OLD.task_id;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        UPDATE tasks SET revision = nextval('entity_revision_seq') WHERE id = NEW.task_id;
    END IF;
    RETURN NULL;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER subtasks_bump_task_revision
    AFTER INSERT OR DELETE OR UPDATE OF title, done, sort_key, task_id ON subtasks
    FOR EACH ROW EXECUTE FUNCTION bump_task_revision_from_child();

CREATE TRIGGER task_tags_bump_task_revision
    AFTER INSERT OR DELETE OR UPDATE ON task_tags
    FOR EACH ROW EXECUTE FUNCTION bump_task_revision_from_child();

CREATE FUNCTION bump_sprint_revision_from_child() RETURNS trigger AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        UPDATE sprints SET revision = nextval('entity_revision_seq') WHERE id = OLD.sprint_id;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        UPDATE sprints SET revision = nextval('entity_revision_seq') WHERE id = NEW.sprint_id;
    END IF;
    RETURN NULL;
END
$$ LANGUAGE plpgsql;

CREATE TRIGGER sprint_default_tags_bump_sprint_revision
    AFTER INSERT OR DELETE OR UPDATE ON sprint_default_tags
    FOR EACH ROW EXECUTE FUNCTION bump_sprint_revision_from_child();

CREATE INDEX idx_processed_ops_task_delete
    ON processed_ops ((payload->>'task_id'), workspace_id) WHERE kind = 'task.delete';
CREATE INDEX idx_processed_ops_sprint_delete
    ON processed_ops ((payload->>'sprint_id'), workspace_id) WHERE kind = 'sprint.delete';
