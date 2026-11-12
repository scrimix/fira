-- Sprint descriptions: Markdown prose about the sprint, edited in the
-- sprint modal and synced by task-cli (the text between a sprint file's
-- title and its first task).
ALTER TABLE sprints ADD COLUMN description_md TEXT NOT NULL DEFAULT '';

-- The CLI manages the description, so it bumps the revision (0037).
DROP TRIGGER sprints_bump_revision ON sprints;
CREATE TRIGGER sprints_bump_revision
    BEFORE UPDATE ON sprints
    FOR EACH ROW
    WHEN ((OLD.title, OLD.description_md, OLD.starts_on, OLD.ends_on, OLD.track_id,
           OLD.default_assignee_id, OLD.project_id)
          IS DISTINCT FROM
          (NEW.title, NEW.description_md, NEW.starts_on, NEW.ends_on, NEW.track_id,
           NEW.default_assignee_id, NEW.project_id))
    EXECUTE FUNCTION bump_revision();
