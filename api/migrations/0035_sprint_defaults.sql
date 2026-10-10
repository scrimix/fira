-- Defaults seed newly created sprint tasks; existing tasks keep their values.
ALTER TABLE sprints ADD COLUMN default_assignee_id UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE TABLE sprint_default_tags (
    sprint_id UUID NOT NULL REFERENCES sprints(id) ON DELETE CASCADE,
    tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (sprint_id, tag_id)
);
