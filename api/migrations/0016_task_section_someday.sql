-- Add 'someday' to the tasks.section CHECK constraint.
--
-- Someday is the parking lot beyond Later: ideas you don't want to lose
-- but aren't planning around. Inbox renders it as a fourth section,
-- collapsed by default, and the task modal lets you move tasks in/out.

ALTER TABLE tasks DROP CONSTRAINT tasks_section_check;
ALTER TABLE tasks ADD CONSTRAINT tasks_section_check
    CHECK (section IN ('now','later','done','someday'));
