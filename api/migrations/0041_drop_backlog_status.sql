-- "backlog" was a second way of saying "todo" (the CLI already read it
-- as todo). Fold existing rows into todo and stop accepting it.
UPDATE tasks SET status = 'todo' WHERE status = 'backlog';
ALTER TABLE tasks DROP CONSTRAINT IF EXISTS tasks_status_check;
ALTER TABLE tasks ADD CONSTRAINT tasks_status_check
  CHECK (status IN ('todo', 'in_progress', 'done'));
