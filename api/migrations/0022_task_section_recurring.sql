-- Add 'recurring' to the tasks.section CHECK constraint.
--
-- Recurring is for ongoing commitments (weekly 1:1, daily journaling)
-- whose unit of work is the time block, not the task itself. The
-- calendar treats blocks on recurring tasks like blocks on a finished
-- task once they're ticked complete (muted, struck through) while
-- planned blocks still render normally — there's no "stale planned"
-- warning, because the task itself is the schedule, not a one-time goal.

ALTER TABLE tasks DROP CONSTRAINT tasks_section_check;
ALTER TABLE tasks ADD CONSTRAINT tasks_section_check
    CHECK (section IN ('now','later','done','someday','recurring'));
