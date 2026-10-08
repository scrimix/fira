-- Plan view: tracks (board rows) and sprints (week-spanning cards).
--
-- `epics` has sat unused since 0001 with a tasks FK, a bootstrap field,
-- a model, a TS type and a store array. Rename rather than add a table,
-- and not to "epic" — /api/jira/epics already means Jira epics.
--
-- Membership chain is single-valued at every hop:
--     task --sprint_id--> sprint --track_id--> track --> board row
-- so nothing can render twice and no validation rule is needed. Tags
-- are untouched. `tasks.track_id` means "in a workstream, not yet in a
-- sprint"; a task's track resolves at render time as its sprint's track
-- if it has a sprint, else this.

ALTER TABLE epics RENAME TO tracks;
ALTER INDEX idx_epics_project RENAME TO idx_tracks_project;
ALTER TABLE tasks RENAME COLUMN epic_id TO track_id;

-- created_at is the stable tiebreak for the derived A1/A2 badge codes.
ALTER TABLE tracks
    ADD COLUMN color      TEXT NOT NULL DEFAULT '#334155',
    ADD COLUMN sort_key   TEXT NOT NULL DEFAULT 'M',
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- [starts_on, ends_on) — end-exclusive, both week-aligned Mondays. So
-- colspan is (ends_on - starts_on)/7 with no +1, and a zero-width
-- sprint is invalid rather than the thing you get by filling in one
-- field. Both nullable: an unspanned sprint doesn't render on the
-- board. track_id nullable because "No track" is reachable, not an
-- error — deleting a track SET NULLs its sprints (0001) and the board
-- shows the orphans in a row at its foot.
ALTER TABLE sprints
    ADD COLUMN track_id   UUID REFERENCES tracks(id) ON DELETE SET NULL,
    ADD COLUMN starts_on  DATE,
    ADD COLUMN ends_on    DATE,
    ADD COLUMN sort_key   TEXT NOT NULL DEFAULT 'M',
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- DATE has no timezone, so ISODOW is absolute — these mean the same for
-- every client.
ALTER TABLE sprints
    ADD CONSTRAINT sprints_span_forward
        CHECK (ends_on IS NULL OR starts_on IS NULL OR ends_on > starts_on),
    ADD CONSTRAINT sprints_starts_on_monday
        CHECK (starts_on IS NULL OR EXTRACT(ISODOW FROM starts_on) = 1),
    ADD CONSTRAINT sprints_ends_on_monday
        CHECK (ends_on IS NULL OR EXTRACT(ISODOW FROM ends_on) = 1);

-- `sprints.dates` and `sprints.active` stay untouched. `active` is
-- redundant with the span on a board that draws a "now" marker, so the
-- plan view neither reads nor writes it.

CREATE INDEX idx_sprints_track ON sprints (track_id) WHERE track_id IS NOT NULL;
CREATE INDEX idx_tasks_sprint  ON tasks   (sprint_id) WHERE sprint_id IS NOT NULL;

-- For the version scrubber's `project_id = $1 AND applied_at <= $2
-- ORDER BY seq`. idx_processed_ops_seq_project can't serve it (seq
-- leads). Cheap now, a different kind of change once the table is big.
CREATE INDEX idx_processed_ops_project_applied
    ON processed_ops (project_id, applied_at, seq);
