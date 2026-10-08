#!/usr/bin/env bash
# Verify migration 0034 (epics -> tracks) over POPULATED data.
# `seed --drop` only ever exercises a fresh DB, and a rename that drops
# an FK looks like a success at the psql prompt.
#
# Scratch DB -> migrate to 0033 -> insert a task with both plan links ->
# apply 0034 -> assert. Dropped on exit either way.
#
#   ./scripts/test-migration.sh

set -euo pipefail
cd "$(dirname "$0")/.."

PGHOST="${PGHOST:-postgres}"
PGUSER="${PGUSER:-fira}"
SCRATCH="fira_migration_test_$$"

export PGHOST PGUSER

admin() { psql -q -d postgres -v ON_ERROR_STOP=1 "$@"; }
db()    { psql -q -d "$SCRATCH" -v ON_ERROR_STOP=1 "$@"; }
val()   { psql -tAX -d "$SCRATCH" -v ON_ERROR_STOP=1 -c "$1"; }

fails=0
pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"; fails=$((fails + 1)); }

# assert_eq <description> <expected> <sql>
assert_eq() {
  local desc="$1" want="$2" got
  got="$(val "$3")"
  [ "$got" = "$want" ] && pass "$desc" || fail "$desc" "$want" "$got"
}

# assert_rejects <description> <sql> — the statement must raise.
assert_rejects() {
  local desc="$1"
  if db -c "$2" >/dev/null 2>&1; then
    fail "$desc" "an error" "statement succeeded"
  else
    pass "$desc"
  fi
}

cleanup() { admin -c "DROP DATABASE IF EXISTS \"$SCRATCH\";" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "scratch database: $SCRATCH"
admin -c "CREATE DATABASE \"$SCRATCH\";"

# --- migrate to 0033 ---
echo "applying 0001..0033"
for f in api/migrations/*.sql; do
  case "$(basename "$f")" in
    0034_*) continue ;;
  esac
  db -f "$f" >/dev/null
done

# --- populate ---
echo "populating"
db >/dev/null <<'SQL'
INSERT INTO users (id, email, name, initials)
  VALUES ('11111111-1111-1111-1111-111111111111', 'm@example.com', 'Maya', 'MA');
INSERT INTO workspaces (id, title, is_personal)
  VALUES ('22222222-2222-2222-2222-222222222222', 'Test WS', true);
INSERT INTO projects (id, workspace_id, title, icon, color, source)
  VALUES ('33333333-3333-3333-3333-333333333333',
          '22222222-2222-2222-2222-222222222222', 'Atlas', 'A', '#0F766E', 'local');
INSERT INTO epics (id, project_id, title)
  VALUES ('44444444-4444-4444-4444-444444444444',
          '33333333-3333-3333-3333-333333333333', 'Architecture');
INSERT INTO sprints (id, project_id, title, active)
  VALUES ('55555555-5555-5555-5555-555555555555',
          '33333333-3333-3333-3333-333333333333', 'A1 Groundwork', true);
INSERT INTO tasks (id, project_id, epic_id, sprint_id, title, section, status, source)
  VALUES ('66666666-6666-6666-6666-666666666666',
          '33333333-3333-3333-3333-333333333333',
          '44444444-4444-4444-4444-444444444444',
          '55555555-5555-5555-5555-555555555555',
          'Pick a queue', 'later', 'todo', 'local');
SQL

# --- the migration under test ---
echo "applying 0034"
db -f api/migrations/0034_plan_tracks_sprints.sql >/dev/null

echo "asserting"

assert_eq "tracks holds the former epics row" "Architecture" \
  "SELECT title FROM tracks WHERE id = '44444444-4444-4444-4444-444444444444';"

assert_eq "tracks count equals the pre-migration epics count" "1" \
  "SELECT count(*) FROM tracks;"

assert_eq "tasks.track_id carries the old epic_id value" \
  "44444444-4444-4444-4444-444444444444" \
  "SELECT track_id FROM tasks WHERE id = '66666666-6666-6666-6666-666666666666';"

assert_eq "tasks.epic_id is gone" "0" \
  "SELECT count(*) FROM information_schema.columns
    WHERE table_name = 'tasks' AND column_name = 'epic_id';"

assert_eq "tasks.sprint_id is preserved" \
  "55555555-5555-5555-5555-555555555555" \
  "SELECT sprint_id FROM tasks WHERE id = '66666666-6666-6666-6666-666666666666';"

# The FK itself: a dropped constraint leaves every assertion above passing.
assert_eq "tasks.track_id still references tracks(id)" "1" \
  "SELECT count(*) FROM pg_constraint c
     JOIN pg_class child  ON child.oid  = c.conrelid
     JOIN pg_class parent ON parent.oid = c.confrelid
    WHERE c.contype = 'f' AND child.relname = 'tasks' AND parent.relname = 'tracks';"

assert_eq "the renamed project index survived" "1" \
  "SELECT count(*) FROM pg_indexes
    WHERE tablename = 'tracks' AND indexname = 'idx_tracks_project';"

assert_eq "the scrubber's history index exists" "1" \
  "SELECT count(*) FROM pg_indexes
    WHERE indexname = 'idx_processed_ops_project_applied';"

# Defaults landed, so old rows need no backfill.
assert_eq "existing track row got the default colour" "#334155" \
  "SELECT color FROM tracks WHERE id = '44444444-4444-4444-4444-444444444444';"

assert_eq "existing sprint row has a null span" "t" \
  "SELECT starts_on IS NULL AND ends_on IS NULL FROM sprints
    WHERE id = '55555555-5555-5555-5555-555555555555';"

# The CHECKs fire.
assert_rejects "a Tuesday starts_on is rejected" \
  "UPDATE sprints SET starts_on = DATE '2026-10-06'
     WHERE id = '55555555-5555-5555-5555-555555555555';"

assert_rejects "a Tuesday ends_on is rejected" \
  "UPDATE sprints SET ends_on = DATE '2026-10-06'
     WHERE id = '55555555-5555-5555-5555-555555555555';"

assert_rejects "an inverted span is rejected" \
  "UPDATE sprints SET starts_on = DATE '2026-10-12', ends_on = DATE '2026-10-05'
     WHERE id = '55555555-5555-5555-5555-555555555555';"

assert_rejects "a zero-width span is rejected" \
  "UPDATE sprints SET starts_on = DATE '2026-10-05', ends_on = DATE '2026-10-05'
     WHERE id = '55555555-5555-5555-5555-555555555555';"

# The ordinary case is still writable.
db -c "UPDATE sprints
          SET starts_on = DATE '2026-10-05', ends_on = DATE '2026-10-19',
              track_id  = '44444444-4444-4444-4444-444444444444'
        WHERE id = '55555555-5555-5555-5555-555555555555';" >/dev/null
assert_eq "a forward Monday-to-Monday span is accepted" "14" \
  "SELECT ends_on - starts_on FROM sprints
    WHERE id = '55555555-5555-5555-5555-555555555555';"

# Deleting structure must never destroy tasks.
db -c "DELETE FROM tracks WHERE id = '44444444-4444-4444-4444-444444444444';" >/dev/null
assert_eq "deleting a track NULLs its sprints' track_id" "t" \
  "SELECT track_id IS NULL FROM sprints
    WHERE id = '55555555-5555-5555-5555-555555555555';"
assert_eq "deleting a track did not cascade the sprint away" "1" \
  "SELECT count(*) FROM sprints
    WHERE id = '55555555-5555-5555-5555-555555555555';"
assert_eq "deleting a track NULLs its tasks' track_id" "t" \
  "SELECT track_id IS NULL FROM tasks
    WHERE id = '66666666-6666-6666-6666-666666666666';"
assert_eq "deleting a track did not cascade the task away" "1" \
  "SELECT count(*) FROM tasks
    WHERE id = '66666666-6666-6666-6666-666666666666';"

db -c "DELETE FROM sprints WHERE id = '55555555-5555-5555-5555-555555555555';" >/dev/null
assert_eq "deleting a sprint NULLs its tasks' sprint_id" "t" \
  "SELECT sprint_id IS NULL FROM tasks
    WHERE id = '66666666-6666-6666-6666-666666666666';"
assert_eq "deleting a sprint did not cascade the task away" "1" \
  "SELECT count(*) FROM tasks
    WHERE id = '66666666-6666-6666-6666-666666666666';"

echo
if [ "$fails" -eq 0 ]; then
  echo "all assertions passed"
else
  echo "$fails assertion(s) failed"
  exit 1
fi
