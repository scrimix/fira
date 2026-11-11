#!/bin/sh
# Restore a Fira dump into a fresh throwaway database and print row counts.
#
#   ops/backup/restore-check.sh <dump-file> <admin-url> [db-name]
#
# <admin-url> is a postgres URL for a role that may CREATE DATABASE, e.g.
# postgres://fira:fira@postgres:5432/postgres. The target database
# (default fira_restore_check) must not already exist.
set -eu

dump="${1:?usage: restore-check.sh <dump-file> <admin-url> [db-name]}"
admin_url="${2:?usage: restore-check.sh <dump-file> <admin-url> [db-name]}"
db="${3:-fira_restore_check}"

# Replace the database segment of the URL (keeps any ?query string).
target_url=$(echo "$admin_url" | sed -E "s#^(postgres(ql)?://[^/]+)/[^?]*#\1/$db#")

exists=$(psql "$admin_url" -Atc "select 1 from pg_database where datname = '$db'")
if [ -n "$exists" ]; then
  echo "database $db already exists; drop it or pick another name" >&2
  exit 1
fi

sql_file="$(mktemp)"
restored=0
cleanup() {
  rm -f "$sql_file"
  # A failed restore must not leave a half-filled database behind.
  if [ "$restored" -ne 1 ]; then
    psql "$admin_url" -qc "drop database if exists \"$db\" with (force)" || true
  fi
}
trap cleanup EXIT

psql "$admin_url" -qc "create database \"$db\""
# Restore through psql so the one setting newer servers emit can be dropped:
# pg_dump 17 writes `SET transaction_timeout`, which a 16 server (the dev
# compose DB) rejects. Any other error still stops the restore.
# (A temp file rather than a pipe, so a pg_restore failure isn't masked.)
pg_restore --no-owner --no-privileges -f "$sql_file" "$dump"
grep -v '^SET transaction_timeout = ' "$sql_file" \
  | psql -q -v ON_ERROR_STOP=1 -o /dev/null "$target_url"
restored=1

psql "$target_url" -c "
select 'workspaces' as table, count(*) from workspaces
union all select 'projects', count(*) from projects
union all select 'users', count(*) from users
union all select 'sprints', count(*) from sprints
union all select 'tasks', count(*) from tasks
union all select 'subtasks', count(*) from subtasks
union all select 'time_blocks', count(*) from time_blocks
union all select 'migrations', count(*) from _sqlx_migrations"

echo "restored into $target_url"
echo "run the API against it:  DATABASE_URL='$target_url' cargo run --bin fira-api"
