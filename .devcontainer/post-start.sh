#!/usr/bin/env bash
# Runs every time the devcontainer starts (including resume).
# Seeds the database if it looks empty.

set -euo pipefail
set -x

echo "==> waiting for postgres to accept connections"
for i in {1..30}; do
  if pg_isready -q; then
    echo "postgres ready"
    break
  fi
  echo "   not ready ($i/30) — sleep 1s"
  sleep 1
done

# PGHOST/PGUSER/PGPASSWORD/PGDATABASE come from compose env.
count=$(psql -tAc \
  "SELECT to_regclass('public.tasks') IS NOT NULL AND (SELECT COUNT(*) FROM tasks) > 0" \
  2>/dev/null || echo "f")

if [[ "$count" == "t" ]]; then
  echo "==> database already seeded — skipping"
else
  echo "==> running migrations + seed (cargo run --bin seed)"
  cd /workspace/api
  cargo run --bin seed
fi
