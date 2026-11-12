#!/bin/sh
# Deploy the backup job AND put its machine on the daily schedule.
#
# The schedule cannot live in fly.toml: Fly only supports it per machine
# (`fly machine update --schedule`), and a deploy does not set it. So this
# script applies it after every deploy and fails loudly if it did not stick.
#
# Works from any directory: the image builds api/, so the build context must
# be the repo root, not ops/backup/.
#   ops/backup/deploy.sh            (extra args are passed to fly deploy)
set -eu
app=fira-backup
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"

fly deploy "$root" \
  --config "$root/ops/backup/fly.toml" \
  --dockerfile "$root/ops/backup/Dockerfile" \
  "$@"

ids="$(fly machine list -a "$app" -q)"
count="$(printf '%s\n' "$ids" | grep -c . || true)"
if [ "$count" -ne 1 ]; then
  echo "deploy.sh: expected exactly 1 machine in $app, found $count:" >&2
  printf '%s\n' "$ids" >&2
  echo "fix with: fly scale count 1 -a $app --yes, then rerun this script" >&2
  exit 1
fi
id="$ids"

# May start the job once; a same-day rerun just overwrites today's dump.
fly machine update "$id" -a "$app" --schedule daily --restart no --yes

if fly machine status "$id" -a "$app" -d | grep -q '"schedule": *"daily"'; then
  echo "deploy.sh: OK, machine $id is scheduled daily"
else
  echo "deploy.sh: FAILED: machine $id has no daily schedule after update" >&2
  exit 1
fi
