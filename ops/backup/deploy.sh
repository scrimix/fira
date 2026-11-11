#!/bin/sh
# Deploy the backup job. Works from any directory: the image builds api/, so
# the build context must be the repo root, not ops/backup/.
#   ops/backup/deploy.sh            (extra args are passed to fly deploy)
set -eu
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
exec fly deploy "$root" \
  --config "$root/ops/backup/fly.toml" \
  --dockerfile "$root/ops/backup/Dockerfile" \
  "$@"
