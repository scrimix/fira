#!/usr/bin/env bash
# Run a second API instance on :3001 sharing the same Postgres as the
# primary. Used to verify the LISTEN/NOTIFY-based cross-instance WS
# fan-out: a write through one API instance must nudge WS clients
# connected to the other.
#
# Usage:
#   Terminal 1:  cd api && cargo run                     # API on :3000
#   Terminal 2:  scripts/dev-second-api.sh               # API on :3001
#   Terminal 3:  cd web && pnpm dev                      # web on :5173 → API :3000
#   Terminal 4:  cd web && pnpm dev:second               # web on :5174 → API :3001
#
# Open http://localhost:5173 and http://localhost:5174 in two tabs (same
# session — log in once, the cookie applies). Make a change in one tab;
# the other should update over WS without waiting for the 60s poll.

set -euo pipefail
cd "$(dirname "$0")/.."
exec env API_BIND_ADDR=0.0.0.0:3001 cargo run --manifest-path api/Cargo.toml --bin fira-api
