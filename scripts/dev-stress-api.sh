#!/usr/bin/env bash
# Run a stress-test API instance: the standard `fira-api` binary pointed
# at the dedicated `fira_stress` database and bound to :3100, so it never
# collides with the regular dev API on :3000 (different DB, different
# port — the two run side by side).
#
# Prereq: the stress database must be seeded first —
#   DATABASE_URL=postgres://fira:fira@postgres:5432/fira_stress \
#     cargo run --release --manifest-path api/Cargo.toml --bin stress_seed
#
# Usage:
#   Terminal 1:  scripts/dev-stress-api.sh              # stress API on :3100
#   Terminal 2:  ./api/target/release/stress_load       # 1000-user load test
#
# To browse the stress env as a real user:
#   Terminal 2:  cd web && pnpm dev:stress              # stress web on :5175
#   then visit   http://localhost:5175/api/auth/dev-login?email=user1@stress.test
#
# Env overrides:
#   STRESS_DB_URL       Postgres URL   (default: .../fira_stress)
#   API_BIND_ADDR       bind address   (default: 0.0.0.0:3100)
#   DB_MAX_CONNECTIONS  pool size      (default: 100; the prod default is 5 —
#                                       set =5 to load-test the prod posture)
#   DEV_AUTH            1 enables /auth/dev-login        (default: 1)
#   APP_BASE_URL        post-login redirect target       (default: :5175 web)
#
# A --release build is used on purpose: debug builds skew load-test
# latency by an order of magnitude.

set -euo pipefail
cd "$(dirname "$0")/.."

exec env \
  DATABASE_URL="${STRESS_DB_URL:-postgres://fira:fira@postgres:5432/fira_stress}" \
  API_BIND_ADDR="${API_BIND_ADDR:-0.0.0.0:3100}" \
  DB_MAX_CONNECTIONS="${DB_MAX_CONNECTIONS:-100}" \
  DEV_AUTH="${DEV_AUTH:-1}" \
  APP_BASE_URL="${APP_BASE_URL:-http://localhost:5175}" \
  RUST_LOG="${RUST_LOG:-info,sqlx=warn,tower_http=warn}" \
  cargo run --release --manifest-path api/Cargo.toml --bin fira-api
