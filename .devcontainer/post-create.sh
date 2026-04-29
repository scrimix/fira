#!/usr/bin/env bash
# Runs once when the devcontainer is built/created.
# Pre-fetches Rust deps and installs web deps so the first edit feels fast.
#
# Verbose by design: pnpm/cargo each take a minute or two on a cold cache and
# silence here looks like a hang. Don't redirect stderr; don't `|| true`.

set -euo pipefail

# Stream every command line as it runs so the VS Code "Dev Containers" log
# shows real progress instead of a spinner.
set -x

cd /workspace

rustc --version
cargo --version
node --version
pnpm --version

echo
echo "==> [1/2] cargo fetch (api/) — populates ~/.cargo/registry"
cd /workspace/api
time cargo fetch --verbose

echo
echo "==> [2/2] pnpm install (web/) — populates web/node_modules"
cd /workspace/web
# --reporter=append-only makes pnpm emit one line per package event, which
# shows up in non-TTY logs (the default reporter uses a spinner that's
# invisible when captured to a pipe).
time pnpm install --reporter=append-only

set +x
echo
echo "============================================================"
echo "Devcontainer ready."
echo "  - Postgres:  postgres:5432  (user/pass/db: fira)"
echo "  - Bring up the rest with compose:"
echo "      docker compose up api web"
echo "  - Or run them in this shell:"
echo "      cd api && cargo run --bin seed     # one-time seed"
echo "      cd api && cargo watch -x run       # api on :3000"
echo "      cd web && pnpm dev --host          # web on :5173"
echo "============================================================"
