#!/usr/bin/env bash
# Runs as PID 1 of the dev container as root.
# Fixes ownership of the named-volume mountpoints (docker creates them
# root-owned, but the workbench user is vscode), then keeps the container
# alive so VS Code can attach.

set -eu

for path in \
  /workspace/web/node_modules \
  /workspace/api/target \
  /home/vscode/.cargo/registry \
  /home/vscode/.cargo \
  /home/vscode/.claude \
  /home/vscode/.vscode-server
do
  if [ -d "$path" ]; then
    chown -R vscode:vscode "$path" || echo "warn: chown $path failed (continuing)"
  fi
done

exec sleep infinity
