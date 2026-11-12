#!/bin/sh
# Installs the task-cli binary from the GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/scrimix/fira/master/cli/install.sh | sh
#
# TASK_CLI_VERSION=0.1.5   a specific version (default: the latest release)
# TASK_CLI_INSTALL_DIR=…   where to put it (default: ~/.local/bin)
set -eu

repo="scrimix/fira"
dir="${TASK_CLI_INSTALL_DIR:-$HOME/.local/bin}"

case "$(uname -s)" in
  Linux) os=unknown-linux-musl ;;
  Darwin) os=apple-darwin ;;
  *) echo "task-cli: no prebuilt binary for $(uname -s); use cargo install (see cli/README.md)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=aarch64 ;;
  *) echo "task-cli: no prebuilt binary for $(uname -m); use cargo install (see cli/README.md)" >&2; exit 1 ;;
esac
asset="task-cli-$arch-$os.tar.gz"

if [ -n "${TASK_CLI_VERSION:-}" ]; then
  base="https://github.com/$repo/releases/download/cli-v${TASK_CLI_VERSION#v}"
else
  base="https://github.com/$repo/releases/latest/download"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
echo "Downloading $base/$asset"
curl -fsSL "$base/$asset" -o "$tmp/$asset"
curl -fsSL "$base/$asset.sha256" -o "$tmp/$asset.sha256"

want="$(cut -d' ' -f1 < "$tmp/$asset.sha256")"
if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$tmp/$asset" | cut -d' ' -f1)"
else got="$(shasum -a 256 "$tmp/$asset" | cut -d' ' -f1)"; fi
if [ "$want" != "$got" ]; then
  echo "task-cli: checksum mismatch for $asset; nothing installed" >&2
  exit 1
fi

tar xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$dir"
mv "$tmp/task-cli" "$dir/task-cli"
chmod +x "$dir/task-cli"
echo "Installed $("$dir/task-cli" --version) to $dir/task-cli"
case ":$PATH:" in
  *":$dir:"*) ;;
  *) echo "Note: $dir is not on PATH; add it to your shell profile." ;;
esac
