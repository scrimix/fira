# task-cli

Keeps sprint and task Markdown documents in a repository in sync with
Fira. Every publish or import shows a field-by-field diff, and nothing is
written on either side until you accept it.

## Install

```sh
cargo install --git https://github.com/scrimix/fira --tag cli-v0.1.0 task-cli
```

or, from a checkout:

```sh
cargo install --path cli
```

## Set up a repository

```sh
task-cli init --url https://usefira.app   # creates tasks/config.toml (commit it)
task-cli login fira                       # paste a token from Fira → Account settings → Automation tokens
```

The token is personal and stored outside the repository, in
`~/.config/task-cli/credentials.toml`. That location can be changed with
`TASK_CLI_CONFIG_DIR`. For CI, set `TASK_CLI_FIRA_TOKEN` instead.

One file holds every login (keyed by Fira URL and workspace), so a single
directory serves all your projects. In a dev container, bind-mount the
host's directory, like `~/.ssh`:

```yaml
# docker-compose (devcontainer)
volumes:
  - ${HOME}/.config/task-cli:/home/vscode/.config/task-cli
```

```jsonc
// devcontainer.json: create it on the host first, or Docker creates it root-owned
"initializeCommand": "mkdir -p \"$HOME/.config/task-cli\" && chmod 700 \"$HOME/.config/task-cli\""
```

Mount the directory, not the file: credentials are written by atomic
rename, which fails on a single-file bind mount.

Add one line to the repository's agent instructions (e.g. `CLAUDE.md`):

> Run `task-cli help agents` before editing `tasks/`.

## Use

```sh
task-cli fmt                                  # add ids, normalise structure lines
task-cli diff                                 # read-only; exit 0 in sync, 1 differences
task-cli publish fira tasks/sprints/001.md    # diff → choose per field → confirm → write
task-cli import fira <sprint-id | task link>  # bring Fira work into the repo
```

The full docs are built into the binary, so they always match the
installed version:

```sh
task-cli help workflow
task-cli help format
task-cli help agents
task-cli <command> --help
```

## Development

```sh
cargo test --manifest-path cli/Cargo.toml     # unit tests (no network)
cargo test --manifest-path api/Cargo.toml --test task_cli_api   # server side
```

The design is documented in
[docs/sprints/34-task-cli-mvp.md](../docs/sprints/34-task-cli-mvp.md).
