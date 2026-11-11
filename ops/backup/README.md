# Database backups

A scheduled Fly machine (`fira-backup` app) dumps production once a day with
`pg_dump -Fc` and uploads it to a private Tigris bucket, separate from the
attachments bucket, as `fira-YYYY-MM-DD.dump`. After each successful upload,
dumps older than 30 days are deleted. Attachment files are **not** backed up;
only their metadata rows are in the dump.

The job is the `fira-backup` binary in the API crate
([`api/src/bin/backup.rs`](../../api/src/bin/backup.rs)). It uses the same
`storage::S3Storage` client as the API. The image is `debian:bookworm-slim`
with `postgresql-client-17`, no server and no Python.

| File | Purpose |
|---|---|
| `Dockerfile` | builds `fira-backup`, adds the Postgres client tools; `PG_MAJOR` build arg (default 17) |
| `deploy.sh` | runs `fly deploy` with the repo root as build context |
| `fly.toml` | `fira-backup` app, restart policy `never` |
| `restore-check.sh` | restore a dump into a new database and print row counts |

## What a run does

1. Checks the server version against `pg_dump` and warns on a mismatch.
2. `pg_dump -Fc --no-owner --no-privileges` to a temp file.
3. `pg_restore --list`: the archive must contain data for `tasks`,
   `subtasks`, `sprints`, `projects`, `users` and `_sqlx_migrations`.
4. Uploads the dump and checks the stored size matches.
5. Deletes `fira-*.dump` objects older than `RETENTION_DAYS`. It never
   deletes the dump it just wrote, and it only prunes after a successful
   upload, so a broken job leaves the old dumps in place.

Any failure exits 1 with `fira-backup: FAILED: …` in the logs. There is no
alert; check `fira-backup list` now and then, and a missing day means a
failed run.

## Configuration (Fly secrets on `fira-backup`)

| Name | Value |
|---|---|
| `DATABASE_URL` | read-only role, e.g. `postgres://fira_backup:<pw>@fira-tasks-db.flycast:5432/<db>?sslmode=disable` |
| `BUCKET_NAME` | the backup bucket |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | a key with Editor access to the backup bucket only |
| `AWS_ENDPOINT_URL_S3` | `<storage-url>`, the bucket's S3 endpoint. Required: without it the SDK would go to AWS |
| `AWS_REGION` | `auto` |

Optional: `RETENTION_DAYS` (default 30), `BACKUP_KEY` (object key override),
`BACKUP_DRY_RUN=1` (dump and verify only, no storage access).

Set secrets **without** `--stage`. Staged secrets don't reach the machine.

Read-only role, created in `fly postgres connect -a fira-tasks-db`:

```sql
create role fira_backup login password '<openssl rand -hex 24>';
grant pg_read_all_data to fira_backup;
-- stop PUBLIC from creating objects in public (grant the app role first):
grant create on schema public to <app role>;
revoke create on schema public from public;
```

## Deploy

```sh
ops/backup/deploy.sh                          # or ./deploy.sh from ops/backup/
fly scale count 1 -a fira-backup --yes
fly machine list -a fira-backup
fly machine update <id> -a fira-backup --schedule daily --restart no --yes
```

`deploy.sh` always builds with the repo root as context, from any directory.
The image compiles `api/`, so a plain `fly deploy` inside `ops/backup/` fails
at `COPY api/` with "not found".

After any redeploy, check that `fly machine status <id> -a fira-backup` still
shows the daily schedule.

## Manual backup

Before risky operations, such as the first large task-cli import:

```sh
fly logs -a fira-backup                       # terminal 1
fly machine start <id> -a fira-backup         # terminal 2; look for "done: fira-YYYY-MM-DD.dump"
```

A second run on the same day overwrites that day's file.

## Restore

`fira-backup list` and `fira-backup fetch` read the same env as the job. To
run them locally, export the bucket's credentials first:

```sh
cd api
cargo run --bin fira-backup -- list
cargo run --bin fira-backup -- fetch fira-YYYY-MM-DD.dump /tmp/fira.dump

# into a throwaway database (fails if it already exists):
../ops/backup/restore-check.sh /tmp/fira.dump postgres://fira:fira@postgres:5432/postgres
DATABASE_URL=postgres://fira:fira@postgres:5432/fira_restore_check cargo run --bin fira-api
```

The dump includes `_sqlx_migrations`, so the API starts without running any
migrations. Check the printed row counts against production.

`pg_restore` must be at least as new as the dump's `pg_dump` (17). The dev
container installs `postgresql-client-17`.

To restore production itself, stop the app (`fly scale count 0 -a
fira-tasks-app`), restore into a **new** database on `fira-tasks-db` with
`pg_restore --no-owner --no-privileges -d <new-db-url> <dump>`, point the
app's `DATABASE_URL` at it, and scale back up. Never restore over the live
database in place.

## Local test

Against the dev container's Postgres and rustfs:

```sh
cd api
BACKUP_DRY_RUN=1 cargo run --bin fira-backup
AWS_ACCESS_KEY_ID=rustfsadmin AWS_SECRET_ACCESS_KEY=rustfsadmin AWS_REGION=us-east-1 \
AWS_ENDPOINT_URL_S3=http://rustfs:9000 BUCKET_NAME=<existing test bucket> \
  cargo run --bin fira-backup
```
