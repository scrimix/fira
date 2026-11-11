# Sprint 33 — Database backups

**Status:** done
**Date:** 2026-11-11

## Goal

Keep a daily copy of the production database somewhere other than the
Postgres volume, so that Fira data can be recovered. Put this in place before
sprint 34 turns on CLI writes to production.

## Implementation

- [x] A small scheduled Fly machine runs `pg_dump -Fc` once a day over Fly
      private networking. Use a `pg_dump` version that matches the server.
- [x] Upload the dump to a private Tigris bucket, separate from the
      attachments bucket, as `fira-YYYY-MM-DD.dump`.
- [x] ~~Bucket lifecycle rule~~: the job prunes dumps older than 30 days itself.
- [x] Store the database URL and bucket credentials as Fly secrets.
- [-] ~~Ping a free check-in monitor (e.g. healthchecks.io)~~ — dropped by
      decision.
- [x] Add `ops/backup/README.md` covering how to trigger a manual backup and
      how to restore a dump into a fresh database.

## Built

The job is a Rust binary, `fira-backup`
([`api/src/bin/backup.rs`](../../api/src/bin/backup.rs)), in the API crate.
It uses the API's own `storage::S3Storage` client, which already reads the
`AWS_*` names that `fly storage create` sets. A run checks versions, dumps,
verifies the archive with `pg_restore --list` (the core tables must be
present), uploads, confirms the stored size, then prunes `fira-*.dump`
objects older than `RETENTION_DAYS` (default 30). `list` and `fetch`
subcommands cover restores. `AWS_ENDPOINT_URL_S3` is required, because
without it the SDK would go to AWS S3. That silent fallback was the
suspected cause of the `AccessDenied` on the first deploy.

The image ([`ops/backup/Dockerfile`](../../ops/backup/Dockerfile), built
from the repo root) is `debian:bookworm-slim` plus `postgresql-client-17`.
It replaces a first version (`postgres:17-alpine` + apk `aws-cli` + a shell
script) that came to ~500 MB because it shipped the full Postgres server and
a Python runtime just to upload one file. Production is Postgres 17, and
`PG_MAJOR` defaults to 17.

Retention is done by the job instead of a bucket lifecycle rule, so no S3
CLI is needed anywhere. There is no failure alert (healthchecks.io was
dropped by decision).

Verified locally against the dev Postgres and rustfs: dry run; upload and
size check; a missing endpoint fails before dumping; a bad bucket exits 1;
pruning deletes only the expired `fira-*.dump` (not today's, not other
objects); `fetch` returns a dump that `pg_restore --list` reads. The
earlier shell version's restore check also passed (counts matched, and
`fira-api` started against the restored DB with migrations as no-ops).

Ops notes: set secrets without `--stage` (staged secrets never reached the
machine); `fly deploy` creates machines without a schedule, so the schedule
is added with `fly machine update --schedule daily`; the backup DB role
could create tables in `public` until `CREATE` was revoked from `PUBLIC`.

Production verified on 2026-11-11: the scheduled `fira-backup` machine
uploaded a ~4 MB dump. It was fetched with `fira-backup fetch`, restored
with `restore-check.sh` into the dev Postgres, and Fira ran against it. Dev
login as a production account showed workspaces, sprints, tasks and
subtasks intact. Restoring a 17 dump into the dev server (16) needed
`restore-check.sh` to drop pg_dump 17's `SET transaction_timeout`. The
first failed attempt also showed that a failed restore must drop the
database it created, which the script now does.

## Done when

One uploaded dump has been restored into a throwaway database and Fira runs
against it with tasks, sprints and subtasks intact.

## Out of scope

Attachment files (only their metadata is in the dump). Hourly backups,
point-in-time recovery, and extra encryption beyond Tigris's at-rest
encryption can be added later if they turn out to be needed.

Take a manual backup before the first large CLI import in sprint 34.
