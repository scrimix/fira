# Sprint 33 — Database backups

**Status:** planned
**Date:** 2026-11-11

## Goal

Keep a daily copy of the production database somewhere other than the
Postgres volume, so that Fira data can be recovered. Put this in place before
sprint 34 turns on CLI writes to production.

## Implementation

- [ ] A small scheduled Fly machine runs `pg_dump -Fc` once a day over Fly
      private networking. Use a `pg_dump` version that matches the server.
- [ ] Upload the dump to a private Tigris bucket, separate from the
      attachments bucket, as `fira-YYYY-MM-DD.dump`.
- [ ] Set a bucket lifecycle rule that deletes objects after 30 days.
- [ ] Store the database URL and bucket credentials as Fly secrets.
- [ ] Ping a free check-in monitor (e.g. healthchecks.io) after a successful
      upload, so that a missed or failed day triggers an email.
- [ ] Add `ops/backup/README.md` covering how to trigger a manual backup and
      how to restore a dump into a fresh database.

## Done when

One uploaded dump has been restored into a throwaway database and Fira runs
against it with tasks, sprints and subtasks intact.

## Out of scope

Attachment files (only their metadata is in the dump). Hourly backups,
point-in-time recovery, and extra encryption beyond Tigris's at-rest
encryption can be added later if they turn out to be needed.

Take a manual backup before the first large CLI import in sprint 34.
