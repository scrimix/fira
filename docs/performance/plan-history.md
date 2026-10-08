# Plan history performance — 8 October 2026

The current implementation is usable with small histories, but the revision
picker and marker rendering become slow with large histories. Backend snapshot
caching alone will not resolve the measured browser bottleneck.

The raw measurements below are the baseline **before** separating revision
metadata from snapshots. Re-running the updated harness measures the new
protocol; the saved baseline is retained for comparison.

Raw measurements: [plan-history-2026-10-08.json](plan-history-2026-10-08.json).

## Current data flow

1. `/api/bootstrap` loads current workspace entities into the Zustand store.
   `/api/changes?since=cursor` supplies new operations to keep that live store
   current. This does not download the whole historical op log.
2. Opening Past loads `/api/plan/history?project_id=…&since=0`. The frontend
   retains that revision list while scrubbing and reopening the panel. A
   relevant operation for that project in the WS-nudged change feed requests
   only metadata newer than the last known revision (`since=seq`), including
   acknowledged local writes. Other projects and non-plan operations do not
   trigger history requests. Bootstrap recovery checks deltas if its cursor
   advances past unseen feed entries.
3. Choosing a revision or scrubbing calls `/api/plan/at` with `seq` or `t`.
   This no longer queries or sends the entire revision list. The frontend
   throttles requests to roughly 10 starts per second; superseded responses
   are ignored. Already-started requests still continue doing server work.
4. Each snapshot read checks current access, then uses a read-only repeatable-
   read transaction to obtain genesis, validate an exact revision if supplied,
   and read the operation payloads through the selected point. Rust folds them
   into tracks, sprints and tasks, including recorded creation/completion dates.
   Calendar block operations are excluded. Current tables are not consulted to
   fabricate historical entities.
5. The snapshot response contains one complete project snapshot, its effective
   timestamp, genesis and revision sequence. It is not limited to visible weeks
   or tasks. Historical raw payloads stay on the server. Opening the history
   panel while live no longer requests an unused snapshot.
6. The browser keeps its live workspace state, the latest completed historical
   snapshot and that revision list. `buildPlanSnapshot` computes week columns,
   lane packing, badges, checklist ordering and Unplanned fortnight grouping for
   the current viewport. These display calculations remain in the browser;
   operation replay stays in the backend.

There are currently no persistent plan checkpoints or historical snapshot
caches. Every historical request replays from the start. Storage consists of
current tables plus an append-only operation log, rather than a full copy of
the workspace for every revision. History makes the log grow over time, and
large current projects still produce large individual snapshot responses.

## Backend measurements

The opt-in sqlx test uses a disposable database, a release build, four Tokio
workers, five pool connections and eight concurrent readers. It covers repeated
reads, varying scrub positions, concurrency, serialized response sizes and
isolated full-log projection CPU. Each profile creates tasks followed by title
and completion updates. Other fixture projects remain present.

| Operations | Tasks | Scrub p50 / p95 | 8-reader p95 | Full replay p50 | Full response | Revision metadata |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1,000 | 100 | 1.8 / 2.8 ms | 12 ms | 0.20 ms | 0.107 MB | 0.080 MB |
| 10,000 | 1,000 | 12.3 / 16.3 ms | 43 ms | 1.92 ms | 1.08 MB | 0.807 MB |
| 100,000 | 1,000 | 103.6 / 162.6 ms | 331 ms | 16.54 ms | 8.45 MB | 8.18 MB |
| 100,000 | 10,000 | 135.6 / 172.5 ms | 349 ms | 19.48 ms | 10.95 MB | 8.26 MB |

Service timings include authorization lookup, database reads, projection and
JSON serialization. They exclude HTTP handling, compression, remote network
latency and browser work. Scrub timings have 12 samples; concurrency has 32.
Response sizes are uncompressed decimal MB. The full response and replay
columns refer to the latest point; scrub positions vary from 30% to 85%.
The first read is after fixture insertion and is not a cold-cache measurement.
`log_relation_bytes` in the raw report includes the log table and indexes,
other fixture projects and retained free pages; it is not per-project disk use.

These are local characterization results, not production latency guarantees.
The test asserts dataset/reconstruction correctness and reports performance;
it deliberately avoids machine-dependent latency assertions.

## Browser measurements

Chromium used the production frontend bundle at 1280 × 900. The normal fixture
snapshot was held constant and revision metadata was synthesized across its
history range. Mocked history responses remove backend replay and remote
network latency. Timings include local JSON delivery, React/DOM work and
Playwright orchestration. There is one measured run per profile, not a latency
percentile or a benchmark of rendering 10,000 tasks.

| Revisions | Open history | Select revision | Zoom once | Additional JS heap |
| ---: | ---: | ---: | ---: | ---: |
| 1,000 | 111 ms | 171 ms | 91 ms | 1.1 MiB |
| 10,000 | 1,084 ms | 1,997 ms | 629 ms | 12.3 MiB |
| 50,000 | 8,575 ms | 16,127 ms | 5,570 ms | 68.3 MiB |

The picker renders every revision as a native option. At Fit, the axis renders
every change as a button; at half-range zoom it still renders roughly half the
changes. UI render cost therefore grows with the log even if the reconstructed
board is small. The heap column is sampled JS heap growth, not total browser
memory or retained memory after a forced collection.

The same production bundle also passed the existing authenticated history
interaction sweep, including Unplanned, keyboard direction, read-only guards,
independent zoom/pan, fixed loading layout and retry. Plan is now visible in the
production desktop sidebar after UX acceptance. A production deployment or
complete production-container/OAuth smoke test was not performed here.

## Browser measurements after metadata separation

The same production-bundle test was rerun after the fetch fix. Each profile
made **one metadata request and one snapshot request**. The initial list and
all options/markers are still rendered; keeping metadata out of subsequent
snapshot responses does not eliminate that DOM cost.

| Revisions | Open history | Select revision | Zoom once |
| ---: | ---: | ---: | ---: |
| 1,000 | 110 ms | 208 ms | 100 ms |
| 10,000 | 1,258 ms | 1,939 ms | 480 ms |
| 50,000 | 9,277 ms | 15,459 ms | 5,477 ms |

These are single local samples with a fixed small snapshot and synthetic
metadata, excluding backend replay and remote network latency. They measure
interaction completion including React/DOM work and Playwright orchestration,
not isolated React render CPU. Differences from the baseline are not a
statistically established speedup or regression.
[Raw current measurements](plan-history-browser-after-metadata-split.json).

For hands-on testing against real historical API reads, use the separate
[plan-history stress seeder](plan-history-stress-seeder.md). It gives each
profile the same task count and generates mixed plan operations over time.

## Caching proposal and priorities

1. **Separate revision metadata from snapshots — implemented.** History loads
   separately and subsequent relevant change-feed updates fetch only deltas.
   Scrubbing returns snapshot entities without repeating unchanged metadata.
   The remaining initial large-list rendering cost still needs attention.
2. **Bound browser rendering.** Use a searchable picker that renders a limited
   number of options, and aggregate densely packed changes into time/pixel
   buckets. Preserve exact sequence selection when zoomed in or searching.
   Snapshot caching cannot fix the cost of tens of thousands of DOM elements.
3. **Cache backend checkpoints and exact revisions.** A bounded cache keyed by
   workspace, project, exact revision and projection version can reuse repeated
   selections. Sparse checkpoints let Rust restore state and replay only a
   suffix for uncached revisions. Do not materialize every full state: that
   multiplies entity count by revision count. Keep the durable log as the source
   of truth, and retain current access checks before every cache hit.
4. **Define time-cutoff semantics before sharing cache keys.** Exact revision
   reads have a fixed sequence and timestamp. Arbitrary `t` reads are currently
   filtered by both timestamps and sequence ordering; normalize them to cached
   revisions only when equivalent replay semantics are proven. Account for
   backfills and projection-version changes, and bound cache memory. Coalescing
   identical in-flight computations prevents a cache miss stampede.
5. **Then tune SQL from query plans.** Measure with realistic unrelated-project
   log volume before choosing a project/workspace/time index. The current
   benchmark characterizes a large target project, not a huge multitenant log.

Metadata separation is implemented and covered by backend and browser
regressions. The remaining optimizations are proposals; no snapshot cache or
checkpoint storage has been added.

## Reproduce

From the repository root, with the normal local test-database configuration:

```sh
cargo test --offline --release --manifest-path api/Cargo.toml --test plan_history_perf -- --ignored --nocapture
```

The sqlx harness creates and cleans up its own database. It does not alter the
development or stress database.

For browser measurements, build and preview the production frontend against
the local seeded API; this uses dev fixture authentication solely for the test:

```sh
cd web
pnpm build
API_HOST=localhost pnpm exec vite preview --host 0.0.0.0 --port 5180 --strictPort
# In another terminal in web/:
PLAN_PERF_URL=http://localhost:5180 pnpm plan-history:perf
```

`PLAN_PERF_REVISIONS` changes profiles (comma-separated counts), and
`PLAN_PERF_OUT` changes the JSON report path. Default output is
`/tmp/fira-plan-history-browser-perf.json`.
