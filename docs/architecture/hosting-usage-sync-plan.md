# Hosting usage sync (#782)

Accepted implementation plan, 2026-10-30. Delivery is one PR against master.

## Contract

Observational only: no metering events, charges, notification emails, quota enforcement,
OS upgrade or service-page redesign. Measure allocated home bytes plus databases exactly
once. Bandwidth is HTTP(S) response-body bytes at completion, assigned to operator calendar
months from UTC microsecond timestamps. Missing, partial, stale and measured zero differ.

## Execution ledger

- [ ] Node collector: Python 3.10+, sanitized Virtualmin Perl adapter, bounded physical
  home measurement; root-only SQLite ledger outside account backups; hourly systemd timer.
- [ ] Root-controlled literal domain/node identities in HTTP/HTTPS/subserver logs; preserve
  existing hooks and logs, validate configuration before reload. Prove creation bindings.
- [ ] Atomic ingestion and rotation recovery, 90-day/1-GiB retention budget, bounded
  boundary-day replay; gaps and exhausted budgets mean incomplete coverage.
- [ ] One cached, bounded export per node via the existing verified SSH transport; private
  keys/trust/port/version/operator zone participate in the usage input identity.
- [ ] Platform immutable readings, per-metric last-good state, node claims and durable
  owner/node intervals. Unique account/sync-token; indexed account/time; 90-day retention.
- [ ] Owner scopes change through every fenced ownership writer; migration closes/opens
  canonical node intervals in both ownership commits. No remote I/O under business locks.
- [ ] Reject stale publications by lease, ownership, source identity and operation epoch.
  Persist gauge_not_before atomically with terminal mutations, including failed restores;
  the whole source collection interval must follow it. Cover every terminal write path.
- [ ] Bandwidth equals month intersect owner interval intersect node interval. Preserve
  source segments, exclude bridge duplicates, never block migration on telemetry. Missing
  source or first-month coverage means incomplete, never invented history.
- [ ] Register hourly dispatch at :10, collector at :00; coalesce duplicate deliveries.
  Task 300 seconds, claim 330 seconds. Remove competing discovery/sync/reset usage writers.
- [ ] Retire the owned Virtualmin billing collector; queued calls become harmless. Generic
  collection excludes Virtualmin-backed services. Backups remain independent of telemetry.
- [ ] Shared API selectors and all portal usage surfaces: nullable unavailable metrics,
  original source times, breakdown and server-rendered 30-day sparkline; scoped history.
- [ ] Existing staff status surfaces show usage attention after six hours and drift without
  remediation; node-health expiry remains 25 minutes.
- [ ] ADR-0068, ADR-0064/0029 clarifications, deployment/queue/lab/billing docs, CHANGELOG.
- [ ] Disabled-by-default rollout, additive schema and portal compatibility first, install
  and verify collectors, then enable; rollback preserves observations.

## Verification

Red-first tests: independent file/database growth, zero/missing/unsupported data, links and
overlapping storage; real HTTP/HTTPS attribution and spoof attempts; crash, rotation and
loss; exact month and DST using injected timestamps; owner A-B-A, moves, bridges, source
loss, restore-before-poll and scan-across-restore; leases and concurrent publications;
real HMAC portal flow, stale data and existing 85% warning; no billing/email/secret effects;
200-account batch export/publication under 30 seconds.

Run Makefile lint, test, types, migrations, templates, security, PostgreSQL concurrency and
full Virtualmin lab checks. Every completion claim requires fresh output.

## Implementation checkpoint (2026-10-30)

Branch: `feat/782-hosting-usage`. Collector, sanitized adapter, enrolled SSH read,
additive models, claimed hourly dispatch, fenced publication, ownership/move/
recovery integration, billing retirement, nullable API/portal and operator guides
are implemented. Acceptance checkboxes above remain open until final verification.

Independent review reproduced duplicate ingestion, alias attribution, DB scan-fence,
stale lease, first-month completeness and migration-prefix gaps. Regression tests
guard those paths. Portal focused verification passed 176 tests and 242 subtests.
Perl adapter boundary tests pass, but are not a substitute for the real node lab.
Full checks are in progress; no completion claim or issue closure is implied here.

The local Docker Desktop API does not answer, including elevated diagnostics.
No unknown containers were restarted. The isolated GitHub full Virtualmin lab will
validate the pushed branch before merge queue entry. Required PR/queue checks are
the final delivery gate; production deployment remains separate.

## Delivery

DCO-sign commits and PR description. Conventional title; concrete behavior, migration and
verification details; Closes #782 only after acceptance. Required PR checks must pass before
`gh pr merge NUMBER` queues the squash (docs/development/MERGING.md). Monitor queue checks
and verify the tested commit lands. Deployment/release promotion is separate.
