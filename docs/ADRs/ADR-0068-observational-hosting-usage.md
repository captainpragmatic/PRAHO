# ADR-0068: Observational hosting usage

- Status: Proposed
- Date: 2026-10-30
- Related: #782, #776, #783, ADR-0020, ADR-0029, ADR-0039, ADR-0064

## Context

The portal reads Service usage, but discovery wrote only VirtualminAccount usage.
Missing quota-derived listing fields became zero. The legacy extractor preferred
database size over home size, while cumulative node bandwidth cannot establish
an exact operator-month boundary or split a migration between two nodes.

## Decision

Use a private, root-owned node collector and one cached SSH export per active node
per hour. The Python helper supports Python 3.10 and uses only the standard library;
the Perl adapter calls installed Virtualmin APIs and emits an explicit allowlist.
No raw domain listings, passwords, filesystem paths or request URLs reach Platform.
Read-only exports use existing enrolled root SSH identity and exact host trust.

Disk is allocated home bytes plus separately allocated local database bytes, once.
The traversal refuses symlink roots, follows no symlink, deduplicates hard links and
refuses overlapping or unsupported database layouts. These are observations, not
filesystem quotas. Nodes are web-only; unsupported mail/storage remains unknown.

Bandwidth means HTTP(S) response-body bytes, excluding headers and transport costs.
Apache writes a literal installation and account-domain identity plus completion
epoch microseconds and `%B`. Tenant Host headers and environment variables cannot
choose the accounting identity. Normal access logs remain intact. UTC node records
are selected using half-open operator calendar-month bounds (`settings.TIME_ZONE`),
including DST changes. First-month coverage and a lost/budget-exhausted log interval
remain incomplete. UTC host time and ordinary request completion clocks are retained.

Platform records immutable, owner-scoped observations and independent last-good
disk/bandwidth pointers. Account locks fence ownership, operation epoch and canonical
node changes. Every ownership transfer creates a new scope, including A→B→A. A
durable mutation watermark rejects a collection that began before a terminal create,
restore or delete outcome. Failed mutations also advance it. Node poll claims last
330 seconds for a 300-second Q2 job and bind the actual SSH inputs, not API credentials.

Migration commits close/open canonical node intervals without remote I/O. Only the
intersection of month, owner and canonical-node intervals contributes bandwidth;
bridge traffic outside the interval is excluded. Finalized source totals survive
source-node removal. A missing source keeps the month incomplete and never blocks
migration. Readings and source evidence are retained for 90 days, with last-good
pointers preserved so stale data does not acquire a fresh timestamp.

The sole usage publisher updates account and Service projections in the observation
transaction. Discovery and old management commands no longer write usage. The owned
Virtualmin billing schedule is retired; queued invocations are harmless. Generic
service metering excludes Virtualmin-backed services. This feature creates no meter
events, invoices, charges, warning emails or quota enforcement, and does not redefine
ADR-0039 billing periods. Quota enforcement/headroom and threshold emails remain #776
and #783 responsibilities.

## Consequences

Portal reads remain local API reads. Missing, partial, stale and measured zero differ;
source times, files/database breakdown and bounded daily disk history are returned.
Account usage attention begins after six hours; infrastructure health still expires
after 25 minutes. Technical observations do not emit business AuditEvent rows per
poll; existing credential access, configuration and provisioning audits remain.

The additive schema and nullable portal contract deploy before enablement. Install
and verify collectors on nodes deployed before this change; new nodes install them during deployment.
`provisioning.usage_sync_enabled` defaults to on (changed from off after the first staging rollout).
Disable the flag to stop polling; preserve observations and display their original
age. Collector installation/reconciliation is an operator action on existing nodes.
See [the deployment guide](../deployment/DEPLOYMENT.md#hosting-usage-observations).
