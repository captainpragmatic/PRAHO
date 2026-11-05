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
service metering excludes Virtualmin-backed services. Collection creates no meter
events, invoices or charges, and does not redefine ADR-0039 billing periods. Native
enforcement remains the separate #776 application protocol. The #783 warning policy
below consumes accepted observations in the publisher transaction. Assigned purchased allowances are pinned per Service;
catalog changes do not redefine existing observation denominators. The quota
safety maximum of canonical disk, kernel UID and kernel GID usage is separate
from this ADR's customer-visible disk numerator. Pending native changes preserve
the previous operational allowance until a verified application commits.

### Warning episodes and delivery

Evaluate disk and bandwidth independently against the last operational purchased
allowance, using raw bytes. Inclusive 80/95/100 percent crossings create durable,
owner-scoped episode intents; a jump to 100 latches lower levels without sending
three notices. Rearm a threshold only after two distinct consecutive accepted UTC
hours strictly below 75/90/95 percent respectively. A replayed hour cannot advance
that streak. Unknown, unlimited and stale evidence cannot cross, resolve or rearm;
partial bandwidth is a lower bound and can establish a crossing when sufficient.
An operator-month change resets bandwidth independently of disk. Ownership changes,
including A to B to A, never restore a previous audience's episode authority.

Publish only the intents while holding the account collection boundary. Later
delivery workers group eligible content, link each delivery version to one
EmailLog and queue after commit. The 80-percent digest is due within 24 hours;
95 and 100 are immediate. One reminder is due 48 hours after the first critical
delivery only if a fresh reading still proves the condition. This is a notification
policy, not a bandwidth suspension or a prediction that headroom will last until
the next hourly poll.

The quota-warning preference and global non-essential unsubscribe apply to optional
content. Critical 100-percent content and its reminder bypass those two optional
settings; they never bypass hard suppression, erased or inactive customers,
ownership, recipient, service lifecycle, source-period or native mail ownership
checks. Recheck these policies at grouping and immediately before provider I/O.
If an undispatched mixed message becomes invalid, retain its refusal history and
rebuild only permitted content. An uncertain provider acceptance cannot be
re-batched into another send. EmailLog retention cannot reopen a linked obligation.

The rendered warning names the threshold rather than claiming exhaustion below
100 percent. Pending paid changes retain the previous operational denominator and
show requested allowances separately. Versioned delivery evidence binds both
operational and desired revisions; a retargeted or newly verified plan refuses a
stale body before dispatch. Older queued evidence fails closed and can be rebuilt
only through the proven-undispatched recovery path.

Platform warning delivery remains disabled until the node's native customer-mail
handover and the actual delivery readiness contract pass. Import alone grants no
handover. Handover first establishes a silent baseline, then staggers one current
critical-state digest per eligible audience. Virtualmin cannot send parallel quota
or other customer operational mail; operator alerts, existing mailbox traffic and
website mail keep their separate responsibilities.

### Surfaces and temporary relief

Customer and staff reads use local, batched selectors. Show purchased allowance,
measurement age and partial/stale context; advertise neither hidden native
headroom nor an unverified requested upgrade as free space. Pending changes keep
the operational warning context until verified. A newly verified larger plan is
evaluated normally: 19.5 GiB of 20 GiB remains a high-usage condition. Dashboard
bandwidth counts carry the real operator-month expiry through its cache.

Temporary relief is a separate, staff-approved disk overlay. An administrator or
manager supplies a same-customer ticket, reason, current base/overlay revisions,
submission identity and explicit consent to expiry removal even above allowance.
For finite purchased A, fixed extra R is at most min(floor(A/4), 5120 MiB), above
the normal effective cap E. It defaults to 72 hours and expires within seven days
of the first active grant. An active extension changes only expiry; a smaller base
clamps R to its bound. Billing and the purchased warning denominator stay unchanged.

Base and overlay revisions, expiry and full E+R capacity are bound through create,
restore, migration and native applications. Protocol 2 rechecks expiry after the
native lock, retains a durable protocol floor and verifies both UID and GID caps.
Expiry is a separately preauthorized reduction; it removes R from the current
canonical operational base, preserves a newer unapplied desired plan, and never
reenables a service. Unknown or issued work keeps its fencing and reservations.
Failed expiry stays visible until current receipt proof establishes removal.
See [the warning and relief runbook](../deployment/HOSTING_USAGE_WARNINGS.md).

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
