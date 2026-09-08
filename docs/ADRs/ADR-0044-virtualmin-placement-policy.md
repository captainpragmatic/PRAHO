# ADR-0044: Virtualmin Placement Policy

**Status**: Accepted
**Date**: 2026-09-08
**Deciders**: Platform Engineering
**Related**: ADR-0019 (automatic provisioning), ADR-0020 (async tasks), ADR-0042 (settings catalog), issues #359, #360, #361

## Context

Single-account migration (#359), managed node drain (#360), and placement
policy (#361) form one PR. Migration and drain require the same predictable
target policy as automatic provisioning. Previously provisioning selected the
least-loaded healthy server, migration returned eligible targets without a
placement order, and drain applied its own least-loaded sort. Server weight,
region, and tags existed but did not govern these choices consistently.

## Decision

A shared provisioning `placement.py` helper owns tag filtering and ordering.
Automatic provisioning and migration target discovery call it; drain preserves
the returned order and supplies its source server's region.

Candidates must be active, not draining, below capacity, and pass
`can_host_domain()`. Automatic provisioning also excludes explicitly supplied
server IDs and retains its final per-candidate admission recheck. Migration
retains its distinct hard requirements: exclude the source, require a managed
`node_deployment`, and enforce
`current_domains + active_reservations < max_domains`. Migration admission
rechecks capacity under the existing server locks; discovery is not a reservation.
Reservation-aware capacity remains specific to migration in this PR.

The catalog defines `provisioning.placement_required_tags` and
`provisioning.placement_excluded_tags` as JSON lists of strings, both defaulting
to `[]`. Request-required tags are unioned with the configured requirements.
A candidate must carry every required tag and none of the excluded tags.
Tags match exactly and case-sensitively; exclusion wins if policies overlap.
Filtering runs in Python to preserve SQLite compatibility.

Within each region partition, candidates sort by descending weight, ascending
current domain count, then `str(pk)`. Weight is strict priority, not a
probability or capacity multiplier: a higher-weight eligible server wins even
with a higher current load. A truthy preferred region creates a case-insensitive
same-region-first partition; all other eligible servers remain available as
fallback. Region preference therefore precedes weight across partitions.
Without a preferred region there is one global ordered pool.

## Consequences

- Equal-weight fleets retain least-loaded behavior with empty tag settings and
  no region preference. Equal weight and equal load use an explicit UUID tie.
- Operators must rebalance weights knowingly: higher-weight servers receive
  placements until admission excludes them; weights do not spread load
  proportionally and changes do not migrate existing accounts.
- Region preference can select a lower-weight local server. Missing or
  unavailable local capacity falls back to another region instead of failing.
- Hard tag policies can intentionally empty the pool. An overlapping required
  and excluded tag prevents all placement until the operator resolves it.
- Draining nodes reject new placements while existing migration ownership,
  reservation, and drain coordination protections remain in effect.
- The weight help-text change requires a generated Django migration; it does
  not change existing weight values.
- Routing/DNS confirmation and retained-copy cleanup remain operator actions
  from the migration/drain work; placement does not automate them.

## Alternatives Considered

- **Weighted random:** rejected because repeated identical inputs can select
  different targets, making incidents and drain choices harder to reproduce.
- **Blended weight/load/region score:** rejected because coefficients obscure
  priority and make operator expectations harder to explain and debug.
