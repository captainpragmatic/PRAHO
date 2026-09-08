# ADR-0045: Committed Side-Effect Boundaries for Provider Mutations

**Status**: Accepted
**Date**: 2026-09-08
**Deciders**: Platform Engineering
**Related**: ADR-0020 (async tasks), ADR-0042 (settings catalog), issues #350, #431

## Context

`DriftRemediationService._take_snapshot` uses a three-phase protocol: a durable
`creating` row commits BEFORE the provider `create_snapshot` call, and a
terminal status commits after. Its correctness depended on an invariant stated
only in a comment — the method must never run inside an enclosing
`transaction.atomic()`, or an outer rollback erases the phase-1/phase-3 rows
while the provider snapshot exists (a billable orphan with no PRAHO trace).
Nothing enforced this, and the entire drift test suite ran under `TestCase`
(inside a wrapping transaction), so the failure mode was structurally
invisible to every existing test.

A transactional-outbox split (record intent, commit, perform the provider call
from a follow-up task) was designed and REJECTED at plan review: splitting the
claim from the execution lets queue wait consume the execution clock, so the
stale-remediation reaper can terminalize a legitimately queued execution and
disarm the snapshot-restore safety net exactly when a failed apply needs it —
with a second independent trigger through the inline sibling reap. The split
also required a request↔snapshot relationship the schema does not have. No
current or planned caller needs to run remediation inside a transaction, so
the split solved a requirement that does not exist.

Separately, the assumption "a returned `Err` proves the provider created
nothing" was false: the hcloud gateway catches every exception, including
timeouts AFTER image creation, so an ambiguous outcome was recorded as
`failed` ("nothing to clean up") while a snapshot billed.

## Decision

1. **Fail-closed autocommit guard.** `_take_snapshot` returns `Err` when the
   connection is inside an atomic block OR autocommit is disabled — before any
   row is written or provider call issued. The three snapshot-honesty tests
   run under `TransactionTestCase` (real commits); a discriminator proves the
   guard refuses an enclosing transaction with zero side effects. Pipeline
   tests that patch `_take_snapshot` never hit the guard, so `TestCase`
   coverage elsewhere is unaffected.
2. **Side-effect evidence via retriability.** `create_snapshot` classifies
   failures: `NOT_RETRIABLE` = failed BEFORE dispatch (provably no resource) →
   snapshot row `failed`; anything else, including the default `UNKNOWN` of an
   unclassified `Err`, is ambiguous → `cleanup_failed` (possible billable
   orphan surfaced for reconciliation). hcloud marks dispatch immediately
   before `create_image`.
3. **Ownership CAS after the snapshot.** The provider snapshot id lands on the
   request only through `filter(status="in_progress").update(...)`; losing
   that CAS aborts before any node mutation (the orphaned `available`
   snapshot expires via the 7-day sweep — accepted residual).
4. **Two enqueue conventions, by domain.** With the django-q2 ORM broker on
   the business database (`Q_CLUSTER["orm"] = "default"`, pinned by test),
   enqueue-INSIDE-atomic makes an intent row and its queue message
   transactional together — used where the intent row IS the outbox (drift
   approval, backup/restore job admission, always with `sync=False` forced).
   `transaction.on_commit` + a compensating sweep is used where the side
   effect follows an already-committed aggregate (provisioning reconcile,
   migration enqueue). Moving the broker off the business database breaks the
   first convention — the pinning test is the tripwire.

## Consequences

- A future refactor that wraps `execute_remediation` in a transaction fails
  fast with an actionable error instead of silently reopening the orphan
  window.
- Ambiguous provider outcomes now surface as `cleanup_failed` reconciliation
  work instead of being mislabeled `failed`; operators see more
  `cleanup_failed` rows and can trust that `failed` means no resource exists.
- The daily snapshot sweep stays conservatively stamp-blind: a `creating` row
  older than 24h is still marked `cleanup_failed` even when the crash provably
  preceded dispatch — the honest direction.

## Alternatives Considered

- **Transactional outbox / task split**: rejected (reaper race, missing
  schema relationship, no in-transaction caller requirement) — detailed above.
- **`connection.in_atomic_block` guard alone**: insufficient; Django permits
  `set_autocommit(False)` outside atomic blocks, which the guard also rejects.
- **Documenting the invariant harder**: comments do not fail builds.
