# ADR-0051: Hosting Account Enabled-State Ownership

- Status: Proposed
- Date: 2026-10-01
- Authors: PRAHO maintainers
- Related: #566, ADR-0045 (committed side-effect boundaries), ADR-0019 (auto-provisioning)

## Context

Two fields independently decide whether a Virtualmin hosting account is enabled, and
they disagree.

- **Domain path.** `apps/domains/signals.py` reacts to a `Domain.status` change after
  commit. For every service bound to the domain (`ServiceDomain`) in `active` or
  `provisioning`, and its account with `VirtualminAccount.domain == Domain.name`, it
  disables the account when the domain is anything but `active`, and re-enables it when
  the domain returns to `active`.
- **Service path.** `reconcile_virtualmin_service_state` converges the account on
  `Service.status` alone: an active service with a suspended account is unsuspended.
  It is triggered on every service lifecycle change, by
  `_reconcile_again_if_state_moved`, and by the 15-minute divergence sweep.

So an expired domain disabled the account and the next reconcile or sweep turned it
back on while the service stayed active. Whichever path wrote last won.

### Writer inventory

| Writer | Reads | Effect |
|---|---|---|
| Domain status sync (`_handle_existing_virtualmin_account`) | `Domain.status` | suspend / unsuspend |
| Service reconciler and divergence sweep | `Service.status` | suspend / unsuspend / auto-provision |
| Lifecycle job retry (`_execute_lifecycle_operation`) | `Service.status` | replays suspend / unsuspend / delete |
| Staff activation view, direct `unsuspend_virtualmin_account` task | operator intent | unsuspend |
| Drift enforcement | `VirtualminAccount.status` | re-asserts the recorded state |
| Migration activation | migration snapshot | preserves the snapshot's suspension |

The domain path's failed suspend creates a retryable job, but the retry handler rejects
`suspend_domain` while the service is active, terminalizes the job and queues a
Service-only reconcile. The two paths have incompatible retry ownership, not merely a
missing retry.

## Interim guard (implemented with #566)

Paths that only read the Service must not re-enable an account that a bound domain is
holding off:

- `Domain.HOSTING_DISABLING_STATUSES = {expired, suspended, cancelled}`. This is
  deliberately narrower than the domain path's "not active", so a pending or
  in-transfer domain cannot hold hosting off for a reactivated service.
- The reconciler returns `domain_disabled` instead of unsuspending when a domain bound
  to the account's service (the same `ServiceDomain` + name match the domain path uses)
  is in one of those statuses.
- The divergence sweep excludes those accounts before its 50-row cap, so they cannot
  starve accounts that really are divergent.
- An `unsuspend_domain` retry for such an account is terminalized without calling
  `enable-domain`.

The guard does not make the reconciler suspend for domain reasons, and it leaves staff
activation, the direct unsuspend task, drift enforcement and migration untouched.

Limits of the guard, stated so nobody relies on more:

- Accounts the domain path suspended for `pending`, `transfer_in` or `transfer_out` are
  still unsuspended by the reconciler, as before.
- `_reconcile_again_if_state_moved` observes only Service changes. A domain that
  expires after the guard passes but before `enable-domain` returns can still lose to
  the unsuspend. Nothing re-converges that until the domain changes again.

## Decision (proposed)

Make the reconciler the single writer of the account's enabled state:

1. **Effective enabled** = `Service.status == active` AND the bound domain is not in
   `HOSTING_DISABLING_STATUSES`. The reconciler suspends and unsuspends on that
   predicate, for both directions.
2. A domain status change becomes a **reconcile trigger** for every bound service,
   enqueued after commit, instead of a direct gateway call. Retries then belong to one
   owner, and the race above is closed because every change re-runs the same predicate.
3. Decide explicitly whether `pending` and transfer statuses disable hosting. The
   current domain path says yes, the interim guard says no.
4. Staff activation and the direct unsuspend task either respect the predicate or
   record a deliberate override in the audit trail.

## Consequences

- Existing accounts suspended because of an expired, suspended or cancelled domain stay
  suspended under the interim guard and under the decision.
- Accounts suspended by the domain path for pending or transfer statuses are already
  re-enabled today; item 3 decides whether that changes.
- The domain signal loses its direct Virtualmin calls, which removes the second retry
  owner and its ADR-0045 commit-boundary handling from the domains app.
