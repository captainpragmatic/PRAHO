# ADR-0051: Hosting Account Enabled-State Ownership

- Status: Accepted
- Date: 2026-10-01 (accepted 2026-10-06)
- Authors: PRAHO maintainers
- Related: #566, ADR-0045 (committed side-effect boundaries), ADR-0019 (auto-provisioning)

## Context

Two fields independently decided whether a Virtualmin hosting account is enabled, and
they disagreed.

- **Domain path.** `apps/domains/signals.py` reacted to a `Domain.status` change after
  commit. For every service bound to the domain (`ServiceDomain`) in `active` or
  `provisioning`, and its account with `VirtualminAccount.domain == Domain.name`, it
  disabled the account when the domain was anything but `active`, and re-enabled it when
  the domain returned to `active`.
- **Service path.** `reconcile_virtualmin_service_state` converged the account on
  `Service.status` alone: an active service with a suspended account was unsuspended.
  It runs on every service lifecycle change, from `_reconcile_again_if_state_moved`, and
  from the 15-minute divergence sweep.

So an expired domain disabled the account and the next reconcile or sweep turned it
back on while the service stayed active. Whichever path wrote last won. The same shape
existed for staff: the Virtualmin account page's Suspend called the panel directly and
left the Service active, so the next sweep re-enabled the account.

An interim guard (#588) stopped Service-only paths re-enabling a domain-held account. This
ADR records the full design that replaced it.

## Decision

**The reconciler is the single writer of an account's enabled state.**

1. **Effective enabled** = `Service.status == active` AND no bound domain is in
   `Domain.HOSTING_DISABLING_STATUSES` (`expired`, `suspended`, `cancelled`). "Bound" means a
   `ServiceDomain` linking the account's service to a domain named `VirtualminAccount.domain`;
   an add-on domain bound under another name does not hold the account off. The predicate
   lives in `apps/provisioning/domain_veto.py`.
2. The reconciler applies it in **both** directions for an active service: it suspends an
   active account a domain holds off (reason `domain_<status>`), keeps a held account off,
   and unsuspends otherwise. It snapshots the hold before the gateway call and re-queues
   itself when the hold or the Service moved while the call was in flight.
3. **A domain status change is a reconcile trigger**, not a gateway call. `sync_domain_to_virtualmin`
   queues one reconcile per bound service, after commit. Binding or unbinding a domain does
   the same. Retries have one owner.
4. **pending and transfer statuses do not disable hosting** (decided 2026-10-06). A domain
   stuck in transfer must not hold a paying customer's hosting off.
5. **Staff act on the Service.** The account page's Suspend and Activate, and the bulk-actions
   page, go through `HostingAccountStaffActions` (`apps/provisioning/services.py`). Suspend
   suspends the Service with the token `staff_account_suspend`; Activate lifts only that
   token, and refuses while the customer is suspended or inactive, or the subscription is
   delinquent. Neither calls the gateway. Each re-reads the Service under a row lock and
   locks nothing else, so there is no lock-order inversion against billing.
6. **Scope.** The reconciler owns active and suspended-family (`suspended`, `terminated`,
   `expired`) services. `pending`, `provisioning` and `failed` belong to the provisioning
   pipeline: an account only turns on when provisioning completes, which moves the service
   to `active`. The staff buttons refuse those three statuses.

### Writer inventory

| Writer | Role after this decision |
|---|---|
| Reconciler (`reconcile_virtualmin_service_state`, `_converge_active_service`) | The writer |
| Divergence sweep (`reconcile_divergent_services_task`) | Queues reconciles. Signature (d) finds an active account under a name-matched hold; (b) excludes held accounts before its cap |
| Domain status sync (`apps/domains/signals.py`) | Queues reconciles only |
| `ServiceDomain` save/delete receiver | Queues a reconcile |
| Lifecycle job retry (`_execute_lifecycle_operation`) | Replays a job only while it matches the predicate (`_job_matches_service_state`); a suspend under a domain hold is current |
| Staff account page and bulk page | Change the Service through `HostingAccountStaffActions` |
| Direct `unsuspend_virtualmin_account` task | Refuses unless the predicate says enabled |
| Account creation, reprovisioning, create-job recovery | The one intentional exception: an account comes into existence enabled. The provisioning task's follow-up reconcile and sweep (d) apply any hold |
| Disaster recovery, migration | Converged by the sweep; migration holds the lock |
| `enforce_praho_state` (drift) | Re-asserts the recorded state; no callers |

## Consequences

- An expired, suspended or cancelled bound domain now turns hosting off through the
  reconciler, and nothing Service-only can turn it back on.
- A staff suspension survives the sweep, and shows as suspended in the customer's portal.
  Billing is unchanged: renewals cover `active` and `suspended`.
- The domain signal lost its direct Virtualmin calls, and with them a second retry owner
  and its ADR-0045 commit-boundary handling.
- **The domain path is dormant today.** No production code creates `ServiceDomain` rows
  (only tests do), so no domain currently holds any account off. The design takes effect
  as soon as something binds domains to services.
- **Out of scope:** a worker that dies after the gateway call succeeds but before
  `account.save` leaves the panel and the database disagreeing in a way only drift
  detection can see. This exposure predates the decision and is unchanged by it.
