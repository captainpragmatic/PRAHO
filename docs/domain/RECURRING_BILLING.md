# Recurring Billing Operations

> **Status**: Active reference
> **Last updated**: 2026-11-04
> **Architecture decisions**: [ADR-0039](../ADRs/ADR-0039-praho-owned-recurring-billing.md), [ADR-0074](../ADRs/ADR-0074-paid-hosting-plan-changes.md)

## Ownership Boundary

PRAHO owns subscriptions, periods, proformas, invoices, taxes, usage rating, retries, dunning, entitlement, and cancellation. Stripe processes SetupIntents and PaymentIntents only. Do not create Stripe Subscriptions, Prices, Meters, or usage records for PRAHO services.

## Rollout Checklist

1. Apply all platform migrations.
2. Verify every active or suspended auto-renew service has exactly one linked PRAHO subscription. Scheduler setup refuses to replace the legacy renewal engine while any such service is unmanaged; migrate those services from their authoritative service price, currency, billing cycle, and paid-through date first.
3. Run `python manage.py setup_dunning_policies` and verify exactly one active default payment-retry policy exists.
   Billing administrators can review and edit the live retry cadence and dunning-email switch from
   **Settings → Billing → Payment retry policies**. Retry days are absolute offsets from the original
   Payment's persisted definitive failure timestamp, not its creation time and not delays chained from the
   previous attempt. Subscription suspension and cancellation remain governed by the subscription
   grace-period lifecycle; the retry-policy editor does not expose the legacy dormant escalation columns.
4. Run `python manage.py setup_scheduled_tasks --billing-only` and verify the Django-Q schedules.
5. Ensure a Django-Q worker is running with `python manage.py qcluster`.
6. Verify Stripe webhook delivery for `payment_intent.succeeded` and `payment_intent.payment_failed`.
7. Ensure every billable meter has an explicit subscription-item mapping or exactly one effective default price in the subscription currency at each billing-period start. Bracket schedules must be contiguous from zero through an unlimited final bracket. Ensure `disk_usage_gb` and `bandwidth_gb` use `last` or `max` aggregation; snapshot sources are rejected for `sum` meters.
8. Keep `billing.recurring_auto_collection_enabled` set to `false` while exercising authorization, document creation, and manual payment in staging.
9. Complete a real customer-owner SetupIntent authorization, enroll one subscription, prepare its proforma, and verify a successful test-mode charge advances exactly one period.
10. Place and pay a monthly and an annual test order. Verify each review-approved recurring service has exactly one linked subscription with the paid currency, quantity, term price, and billing period.
11. Enable `billing.recurring_auto_collection_enabled` only after the preceding checks pass.

## Romanian e-Factura Boundary

Every Romanian invoice PRAHO issues must enter the RO e-Factura submission workflow, whether B2B or B2C and regardless of total. PRAHO invoices are not fiscal-register receipts, so the narrow simplified-receipt exception does not create a 100 RON invoice threshold. Customer-segment enable flags and minimum-amount settings are intentionally absent; only the global integration rollout switch may pause transport while the deployment is validated.

From 1 January 2026, the submission deadline is five Romanian working days. A CNP supplied by an individual is snapshotted onto the proforma and invoice and emitted as buyer legal identifier BT-47. If the buyer supplies no fiscal identifier, BT-47 uses the legally prescribed 13 zero digits. See consolidated [OUG 120/2021, articles 10 and 10^1](https://legislatie.just.ro/Public/DetaliiDocument/310662).

## Scheduled Work

| Schedule | Responsibility |
|---|---|
| `billing-recurring-orchestrator` | Prepare grouped renewal proformas and create due authorized PaymentIntents |
| `billing-payment-retries` | Create fresh PaymentIntents for due failed-payment retries every 15 minutes |
| `billing-recurring-payment-reconciliation` | Reconcile stale or unbound recurring PaymentIntents every 10 minutes |
| `billing-plan-change-payments` | Recover the original on-session plan-change attempt every 5 minutes |
| `billing-scheduled-plan-changes` | Expire safely unissued quotes and activate due scheduled changes every 5 minutes |
| `billing-plan-change-financial-review` | Process durable dispute/refund review facts every 5 minutes |
| `billing-plan-change-fulfilment` | Reconcile committed native applications and pending phase notices every 5 minutes |
| `billing-expired-trials` | Cancel unpaid expired trials and expire their services |
| `billing-grace-expirations` | Apply subscription and service non-payment lifecycle |
| `Process Pending Usage Events` | Retry usage events that were not aggregated immediately |
| `Run Billing Cycle Workflow` | Close expired cycles, rate usage, issue usage invoices, and collect due authorized usage charges |
| `Collect Service Usage` | Record eligible non-Virtualmin service snapshots |

`virtualmin-usage-sync` is an observational provisioning task (ADR-0068), not a
billing source. `Collect Virtualmin Usage` is retired, queued calls are no-ops,
and the generic service collector excludes Virtualmin-backed services. Operator
calendar-month response bytes never redefine a subscription's billing periods.

The fixed renewal schedule is proforma at period end minus the configurable `billing.invoice_generation_lead_days` (default 14, bounded 7-30) and automatic charge at period end minus the fixed 7-day collection lead; the invoice lead is floored at the collection lead so a charge can never precede its billing notice. A definitive recurring decline schedules exactly one policy-controlled retry chain; duplicate webhook or synchronous handling cannot consume another retry slot. Retry ownership is persisted before the Stripe call, and stale worker leases resume idempotently after two task timeouts without recharging an already-succeeded result. Usage is rated and invoiced after the measured period ends; its automatic charge is scheduled for period end plus 7 days and is not attempted when the invoice is issued.

Retry attempts are created only by recurring-payment convergence or invoice dunning. The generic Payment status signal sends failure notifications and updates customer history, but must not create a second retry chain.

Invoice numbering is controlled from **Settings → Billing → Invoice numbering series**. Starting a new
legal series snapshots the active prefix and counter, then resets the stable active control row under one database lock.
The counter is never editable, previous prefixes cannot be reused through the operator surface, and
invoice callers consume the prefix persisted on the active sequence instead of supplying one per invoice.

Usage rating is fail closed. Billing periods must be positive and non-overlapping, every aggregation must belong to the cycle's customer and subscription, and each billable meter must resolve an exact meter price in the subscription currency at the cycle start. Expired, overlapping, negative, gapped, or incomplete price schedules are rejected; fractional cents use banker's rounding, and the exact tier and brackets are snapshotted onto the rated aggregation. Missing prices or one failed meter roll back the complete cycle rating, so partial usage can never be invoiced.

The first paid order is the initial entitlement. Once payment and any review gate have succeeded, its immutable item snapshot creates the service-linked subscription and an initial waived collection cycle; future periods are generated only by the recurring orchestrator. Replaying enrollment is idempotent only when the requested cycle, quantity, term price, and custom-cycle length match the existing subscription. An explicitly one-time order item creates no subscription.

## Customer Controls

- Only customer owners and billing members may grant, withdraw, or change recurring-payment enrollment.
- One active authorization covers one saved card; multiple independently cancellable subscriptions may enroll under it.
- Customers may disable auto-payment for one subscription without affecting siblings.
- Withdrawing the authorization disables every linked subscription immediately but does not cancel services or existing invoices.
- Staff may revoke an authorization but cannot manufacture customer consent.
- PRAHO accepts the current recurring-payment terms version server-side before creating the SetupIntent; the SetupIntent metadata binds the exact terms hash and accepting principal, so another billing user cannot inherit the consent flow. PRAHO stores the exact accepted text alongside its version and hash so later wording changes cannot rewrite historical evidence. The browser checkbox is only the user interface for that signed acceptance.

## Revocation and In-Flight Charges

Final recurring authorization and a durable submission claim share a PostgreSQL ordering boundary. PRAHO locks the global collection-switch row and then the customer row, revalidates the document and every enrolled service, and commits an `in_flight` submission record before Stripe I/O. Mandate withdrawal/revocation, subscription cancellation, per-service auto-payment changes, renewal opt-out, and terminal service lifecycle changes take the same customer lock before changing authority.

The customer mutex uses PostgreSQL `NO KEY UPDATE`: all boundary participants still serialize, while manual Payments and other rows may safely retain or add foreign keys to the customer instead of creating a document/customer lock inversion.

- If a disabling mutation obtains the boundary first, the charge waits, observes the committed opt-out, and abandons its unbound local Payment before contacting Stripe.
- If a charge commits its durable claim first, it is considered in flight. The disabling mutation may complete while Stripe is still processing; PRAHO preserves the authorized attempt and does not automatically refund it.
- Once a withdrawal, cancellation, opt-out, or kill-switch update returns successfully, no new automatic submission may become authorized under the old authority. An attempt whose durable claim committed first remains authorized and may still reach Stripe afterward with its original idempotency key.

The short database transaction ends before Stripe is contacted. The durable claim—not an in-memory flag or an open transaction—is the ordering evidence. Do not add provider I/O inside the boundary or acquire service/subscription locks before the customer boundary.

## Plan Changes

The historical `SubscriptionChange` table is read-only. Do not apply changes through model mutation or ad-hoc invoices. The separate, flag-gated `PlanChange` workflow below replaces only supported commercial changes; it does not revive the retired engine.

## Paid hosting plan changes

Keep `billing.hosting_plan_changes_enabled=false` until the
[deployment acceptance gates](../deployment/DEPLOYMENT.md#paid-hosting-plan-changes)
pass. This flag is independent of automatic recurring collection. Reconcile the
four schedules above with `setup_scheduled_tasks --billing-only` before enabling
new customer acceptance.

Use the Portal **Change plan** workflow for active compatible Virtualmin services.
Owners and billing members accept an itemized quote; staff shares the proposal link
from the service's commercial plan-change page. Catalog `upgrades_to` edges define
forward upgrades and reverse downgrades. Targets retain currency, cycle, quantity
one and the compatible service feature profile. Setup fees, mixed resource changes
and unsupported targets require support review. Future recurring authorization is
preserved, never newly granted by paying an upgrade.

An upgrade uses one standalone on-session supplement document for the remaining
current interval and every already committed future interval. A frozen future base
of 80 plus a paid supplement of 120 covers 200; a later target of 300 owes 100 for
that interval. The old base document remains payable if it was unpaid. An early-paid
renewal does not change which interval contains today. Zero-due upgrades require
explicit no-charge acceptance and create no synthetic Payment or invoice.

After financial commitment, new renewals use the accepted per-service price and
included disk/bandwidth allowances. They do not restore ended price locks or future
renewal benefits from the old plan. Existing reserved benefits, frozen cycles and
document amounts remain unchanged. Other services' shared grandfathering promises
remain protected. An independently accepted later currency transition keeps its own
notice, preparation and activation rules; historical plan-change evidence retains
its original currency.

Downgrades target the first uncommitted renewal, with an explicit effective date and
no immediate credit/refund. The target renewal uses the agreed lower terms. Paying
it early does not lower native limits early, and committing that renewal to
preparation closes cancellation. If usage grows or native admission is held at the
boundary, lower billing terms remain agreed while limits enter attention. Do not
raise the price again, delete data or force a below-usage cap.

An unsettled plan-change attempt temporarily blocks conflicting renewal
preparation/collection while its application authority is live. Authority expiry
ends that billing hold; recovery still owns unknown money and any late payment must
enter review rather than apply stale terms. A paid change awaiting native quota
verification does not pause normal renewals. Monitor `paid_review`,
`applying_limits`, `limits_attention`, pending review events and stale native proof;
see [recovery](../deployment/PLATFORM_RESTORE.md#hosting-plan-change-recovery).

A due scheduled downgrade that remains in `limits_attention` is escalated on its
first operation reconciliation to the existing staff **Audit → Review Queue**
(`/audit/review/`) as one HIGH, review-required event. No extra 24-hour grace is
invented. The durable marker and event commit together; replay/concurrent workers
do not create another event, and an audit write failure leaves the marker unset for
retry. Review the agreed boundary and current ownership before intervention. The
alert preserves the lower price, data and native enabled state and sends no new
customer email. Audit review records staff acknowledgement without rewriting the
original event or automatically resolving the plan change.

## Monitoring and Reconciliation

Monitor for:

- gateway fact mismatch and recovered early-webhook security events;
- `reserved` submissions that do not promptly become `in_flight` or `abandoned`;
- any `manual_review` submission created from an unbound pre-migration Payment;
- recurring submissions whose reconciliation lease repeatedly expires or whose `last_error` persists;
- pending usage events with aggregation errors;
- failed recurring Payments without a pending or completed retry chain;
- cycles stuck in `prepared`, `processing`, `past_due`, or `closing`;
- issued usage invoices without a Payment attempt when their subscription is enrolled;
- invoices whose successful Payment total does not reconcile to the invoice balance;
- subscriptions whose period or linked service expiry did not advance after payment.

A successful Stripe object is not sufficient evidence by itself. PRAHO accepts success only after amount, currency, customer, payment method, metadata, document, and local Payment state reconcile.

An automatic attempt reserves its document locally, then revalidates the locked order, proforma or invoice balance and commits its durable submission claim immediately before contacting Stripe. Manual settlement and cancellation reject unresolved automatic card reservations. If a Stripe success or failure webhook wins the race with local PaymentIntent-ID persistence, PRAHO binds it only to one exact, fact-matched recurring attempt; unmatched renewal events are not acknowledged as external traffic and must be retried by Stripe. If no webhook arrives, the scheduled reconciler waits for the stale window, leases a bounded batch, replays only durably claimed unbound requests with their original idempotency keys, and retrieves bound PaymentIntents. Amount, currency, customer, saved method, document metadata, and attempt identity must match before local terminal state advances. Unbound recurring Payments that predate the durable claim migration are `manual_review`: verify their idempotency key in Stripe and repair them through the existing convergence service; never change them to `reserved` or replay them speculatively.

## Emergency Stop and Recovery

Set `billing.recurring_auto_collection_enabled` to `false` to stop all new automatic PaymentIntents. This does not stop proforma/invoice creation, manual settlement, webhook reconciliation for already-created attempts, or service lifecycle processing.

For paid hosting changes, also disable `billing.hosting_plan_changes_enabled` to
stop new acceptance/first claims. Keep all four plan-change schedules, existing
webhook and invoice-convergence consumers, EmailLog delivery and native
reconciliation running. The switch does not cancel accepted scheduled terms,
erase a processor attempt or undo money/resources. Do not roll back to a worker
version that cannot process already accepted plan-change payments.

After an incident:

1. Leave automatic collection disabled.
2. Run the recurring-payment reconciliation task and investigate any remaining submission `last_error` values before manually reconciling Stripe PaymentIntents against PRAHO Payments and invoices.
3. Repair local state through the established convergence services; do not edit FSM status fields directly.
4. Reprocess pending usage events and failed retries only after their ownership and period are unambiguous.
5. Re-enable collection after a test-mode end-to-end payment succeeds.

Do not reverse the ownership-removal migration as an emergency response: restoring obsolete Stripe subscription fields does not restore a working Stripe Billing integration. Roll back application and schema changes only as a coordinated deployment, while preserving all financial records and consent evidence.
