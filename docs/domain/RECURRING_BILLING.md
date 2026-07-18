# Recurring Billing Operations

> **Status**: Active reference
> **Last updated**: 2026-07-18
> **Architecture decision**: [ADR-0039](../ADRs/ADR-0039-praho-owned-recurring-billing.md)

## Ownership Boundary

PRAHO owns subscriptions, periods, proformas, invoices, taxes, usage rating, retries, dunning, entitlement, and cancellation. Stripe processes SetupIntents and PaymentIntents only. Do not create Stripe Subscriptions, Prices, Meters, or usage records for PRAHO services.

## Rollout Checklist

1. Apply migrations through billing migration `0036`, customers migration `0018`, and settings migration `0002`.
2. Verify every active or suspended auto-renew service has exactly one linked PRAHO subscription. Scheduler setup refuses to replace the legacy renewal engine while any such service is unmanaged; migrate those services from their authoritative service price, currency, billing cycle, and paid-through date first.
3. Run `python manage.py setup_dunning_policies` and verify exactly one active default payment-retry policy exists.
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
| `billing-expired-trials` | Cancel unpaid expired trials and expire their services |
| `billing-grace-expirations` | Apply subscription and service non-payment lifecycle |
| `Process Pending Usage Events` | Retry usage events that were not aggregated immediately |
| `Run Billing Cycle Workflow` | Close expired cycles, rate usage, issue usage invoices, and queue authorized collection |
| `Collect Virtualmin Usage` / `Collect Service Usage` | Record local cumulative hosting snapshots |

The fixed renewal schedule is proforma at period end minus 14 days and automatic charge at period end minus 7 days. A definitive recurring decline schedules exactly one policy-controlled retry chain; duplicate webhook or synchronous handling cannot consume another retry slot. Retry ownership is persisted before the Stripe call, and stale worker leases resume idempotently after two task timeouts without recharging an already-succeeded result. Usage is rated after the measured period ends and is invoiced separately.

Usage rating is fail closed. Billing periods must be positive and non-overlapping, every aggregation must belong to the cycle's customer and subscription, and each billable meter must resolve an exact meter price in the subscription currency at the cycle start. Expired, overlapping, negative, gapped, or incomplete price schedules are rejected; fractional cents use banker's rounding, and the exact tier and brackets are snapshotted onto the rated aggregation. Missing prices or one failed meter roll back the complete cycle rating, so partial usage can never be invoiced.

The first paid order is the initial entitlement. Once payment and any review gate have succeeded, its immutable item snapshot creates the service-linked subscription and an initial waived collection cycle; future periods are generated only by the recurring orchestrator. Replaying enrollment is idempotent only when the requested cycle, quantity, term price, and custom-cycle length match the existing subscription. An explicitly one-time order item creates no subscription.

## Customer Controls

- Only customer owners and billing members may grant, withdraw, or change recurring-payment enrollment.
- One active authorization covers one saved card; multiple independently cancellable subscriptions may enroll under it.
- Customers may disable auto-payment for one subscription without affecting siblings.
- Withdrawing the authorization disables every linked subscription immediately but does not cancel services or existing invoices.
- Staff may revoke an authorization but cannot manufacture customer consent.
- PRAHO accepts the current recurring-payment terms version server-side before creating the SetupIntent; the SetupIntent metadata binds the exact terms hash and accepting principal, so another billing user cannot inherit the consent flow. PRAHO stores the exact accepted text alongside its version and hash so later wording changes cannot rewrite historical evidence. The browser checkbox is only the user interface for that signed acceptance.

## Plan Changes

The historical `SubscriptionChange` table is read-only. Do not apply mid-cycle product, quantity, or billing-cycle changes through model mutation or ad-hoc invoices. The retired implementation did not update the provisioned service, never applied scheduled changes, and discarded negative proration instead of issuing the required credit/refund documents. A future plan-change workflow must coordinate provisioning, renewal timing, customer communication, payment, and Romanian fiscal documents atomically.

## Monitoring and Reconciliation

Monitor for:

- gateway fact mismatch and recovered early-webhook security events;
- pending usage events with aggregation errors;
- failed recurring Payments without a pending or completed retry chain;
- cycles stuck in `prepared`, `processing`, `past_due`, or `closing`;
- issued usage invoices without a Payment attempt when their subscription is enrolled;
- invoices whose successful Payment total does not reconcile to the invoice balance;
- subscriptions whose period or linked service expiry did not advance after payment.

A successful Stripe object is not sufficient evidence by itself. PRAHO accepts success only after amount, currency, customer, payment method, metadata, document, and local Payment state reconcile.

An automatic attempt reserves its document locally, then revalidates the locked order, proforma or invoice balance immediately before contacting Stripe. Manual settlement and cancellation reject unresolved automatic card reservations. If a Stripe success or failure webhook wins the race with local PaymentIntent-ID persistence, PRAHO binds it only to one exact, fact-matched recurring attempt; unmatched renewal events are not acknowledged as external traffic and must be retried by Stripe.

## Emergency Stop and Recovery

Set `billing.recurring_auto_collection_enabled` to `false` to stop all new automatic PaymentIntents. This does not stop proforma/invoice creation, manual settlement, webhook reconciliation for already-created attempts, or service lifecycle processing.

After an incident:

1. Leave automatic collection disabled.
2. Reconcile Stripe PaymentIntents against PRAHO Payments and invoices.
3. Repair local state through the established convergence services; do not edit FSM status fields directly.
4. Reprocess pending usage events and failed retries only after their ownership and period are unambiguous.
5. Re-enable collection after a test-mode end-to-end payment succeeds.

Do not reverse the ownership-removal migration as an emergency response: restoring obsolete Stripe subscription fields does not restore a working Stripe Billing integration. Roll back application and schema changes only as a coordinated deployment, while preserving all financial records and consent evidence.
