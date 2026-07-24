# ADR-0039: PRAHO-Owned Recurring Billing

## Status

**Accepted** - July 2026

## Context

PRAHO sells independently cancellable hosting services. Stripe is the card processor, but PRAHO must remain the authoritative system for service periods, Romanian billing documents, tax, entitlement, dunning, and cancellation.

The previous code mixed three local renewal engines with dormant Stripe Subscription and Stripe Meter code. It also had no customer-grade off-session consent record, could accept incomplete gateway success facts, retried old PaymentIntents, and conflated prepaid fixed charges with post-paid usage.

Customers should not have to authorize or cancel a separate Stripe subscription for every hosting item. They need one understandable card authorization, with explicit per-service enrollment and independent service cancellation inside PRAHO.

## Decision

PRAHO owns the recurring-billing ledger and lifecycle. Stripe owns only SetupIntent and PaymentIntent processing.

### Customer authorization

- A customer owner or billing member grants a versioned recurring-payment authorization for one saved Stripe card through a verified off-session SetupIntent.
- The authorization flow requires the current terms version to be accepted in the server-signed request before PRAHO creates the SetupIntent; its processor metadata binds the exact terms hash and accepting customer principal, so client-side checkbox state alone is not consent evidence and another billing user cannot complete the grant as their own.
- The authorization stores the exact accepted terms text, hash, version, actor role, timestamp, IP address, and user agent; later application releases cannot rewrite historical agreement evidence.
- Each PRAHO subscription is enrolled independently under that authorization. Disabling or cancelling one service does not affect its siblings.
- Compatible services for the same customer, currency, due date, mandate, and payment method may share one proforma and one charge.
- Withdrawal or staff revocation immediately disables future automatic collection for every linked subscription. It does not cancel services or erase existing debt.

### Fixed recurring charges

After an initial recurring order is paid and any required review is approved, PRAHO creates exactly one subscription for the order item's service. The subscription preserves the paid order's currency, quantity, term, and unit-price snapshot; it is never inferred from a later catalog price. Unpaid orders cannot reach this enrollment boundary, and explicitly one-time services are not enrolled.

For each independently cancellable service, PRAHO creates a `BillingCycle` for the next calendar-anchored period. A proforma is prepared 14 days before period end and an authorized off-session charge is attempted 7 days before period end. Payment converts the proforma to an invoice and advances the subscription and service entitlement exactly once.

The cycle remains the link among subscription, service, proforma, invoice, payment, and entitlement. A paid upcoming cycle becomes active; an expired active cycle can then be closed for usage rating.

### Usage charges

Local usage events resolve to the one billing cycle whose half-open interval contains the event timestamp: `period_start <= timestamp < period_end`. Missing or ambiguous ownership is an error and the event stays pending.

Fixed price and usage are different financial obligations:

- `BillingCycle.invoice` is the prepaid renewal invoice.
- `BillingCycle.usage_invoice` is the separate post-paid usage invoice.
- A usage invoice contains only rated usage; it never repeats the fixed plan charge.
- A cycle with no billable usage finalizes without issuing a zero-value invoice.
- Authorized usage invoices use the same customer mandate and the same fail-closed collection gate.
- Billing periods are positive, non-overlapping half-open intervals. Rating requires an exact meter mapping or exactly one effective default tier in the subscription currency at the period start. Price schedules must be non-negative, contiguous, and open-ended; the rated aggregation preserves the exact tier/bracket snapshot and banker's-rounded cents. Missing or ambiguous pricing, ownership mismatches, or any meter failure roll back the complete cycle rating.

Virtualmin and service-monitor disk/bandwidth readings are cumulative snapshots. They may use only `last` or `max` aggregation, never `sum`, to prevent repeated hourly snapshots from being overbilled.

### Payment safety

- Automatic collection is disabled globally by default through `billing.recurring_auto_collection_enabled`.
- Every charge revalidates the active mandate, saved method, customer, document, cycle state, amount, and currency.
- Automatic document reservations are revalidated under lock immediately before the network call; manual payment and cancellation cannot bypass an unresolved automatic attempt.
- The global collection switch and customer row form one ordering boundary shared by final revalidation, a durable submission claim, mandate changes, per-service enrollment, cancellation, and renewal opt-out. The customer lock uses PostgreSQL `NO KEY UPDATE` so unrelated foreign-key inserts, including manual Payments, cannot invert the customer/document lock order.
- The durable submission claim is the authorization linearization point and commits before Stripe I/O. If a disabling mutation acquires the boundary first, PRAHO abandons the still-reserved attempt before Stripe. If the claim commits first, the attempt remains authorized and is submitted even when the customer withdraws while Stripe is processing it; the withdrawal does not wait for provider I/O or manufacture an automatic refund.
- Every recurring Payment has one submission-state row. `reserved` proves Stripe has not been called, `in_flight` records a committed claim whose result may be unknown, `submitted` records a returned PaymentIntent ID, and `abandoned` is terminal pre-submit evidence. A pre-migration unbound Payment has no equivalent proof and is quarantined as `manual_review`; PRAHO never automatically abandons or replays it.
- Gateway success converges through one atomic service and must match PRAHO's authoritative Payment facts.
- Success and failure webhooks that arrive before the request thread stores the PaymentIntent ID may recover only one exact pending recurring attempt after validating all gateway facts. Unmatched PRAHO renewal events are rejected so Stripe redelivers them.
- A bounded scheduled reconciler recovers stale recurring attempts when webhooks are missed. It replays a durably claimed unbound submission only with its original Stripe idempotency key, retrieves bound PaymentIntents, validates immutable gateway facts before accepting terminal state, and routes success, proforma conversion, entitlement, decline, retry, and dunning through the existing convergence services.
- Every definitive recurring decline idempotently schedules one policy-controlled retry chain, polled every 15 minutes. Each retry creates a new document Payment and PaymentIntent; the retry owns that result Payment before Stripe is called, so a synchronous decline cannot seed a competing chain. Stale worker claims are reclaimed after two task timeouts and resume through the same idempotency key; an already-succeeded result is never charged again.
- Webhook and synchronous confirmation paths are idempotent and apply entitlement once.
- Reminder and dunning tasks use `Invoice.due_at`; failures continue counting after suspension so terminal non-payment updates subscription and service state through FSM transitions.

### Removed ownership

PRAHO does not create Stripe Subscriptions, Prices, Meters, or usage records. The Stripe-specific subscription and metering fields and services are removed. Local usage collection, aggregation, rating, and invoicing remain.

The incomplete local mid-cycle plan-change engine is also non-executable. It could not coordinate provisioned-service changes, apply scheduled changes at the renewal boundary, or issue Romanian fiscal credit documents for downgrades. Historical `SubscriptionChange` records remain readable, but a replacement workflow must design those three boundaries explicitly before it may mutate subscriptions.

## Consequences

### Positive

- PRAHO has one renewal engine and one auditable source of truth.
- Customers authorize a card once and control auto-payment per service.
- Romanian proforma/invoice and e-Factura workflows remain authoritative.
- Every Romanian B2B and B2C invoice remains in mandatory e-Factura scope regardless of total; legal scope is not customer-segment or amount configurable. Individual CNP values are frozen into the billing-document snapshot, and buyer legal identifier BT-47 carries that CNP or the statutory 13-zero fallback when no fiscal identifier was supplied.
- Fixed charges, usage charges, payment attempts, and entitlement cannot silently overwrite one another.
- A single kill switch stops all new automatic charges without stopping document generation or manual payment.

### Negative

- PRAHO must operate its schedulers, webhook processing, retries, and reconciliation correctly.
- Usage is invoiced separately after the measured period closes.
- Changing the authorization terms requires a new terms version and a newly verified customer authorization.
- Stripe's hosted subscription portal and Stripe Billing analytics are intentionally unavailable.
- Mid-cycle upgrades, downgrades, quantity changes, and billing-cycle changes remain unavailable until a provisioning-aware and fiscal-credit-capable workflow is implemented.

## Rejected Alternatives

1. **One Stripe Subscription per hosting item** - duplicates PRAHO's service lifecycle and creates fragmented customer cancellation UX.
2. **One Stripe Subscription for the whole account** - prevents independent service periods, prices, and cancellations.
3. **Stripe owns usage while PRAHO owns fixed billing** - creates two financial ledgers and weakens Romanian document reconciliation.
4. **A staff-controlled auto-pay flag without consent evidence** - does not prove customer authorization for off-session charges.

## Related

- [ADR-0025](ADR-0025-monetary-amounts-in-cents.md) - monetary amounts in cents
- [ADR-0034](ADR-0034-django-fsm2-state-machines.md) - protected lifecycle transitions
- [ADR-0038](ADR-0038-proforma-payment-convergence.md) - proforma payment convergence
- [Recurring billing operations](../domain/RECURRING_BILLING.md)
- GitHub issues #209, #218, #219, #301, #335, and #409
