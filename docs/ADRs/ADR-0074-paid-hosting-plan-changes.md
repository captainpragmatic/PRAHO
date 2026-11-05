# ADR-0074: Paid Hosting Plan Changes

## Status

**Proposed** — implementation is behind a disabled acceptance flag. Release still
requires the documented native, browser and integrated payment/renewal gates.

## Date

2026-11-04

## Authors

PRAHO maintainers

## Context

Changing a service's plan label cannot establish payment, a correct next renewal,
or an enforced hosting allowance. The retired `SubscriptionChange` engine did not
coordinate these boundaries; its historical records remain read-only
([ADR-0039](ADR-0039-praho-owned-recurring-billing.md)). A replacement must preserve
old fiscal documents, independently track received money and native completion,
and recover an uncertain processor result without making another charge.

Assigned allowances and fenced native applications are provided by #776. The
observations in [ADR-0068](ADR-0068-observational-hosting-usage.md) provide usage
context; ordinary observations are not billing events or permission to shrink a
quota. Financial acceptance needs the separately bound native safety checks.

## Decision

### Customer acceptance and supported targets

An active customer owner or billing member requests and accepts a commercial
change through signed Platform APIs and the Portal checkout, with live membership,
service ownership and recent step-up checks. The original requester owns quote
acceptance and payment; other authorized billing viewers can inspect the current
change and use its permitted cancellation controls. Staff shares a customer Portal
proposal link. That link carries no credentials and grants no acceptance or payment
authority. Customer-view impersonation cannot perform checkout.

Active `ProductRelationship.upgrades_to` edges curate forward upgrades and reverse
downgrades. Catalog administrators maintain the graph through its validated editor.
Targets require an active public product, compatible Virtualmin service plan and
module configuration, a standard period price in the existing currency, quantity
one, and no setup fee. Cycle, currency, quantity, template, CPU/RAM, mailbox/database
counts and other incompatible features are outside this workflow. Prices exclude
temporary campaign offers. An upgrade increases the recurring price and reduces
neither assigned resource; a downgrade reduces the price and increases neither.
Finite-to-unlimited disk expansion requires separate capacity review.

Each `PlanChange` freezes its actor/customer/service, submission UUID, assigned
revision, source and target terms, interval coverage, fiscal calculation, allowances
and fingerprint. A repeated submission with the same payload returns the same
agreement; changed payload conflicts. At most one payable, scheduled or applying
change owns a service. Quote validity is at most 15 minutes; application authority
ends at the earlier of one hour after the quote or the current covered interval's
end. A first payment claim also requires the quote still to be valid. Replaying an
already claimed attempt never reprices it from the catalog.

### Interval evidence and documents

Use the actual half-open paid interval containing the quote instant, rather than
subscription period pointers that an early-paid renewal may already have advanced.
For the remaining current interval, charge the difference between target and
current effective period NET prices, multiplied by the exact remaining/full elapsed
time ratio. For each already committed future interval, charge target period NET
less its original fixed NET and prior settled, non-refunded supplements. An issued
but unpaid future renewal remains its own base obligation; the supplement does not
settle it. Ambiguous, overlapping, disputed or unsupported coverage requires review.

Calculations use integer cents and exact interval microseconds with Decimal
half-up rounding per NET supplement. `TaxService` calculates and freezes the
document's fiscal treatment and line taxes. No existing invoice, proforma, discount
reservation or paid-through date is rewritten to implement an upgrade. For example,
a frozen future base of 80 plus a settled 120 supplement covers 200; a subsequent
target of 300 needs another 100, rather than 220.

A positive upgrade produces one standalone supplement proforma with quantity-one
interval lines, then the normal invoice/payment convergence. It creates no dummy
order, extra service or subscription. A genuine zero-due upgrade requires explicit
no-charge acceptance and shares the accepted-terms writer; it invents no Payment,
payable invoice or processor call.

### Payment and lock boundaries

The upgrade is an on-session PaymentIntent using hosted processor fields. It does
not use the saved-card off-session renewal method and does not enroll or change a
future recurring authorization. Persist one Payment, immutable processor payload,
attempt identity and idempotency key before external I/O. Client secrets are
encrypted at rest and returned only at the authorized checkout boundary, never in
status responses, audit metadata or logs.

An uncertain create reuses the same attempt and key within its original 23-hour
safe replay window. Bound intents can be retrieved later without creating another
one. Cancellation/expiry needs proof of never-issued work or verified cancellation
of the exact original intent; elapsed time alone does not prove that money cannot
arrive. Late funds after application authority expires become `paid_review` and
cannot apply an obsolete quote.

Existing documents enter the shared document context before Customer, sorted
Subscriptions, Service, PlanChange and Payment/Refund locks. New unpublished quote
or proforma creation may begin at Customer; it must not then acquire a different
existing document. Financial locks are released before processor or native I/O.
Payment-first dispute/refund writers append durable review facts; document-first
workers process them after commit. Coverage readers reject visible disputed or
refunded evidence immediately, even before that worker runs.

An unsettled attempt holds conflicting renewal preparation/collection only while
its application authority remains live. Recovery retains ownership of unknown
money after that deadline without indefinitely freezing unrelated normal renewals.
Committed resource-only pending work does not block ordinary billing.

### Billing commitment and native completion

Full settlement, or explicit zero-due acceptance, atomically commits the target
subscription price/product, service price, accepted resource assignment and durable
native outbox. It ends that subscription's old price lock and future renewal
benefits while retaining already reserved benefits and frozen documents. Paid
coverage is rechecked under the common document context; duplicate settlement
cannot create another assignment or advance paid-through for a top-up.

New renewals use accepted per-service terms ahead of older prepared-cycle and
shared product/customer grandfathering fallbacks. Another service's promise is
unchanged. Recognized disk/bandwidth allowance fallbacks use purchased accepted
limits rather than a subsequently edited shared catalog; explicit subscription-item
terms and unrelated legacy tariffs retain their rules. A later independently
accepted currency transition keeps its own preparation/activation protocol. Native
recovery validates the original agreement's document/currency evidence, not every
unrelated later renewal in the subscription's current currency.

Downgrades are confirmed for the first uncommitted renewal. That future renewal
uses the agreed lower terms; early payment does not activate the resource reduction.
Cancellation stops when that renewal is committed to preparation. At the effective
boundary, preserve the agreed lower billing terms even if usage has grown or a
native operation is held. Such a change enters `limits_attention`; data stays intact
and no below-usage cap is forced. Request-time and execution-time fit checks use
purchased allowances and any separately authorized applicable raise, never hidden
native headroom. A changed owner or invalid financial source instead requires
explicit review.

The first operation reconciliation at or after a failed agreed downgrade boundary
creates one HIGH, review-required `hosting_plan_change_attention` audit event in
the existing staff review queue. There is no additional 24-hour waiting period.
The event and immutable `staff_escalated_at` marker commit together under the
commercial context; an audit failure leaves the obligation retryable. Only the
current owner scope is eligible, and the event contains closed operational IDs and
agreed terms, not raw diagnostic, recipient or native payloads. Escalation neither
reprices the service nor sends another customer email.

Native workers acquire no Customer, Subscription or PlanChange locks. They require
the exact commercial application and still-valid original paid coverage before
new dispatch. A dispute, refund or erasure does not authorize more resources.
Already-issued restore/migration repairs retain only their specifically fenced,
frozen repair authority; that exception cannot authorize an unissued operation or
new expansion. Native failure leaves received payment and agreed terms committed.
`applying_limits`, `limits_attention` and `completed` remain distinct; only current
canonical-node receipt verification can complete a change.

### Communication and recovery

Durable phase notices deduplicate proforma, issued invoice, payment received,
scheduled, completed and attention obligations. Financial notices use the existing
document templates/policies; operational notices honor the service preference.
Issuance/payment notices follow the actual legal document state even if resource
application needs review. Completion requires current native proof. Final send
checks revalidate current owner, recipient, erasure/suppression, phase and delivery
claim before provider I/O. EmailLog retention cannot reopen a closed notice into
another send. There is no exactly-once provider-delivery claim.

Five-minute schedules recover payments, activate scheduled changes, process
financial review facts, and reconcile native completion plus pending notices. A
`paid_review` result requires existing support/accounting refund/storno handling;
it is not permission to charge again or automatically roll back another plan.

### Rollout and rollback

`billing.hosting_plan_changes_enabled` defaults to false. Deploy additive Platform
schema, API, settlement/recovery workers and node helpers before Portal. Enabling
new acceptance requires qualified, explicitly managed accounts and the real
native/provider-DNS, browser, payment, renewal, restore and mail checks described
in the runbooks. Passing source, PostgreSQL or mocked boundary tests does not
establish those native gates.

Disabling the flag stops new acceptance and first claims. It must leave existing
webhook/convergence consumers, original-attempt recovery, scheduled activation,
financial review and native reconciliation deployed. Preserve documents, money,
idempotency identities and applied caps. Never use schema reversal, `quotaoff`,
direct FSM edits or automatic repricing as rollback.

## Consequences

- Commercial and native progress can differ; customers and operators need truthful
  pending/attention states rather than a single successful plan label.
- Frozen interval allocation and historical currency evidence add storage and
  review complexity, but avoid revising issued documents or double-charging a
  future interval.
- Automated changes deliberately cover a narrow compatible catalog. Exceptional
  resource-only staff overrides remain separately named and audited, with unchanged
  billing acknowledged; ticket approval alone performs neither workflow.
- A release cannot be declared end to end from unit/contract controls. Native
  authority and the explicit acceptance gates remain blocking requirements.

## References

- [Recurring billing operations](../domain/RECURRING_BILLING.md)
- [Customer service requests](../domain/CUSTOMER_RECOVERY_AND_SERVICE_REQUESTS.md)
- [Queue methodology](../domain/QUEUE_TASK_METHODOLOGY.md)
- [Deployment](../deployment/DEPLOYMENT.md#paid-hosting-plan-changes)
- [Platform restore](../deployment/PLATFORM_RESTORE.md#hosting-plan-change-recovery)
- [Owned native acceptance](../../tests/virtualmin_lab/native/README.md)
