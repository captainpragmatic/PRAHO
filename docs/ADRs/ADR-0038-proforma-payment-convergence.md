# ADR-0038: Proforma Payment Convergence Architecture

## Status
**Accepted** - March 2026

## Context

PRAHO must issue a Romanian tax invoice for every completed order. Romanian fiscal law (ANAF e-Factura) requires that an invoice exists before or at the point of service provisioning — not after. This creates a constraint: the invoice must be created as part of payment processing, not as a background afterthought.

There are three payment paths that can settle an order:

1. **Stripe card payment** — Stripe fires `payment_intent.succeeded` webhook asynchronously
2. **Bank transfer** — Staff manually records receipt via the Process Proforma Payment view
3. **Admin manual payment** — Admin records payment directly through the billing interface

Without a single convergence point, each path would contain its own invoice-creation logic. Past experience showed this leads to:
- Duplicate invoice creation (race between webhook and confirm_order endpoint)
- Invoice created without linking to the proforma (breaking the audit trail)
- Missing invoice when payment is recorded via one path but not fully reflected in another

Additionally, every order now follows the proforma-first lifecycle: when an order transitions `draft → awaiting_payment`, a `ProformaInvoice` is created and emailed to the customer. The proforma must be converted to a tax invoice exactly once, regardless of which payment path fires first.

## Decision

All payment paths converge through a single method: `ProformaPaymentService.record_payment_and_convert()` in `apps/billing/proforma_service.py`.

### What the convergence point does

1. Acquires a `select_for_update` lock on the `ProformaInvoice` row
2. Returns the existing invoice immediately if `proforma.status == "converted"` (idempotency)
3. Validates the payment amount against the proforma total
4. Creates or links the `Payment` record
5. Fires the `ProformaInvoice.convert()` FSM transition → `sent/accepted → converted`
6. Creates the `Invoice` record (immutable tax document)
7. Emits `proforma_payment_received` signal via `transaction.on_commit()`

### Signal chain

`proforma_payment_received` (sent after outer transaction commits) is handled by `_handle_proforma_payment_received` in `apps/orders/signals.py`, which calls `OrderPaymentConfirmationService.confirm_order()`. That service advances the order:

```
awaiting_payment → paid → provisioning   (standard orders)
awaiting_payment → paid → in_review      (high-value orders)
```

`confirm_order()` has its own idempotency guard: if the order is already `paid` or `provisioning`, it returns `Ok(order)` immediately.

### Stripe dual-path handling

For card payments, both the webhook and the Portal's `confirm_order` endpoint can call `record_payment_and_convert()`. Whichever arrives first converts the proforma; the second call finds `status == "converted"` and returns the existing invoice without creating a second one. The `select_for_update` lock on the proforma row serialises concurrent callers at the database level.

### Transaction boundary

`record_payment_and_convert()` runs inside an atomic savepoint when called from within an existing transaction. The `on_commit` signal fires only after the outermost transaction commits. This means:
- If the caller's transaction rolls back, no signal fires and no side effects leak
- `confirm_order()` called directly (not via signal) handles the case where the Portal needs synchronous order advancement before the signal fires

## Consequences

**Positive:**
- Single invoice-creation code path — no duplication, no divergence
- Idempotency guaranteed at the database row lock level, not application logic
- `on_commit` signal prevents ghost emails and ghost provisioning jobs on rollback
- All payment methods produce identical audit trails (proforma → payment → invoice → signal)
- Romanian tax compliance: invoice always exists before provisioning begins

**Negative:**
- Staff payment recording, Stripe webhook, and confirm_order endpoint all depend on this one method — a bug here affects all paths simultaneously
- `select_for_update` on ProformaInvoice creates a serialisation point; concurrent payments on the same order contend for this lock (acceptable, since an order should not be paid twice)
- The `on_commit` + signal chain adds one async hop between payment recording and order advancement; the Portal's confirm_order endpoint compensates with a direct `confirm_order()` call

## Related

- ADR-0034: django-fsm-2 state machines (FSM transitions used by the convergence point)
- ADR-0003: Result pattern (all methods return `Ok[T]` / `Err[str]`)
- ADR-0025: Monetary amounts in cents (amount validation in `record_payment_and_convert`)
- `apps/billing/proforma_service.py` — implementation
- `apps/orders/signals.py` — `_handle_proforma_payment_received` handler
- `apps/orders/services.py` — `OrderPaymentConfirmationService.confirm_order()`
- `docs/domain/ORDER_LIFECYCLE.md` — full lifecycle diagram including proforma states
