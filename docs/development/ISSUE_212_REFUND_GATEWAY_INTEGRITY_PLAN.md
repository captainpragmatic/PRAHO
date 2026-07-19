# Issue #212: Refund gateway integrity

**Status:** Implemented and verified

**Issue:** [#212](https://github.com/captainpragmatic/PRAHO/issues/212)

## Objective

Make the external payment result authoritative for staff-initiated refunds. A
gateway failure or a missing/ambiguous refundable payment must return an error
without leaving an invoice marked refunded or a refund amount reserved locally.
Successful order refunds must follow PRAHO's real
`Order -> Proforma/Invoice -> Payment` relationships and retain the gateway
refund identifier on the `Refund` audit row.

## Verified root cause

1. `_process_bidirectional_refund()` creates a `Refund` row and updates the
   invoice before calling the payment gateway.
2. It converts a gateway `Err` into `Ok(final_result)` with an ignored
   `payment_refund_error` dictionary entry. The staff views treat that result as
   success.
3. `_process_payment_refund_if_exists()` looks for `order.payments`, but `Order`
   has no such relation. `Order` links to `proforma` and `invoice`; `Payment`
   links to those documents and also records `meta.order_id` during payment
   intent creation.
4. `Refund` already has nullable `payment` and `gateway_refund_id` fields, but
   the service does not populate either one.
5. An existing unit test explicitly expects the false-success behavior, so a
   green suite currently preserves the defect.

## Approach

Resolve and lock exactly one refundable payment before initiating local refund
state. For an invoice, use its payment relation. For an order, use its linked
invoice, linked proforma, or authoritative `Payment.meta.order_id` fallback,
always constrained to the same customer and refundable payment statuses. Fail
closed when no payment or more than one candidate is found; PRAHO's current
proforma flow supports one successful full payment, so silently choosing among
multiple successful payments would be unsafe.

Call the gateway before creating a durable `Refund` row or mutating local
financial state. If the gateway fails, propagate the exact error. If it
succeeds, create the audit row with its Payment link, gateway refund ID, and
the payment's currency, then update the Payment and linked Invoice states.
Every public gateway call receives the exact validated cent amount; cumulative
partial refunds converge both Payment and Invoice to fully refunded. The
pending/completed refund workflow remains separate issue #196.

## Implementation plan

### Task 1: Establish RED behavior tests

**New file:** `services/platform/tests/billing/test_refund_gateway_integrity.py`

Add public-service tests using real `Order`, `Invoice`, `Payment`, and `Refund`
rows while mocking only the payment gateway boundary:

1. A failed invoice gateway refund returns `Err`, leaves the invoice `paid`,
   leaves the payment `succeeded`, and leaves no `Refund` row.
2. An order linked to an invoice reaches that invoice's successful payment,
   calls the gateway exactly once, updates the payment, and stores both
   `Refund.payment` and `Refund.gateway_refund_id`.
3. A paid invoice without a refundable payment fails without local mutation.
4. Multiple refundable payments fail closed rather than choosing one
   nondeterministically.

Update the existing focused unit assertion that currently expects a payment
gateway error to become an overall success.

Run the new tests before production changes and record failures proving the
current false-success and missing-relation behavior.

### Task 2: Resolve the authoritative payment

**File:** `services/platform/apps/billing/refund_service.py`

1. Add a private payment resolver that queries `Payment` through the invoice,
   proforma, and order metadata relationships described above.
2. Restrict candidates to the entity's customer and statuses that can still be
   refunded.
3. Acquire a row lock inside the existing refund transaction.
4. Return a clear `Err` for zero or multiple candidates.
5. Revalidate the payment status at the gateway boundary so concurrent refund
   attempts cannot replay a completed payment refund.

### Task 3: Make gateway outcome authoritative

**File:** `services/platform/apps/billing/refund_service.py`

1. Run the gateway leg before creating the `Refund` row or mutating financial
   document state.
2. On gateway `Err`, return `Err` to the view with no local refund mutation.
3. On gateway success, store the bounded gateway refund ID and Payment link on
   the `Refund` row using the Payment's currency.
4. Send the exact cent amount for both full and partial public refunds.
5. Update the linked invoice only after the monetary operation succeeds, and
   return `payment_refund_processed=True` only on that path.
6. Derive full-versus-partial Payment and Invoice state from cumulative refund
   amounts so sequential partial refunds converge correctly.
7. Preserve the Order FSM invariant: refunds remain an Invoice/Payment concern
   and do not change Order status.

No schema migration is required because the audit fields already exist.

### Task 4: Regression and review gates

Run, in order:

```bash
make test-file FILE=tests.billing.test_refund_gateway_integrity
make test-file FILE=tests.billing.test_refund_service_regressions
make test-file FILE=tests.billing.test_payments_refunds
make test-file FILE=tests.billing
make lint
make test-platform
```

Then review the full branch diff and all direct callers in the order, invoice,
payment, gateway, signal, and refund-model paths. Confirm DCO on every commit
before the first push, publish a live PR, and inspect all automated review
threads.

## Invariants and non-goals

- Never report monetary success when the gateway returns failure.
- Never mutate invoice/payment/refund state for a missing or ambiguous payment.
- Never select a payment belonging to another customer.
- Do not add a staff-controlled gateway bypass.
- Do not redesign the Refund approval/completion FSM; that remains #196.
- Do not backfill historical refund/payment links in this change.
- Do not add multi-payment refund allocation; fail closed until that workflow is
  explicitly designed.
