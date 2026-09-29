# Promotion and gift-balance operations

## Rollout

Apply the additive Platform migrations (`billing.0059`, `promotions.0005` and
`promotions.0006`) before starting the updated workers. The Portal gains no business
tables; it continues to call the Platform through the signed, tenant-checked API.

`promotions.new_offers_enabled` defaults to false. Enable it only after reviewing
campaign currencies, budgets, coupon restrictions and rule conditions. Existing
rules require explicit publication in the staff form before new checkout quotes
can use them. Pausing new offers leaves existing balances, refunds and promised
renewal credits usable.

Campaign budgets include both immediate discounts and promised future credits.
The staff form rejects a budget below the amount already spent or reserved and
prevents changing the currency of a used budget.

## Staff workflow

Business → Promotions contains the existing campaign, coupon, automatic-offer,
gift-card, referral and loyalty screens. Staff can read them; billing-capable staff
can change financial configuration. No new referral or loyalty automation is added.

- Set the eligibility controls explicitly. Disable “Applies to all products” before
  adding restrictions. The form preserves those selections when editing.
- Enter tiers as `threshold:discount`, for example `10000:10%` or `5:500`, and
  select whether the threshold means cents or quantity. The highest qualifying tier
  wins. Fixed discounts require a currency.
- Offers combine only when both permit stacking. Exclusive offers stand alone.
  A nonstackable entered coupon replaces conflicting automatic offers, and the
  customer confirms the recalculated quote.
- BOGO discounts the cheapest remaining eligible first-term service units. Setup
  fees remain payable. Future free-month credits keep the original monetary value;
  upgrades do not enlarge that promise or replace grandfathered subscription prices.

Paused subscriptions defer unused credits. Cancellation ends future benefits while
retaining credit already committed to a payable document. Expired-document cleanup
releases unused holds after checking for unresolved card payments.

## Existing gift balances

Customers explicitly enter a code at checkout or on an invoice/proforma. Only the
matching currency is accepted. The balance pays the tax-inclusive document total;
it does not reduce the service's taxable price. Automatic renewal collection does
not spend a gift balance without a customer request.

A mixed proforma retains its gift reservation until the remaining payment is
verified. The staff Record Payment modal displays only that remaining cash amount
and checks that it has not changed. Zero-cash settlement uses the same document and
subscription convergence path. An abandoned expired proforma returns its reservation
unless an unresolved Stripe attempt could already have charged the customer.

Historical ledger version 1 discount records remain unchanged. New captures and
refunds use version 2 tender records and immutable operation identifiers. Issued
documents are never repriced to adopt a newer promotion.

Customer gift-card purchase and Stripe initiation endpoints are not exposed by this
change. Customer purchases and the configurable selling-currency policy belong to a
separate follow-up. The funding service/staff scaffolding here is not a completed
public purchase flow.

## Refunds and recovery

Refunds return value proportionally to the original payment methods, with cent
rounding reconciled across partial refunds. A durable command records each leg before
provider I/O. Confirmed provider facts commit before local projection, so a retry
reuses the original operation and skips completed legs.

On the staff invoice or order page, **Resume refund** retries the stored unfinished
command. The API reports completed, processing or failed status explicitly. Customers
cannot invoke the staff recovery action. An old uncertain provider attempt requires
reconciliation rather than submitting a replacement payment/refund instruction.
That provider deadline does not block local bank/cash or gift-balance projections.
Conditional ledger transitions produce audit entries in the same transaction;
customer-initiated gift reservations retain the authenticated customer's user ID.

A single completed full split-refund command can produce one provider credit note
only when its settled refund IDs and amounts exactly account for the original invoice.
The existing safeguards for independent partial refunds remain in place.

Financial settlement locks the document, linked order, customer, subscription,
campaign/coupon, sorted gift cards and payment records in that order. Dunning locks
subscriptions before billing cycles. Gateway fact persistence remains a separate
transaction from local document settlement.

## Verification

Local verification uses isolated SQLite and PostgreSQL databases and separate browser
servers on ports 18700/18701. It does not verify production firewall rules, SMTP delivery,
Stripe delivery or accounting-provider delivery. Detailed commands, outcomes and
browser artifacts are recorded in `logs/staff-promotions/` for this worktree.
