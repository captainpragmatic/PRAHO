# Selling currency and gift purchases

## One currency for new sales

Financial staff choose RON, EUR or USD with `billing.default_currency`. The setting
controls new package sales, manual proformas, domain registrations and gift-card
denominations. Customers do not select a storefront currency.

Each currency needs explicit prices. `/settings/prices/` manages product, service
plan and domain retail prices. Changing the default does not calculate new prices
with an exchange rate. The switch checks published products, continuing renewals,
usage tariffs, domains, enabled gift denominations, payment configuration and tax
exchange-rate evidence. Missing or ambiguous values block the switch with details.

The policy has a revision. New-sale requests submit the displayed revision and
share a database lock with setting and price writers. A stale checkout asks the
customer to review the new prices. An uncertain prior submission keeps its original
payload and idempotency key so it can recover the accepted order after a switch.

## Existing money keeps its identity

- Orders, proformas, invoices, payments and gift cards keep their original amounts
  and currencies. Changing the default never converts or relabels them.
- Credit balances are shown separately by currency. A credit pays only an
  obligation in that same currency. Unproven historical currency requires review.
- Payment attempts and refunds use the original document or funding payment.
  Existing bank-transfer instructions use the document's currency-specific account.
- Prepared billing periods retain their currency, base price, quantity, usage
  allowance, tariffs, brackets and rounding. Later usage uses those frozen terms.
- Reporting groups customer money by currency. RON statutory tax reporting remains
  separate and uses the document's recorded exchange-rate evidence.

Legacy service-plan and TLD columns represent RON prices. New currency-specific
prices do not overwrite them with foreign amounts. Existing nullable contract
fields are not backfilled by guessing from today's catalog or default setting.

## Renewal notices and activation

Subscription and domain renewals preserve their current terms until an eligible
transition. Each offer stores the original and proposed terms and the exact notice.
The first renewal document in the new currency requires a matching successfully
sent notice at least 30 days earlier. A queued message alone does not satisfy this.

Failed notices leave renewals on their old terms. Changing an uncommitted offer
requires a fresh notice period. Grandfathered prices, promised renewal benefits,
existing prepared documents and prepaid commitments defer the transition. Unknown
historical commitments require review rather than an inferred price or period.

The new terms become effective at the recorded renewal boundary. Paying a future
period early does not change the currently effective price. Late settlement cannot
restore an older price, duplicate entitlement or resume a canceled subscription.
Canceled or refunded domain orders do not reserve future renewal periods.

The existing task scheduler reconciles offers and retries notices. Send completion
is recoverable from the matching accepted email record. Routine reconciliation
must run even when there are no new setting changes.

## Customer gift purchases

Portal **Billing → Gift cards** provides purchase history, digital purchases,
delivery status, reveal and resend actions. The catalog links to the same page.
Staff use **Business → Promotions → Gift cards**.

`promotions.gift_card_sales_enabled` defaults off. When enabled, customers can buy
configured denominations in the active selling currency using configured Stripe
or bank-transfer funding. Coupons and other gift balances cannot fund a gift.
Only verified payment activates spendable value; gift purchases create no hosting
service or renewal subscription.

**For me** saves the buyer's address; **Send as a gift** saves the recipient's
address and optional message. Delivery retries send the same bearer code to that
saved address. Anyone holding a code can redeem it. Ordinary staff pages and admin
views mask codes; an authorized POST reveal is audited and cannot be cached.

The queue stores delivery IDs, not codes. Delivery records show pending, sent or
failed attempts, with retry limits and resend cooldowns. Sent means the configured
email backend accepted the message; it does not prove inbox delivery.

Financial staff can request an unused-value refund, refresh its provider status,
or confirm an actual bank refund with a reference. Requesting a refund holds the
value before provider I/O. Pending or uncertain results keep the hold. Only a
verified failed/canceled result releases it, and success reduces the balance once.
Bank confirmation records a transfer already made; it does not send money.

Refunds retain the original funding intent and currency. Stripe metadata carries
the opaque refund UUID for reconciliation. An uncertain unbound provider request
cannot be resubmitted past the safe idempotency window. Bound requests can still
be retrieved. External refunds reconcile against funding, and disputes independently
freeze spending. Both apps show recorded, reserved, refund-held and available values.

## Configuration and rollout

1. Apply the additive Platform migrations before updated workers start. RON stays
   the upgrade default; an old environment variable cannot silently switch sales.
2. Configure explicit target prices and matching `billing.bank_accounts`. The
   legacy company bank account applies to RON only.
3. Configure provenance-bearing tax exchange rates. They support reporting and
   admission checks; they do not convert customer prices or balances.
4. Coordinate Platform and Portal deployment: new-sale requests carry the policy
   revision required by the Platform API.
5. Run `make check-currency` against the configured database. Run the read-only
   `audit_billing_cycle_terms` command to inspect unresolved historical evidence.
6. Verify normal task scheduling, email delivery and provider configuration before
   enabling gift sales or changing the selling currency.

Offline Django checks do not query the financial policy tables. Currency-specific
refund and provisioning attention thresholds are configured separately; an unknown
foreign threshold requests review instead of comparing it to a RON threshold.

## Verification boundaries

The implementation is exercised with isolated test databases, mocked provider
calls, local email backends and browser checks through the signed Portal API.
These checks do not send real customer email, make real charges or refunds, call
registrars, or verify a deployed firewall. Session-specific command results and
browser artifacts are retained separately in the local QA evidence.
