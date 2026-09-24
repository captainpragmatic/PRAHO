# ADR-0048: External Invoice Issuer (SmartBill)

**Status:** Accepted
**Date:** 2026-09-22
**Authors:** Development Team
**Related:** ADR-0015 (configuration resolution), ADR-0016 (audit coverage),
ADR-0025 (cents), ADR-0034 (FSM), ADR-0038 (payment convergence),
ADR-0042 (settings catalog), ADR-0045 (committed side-effect boundaries),
ADR-0047 (jurisdiction tax policy)

## Context

PRAHO issues its own invoices, owns the legal sequence, renders its own PDFs, and
files e-Factura with ANAF itself through `apps/billing/efactura/`. Two operator
needs prompted adding SmartBill as an alternative issuer: the accountant works in
SmartBill, and ANAF-integration risk should sit with a vendor who does it full time.

Investigating SmartBill's API changed what was buildable. From the published
OpenAPI spec and one live capture:

- **V3 is read-only.** Every V3 operation is a GET. V1 is the only way to issue.
- **There is no e-Factura surface at all.** SmartBill auto-submits API-issued
  invoices to SPV, but that is configured and observed only in its web UI. No
  endpoint, no webhook, no status. Delegating e-Factura means going blind to the
  ANAF outcome and losing the signed-response archive PRAHO collects today.
- **No idempotency key, and no way to find a document by our reference.** A
  timed-out POST may have created a legally numbered invoice we cannot look up.
- **HTTP status is not the verdict.** An ordinary failure is `200 OK` with a
  populated `errorText`. A misspelled field returns `500` with an HTML body.
- **The published spec is incomplete.** A real `401` carries `successfully`,
  `errorCode`, `key`, `id`, `documentNumber` and more, none of them in the schema.
- **The rate limit has teeth.** 30 calls per 10 seconds, and exceeding it blocks
  the token for ten minutes — during an hourly billing run, an outage.
- **`/invoice/reverse` carries no amounts.** It reverses a whole document or
  nothing, once per invoice.
- **The request has no EN16931 tax category and no exemption reason.** A 0% rate
  can state how much but never why.

An independent review recommended against building a pluggable issuer at all,
costing it at 5–15 engineer-months against a live system and arguing the honest
alternative was a bookkeeping mirror. That objection is recorded here because the
decision was taken against it: PRAHO is pre-launch, which removes the migration
cost the estimate assumed, and the operator accepted SPV blindness knowingly.

## Decision

1. **Provenance is per document, never a global read.** `Invoice.issuer_provider`
   is stamped at creation and frozen into the fiscal snapshot. A document issued
   before a switch keeps its issuer, its numbering path and its e-Factura owner
   forever. This single choice removes most of the switching problem: a worker
   holding an invoice cannot have the answer change underneath it, which is why no
   provider-generation lease was needed.

2. **One authoritative invoice, one number, one e-Factura submission owner.**
   PRAHO's e-Factura stack stays in the repository but is refused per document at
   the lowest outbound boundary. Two uploads of one invoice to SPV cannot be undone.

3. **Three outcomes, not two.** A provider call succeeds, provably fails having
   created nothing, or leaves the outcome unknown. `outcome_unknown` has exactly
   one exit: an operator who checked the provider and recorded what they found.
   No sweep, retry or replay can reach a second POST from it. An abandoned claim is
   quarantined into that same state rather than retried, because a crash before the
   POST and one after the document was created leave identical durable state.

4. **Classification is write-aware.** On a read a wrong verdict costs a repeated
   GET; on a write `REJECTED` is a licence to send the same POST again. Writes earn
   it only from a recognised refusal envelope; everything else unknown is ambiguous.

5. **Refuse rather than approximate.** Only EN16931 category `S` is issued through
   SmartBill. Reverse charge, zero-rated and out-of-scope are refused, as are
   multi-rate documents and partial refunds. A blocked invoice is a staff alert; an
   invoice filed with ANAF under the wrong VAT category is found by an inspector.

6. **Totals are reproduced locally and compared on all three components** before
   sending. A matching grand total is not enough: net 10001 with VAT 2099 and net
   10000 with VAT 2100 both sum to 12100 and are different documents for VAT.

7. **Pacing grants or defers; it never reserves.** Refusal consumes nothing, so a
   backlogged task cannot starve itself. A 429 suppresses every worker, not only
   the one that saw it.

8. **The provider's document is the document.** An externally issued invoice serves
   the provider's own PDF, archived on first access. Rendering our own would be a
   second, unofficial copy of a legal document.

9. **A reversal is decided by durable state, never by the existence of a row.**
   Eligibility, the credit note and the claim are settled under one row lock on the
   original, and a credit note that exists but was never submitted is *resumed*.
   Treating row existence as proof of reversal makes any interruption permanent: a
   refund the customer can never be issued, recoverable only by editing the
   database. A uniqueness constraint on `reverses_invoice` backs the lock, so
   concurrent callers converge on one credit note instead of minting two.

   A whole-document reversal is refused unless exactly one *settled* refund accounts
   for exactly the invoice total. `/invoice/reverse` carries no amount, so an
   invoice refunded in instalments — where an earlier part may already have been
   corrected by hand in SmartBill's own interface — would be credited twice, and
   nothing downstream would notice. Settled refunds are counted rather than
   attempted ones; counting attempts would let a failed refund wedge the invoice in
   the same way row existence did.

   Credit-note lines are the original's, negated. EC-Sales reconciles partner totals
   against `InvoiceLine` rows, so a line-less correction cannot balance against a
   negative header. The three non-negative line constraints therefore became one
   sign-consistency constraint: the invariant worth keeping was that the parts of a
   line agree with each other, and which direction is legitimate is settled one
   level up by the document-kind constraints on `Invoice`.

10. **The switch preflight lives at the settings write chokepoint.** It runs inside
    `_write_setting_locked`, which every writer reaches — the settings view, a
    change set, the admin, a management command, a data migration, a direct service
    call — so it cannot be bypassed, and it runs immediately before the row lock so
    two operators racing the same switch cannot both be told yes. A value that is
    not a registered issuer is refused there and never stored.

    That refusal is what lets `default_issuer_provider()` stay non-raising: it is
    read inside the transaction that converges a customer payment, where a mistyped
    setting must not become a 500. Reaching it with an unknown provider now means
    the value arrived out of band, and it alarms rather than quietly stamping
    built-in — quietly stamping built-in would have PRAHO mint legal Romanian
    invoice numbers from its own sequence for an operator trying to hand exactly
    that responsibility elsewhere.

    The residual race — a document created in the window between the check and the
    write — is deliberately not coded around. Provenance is stamped at creation and
    frozen, so such a document gets *an* internally consistent issuer, never a
    corrupt one. That is the same reasoning that made a provider-generation lease
    unnecessary in decision 1.

## Consequences

- EU B2B and non-EU customers cannot be billed through SmartBill until a generated
  e-Factura XML proves the category is emitted correctly. V3 exposing
  `isReverseCharge` is encouraging but proves only that SmartBill distinguishes such
  rates internally, not what XML it emits.
- Partial refunds of provider-issued invoices need manual correction and raise a
  security event. `/invoice/reverse` cannot express them.
- There is no automated proof an invoice reached SPV, no deadline tracking and no
  signed-ZIP evidence in PRAHO while SmartBill owns e-Factura. This is the accepted
  cost of the decision, and the operator checks SmartBill Cloud for it.
- A credit note is a real invoice row with a negative total, and it satisfies every
  "issued or overdue" check, so dunning had to exclude it explicitly or customers get
  chased for money owed them.
- **Revised (PR #533): reporting does NOT net corrections for free.** This consequence
  originally said it did. It does not, because a credit note exists only on the provider
  path — the built-in issuer produces no correcting document at all — so any report that
  nets via the credit note answers differently depending on which issuer is configured,
  and cannot represent a partial refund at all, since `/invoice/reverse` refuses one so no
  credit note is ever minted for it. Revenue and VAT therefore exclude credit notes and
  take the correction from the `Refund` row, which both paths write at a single site. The
  credit note remains the fiscal document; it is no longer the reporting mechanism.
- Every invoice-touching feature now has two paths. The built-in issuer is kept
  exercised through the same gateway so the fallback stays real rather than becoming
  code that merely still compiles.
- Three behaviours are assumed and gated in code pending vendor confirmation:
  that a 429 on a write is refused before the document is created, whether VAT is
  computed per line or on the document total, and whether `precision` applies to VAT
  rounding. Recorded as questions 5 and 6 to `api@smartbill.ro`.

## Alternatives Considered

- **Bookkeeping mirror only** (PRAHO issues and files; SmartBill receives a copy):
  cheaper and safer, and the reviewer's recommendation. Rejected because it does not
  move ANAF-integration risk, which was half the motivation. SmartBill also cannot
  accept a number, so a "mirror" would be a second authoritative document.
- **Intercepting the numbering service**: rejected. SmartBill's number is produced
  by issuing the document, so numbering is not an independent operation, and remote
  I/O inside a `pre_save` would hold a transaction open across the network.
- **Transport-level retries**: rejected. A replayed POST whose response was merely
  lost creates a second legally numbered invoice.
