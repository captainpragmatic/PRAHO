# External Invoice Issuer — Operator Guide

How PRAHO issues invoices through SmartBill, and what to do when it goes sideways.
The architectural reasoning is in [ADR-0048](../ADRs/ADR-0048-external-invoice-issuer.md);
this is the runbook.

## What the switch does and does not do

`Settings → Integrations → SmartBill → Invoice issuer` chooses who numbers **new**
invoices. It is stamped on each document at creation and frozen.

It does **not** touch anything already issued. A document keeps its issuer, its
number and its e-Factura owner forever. That is deliberate — it is what makes
switching safe — but it has a consequence worth knowing: **after switching away from
SmartBill you still need its credentials**, because reversing or re-downloading the
documents it issued goes through its API.

Before switching, press **Test connection**. It does real work: it lists the
account's series and VAT rates and proves the configured series and every mapped VAT
name actually exist. Those strings must match SmartBill exactly (`buc` and `BUC` are
different units), and a mismatch otherwise surfaces when a document fails — or worse,
succeeds against the wrong rate.

## What SmartBill can and cannot issue

Only EN16931 category **S** — an ordinary positive VAT rate. Refused:

| Refused | Why |
|---|---|
| EU B2B reverse charge (`AE`) | The request has no tax-category and no exemption-reason field. A 0% rate says how much, never why |
| Zero-rated (`Z`), out of scope (`O`) | Same |
| More than one VAT rate on a document | A single document discount cannot be split across rates faithfully |
| Partial refunds | `/invoice/reverse` carries no amounts. It reverses everything or nothing |

A refused invoice is not lost. It stays a draft with a staff alert; it simply is not
sent. Those customers are billed through the built-in issuer instead.

## An invoice is stuck in "outcome unknown"

This is the state that needs you, and it means exactly one thing: **we do not know
whether SmartBill created the document.** A request went out and no usable answer
came back. The invoice may exist there, with a real number, addressed to the
customer, possibly already forwarded to ANAF.

It is never retried automatically, because a second attempt after a lost response is
how one order becomes two legally numbered invoices — and an invoice that is not
last in its series cannot be deleted, only reversed.

**Procedure:**

1. Open the issuance record. It holds the exact payload that was sent and the
   `nextNumber` observed before the attempt.
2. Look in SmartBill Cloud around that time, for that customer and amount.
3. **If you find the document**, adopt it: supply its series and number and a note
   saying what you checked. PRAHO takes that number as the invoice's own.
4. **If it truly is not there**, record that decision explicitly. Only then can the
   invoice be issued again.

Do not skip step 2. The counter moving is not proof: the accountant can issue
manually in the web UI at any moment, so a changed `nextNumber` is evidence, never
ownership.

## Refunds

A full refund of a SmartBill invoice issues a storno automatically. It becomes its
own document — a credit note with its own legal number and negative totals, linked
to the original — so VAT and revenue reporting net the correction without special
handling.

A **partial** refund cannot be done at the provider at all, and raises a security
event asking for manual correction. Reversing the whole document because part of it
was refunded would credit the customer money they never got back.

An invoice can be reversed once. A credit note cannot itself be reversed.

### Which sign a reversal carries, and where

Three readers, two conventions, and they are not a contradiction:

| Reader | Convention | Why |
|---|---|---|
| The **ledger** | signed — every amount negated | reporting that sums invoice rows nets the correction without knowing this integration exists; DB constraints pin a credit note's subtotal, tax and total non-positive |
| The **e-Factura XML** | positive magnitudes | EN16931 states direction once, in `CreditNoteTypeCode` **381**. BR-27 forbids a negative item net price outright, and 381 carrying negative amounts is wrong under either valid reading (380-with-negatives being the other) |
| The **PDF** | signed | it is the copy a customer reads, and a Romanian storno conventionally shows negative totals |

The XML and the PDF therefore agree on every magnitude and deliberately differ on sign.

The conversion happens at one place — `UBLCreditNoteBuilder._format_amount`, the single
boundary all eleven monetary emissions cross — and nowhere upstream of it. Converting in
the source helpers instead would feed a chain (tax-exclusive → tax-inclusive → payable,
plus a taxable amount recomputed independently and required to stay numerically identical),
which is where a partial application silently breaks BR-CO-13.

It negates rather than taking an absolute value. Negation is linear, so every EN16931
reconciliation that held over the signed amounts holds exactly over the magnitudes;
`abs()` would not survive a mixed-sign line, because the absolute value of a sum is not
the sum of the absolutes.

`CIUSROValidator` enforces this (BR-27 and the local `BR-CN-SIGN`) because the
reconciliation rules cannot: BR-CO-10/13/15/16 are equalities, and a consistently negated
document satisfies all four. Without a rule of its own, the validator is a partial-flip
detector that cannot see a whole-document flip — which is why the negative representation
looked correct for as long as it did.

## e-Factura

While SmartBill is the issuer, **it** files with ANAF and PRAHO does not. PRAHO's
own e-Factura stack refuses to submit any document it does not own, so one invoice
cannot reach SPV from two directions.

The trade you are accepting: PRAHO has no API-visible ANAF status, no automated
deadline tracking and no signed-response archive for those documents. SmartBill's
API exposes none of it. **Check SPV status in SmartBill Cloud.** Statuses run
`De trimis → In curs de trimitere → In validare → Valida | Cu eroare`, taking
seconds to hours and occasionally up to 48 hours.

Confirm SmartBill's auto-send setting matches the 5-working-day submission deadline
(OUG 89/2025). It can be scheduled up to 4 days after issue, and ANAF validation
takes time on top of that.

## Rate limits

SmartBill allows 30 calls per 10 seconds, and exceeding it **blocks the token for
ten minutes** — during a billing run, an outage. PRAHO paces itself well under that
and stops every worker when throttled. A download that answers "being prepared,
please retry" is this pacing, not a fault.
