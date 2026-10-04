# ADR-0053: Every Settled Refund Issues a Storno Credit Note

**Status:** Accepted
**Date:** 2026-10-03
**Authors:** PRAHO maintainers
**Related:** ADR-0016 (audit coverage), ADR-0025 (cents), ADR-0034 (FSM), ADR-0041 (foreign-currency
e-Factura), ADR-0045 (committed side-effect boundaries), ADR-0048 (external invoice issuer),
ADR-0049 (reverse charge requires VIES evidence)

## Context

A refund moves money. Under Romanian law (Cod Fiscal art. 330), returning part or all of what an
issued invoice charged also has to reduce that invoice, with a storno credit note that references it.
Until now only the SmartBill path produced one, and only for a whole invoice refunded in one go
(`/invoice/reverse`). A built-in invoice produced no correcting document at all, so its VAT, its
e-Factura record and the customer's copy kept stating a sale that had been partly or wholly undone.

Issuing the note inside settlement was rejected in review: a numbering failure or a slow provider
must never roll back money that has already left. PR #599 (A1) therefore records a durable
`FiscalCorrection` obligation when a refund completes. This ADR records how that obligation is
settled on the built-in path (A2). SmartBill moves onto the same obligation in A3, the reports in A4
and D390 in B.

## Decision

### The rule

Every completed refund records one fiscal correction (a tender command records one for all its
legs). A correction on a built-in original is settled by exactly one built-in storno credit note,
or is closed as `not_required` with a computed reason. Nothing is ever deleted, voided or renumbered.

### The amount

The amount owed is what the refund causes, not what is unpaid. Corrections of one original are
decided one at a time, in refund-completion order, under a lock on the original:

- `slack = max(0, held_before_this_refund − (original.total − already_credited))`
- `reduction = min(max(0, refund − slack), remaining_creditable)`

`held_before_this_refund` is everything collected against the invoice (refunded payments included,
floored at the total for a paid invoice, as `net_collected_cents_for_invoice` does) less the refunds
of the corrections decided before this one. A reduction of 0 closes the correction as `not_required`:
`covered_by_collections` for an overpayment or duplicate payment, `fully_credited` when nothing is
left. Worked examples: invoice 100, collected 40, refund 10 credits 10; collected 120, refund 20
credits 0; collected 120, refund 30 credits 10.

A tender command's correction waits until the command is `completed`. Its model calls `failed`
"needs retry", and an operator can resume it, so freezing an amount at `failed` could under-credit.

### The allocation

The gross is kept exact and the parts are clamped jointly against what the original has left:

- **The whole remainder** takes exactly the remaining base, VAT and discount. An original never
  credited before is mirrored line by line, negated.
- **A partial** is one negated line, quantity 1, line discount 0, split from **running totals**:
  with C_k the gross credited including this correction, `base_k = round_half_even(C_k / (1 + r))`,
  and this correction's base is `base_k` less the base already credited; its VAT is `G − base`. Each
  note's rounding corrects the one before rather than adding to it, so every partial satisfies
  BR-CO-14. If either part exceeds its remainder it takes exactly the remainder and the other is the
  difference; if that one then exceeds its own remainder, the amount is refused. A partial carries no
  discount; the last correction takes the discount left. A partial needs a single VAT rate (A1
  already refuses the refund request otherwise).
- **Acceptance**: every document satisfies BR-CO-14 as the e-Factura validator states it
  (`|tax − round_half_up(base × r)| ≤ 0.01`). The two share one helper.

**The residue (owner decision, 2026-10-04): every document stays valid.** A final remainder whose
exact base and VAT would fall outside BR-CO-14 (possible when the original's own VAT is a sum of
rounded lines) is split at the valid VAT nearest to the VAT left, keeping the gross exact. The VAT
this leaves un-reversed, signed (negative when it reverses beyond the original), is recorded on the
correction as `vat_residue_cents` and logged; it is at most a cent or two. Per-step rounding was
rejected: after 31.43, 31.43 and 29.01 against 121.00 it left base 24.06 with VAT 5.07 for the rest,
two cents outside the rule; from running totals the rest is base 24.07 with VAT 5.06.

The allocation is written once, with its timestamp and residue, and never recomputed.

### Issuance and numbering

Draft, lines, number and `issue()` happen in one transaction, so a rollback leaves neither a numbered
draft nor a gap. Lines are written with `bulk_create`, because `InvoiceLine.save()` recomputes the
VAT from the base and would turn a 10.00 credit at 21% into 9.99. The FX snapshot (all four fields)
and every `bill_to_*` field are copied from the original. Version 3 VAT evidence is written before
`issue()`: the original's decision, identity and VIES proof under the original's evidence version,
the note's own signed amounts, `reverses_number` and `reverses_calculated_at`. The reader accepts
version 3 only on a credit note, with amounts equal to the note's totals.

`Invoice.sequence_scope` records the numbering family a number came from. A credit note is numbered
from its original's family; an archived series answers to the family's active one, which the law
permits. In the code as it stands, every invoice is numbered from `default` (`subscription` numbers
subscriptions, not invoices). Built-in notes get no `ProviderIssuance` row and are never swept as
provider documents.

Until A3 drops `invoice_one_reversal_per_original`, an original can carry one credit note. A second
correction on the same original is parked as `failed` (`awaiting_second_credit_note_support`) with
its allocation, and is retried by the sweep.

### Communication

After the issuance commits, the note's PDF is emailed to the customer through the notifications
service (`credit_note_issued`, RO and EN, seeded by `setup_email_templates`), in the customer's
language (`get_customer_locale`). The first successful send sets `communicated_at` and `fiscal_date`
(its Romanian calendar date) once; per OPANAF 705/2020 that date places the note in its D390 period.
A failed send is counted, stays visible and is retried.

Sending is claim-then-send: a short transaction locks the correction and, if it is unsent and no
live claim exists, records a claim with a five-minute lease and commits; the email is sent outside any
transaction; the first success is then recorded once. A racing worker sees the claim and does not
send. A claim whose sender died is retaken once the lease runs out.

### The e-Factura gate

A 381 is filed only once its original is accepted. The gate is inside
`EFacturaService.submit_invoice`, the path every signal, task and retry goes through, so none of them
can skip it. Its states are `not_applicable` (not Romanian), `waiting_for_original` (retried by the
sweep) and `original_rejected` (manual review). Reaching `communicated` does not take a note out of
e-Factura recovery: the two have separate status fields. While e-Factura is switched off
(`EFACTURA_ENABLED`, the one switch the service obeys) nothing is filed, so the note is
`not_applicable` rather than waiting forever. A held or failed filing is re-checked with exponential
backoff (one hour, doubling, capped at a week), recorded as `efactura_attempts` and
`efactura_next_attempt_at`, so it stays visible without being re-checked every hour.

### Recovery

A Django-Q task is queued when a refund records its obligation, and an hourly sweep resumes every
unfinished correction by id, each step independently: allocation, issuance, communication and
e-Factura. Neither the task nor the sweep ever re-allocates or renumbers.

### Reversal

A refund cannot leave `completed`, and an issued correction is immutable. Restoring an invoice to
paid while a credit note reverses it is refused (A1). If a refund is ever reversed, the correction
is re-billed with a new invoice that references the credit note; that workflow is future work.

## Consequences

- Every refund of a built-in invoice now produces a fiscal document the customer receives.
- Reports still take the correction from the `Refund` row (ADR-0048, revised) until A4 moves them to
  fiscal netting; D390 treats credit notes as exceptions until B.
- `setup_email_templates` must be run once on each database to seed `credit_note_issued`; until it
  is, sends fail visibly and are retried.
- A second correction on one original waits for A3.
