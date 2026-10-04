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
settled: on the built-in path (A2), and on the SmartBill path (A3), and how D390 declares the notes
(B). The reports move in A4.

## Decision

### The rule

Every completed refund records one fiscal correction (a tender command records one for all its
legs). A correction is settled by exactly one storno credit note, or is closed as `not_required`
with a computed reason. On a built-in original the note is PRAHO's own; on a provider (SmartBill)
original it is the provider's (see "Provider originals" below). An original may carry several
credit notes, one per correction. Nothing is ever deleted, voided or renumbered.

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

`invoice_one_reversal_per_original` is gone (A3, migration `0007`). Uniqueness is per correction
instead: a correction names one credit note (`FiscalCorrection.credit_note`, one-to-one) and at most
one provider attempt (`ProviderIssuance.fiscal_correction`, one-to-one). The notes of one original
are numbered in refund-completion order: a correction waits to issue until every earlier one has
issued, been closed, or been handed to staff.

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

Delivery is at least once, not exactly once. If the process dies after the mail server accepts the
email but before the success is recorded, the claim lapses and the sweep sends it again. That is
accepted on purpose: a customer receiving the same credit note twice is harmless, while one never
receiving it leaves the note uncommunicated and out of its D390 period. Only the first recorded
success sets the communication date.

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

### Provider originals (SmartBill, A3)

A correction on a SmartBill original is allocated exactly like a built-in one: the same amount
rule, the same split, frozen once. Only issuance differs, because the provider issues the document.

- **Whole-document reverse, for one case only.** `/invoice/reverse` takes the original's series and
  number and nothing else: no products, no amounts, once per invoice. So it issues a correction only
  when that correction's allocation is the whole original (base, VAT and discount) and nothing else
  credits the original: no other allocated correction and no other numbered note
  (`whole_document_storno_refusal`). The worker decides under the correction's lock and the reversal
  checks again under the original's lock before anything is sent.
- **Keyed by the correction.** `issue_storno_for_correction` finds or creates the credit note through
  the correction's `ProviderIssuance`, never through the original, and the ADR-0048 claim discipline
  (claim committed before the call, `outcome_unknown` for a human, pacing hands the claim back) is
  unchanged. The note carries version 3 VAT evidence for its own signed amounts, as a built-in note
  does, never a copy of the original's. The outcome settles that correction (`record_issued`): its
  frozen allocation must equal the note's totals. If the settling fails after the provider issued the note, the next worker run
  finds the issued attempt on the correction and settles it without calling the provider again.
- **Delivery.** The note is emailed like a built-in one, with the provider's own PDF
  (`get_invoice_pdf_bytes`, ADR-0048 decision 8), and the first send dates it. No e-Factura
  submission is owed: SmartBill files its own documents, so the correction's e-Factura status stays
  `not_due`.
- **Every other correction is `manual_required`.** A partial refund, or the rest of an invoice
  after one, cannot be expressed by the reverse call, and the API has no other way to issue a storno
  that references its original (research, 2026-10-04: `/invoice/v2` accepts negative quantities but
  has no field linking a document to the invoice it corrects; partial storno exists only in
  SmartBill's web interface). The correction keeps its allocation, moves to `manual_required`, and
  raises the `provider_partial_refund_needs_manual_correction` security event once that commits.
- **Staff record the provider's document.** The provider reconciliation screen lists every
  `manual_required` correction with the amounts to credit. Staff issue the storno in SmartBill, send
  it to the customer, and record its series and number (entered twice), its issue date, the
  communication date, the currency, the base and VAT as printed, an evidence reference saying where
  the proof of sending is kept, and an audit reason. `record_provider_storno` refuses amounts or a
  currency that differ from the allocation (sign ignored), an issue date before the original's or
  after today, a communication date before the issue date or after today, and a number already in
  use. It writes a locked credit note with the provider's number and issue date (noon of that day
  in Bucharest, or the recording moment if that is earlier), one negated line carrying the
  allocation, version 3 VAT evidence dated by that issue rather than by the recording (a later date
  would read as a VAT decision taken after the document), and a `ProviderIssuance` recorded by staff
  (`record_issued_by_staff`, no request or response) so the provider's PDF can be fetched. The
  correction goes straight to `communicated`: `fiscal_date` is the staff-entered communication date,
  `communicated_at` noon of that day in Bucharest, and `communication_evidence` the reference. The
  operator, their reason and the values are audited in the same transaction (ADR-0016).
- **No more matching by amounts.** A1 linked a provider storno to the obligation whose refunds summed
  to its total. Every provider storno is now issued from, or recorded against, a named correction, so
  that matching and the sweep that ran it are gone; a provider note answering to no correction is
  logged for an operator and never linked by guesswork. The `attached` state and its transition stay
  in the model because the A4 reports read them, but nothing produces them any more.

### Recovery

A Django-Q task is queued when a refund records its obligation, and an hourly sweep resumes every
unfinished correction by id, each step independently: allocation, issuance, communication and
e-Factura, on either issuer. Neither the task nor the sweep ever re-allocates or renumbers. The sweep
skips a correction whose provider attempt waits for a person (an unknown outcome, a live claim, or a
spent submission budget: the reconciliation queue's) and one that is `manual_required` (staff's).
`sweep_pending_issuances` resumes a paced or refused provider storno through its correction. The
`billing-owed-reversals` sweep, which looked for refunded provider invoices without a reversal, is
retired, and `setup_billing_scheduled_tasks` removes its schedule.

### D390 (B, #541)

A credit note is a supply line with a negative base, declared in the month its correction's
`fiscal_date` falls in: the communication date, per OPANAF 705/2020. Its own tax point never places
it, so a note issued in June and sent in July is declared in July only. A note whose correction is
not `communicated` (issued and unsent, the inert `attached` state, or no correction at all) has no
month yet. It is shown as an `uncommunicated_credit_note` exception in every month from its tax
point on, and never declared.

A note is judged by its original's proof. Its v3 evidence restates the original's decision and VIES
snapshot, so the consultation-reference rule and the VIES freshness rule are those of
`original_version` (`evidence_rules_version`), and freshness is measured at
`reverses_calculated_at`, when the original was decided. A note issued long after its original is
therefore neither a late decision nor stale proof. The late-decision check moved with it: a note is
late when its original's decision came after the original was issued, or when its own snapshot was
written after the note was issued.

Refunds hold the month their correction can land in. A refund is settled for an invoice only by a
correction decided against that invoice that is `communicated` or `not_required`. An unsettled
refund holds every month from the one it was raised in (its Romanian creation date), because its
note can only be sent on or after that day. It never holds the original's earlier, closed month.
A refunded invoice or payment status with no refund row behind it still holds the invoice's own
month, as do a void and legacy refund metadata.

Netting is per `(country, VAT body, operation)`, in RON, before rounding. A negative net is
declared. An exact zero made by a credit note is a "fully netted" group: no XML row, because D390
has no zero row, but kept in the preview, the CSV (`fully_netted`) and the source fingerprint. Any
other group that rounds to zero lei is a `zero_rounded_base` exception, as before.
`totalPlata_A` is `nrOPI` plus the signed bases, bounded by magnitude. Declarations stay initial
(`d_rec=0`); rectificatives are out of scope.

A provider storno staff record carries a communication date they enter, which may be earlier than
the refund was raised in PRAHO. Such a note lands in a month this report did not hold; if that
month was already filed, the accountant decides whether a rectificative is due.

### Reversal

A refund cannot leave `completed`, and an issued correction is immutable. Restoring an invoice to
paid while a credit note reverses it is refused (A1). If a refund is ever reversed, the correction
is re-billed with a new invoice that references the credit note; that workflow is future work.

### Reports (A4)

The revenue report shows two figures side by side (owner decision, 2026-10-03), and the VAT report
follows the fiscal one.

- **Fiscal date.** An invoice declares on `Coalesce(tax_point_date, Romanian date of issued_at)`.
  `issue()` sets both, so a row that never went through it (legacy or imported data) falls back to
  the Romanian date of its creation rather than dropping out of every period. A credit note
  declares on its correction's `fiscal_date`, the day the customer received it: the built-in send,
  SmartBill's own email, or the sending date staff record for a manual storno.
- **Which credit notes have a period.** An allow-list: a note settled by a `communicated`
  correction (dated by the send), and, for rows written before A3, a provider note `attached` to its
  correction or one with no correction at all (both dated by the note's own tax point, the only date
  they carry). A note that is `issued` but not yet sent has no period and is left out of every
  figure. Dating it by its tax point would put the reversal in one month here and another in D390
  once it is sent. An original may carry several notes; each subtracts on its own date.
- **Fiscal revenue** is the collected invoices (`paid`, `refunded`, `partially_refunded`) on their
  fiscal date, less the credit notes with a period whose original is one of those invoices, on the
  note's date. A note against an invoice the report never counted subtracts nothing.
- **Cash revenue** is unchanged: collected invoices in the month the document was created, less
  completed refunds (the shared resolution rule) in the month the money went back.
- **VAT** lists every issued invoice (`issued`, `overdue`, `paid`, `refunded`,
  `partially_refunded`) on its fiscal date, whatever its refund status, and every credit note with a
  period as negative base and VAT on its own date. A refunded invoice no longer drops out, which had
  restated periods already filed.
- **The warning.** Both reports count completed refunds whose correction is unsettled: *not issued
  yet* (no correction, or `pending`, `allocated`, `failed`, `manual_required`) and *issued, not sent*
  (`issued`). A tender leg answers to its command's correction. `not_required`, `attached` and
  `communicated` are settled; that allow-list decides, so a state added later warns until someone
  decides it is settled. The VAT report counts only refunds settled on or before the end of the selected period,
  because a period that ended before the money went back cannot receive that refund's note. It does
  not try to predict which later period the note will land in.
- **Dashboard.** Its monthly card stays on paid invoices by `created_at`, labelled as cash. That
  keeps the scan bounded by the existing `(customer, -created_at)` index. A fiscal-date basis would
  need an index on a coalesced expression for one card, so none was added.

## Consequences

- Every refund of a built-in invoice now produces a fiscal document the customer receives.
- Revenue shows fiscal (invoices less credit notes, by fiscal date) next to cash (collected less
  refunded), and VAT follows the documents (A4, above). D390 declares credit notes as negative lines
  in their communication month (B).
- `setup_email_templates` must be run once on each database to seed `credit_note_issued`; until it
  is, sends fail visibly and are retried.
- A partial refund of a SmartBill invoice, and any refund after the first, needs a person: the
  provider's API cannot issue that storno. It is listed on the reconciliation screen and raises a
  security event until staff record the document they issued.
- A recorded provider storno is dated for D390 by what staff enter. The evidence reference is the
  check on that date; PRAHO cannot verify a send it did not make.
- Two provider cases stay with an operator, with no dedicated exit yet. A whole-document reverse
  that spends its submission budget stays `allocated`: it is listed under "Out of submission
  budget" on the reconciliation screen but cannot be recorded by hand, because only
  `manual_required` corrections can. And a reverse that cannot even be prepared (the original has
  no provider number) is retried by the hourly sweep with a warning each time.
