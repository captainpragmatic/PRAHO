# Codex review — billing / e-Factura arc since v0.28.0 (`v0.28.0..HEAD`)

5 parallel codex passes (4 by code surface + 1 cross-cutting) over 20 commits / 37 files / +2992-1033.
Findings deduplicated + prioritized. **These are review hypotheses**; `[CONFIRMED]` = verified against
code in this session. Per investigation discipline, this is a report — no fixes applied yet.

## CRITICAL
1. **[CONFIRMED] e-Factura submit uploads to ANAF but cannot transition locally → double-send.**
   `service.py:97 submit_invoice` creates the doc in `draft`, uploads, then calls `mark_submitted()`
   whose FSM `source` is only `queued` (`models.py:311`); `mark_queued` is never called. Successful
   upload → `TransitionNotAllowed` → generic `except` → first submission (`existing is None`) persists
   nothing → `upload_index` lost → retry re-sends. Compounds with Gap 1 (JSON parser → `upload_index=""`).
   Found independently by 2 reviewers (chunks D + E). → Phase 0 of the #123 plan.
2. **Discounted orders charge one total but invoice another.** `orders/models.py:478` +
   `financial_arithmetic.py:76` compute order tax on the GROSS line base and subtract discount AFTER
   tax, while `proforma_service.py:175` taxes the NET base. A discounted order → Stripe charge =
   `order.total_cents`, then `record_payment_and_convert` rejects because `amount != proforma.total_cents`.
   (chunk B). NEEDS VERIFICATION (does a discounted order actually reach Stripe?). Same gross/net
   contract as the e-Factura arc, but at the ORDER level — not yet fixed.

## HIGH — idempotency (the dominant systemic theme)
Almost every financial mutation lacks a service-boundary idempotency guard:
3. **Proforma→invoice conversion not idempotent**: `select_for_update()` evaluated before `atomic()`
   (`services.py:336`); already-converted returns `Err` not the existing invoice (B + E).
4. **`create_from_order` (invoice) can duplicate legal invoices** — no order lock, doesn't return
   `order.invoice`/`meta[order_id]` (`services.py:119,153`; `orders/tasks.py:503,948`) (B + E).
5. **`create_from_order` (proforma) can duplicate proformas** — no `order.proforma` check/lock
   (`proforma_service.py:154,183`) (B + E).
6. **Stripe payment-intent retry not order-scoped** — picks newest pending payment for the customer
   (`payment_service.py:230`) → duplicate PaymentIntent (B).
7. **Direct staff payment POST double-applies on retry** — creates a succeeded `Payment` every submit
   (`views.py:1378`, `payment_service.py:50,410`) (E).
8. **Gateway refunds not retry-safe** — Stripe refund called without a stable idempotency key inside a
   DB txn (`refund_service.py:707,1165`; `stripe_gateway.py:267`) → timeout/rollback → double refund (B).
9. **Refund ledger double-count** — `_update_invoice_refund_status()` re-adds the current refund
   (`refund_service.py:779,921,989`) → a >50% partial refund is misclassified as FULL → triggers
   suspension/refund-reporting side effects (C + E).
10. **Submitted/processing e-Factura docs re-upload** — idempotency only short-circuits `accepted`
    (`service.py:124`) (D + E). Folded into Phase 0.

## HIGH — correctness
11. **`recalculate_totals()` drops document discounts** — both `invoice_models.py:319` /
    `proforma_models.py:208` call `calculate_document_totals(lines)` without `discount_cents`
    (C + E). = issue #195 item. Latent (no live caller on a discounted doc) but a model footgun.
12. **Refund balance semantics inconsistent** — `get_remaining_amount()` counts only `completed`
    refunds, but the FSM is never driven to `completed` (C). = issue #196.
13. **Credit-note reporting structurally impossible** — `EFacturaDocument` is OneToOne + unique-invoice,
    but the refund signal tries to create a 2nd doc for the same invoice (`signals.py:1697`;
    `efactura/models.py:95,251`) → compliant credit notes can't persist; partial refunds unrepresentable (E). NEW.
14. **Validator rounding diverges** — `validator.py:555` uses `ROUND_HALF_UP`; platform VAT cents use
    `ROUND_HALF_EVEN`. Half-cent cases → validator rejects the platform's own XML (A).
15. **Non-EU zero-VAT customers misclassified as `Z`** — `xml_builder.py:285` falls to zero-rated `Z`
    for a non-RO, non-EU customer with a tax ID; should be `O` (out-of-scope) for services (A).
16. **Credit-note builder skips the single-rate invariant** — `UBLInvoiceBuilder._validate_invoice`
    rejects multi-rate, `UBLCreditNoteBuilder._validate_invoice` (`xml_builder.py:976`) does not (A).
17. **Deadline scan window too narrow + ignores `hours`** — `service.py:353` `lookback=deadline_days+7`
    is tight for holiday clusters; `hours` arg ignored (model re-reads settings). Near-deadline invoices
    can vanish from alerts (D + E). Touches the #197 work I just shipped.
18. **PDF reverse-charge (AE) diverges from XML** — XML derives AE from doc facts + clamps % to 0;
    PDF trusts `line.tax_category_code=="AE"` + prints `line.tax_rate` (`pdf_generators.py:342,465`) (D).
19. **`bill_to_registration_number` not populated on creation paths** — field + XML/PDF consumers exist,
    but order→proforma/invoice creation never sets it; `OrderService` reads
    `getattr(customer,"registration_number")` while the real field is
    `customer.tax_profile.registration_number` → Romanian invoices miss Nr. Reg. Com. (C). NEW.

## MEDIUM
20. **Emailed invoice PDFs bypass the canonical renderer** — downloads/API use
    `RomanianInvoicePDFGenerator`; email still uses the old WeasyPrint/template path
    (`invoice_service.py:243,341`) → customer gets a different compliance doc (E). NEW.
21. **XML hash goes stale after regeneration** — `save()` computes `xml_hash` only when blank; regen
    updates `xml_content` but not the hash (`efactura/models.py:264`, `service.py:449`) (E). NEW.
22. **`discount_cents` migration not backfilled / not authoritative** — 0025 sets existing rows to 0;
    XML/PDF derive discount from `gross lines − header subtotal`, ignoring the stored field the comment
    calls authoritative (C). Three representations of one discount.
23. **Migration 0025 CHECK validation can lock large tables** — split add/backfill/`NOT VALID`/`VALIDATE` (C).
24. **e-Factura views crash on failure** — `views.py:2181,2207` read `result.message`; `SubmissionResult`
    exposes `error_message` → 500 instead of the compliance error (D). Folded into Phase 0.
25. **Native codelist validation incomplete** — partial UNCL4461/VATEX sets rejecting valid codes (A).
26. **Line discount field emits an XML allowance but totals ignore it** — `xml_builder.py:875`
    `line.discount_amount_cents` → `AllowanceCharge`, but LineExtension/tax use the undiscounted subtotal (A).
27. **PDF bytes non-deterministic** — `canvas.Canvas` without `invariant=1` → timestamp drift (D).
28. **Dead legacy `EFacturaXMLGenerator`** — `efactura_service.py:165-503` (B + E). = #195 item.

## LOW / guards
29. **Proforma `clean()` omits `discount_cents` validation** unlike `Invoice.clean()` (C).
30. **Do NOT over-unify validator/PDF/XML** — keep the validator independent; share only narrow
    arithmetic primitives. Keep the single-category invariant unless multi-rate discounted invoices
    become a real requirement (E). A guard against churn-for-its-own-sake.

## Themes (the requested dimensions)
- **Bugs**: #1 (submission lifecycle, confirmed) and #2 (order vs proforma total) are the headline; plus
  registration-number and the PDF/XML divergences.
- **Idempotency** (dominant): #3-#10 — invoice/proforma creation, payment, refund, and e-Factura submit
  all need service-boundary idempotency guards (lock + return-existing + stable keys). Systemic, not isolated.
- **DRY**: one discount rule lives in 3 places (#22); two e-Factura stacks + dead emitter (#28); order-line
  emission duplicated (#45/B). Worth a single shared monetary-snapshot helper.
- **Simplify**: delete the dead emitter, route all submission through the model-backed stack, one
  discount-totals contract, email PDF → canonical renderer. NOT: collapsing the validator into the builder.
- **Elegance**: ignored `hours` param; `result.message` vs `error_message`.

## Suggested issue mapping
- #195 ← #11, #28 (already tracked). #196 ← #12 (already tracked).
- NEW issues worth filing: submission-lifecycle CRITICAL (#1); idempotency cluster (#3-#10, one umbrella);
  credit-note modeling (#13); registration-number population (#19); discount single-source-of-truth (#22);
  email PDF canonical renderer (#20). Order/proforma total divergence (#2) — verify first, then file if live.
