# Unified e-Factura / billing correctness plan — v2 (post dual-review REWORK)

v1 was REWORKed by BOTH codex and the internal code-reviewer (2 CRITICAL each, verified against code).
This v2 incorporates every CRITICAL/HIGH. Tax-compliance correctness is paramount; no overengineering.

## What the reviews changed
- **Phase A is a double-tax fix, not "just land #192."** `InvoiceService.create_from_order` (services.py:141-142)
  feeds `order.total_cents` (GROSS, tax-inclusive — orders/models.py:130) into
  `calculate_vat_for_document(subtotal_cents=…)`, which adds VAT again → header double-tax. PR #192 fixes
  only the `InvoiceLine` field-name crash below it (lines 168-176), unmasking the double-tax. VERIFIED.
- **Phase B shrinks; the "unify 4 emitters" spine is over-engineered.** The XML + PDF already reconcile via the
  `_get_document_discount = Σ line.subtotal_cents − invoice.subtotal_cents` invariant (xml_builder.py:313),
  which is legacy-safe. The meta allowances/charges path is DORMANT JSON; making `recalculate_totals`
  meta-aware is a LEDGER-INTEGRITY risk (codex HIGH). The only real bug is `recalculate_totals` ignoring
  `discount_cents`. So Phase B = fix that one bug + document the invariant; do NOT build a meta-aware spine.
- **Phase D moves EARLIER** (before B): e-Factura `PrepaidAmount` depends on `get_remaining_amount`
  (xml_builder.py:812). And the refund risk is broader than "double count": live refunds are created
  `status="pending"` with blank `gateway_refund_id`, and `get_remaining_amount` counts ONLY `completed` —
  so pending gateway refunds may be IGNORED for PrepaidAmount, while migration 0024 can dup/skip on
  blank-id same-amount rows. Must investigate prod + the completion path FIRST.

## Gross vs net contract (the invariant everything depends on — make it explicit, do not break it)
- `Order.subtotal_cents` = GROSS line extension (Σ line nets, before discount). `Order.total_cents` = GROSS
  final (subtotal − discount + tax). `calculate_document_totals(items, discount)` returns `subtotal_cents` =
  GROSS, discount applied only inside `total_cents` (financial_arithmetic.py:76).
- `Invoice/Proforma.subtotal_cents` = NET (gross − discount). The XML/PDF DERIVE the document discount as
  `Σ line.subtotal_cents − header.subtotal_cents`, which equals the stored `discount_cents` for new invoices
  AND bridges legacy ones with no backfill. **This invariant must be preserved by every change below.**

## Phases (sequenced A → D → B → C → E → F; all codeable now)

### Phase A — `create_from_order`: land the crash fix AND fix the double-tax — S/M, CRITICAL
1. Apply PR #192's `InvoiceLine` field fix (description/kind/quantity/unit_price_cents/tax_rate), co-authored.
2. **Fix the VAT base**: compute VAT on the NET taxable base like the proforma path
   (`taxable = order.subtotal_cents − order.discount_cents`, proforma_service.py:176), NOT `order.total_cents`.
   Carry `discount_cents=order.discount_cents` onto the invoice. (Or copy the order's already-correct
   subtotal/tax/total — decide during impl.)
3. TDD: assert invoice.subtotal/tax/total **equal the source order's** (no double-tax) AND lines reconcile
   (Σ line.subtotal_cents − invoice.subtotal_cents == discount). Pins the contract before Phase B refactors.

### Phase D — refund / PrepaidAmount correctness (move early; feeds e-Factura) — M, HIGH
1. **Investigate first** (do not assume): grep the WHOLE repo for any live path that sets a `Refund` to
   `status="completed"` (`.complete()` / `status="completed"`). `get_remaining_amount` (invoice_models.py:354)
   counts only `completed`; live `_create_refund_record` creates `pending` with blank `gateway_refund_id`.
   Run a prod-shape check: blank-`gateway_refund_id` same-amount refunds per invoice (dup risk) and
   pending-refund coverage. Establish which failure is LIVE (pending ignored vs migration dup vs dedup skip).
2. Fix what's proven live: (a) populate `gateway_refund_id` on live refund creation (refund_service.py:763,
   source at :1261); (b) ensure `get_remaining_amount` reflects the right refund states; (c) harden 0024-style
   dedup. Regression test on `get_remaining_amount` → XML `PrepaidAmount`/`PayableAmount`.

### Phase B — `recalculate_totals` discount-aware + document the invariant — S, HIGH
1. invoice_models.py:324 + proforma_models.py:213: pass the stored discount →
   `calculate_document_totals(list(self.lines.all()), self.discount_cents)` so `subtotal_cents` stays NET and
   `total_cents = net + tax`. Do NOT make it meta-aware (dormant JSON; ledger-integrity risk).
2. Name the reachable caller that runs `recalculate_totals` on a discounted doc (the primary create paths
   deliberately skip it — proforma_service.py:249). If none, mark it a latent guard + assert it's never
   called on a discounted issued invoice (the freeze already blocks mutation).
3. Add a module docstring stating the gross/net contract + the `gross − net == discount` invariant.
4. Credit-note: the LIVE document-discount path is already correct (`line_gross − _get_document_discount`).
   Leave the dormant meta parity alone (both reviews: don't expand dormant paths).

### Phase C — working-days submission deadline (#123 Gap 6, OUG 89/2025, in force) — M, HIGH
1. New `apps/billing/efactura/working_days.py::add_working_days(d, n)` using `holidays.Romania` (add the dep).
   Convert `issued_at` to **Romania local date** before arithmetic; load holidays across the year boundary
   (`years=[d.year, d.year+1]`) so a December issue sees January holidays.
2. Wire ALL THREE calendar-day sites: `efactura/models.py:411 submission_deadline` (PRIMARY),
   `efactura/service.py:366` (deadline query window), `efactura/settings.py:745`; update the setting label at
   settings.py:606 ("calendar" → "working"). Tests pinning 2026 RO holidays (Orthodox Easter, Pentecost, fixed).

### Phase E — dead-code + test hardening (#195) — M, MEDIUM
1. Delete the dead `EFacturaXMLGenerator` helpers in **apps/billing/efactura_service.py:165-503** + 2 orphaned
   dataclasses + dead test classes. KEEP `generate_invoice_xml` (delegates; `EFacturaSubmissionService` uses it).
   HAZARD: 5 names (`_add_supplier_party`, `_add_customer_party`, `_add_payment_means`, `_add_payment_terms`,
   `_add_invoice_lines`) also exist LIVE in `efactura/xml_builder.py` — delete ONLY the efactura_service.py copies.
2. Strengthen the setup-fee + discount reconciliation lifecycle test (sum line subtotals + proforma totals +
   XML LineExtension/AllowanceTotal reconcile). Harden the immutability test: it's a regression GUARD (behaviour
   already holds) — must CHANGE the value (e.g. discount 500→600 on a locked invoice) so it isn't a no-op.

### Phase F — ANAF response/endpoint fixes 1/3/4 (user-requested; unit-testable) — M
Codeable + UNIT-testable against documented ANAF formats (the LIVE integration still needs a sandbox account):
- Gap 1: `UploadResponse.from_response()` parse XML (lxml), extract `index_incarcare` from `<header>`,
  `ExecutionStatus="0"`=success. Test against a sample ANAF XML response fixture.
- Gap 3: `upload_b2c()` → POST `/uploadb2c?standard=UBL&cif={CUI}`; wire from the B2C detector. Mocked-HTTP test.
- Gap 4: `/listaMesaje` → `/listaMesajeFactura` (+ paginated variant). Mocked-HTTP test.
- Gaps 2/7/8 stay deferred (genuinely need a sandbox to determine content-types / standard names).

## Deferred (justified)
- Full Saxon Schematron (native partial validator already covers BR-CO/S/Z/CL); add saxonche at ANAF go-live.
- #103 currency infra (separate program).

## Process
- Each phase = its own TDD'd, dual-reviewed, PR-sized commit; `make lint`/`check-types`/billing-suite gates;
  lint every changed file incl. tests. Verify every agent CLAIM against code before acting (this rework proved why).
