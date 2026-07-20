# e-Factura go-live hardening — staged implementation plan

**Umbrella issues:** #103, #123, #195, #351, #352
**Current branch / PR A:** `agent/103-efactura-go-live`
**Base:** `origin/master` at `55ca2608`
**Method:** TDD; every behavior change starts with a focused failing test

## Outcome and review boundary

The original #103 proposal is partly stale, and “all e-Factura” is not one rollback domain. An
independent adversarial review found four coupled but independently risky systems: invoice FX
accounting, remote-submission recovery, legal-response storage, and fiscal credit-note modelling.
Combining them would exceed the repository's review-size guidance and make a safe rollback
impossible.

The work is therefore sequenced:

1. **PR A — this branch:** FX provenance and immutable invoice snapshot; invoice-only BT-6/BT-111;
   order-insensitive native validation; mandatory pre-upload native validation.
2. **PR B — #351:** short-lived submission claims, immutable XML bytes/hash, and an explicit
   `outcome_unknown` reconciliation state. No database lock across ANAF I/O.
3. **PR C — #352 + remaining #123 harness work:** raw ANAF ZIP archival, integrity verification,
   and one credential-ready live smoke path.
4. **Separate domain design:** the refund/credit-note defect noted by #219 needs a real immutable
   fiscal-correction ledger. The current one-document-per-invoice model cannot represent it.

This plan describes all stages so dependencies stay explicit. Only PR A is implemented on this
branch.

## Verified contracts and corrected assumptions

- Romanian Fiscal Code article 290(2) requires the latest BNR, ECB, or settlement-bank rate valid
  on the VAT exigibility date.
- FX pair direction is `1 base currency = rate quote currency`; e.g.
  `EUR/RON = 5.09790000`.
- CIUS-RO BR-RO-030 requires `TaxCurrencyCode=RON` (BT-6) when invoice currency is not RON.
- EN16931 BR-53/R053/R054 requires one document-currency `TaxTotal` with subtotals and one
  accounting-currency `TaxTotal` without subtotals.
- Peppol UBL-CR-490 says not to emit `cac:TaxExchangeRate`. PRAHO retains the rate in its invoice
  audit snapshot and uses it to calculate BT-111.
- The current native validator is a deliberately partial EN16931/CIUS-RO business-rule validator.
  The repository does not contain official XSD/Schematron artifacts. This PR makes that partial
  validation mandatory but does not mislabel it as complete ANAF validation.
- ANAF `/descarcare` returns a ZIP, not a PDF; that correction belongs to PR C.

## Issue reconciliation

- **#103:** current PR implements the remaining e-Factura FX slice. Broad product currency UX,
  notification/portal formatting, BNR automation, and hardcoded-RON cleanup remain separate phases.
- **#123:** most code gaps are merged. PR A removes the native-validation bypass. PR C repairs the
  broken credential harness; Content-Type, standard name, and OAuth behavior remain unverified
  until a real sandbox run.
- **#195:** merged work already removed the duplicate builder and strengthened tests. PR A adds the
  directly related multi-currency native checks. Discount arithmetic remains #203; Saxon/
  Schematron remains a separate dependency and supply-chain decision.
- **#298:** already fixed by the settings migration and lock-in tests; closed with evidence.
- **#351/#352:** real defects, but deliberately assigned to PR B/PR C after plan review.

## PR A, Task 1 — Record an honest FX data contract

**Files**

- Create `docs/ADRs/ADR-0041-foreign-currency-efactura-accounting.md`.
- Update `docs/ADRs/README.md`.
- Modify `services/platform/apps/billing/currency_models.py`.
- Create `services/platform/apps/billing/migrations/0038_fxrate_provenance_and_constraints.py`.
- Extend `services/platform/tests/billing/test_billing_models_regressions.py`.

**RED tests**

- Zero/negative rates and self pairs violate database constraints.
- A valid `EUR/RON` row stores direction, effective date, source, source reference, and fetch time.
- Existing rows migrate as `legacy_unknown` with nullable provenance; no migration invents a BNR
  source or fetch timestamp.

**Implementation**

- Add a minimum-value validator plus positive-rate and base-not-quote constraints.
- Add an explicit source choice, source reference, and nullable `fetched_at`.
- Define legacy rows honestly. New issuance may not consume `legacy_unknown` rows.

**Verify**

- `make test-file FILE=tests.billing.test_billing_models_regressions`
- Migration executor test for legacy provenance.
- `manage.py makemigrations --check --dry-run --settings=config.settings.test`

## PR A, Task 2 — Provide audited manual rate ingestion and lookup

Automatic BNR networking is deferred, but foreign-currency invoicing must have a supported
provisioning path. PR A therefore includes a narrow management command for an operator to record a
published rate with its source reference.

**Files**

- Create `services/platform/apps/billing/exchange_rate_service.py`.
- Create `services/platform/apps/billing/management/commands/record_exchange_rate.py`.
- Create `services/platform/tests/billing/test_exchange_rate_service.py`.
- Create `services/platform/tests/billing/test_record_exchange_rate_command.py`.

**RED tests**

- Lookup selects the latest exact-direction row with `as_of <= effective_date`.
- Saturday/holiday lookup resolves the last published row; reversed pairs are never auto-inverted.
- Missing, non-positive, or legacy-unprovenanced data fails with a typed operator-readable error.
- More than three Romanian working days without a publication logs an operational warning but does
  not reject a legally valid last-published rate.
- Conversion uses `Decimal` and `ROUND_HALF_UP` at exact midpoint boundaries.
- The command requires source/reference/date, creates once, audits the actor/context, and refuses to
  overwrite conflicting historical values.

**Implementation**

- Add immutable `ExchangeRateSnapshot`, typed lookup errors, exact-direction lookup, conversion,
  and Romanian-working-day staleness warning.
- Keep all network I/O out of issuance. Document a future BNR/Django-Q2 importer as the next #103
  operational phase.

**Verify**

- Focused service and command test modules.

## PR A, Task 3 — Freeze the VAT tax point and FX snapshot on invoices

**Files**

- Modify `services/platform/apps/billing/invoice_models.py`.
- Create `services/platform/apps/billing/migrations/0039_invoice_tax_point_and_fx_snapshot.py`.
- Modify production issuance seams in:
  - `services/platform/apps/billing/services.py`
  - `services/platform/apps/billing/usage_invoice_service.py`
- Extend invoice, proforma-conversion, and usage-invoice tests.

**Rules**

- Add nullable immutable `tax_point_date`. Current PRAHO invoice paths set it to the Romanian local
  issue date because invoice creation/issuance is the supported tax-exigibility event.
- A caller with a legally distinct tax point must set it explicitly; UBL emits BT-7 only when it
  differs from issue date. Advances/corrections that need richer semantics are not silently guessed.
- Add immutable rate, rate date, source, and source reference to the invoice snapshot.
- Existing locked non-RON invoices are not backfilled from guessed data; e-Factura generation
  quarantines/fails them until trustworthy provenance is supplied through a controlled correction.
- `Invoice.issue()` is the enforcement boundary: non-RON issuance without a complete, provenanced
  snapshot raises before the state transition.

**RED tests**

- RON issuance sets tax point and needs no FX snapshot.
- EUR issuance resolves by tax point, snapshots once, then locks currency/tax point/all FX fields.
- Normal save and `update_fields` cannot mutate the locked snapshot.
- Existing locked foreign invoices without proof cannot generate e-Factura XML.
- `ProformaConversionService.convert_to_invoice`, fixed usage issuance, and rated usage issuance
  all pass through the same preparation boundary.
- `InvoiceService.create_from_order` remains draft-only and does not snapshot prematurely.

**Verify**

- Focused exchange-rate, invoice-model, proforma-conversion, and usage-invoice modules.

## PR A, Task 4 — Emit invoice-only BT-6 and BT-111

**Files**

- Modify `services/platform/apps/billing/efactura/xml_builder.py`.
- Extend `services/platform/tests/billing/efactura/test_xml_builder.py`.

**RED tests**

- RON invoices omit BT-6 and have one RON `TaxTotal` with subtotals.
- EUR invoices emit `TaxCurrencyCode=RON`.
- A EUR invoice has exactly one document-currency total with subtotals and one RON total without.
- BT-111 is document VAT multiplied by the immutable rate and rounded to two decimals.
- Zero VAT preserves zero/sign semantics; incomplete or non-positive snapshots fail.
- No `TaxExchangeRate` appears.
- BT-7 appears only when tax point differs from issue date.

Credit-note assertions are intentionally absent: the only current refund path uses the original
invoice as its own correction and conflicts with the one-document constraint. Builder-only parity
would falsely imply production support.

**Verify**

- `make test-file FILE=tests.billing.efactura.test_xml_builder`

## PR A, Task 5 — Make partial native validation multi-currency aware and mandatory

**Files**

- Modify `services/platform/apps/billing/efactura/validator.py`.
- Modify `services/platform/apps/billing/efactura/service.py`.
- Extend `test_validator.py` and `test_service.py`.

**RED tests**

- Reject non-RON XML with missing/wrong BT-6; missing/duplicate accounting or document totals;
  subtotals under the RON total; wrong currency IDs; opposite signs; or over-precision BT-111.
- Accept swapped `TaxTotal` order by selecting totals by currency and subtotal shape.
- Reject RON XML that incorrectly supplies BT-6/accounting total.
- Every normal submission path validates without opt-in; invalid XML never calls any upload method.
- Local validation failure is a non-retryable local result, not a network error scheduled for
  automatic replay.
- Update all callers/tests when removing `validate_first`.

**Implementation**

- Add native checks for BR-RO-030, BR-53, R051, R053, R054, R055, and BR-DEC-15.
- Remove the validation bypass and validate before the first client call.
- Keep the contract name honest: “native business-rule validation,” not complete XSD/Schematron.

**Verify**

- Focused validator/service/task/view tests.
- Entire e-Factura package.

## PR B — Submission claim, ambiguous outcome, and immutable XML (#351)

Design before code:

- Replace whole-method `transaction.atomic` with a short claim transaction.
- Add explicit claim token/time/lease and `uploading` plus `outcome_unknown` FSM states.
- Commit the claim before network I/O; finalize in a second short locked transaction.
- A timeout/connection loss after request transmission becomes `outcome_unknown`, never automatic
  retry. Reconcile through ANAF messages before deciding whether a POST is safe.
- Generate XML once, hash it atomically whenever content changes, freeze bytes/hash at claim time,
  and reuse byte-identical XML for every safe retry.
- Use PostgreSQL `TransactionTestCase` concurrency tests. Ordinary `TestCase` mocks are
  insufficient proof.

## PR C — Truthful response archive and live harness (#352, #123)

Design before code:

- Rename the misleading PDF field for new writes while acknowledging legacy paths remain under
  `efactura/pdf/`; keep legacy hash nullable/unverified unless a controlled verification command
  proves the stored bytes.
- Validate ZIPs in memory with path/member/size limits and no filesystem extraction.
- Distinguish accepted invoice archives from error/rejection archives; do not require one structure
  for both.
- Prove duplicate download idempotency, storage-write failure behavior, byte identity, and SHA-256.
- Replace the stale hand-written 2024/19% sandbox XML with canonical builder output; use `cif`, the
  production safe-request client, and one explicit `EFACTURA_LIVE_SMOKE` gate.
- Live upload failure is a test failure, not a skip. Do not claim Gaps 2/7/8 verified without
  credentials and a successful real round trip.

## PR A completion proof

1. Review the full `origin/master...HEAD` diff and every changed caller.
2. Run all focused RED/GREEN tests above.
3. `make test-file FILE=tests.billing.efactura`
4. `make lint`
5. `make test`
6. `make lint-security`
7. `make lint-credentials`
8. Migration consistency and Django deploy checks.
9. Independent deep review of the branch and bidirectional tests.
10. Commit with DCO from the first commit (`git commit -s`) and verify `Signed-off-by:` before push.

## Explicit non-claims

PR A does not make all e-Factura production-ready. Automatic BNR ingestion, fiscal credit-note
modelling, exact-once remote recovery, raw legal-response storage, official Schematron execution,
and credential-backed ANAF verification remain explicit work. The implemented invoice path fails
closed rather than pretending those capabilities exist.
