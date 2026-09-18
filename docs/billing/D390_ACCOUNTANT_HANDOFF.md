# D390 accountant handoff

**Services-only draft for accountant review.** Open **Billing → Reports → D390 review** (`/billing/reports/d390/`). The existing billing-role permission applies to preview and both downloads. This ledger belongs to the operating entity configured for invoice issuance; customer companies are counterparties, not separate declarants.

Browser examples with synthetic invoices: [monthly partner preview](images/d390-preview.png) and [blocked XML with reconciliation CSV available](images/d390-exceptions.png).

## Supported review

This feature covers outgoing intra-Community service/setup supplies with a recorded reverse-charge decision and matching invoice evidence, operation **P**, in a calendar month selected by `Invoice.tax_point_date`. The default is the previous month in Europe/Bucharest. ANAF's instructions describe monthly exigibility-based service reporting grouped by customer. Whether the operator must file, its registration/entitlement and the final filing remain for accountant confirmation. [Official instructions, annex 2](https://static.anaf.ro/static/10/Anaf/legislatie/OPANAF_705_2020.pdf).

1. Choose the month and inspect the candidate/included/exception counts. Open the contributing invoices and review partner identities and recorded VIES consultation references. Missing tax-point dates appear in every month as unallocated exceptions; creation time is never silently substituted.
2. Download reconciliation CSV, including when XML is blocked. It contains invoice/line IDs, tax points, original currencies, gross bases, allocated discounts, frozen RON rates, partner totals, rounding differences and structured exceptions. VAT bodies have an apostrophe prefix to preserve leading zeros when opened in spreadsheets; potentially active spreadsheet expressions are escaped.
3. Reconcile the CSV to the books. Each candidate line occurs exactly once as an included contribution or a line exception. Document-only exceptions identify candidate invoices with no lines. Partner-total CSV rows are summaries and must not be added to the contributing-line rows.
4. Check the supplier's existing invoice settings: `COMPANY_NAME`, `EFACTURA_COMPANY_CUI`, `COMPANY_STREET`, `COMPANY_CITY`, `COMPANY_POSTAL_CODE`, `COMPANY_COUNTRY_CODE=RO`. Enter declarant surname, given name and role. XML validates field lengths, supplier CUI and the pinned annex's character set; unsupported characters produce errors without silent transliteration.
5. If reconciliation has no blockers, download the draft XML. Refresh the preview if the source fingerprint changed. Both downloads record actor, period, source SHA-256 and export SHA-256 in `AuditEvent` (`d390_export`). Retain the files with the accountant's review and eventual filing receipt.

There is no XML declaration for an empty period. A fresh export is another initial draft (`d_rec=0`), not evidence that a declaration was filed or permission to file the same period twice. The application has no filing registry or ANAF submission path for D390.

## Evidence and arithmetic

Order → proforma → invoice, direct-order invoices, recurring proformas and usage invoices record a versioned VAT snapshot. It includes the calculation scenario, country, business/VAT identity, rate, amounts and calculation time. Available cached validation results, dates, expiry and consultation references are copied into that snapshot. Proforma conversion copies evidence and agreed amounts without calling the tax engine again. PDF and e-Factura rendering share the explicit category helper for new documents; legacy presentation remains compatible.

The migration gives historical/manual records an empty snapshot. Zero tax, current customer settings and a fresh VIES check cannot establish a historical decision. The report does not invent evidence or expose an override to bypass exceptions. Fiscal fields and line amounts/categories are frozen at issuance, including ORM bulk-write guards. Application code should assemble lines before issuing a document; privileged direct SQL remains outside these application guards.

Eligible lines require explicit `AE`, a zero rate/tax, matching EU country and VAT identity, a valid local VAT checksum and supported service/setup kind. Greece's geographic `GR` and VAT prefix `EL` normalize to `EL`; VAT bodies retain leading zeros. Northern Ireland's goods treatment never qualifies services. Missing VIES proof is displayed as `not_recorded`, not a new entitlement decision. Captured negative, mismatched or expired-at-calculation proof requires review. No current VIES, FX or ANAF request occurs during report generation; reverse-charge entitlement policy stays under #389.

Gross line bases less the recorded document discount must equal the invoice's net subtotal; subtotal plus tax must equal the payable total. A discount over homogeneous supported service lines is allocated once in cents proportionally, with largest remainders resolved by line ID. Mixed-category discounts, metadata allowances/charges and line-level discounts are blocked. Foreign currencies use the frozen rate with date/source/reference. Converted decimal RON bases are summed first, then each partner total is rounded to whole lei with `ROUND_HALF_UP`. The report exposes `rounded − unrounded` per partner and overall.

## Exceptions and deferred corrections

Unpaid and overdue supplies remain candidates. A later refund or void does not silently remove a supply or subtract money from its tax base. Invoice/payment/source-order refund records and unresolved legacy invoice/source-order refund metadata block the affected XML until fiscal review; payment refunds are not fiscal credit notes. Refund events recorded in the selected month against an older supply are also shown as document exceptions, without assigning the refund a tax point or netting its amount. CSV remains available.

Goods, acquisitions, stock transfers, fiscal credit-note accounting, rectificative declarations and live filing are deferred. ANAF distinguishes adjustments declared when their tax becomes exigible (the month the regularization is communicated to the customer) from correcting errors in an earlier declaration, which requires a rectificative declaration for that period. Do not automatically move every credit/refund to the original supply month or put earlier reporting errors into a current-period adjustment. [Official instructions, annex 2, section I](https://static.anaf.ro/static/10/Anaf/legislatie/OPANAF_705_2020.pdf).

Review unresolved historical exceptions outside this export. Any later evidence/correction workflow must preserve original invoice facts, distinguish these two correction cases, and record its accountant-approved basis.

## Local XML validation

The renderer uses `mfp:anaf:dgti:d390:declaratie:v3`, separate issuing-country/VAT-body fields, one P row per partner and calculated summary/control totals. The original ANAF schema and validation annex are pinned with source URLs and SHA-256 hashes. See [schema provenance and the single compatibility adjustment](../../services/platform/apps/billing/d390_schema/README.md). Passing these local checks does not establish later ANAF acceptance; import, assistance-software validation and filing receipt belong to the accountant handoff.
