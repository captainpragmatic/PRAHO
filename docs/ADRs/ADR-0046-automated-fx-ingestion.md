# ADR-0046: Automated FX Ingestion, Freshness Surface, and Currency Admission

- **Status:** Accepted
- **Date:** 2026-09-14
- **Supersedes/extends:** [ADR-0041](ADR-0041-foreign-currency-efactura-accounting.md) (foreign-currency e-Factura accounting)
- **Related:** [ADR-0025](ADR-0025-money-as-integer-cents.md) (money as integer cents), [ADR-0042](ADR-0042-settings-catalog-and-consumer-contract.md) (settings consumer contract), [ADR-0045](ADR-0045-committed-side-effect-boundaries.md) (committed side-effect boundaries), [ADR-0015](ADR-0015-configuration-resolution-order.md)

## Context

ADR-0041 established that foreign-currency invoices freeze a provenanced BNR/ECB/BANK
rate and derive the RON VAT total from it, but left rate provisioning entirely manual
(`record_exchange_rate`, no network). Issue #103 asked for the operational layer:
automated ingestion, safe currency selection, and visibility. The work surfaced two
facts that shape this ADR:

1. `ExchangeRateService.resolve` is **non-monotonic** — it selects the single latest
   `(as_of, pk)` row and *raises* if that row is unprovenanced, with no fallback. Combined
   with an external (irreversible) card charge preceding invoice issuance, a rate row
   inserted after admission could strand a payment as an un-issuable invoice.
2. `Payment.received_at` is reservation-time, not verified-settlement time. No verified
   receipt-date carrier exists.

## Decision

**Rate-validity date (`as_of`).** A BNR rate communicated on day *D* applies from *D + 1
CALENDAR day* and continues until the next publication (Cod Fiscal art. 290(2) + Norme
metodologice pct. 35: "*ultimul curs … comunicat … în ziua anterioară … valabil pentru
operaţiunile … în ziua următoare*"). Formally the applicable rate for a tax point *T* is
the last publication strictly before *T*. We store `as_of = publication_date + 1 calendar
day` and keep the resolver's `as_of <= effective_date` selection (equivalent). We do **not**
use a banking-day/holiday calendar to compute `as_of` (weekends/holidays are simply absent
from the publication set) and do **not** compute `tax_point − 1`.

**Source & failover.** BNR is the primary automated source (`curs.bnr.ro/nbrfxrates.xml`).
ECB/BANK remain manual provenance options; the fetcher never auto-switches source (that
would silently change the statutory rate). On any fetch/parse failure the gateway writes
nothing — last-good rates are retained — and staff are alerted.

**Ingestion immutability.** One shared `record_fx_rate()` writer (used by the manual
command and the fetcher) is the single enforcement point: exact replay is a no-op; any
differing rate/provenance is a hard conflict, never an overwrite; a same-amount
`legacy_unknown` row requires explicit promotion.

**Admission (fail-closed).** A non-RON billable document may only be created when a
provenanced rate resolves for it (`assert_currency_issuable`), enforced at every
money-taking path (staff/order proforma, subscription, recurring, pre-collection, order
checkout). `BILLING_DEFAULT_CURRENCY` is validated by a system check.

**Snapshot-carry.** FX is frozen once at the reversible conversion moment and *consumed*
by `invoice.issue()` (which no longer re-resolves when a snapshot is present), so a later
row cannot flip an issued invoice's RON VAT.

**Staleness policy: alert-only.** A stale-but-usable rate does not block issuance; a
missing/unprovenanced rate already does (unchanged). The freshness subsystem surfaces
GREEN/AMBER/RED live (resolver-accurate) and the daily task alerts on AMBER/RED.

**Feature-flagged.** The automated fetcher is off by default (`billing.fx.bnr_fetch_enabled`);
the manual command stays authoritative until an operator enables it.

## Consequences

- The stuck-money window between an external charge and issuance is closed by admission
  (before charge) + snapshot-carry (consume at issue), not by re-resolution.
- **Deferred (documented residual):** the verified-receipt tax-point refinement for
  advances (§35(2) — freezing at the payment-receipt date) requires a verified-settlement
  timestamp carrier that does not yet exist; `Payment.received_at` (reservation-time) must
  not be used. Until then `tax_point_date` defaults to the issue date (correct for the
  common same-day case); `freeze_fx_snapshot` accepts an explicit date so the carrier can
  plug in later.
- The dashboard freshness reflects the last refresh (daily + on manual record/promote);
  failed fetches alert immediately regardless.
