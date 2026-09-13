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
`legacy_unknown` row requires explicit promotion. The fetcher writes a whole publication
in **one transaction**: a mid-batch failure (a conflict, or a rate that clears the gateway
but trips the model's precision validators) rolls back every currency and alerts — the feed
is never half-applied, and no write failure escapes silently.

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

- **Admission + snapshot-carry shrink the stuck-money window; they do not eliminate it, and
  the residual is handled operationally.** Admission (before charge) blocks the common case:
  no non-RON charge is taken unless a rate resolves. Snapshot-carry freezes FX at the
  reversible conversion moment and `issue()` consumes it, so a later row cannot flip an
  issued invoice's VAT. What is **not** closed: if a charge settles and then — before
  conversion — an *unprovenanced* row appears in the `(admission, conversion]` window
  (an abnormal data condition; the fetcher only writes provenanced rows), `resolve()` flips
  to raise and conversion fails. That failure is **loud and recoverable, not silent loss**:
  the succeeded `Payment` is committed, the proforma stays convertible, the conversion
  webhook logs `critical` and returns non-2xx so Stripe retries (~3 days), and
  ingesting/promoting a resolvable rate lets a retry (or manual re-trigger) convert
  idempotently. A purpose-built auto-refund / operator-clear workflow is **deferred**;
  today's recovery path is rate ingestion + Stripe reconciliation. The recurring
  crash-recovery replay (which can create the *first* real charge) is guarded by the same
  admission check and fails closed for retry rather than charging an un-issuable document.
- **Deferred (documented residual):** the verified-receipt tax-point refinement for
  advances (§35(2) — freezing at the payment-receipt date) requires a verified-settlement
  timestamp carrier that does not yet exist; `Payment.received_at` (reservation-time) must
  not be used. Until then `tax_point_date` defaults to the issue date (correct for the
  common same-day case); `freeze_fx_snapshot` accepts an explicit date so the carrier can
  plug in later.
- **Freshness is computed live** (resolver-accurate) on every status refresh — not a
  separately-cached, invalidation-driven value. The 48h status cache is the dashboard's
  display glance; the alerting path (daily task) recomputes live, so date-sensitivity and a
  same-day rollover are honoured within one daily cycle. A failed daily fetch is recorded
  (`record_fx_fetch_outcome`) and surfaced as AMBER even while last-good rates are still
  fresh, so an ingestion outage is visible independently of rate age — and of whether the
  alert email was delivered.
- **Staleness is a calendar-day age** (`billing.fx.stale_after_days`, default 4), not a
  publication-weekday count: a Friday rate is 3 calendar days old on Monday and 4 on a
  Tuesday-after-holiday, so 4 covers a normal long weekend. It is a heuristic on an
  alert-only signal and deliberately does not consult the holiday calendar.
- **Documentation authority for `as_of`:** this ADR + ADR-0041 + the
  `ExchangeRateService.resolve` docstring. `FXRate.as_of`'s model `help_text` still reads
  "next banking day"; it is knowingly left stale to avoid a no-op schema migration and is
  not authoritative.
