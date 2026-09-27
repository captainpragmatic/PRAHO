# ADR-0049: Reverse Charge Requires VIES Evidence

**Status:** Accepted
**Date:** 2026-09-27

## Context

EU reverse charge could be granted from customer-controlled VAT-payer and
eligibility fields without a successful VIES check.
Changing a VAT number could retain an earlier number's valid status.
A delayed validation could also persist evidence after the profile number changed.
Nightly revalidation during a VIES outage could revoke recent valid evidence.
The legacy amount calculator carried a second, profile-blind reverse-charge rule.

## Decision

One pure evidence function checks VIES status and the exact normalized VAT number.
A valid profile only supplies evidence for its own non-empty number.
Evidence also requires the VAT number's issuing country to match the billing country used for the decision.
Normalisation is aligned with the revalidation sweep so accepted evidence can always be refreshed.
Every document context derives its evidence through this function.
The tax decision ignores the legacy reverse-charge eligibility flag.
The policy setting `billing.reverse_charge_requires_vies` defaults to on.
Disabling it restores number-only eligibility for EU cross-border VAT payers.
The profile-blind calculator delegates to the scenario resolver without audit writes.
Customer API and staff form inputs cannot set the derived eligibility flag.

VAT-number changes clear prior evidence before validation is queued.
Validation locks and rereads the profile before persisting any result.
Results for a different current number are discarded.
During an outage, valid evidence verified within `VIES_OUTAGE_GRACE_DAYS`
(default 14) is retained, and an existing valid cache row is extended by 24 hours.
Outside that grace window, unavailable VIES produces format-only status.

## Consequences

EU customers without evidence pay destination VAT until confirmed.
Unpaid pre-existing zero-tax orders fail preflight and must be re-created.
The validation command can backfill evidence and report affected unpaid orders.

## Related

- #389 Phase 2.
- [ADR-0047](ADR-0047-jurisdiction-tax-policy.md): this boolean is the interim
  expression of the evidence-policy input. The True code fallback is fail-safe,
  not a fiscal position.
