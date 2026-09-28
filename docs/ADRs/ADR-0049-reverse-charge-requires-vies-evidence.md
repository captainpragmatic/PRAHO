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

One evidence function checks VIES status and the exact normalized VAT number.
The addendum below defines its age, reference, name and refusal-audit requirements.
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
During an outage, valid evidence verified within `billing.vies_outage_grace_days`
(default 14, capped below the evidence lifetime) is retained, and an existing valid cache row is extended by 24 hours.
Outside that grace window, unavailable VIES produces format-only status.

## Consequences

EU customers without evidence pay destination VAT until confirmed.
Unpaid pre-existing zero-tax orders fail preflight and must be re-created.
The validation command can backfill evidence and report affected unpaid orders.

## Addendum: evidence age, identity and exemptions

Entitlement requires an exact number, valid status, a verification timestamp no
older than `billing.vies_evidence_max_age_days` (30 days), and a consultation
reference and matching legal name when their respective policies are enabled
(both default to enabled). Refusals write audit rows with reason, customer and
VAT number, at most once per hour for an identical refusal. Staff can inspect
refusals on the tax page.

Names use Unicode decomposition and case folding, remove punctuation, legal
forms and generic words, and require the invoiced distinctive tokens to be a
subset of the VIES tokens. Empty or withheld names are unavailable evidence and
do not block. Order billing names take precedence over the current customer
name. Correct the legal name and re-run validation to resolve a mismatch; both
operations are audited. There is no per-customer name override.

The 24-hour cache expiry is a recheck date. Entitlement and version-2 reporting
use verification age, with the configured lifetime frozen in each new snapshot.
The outage grace setting is `billing.vies_outage_grace_days` (14 days), capped
strictly below that lifetime. Grace extends only the recheck date. A new
response replaces its reference, including an empty reference; grace preserves
the entire previous proof. A valid response without a required reference
produces format-only status.

Version 2 has the same required fields as version 1, with optional
`evidence_max_age_days` (30 when absent). It records that consultation-reference
policy was enforceable when written. Version-1 supplies keep their historical
missing-reference treatment. Run `validate_vat_numbers --blocked-orders` before
rollout to identify missing timestamps/references and name mismatches.

Zero overrides for EU cross-border VAT payers need evidence or an explicit
exemption reason (`diplomatic`, `exempt_body`, `other`). Refused overrides fall
through to normal taxation and leave a calculation note. Other zero overrides
retain their existing meaning. Staff rate fields accept only 0 through 100.

## Related

- #389 Phase 2.
- [ADR-0047](ADR-0047-jurisdiction-tax-policy.md): this boolean is the interim
  expression of the evidence-policy input. The True code fallback is fail-safe,
  not a fiscal position.
