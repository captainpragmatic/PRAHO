# ADR-0015: Configuration Resolution Order (CRO)

**Status:** Accepted  
**Date:** 2026-02-12  
**Authors:** Development Team  
**Supersedes:** N/A  
**Related:** ADR-0005 (Single Constants File Architecture)

## Context

PRAHO currently uses multiple configuration mechanisms:

1. Code constants in `apps/common/constants.py`
2. Django settings and environment variables
3. Database-backed runtime settings (`SystemSetting`, `TaxRule`)
4. In-process cache for hot-path reads

This evolved organically and created drift in regulatory values (for example VAT), where multiple modules implemented separate fallback chains and defaults. The main failure mode was "three sources of truth" for VAT resolution.

At the same time, ADR-0005 correctly centralizes immutable cross-app constants. That decision should remain valid for values that do not need temporal validity, runtime edits, or auditable changes.

We need one platform-wide rule that defines:

1. Which values belong in constants vs dynamic configuration
2. A canonical read order for dynamic configuration
3. A requirement that each domain exposes one resolver path

## Decision

PRAHO adopts a platform-wide **Configuration Resolution Order (CRO)** for dynamic and regulatory configuration:

1. **Cache** (performance tier, shortest path, explicit invalidation)
2. **Database** (authoritative runtime tier, auditable, temporal where needed)
3. **Django settings / environment** (deployment tier)
4. **Code defaults** (safety tier)

For immutable values, we keep ADR-0005 as-is: use constants and do not route through DB.

### Tier Selection Rules

Use **constants only** when all are true:

1. Value is effectively immutable (protocol/RFC/legal format bounds)
2. No runtime edits are required
3. No temporal history is required

Examples:

1. IBAN/CUI length constraints
2. RFC limits
3. Static enum-like bounds

Use **settings -> defaults** (no DB runtime edits) when:

1. Value varies per deployment
2. Runtime admin edits are not required
3. Temporal history is not required

Examples:

1. Non-regulatory timeout defaults
2. Batch sizes
3. Endpoint base URLs

Use full **CRO (cache -> DB -> settings -> defaults)** when any of the following is true:

1. Regulatory value with legal effective dates
2. Admin-editable at runtime
3. Per-entity or per-country variation
4. Auditability/history is required

Examples:

1. VAT rates by country and validity window
2. Billing policy toggles with operational impact
3. Time-bounded legal/compliance parameters

## Architectural Rules

1. **One resolver per domain:** each domain must expose a single public resolver API (for example `TaxService.get_vat_rate`).
2. **No bypassing resolver:** business logic must not hardcode dynamic regulatory values.
3. **Temporal values live in DB models:** use `valid_from` / `valid_to` (or equivalent) for historical correctness.
4. **Cache is an implementation detail:** cache keys and TTL live inside the resolver, not scattered callers.
5. **Fallbacks are explicit:** resolver documents and tests the exact fallback order.

## Reference Implementations

1. **Tax domain:** `apps/common/tax_service.py` + `apps/billing/tax_models.py` (`TaxRule`)
2. **System settings:** `apps/settings/services.py` + `apps/settings/models.py` (`SystemSetting`)

## Migration Guidance

When introducing or changing a config value:

1. Classify it using Tier Selection Rules.
2. If CRO is required, implement/extend the domain resolver first.
3. Move callers to resolver usage before removing old constants/hardcoded values.
4. Add tests for:
   1. Fallback order behavior
   2. Temporal boundary behavior (if applicable)
   3. Guardrails against hardcoded reintroduction

## Consequences

### Positive

1. Eliminates multi-source drift for dynamic values
2. Keeps immutable constants simple and discoverable
3. Supports temporal/legal correctness and audits
4. Improves incident response via explicit fallback chain

### Trade-offs

1. CRO adds complexity compared to constants-only lookups
2. Cache invalidation discipline is required
3. Resolver ownership must be clear per domain

## Notes on ADR-0005 Compatibility

ADR-0005 remains valid for immutable cross-app constants. ADR-0015 adds a complementary rule for dynamic/regulatory settings that require runtime and temporal behavior.

## References

1. [Django Constance](https://django-constance.readthedocs.io/)
2. [The Twelve-Factor App - Config](https://12factor.net/config)
3. [Git Config Documentation](https://git-scm.com/docs/git-config)
