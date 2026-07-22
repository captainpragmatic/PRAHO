# ADR-0042: Settings Catalog, Three-Surface UI, and Consumer Contract

**Status:** Accepted
**Date:** 2026-07-22
**Authors:** Development Team
**Supersedes:** N/A
**Related:** ADR-0005 (constants), ADR-0015 (Configuration Resolution Order), ADR-0016 (audit coverage), ADR-0033 (vault-first credentials)

## Context

The runtime settings system accumulated 241 registered keys of which a full wiring
census proved only ~178 were consumed. Sixty-eight were "decoy settings": visible
and editable in the staff UI, connected to nothing (including `billing.vat_rate`,
whose truth lives in the temporal `TaxRule` table, and `system.maintenance_mode`,
whose only gate read an environment variable through a decorator with zero call
sites). Eight further keys — including the S3 backup credentials — were consumed
but never registered, silently resolving to `None`. Category metadata lived in a
`SettingCategory` table related to settings only by string equality, seeding was
spread across five management commands with duplicated metadata dictionaries, and
the edit surface re-posted decrypted secrets, could not un-check booleans, and
inverted the cache order mandated by ADR-0015.

## Decision

1. **The catalog is the single source of truth.** `apps/settings/catalog.py`
   declares every runtime setting: key, type, default, UI placement
   (zone → group → section), input kind, sensitivity, criticality, and validation
   rules. `SettingsService.DEFAULT_SETTINGS` derives from it; the model's
   `validation_rules` and `is_public` columns and the `SettingCategory` table are
   removed. `setup_default_settings` is an idempotent catalog sync that creates
   missing rows and reconciles catalog-owned metadata.

2. **A consumer contract makes decoys structurally impossible.** A shared
   tokenize-based scanner (`apps/settings/key_scan.py`) powers both
   `scripts/lint_settings_coverage.py` and
   `tests/settings/test_catalog_consumer_contract.py`: every catalog key must be
   consumed by production code or templates, and every key passed to a
   `SettingsService` read must be declared. String literals are extracted with
   `tokenize`, so a comment can never fake consumption. Exemptions require a
   written justification and are themselves validated.

3. **Three UI surfaces.** Business groups (staff-editable operator policy),
   Integrations (admin-only; write-only credentials with real test-connection
   actions and honest source-of-truth notes), and Platform (maintenance controls
   plus an explicitly quarantined Advanced Tuning group). Policy that already has
   a domain model (`PaymentRetryPolicy`, `InvoiceSequence`, `TaxRule`) is linked,
   never duplicated as scalar keys.

4. **Atomic change sets.** The UI posts only dirty keys with their `updated_at`
   baselines; the service validates everything, locks rows in deterministic key
   order, compares baselines under lock, and applies all-or-nothing with one
   change-set ID across the audit events. The response carries fresh baselines so
   consecutive edits never self-conflict. Sensitive keys are rejected — secrets
   move only through dedicated admin endpoints that never render values back.

5. **Maintenance mode is enforced, not decorative.** `MaintenanceModeMiddleware`
   returns a staff-exempt 503; the `MAINTENANCE_MODE` deployment setting
   overrides the runtime flag when set (ADR-0015 tier order).

## Compatibility

- Old exports referencing retired keys import as skipped-with-reason; this is the
  intended migration story.
- The admin-only full export remains the one documented surface that carries
  sensitive values, and only as ciphertext.
- The e-Factura namespace is catalog-declared; its resolver keeps the
  row-first → Django-settings → defaults chain by reading rows directly.

## Consequences

- Adding a setting means adding a catalog entry **and** a consumer, or CI fails.
- Retiring a setting is a catalog deletion plus a data migration deleting rows.
- The `advanced` group is a curated exception list, not a dumping ground: new
  engineering constants belong in deployment configuration unless they earn an
  entry with an owner and safe range.
