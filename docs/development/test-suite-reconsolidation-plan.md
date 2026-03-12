# Test Suite Re-Consolidation Plan

## Current branch inventory

- Local branches discovered: `work`
- Remote branches discovered: _none configured in this clone_ (`git remote -v` empty, no `refs/remotes/*`).
- Result: cross-branch comparison is currently blocked in this environment; only `work` history is auditable here.

## Findings from current tree

### 1) Root integration split (`tests/integration` vs `tests/integration_tests`)

Both directories currently contain 6 files each and overlap in intent (integration-level behavior):

- `tests/integration`: infra/system integration and tooling checks.
- `tests/integration_tests`: mostly API/business integration against Platform internals.

**Consequence:** discoverability is poor because suite intent is split by historic naming, not by taxonomy.

### 2) Random/temporary-style naming in service-level tests

A focused naming scan identified files that look like temporary bundles (`*_fixes`, `*_todos`, `*_misc_coverage`, `*_remaining_*`, `*_round2`).

Examples:

- `services/platform/tests/billing/test_billing_27_todos.py`
- `services/platform/tests/billing/test_billing_codex_fixes.py`
- `services/platform/tests/billing/test_billing_misc_coverage.py`
- `services/platform/tests/orders/test_idempotency_fixes.py`
- `services/portal/tests/orders/test_remaining_fixes.py`

These names are weak at signaling domain behavior and are likely to become catch-all files.

### 3) Duplication signals

A repository-wide audit script (`scripts/audit_test_layout.py`) found:

- 344 test files scanned
- 22 suspiciously named files
- 22 exact duplicate test-body clusters across different files

Some duplicate clusters are likely intentional parity checks (e.g., platform vs portal common helpers), but they should be explicitly documented to distinguish **approved parity duplication** from **accidental copy-paste duplication**.

### 4) History of ad-hoc additions

Selected file history shows these bundles were introduced by tactical fix/hardening commits rather than structural test design commits, which explains naming drift.

## Consolidation target architecture

### A. Root tests taxonomy (single canonical integration folder)

Adopt one canonical folder:

- Keep: `tests/integration/`
- Migrate: `tests/integration_tests/*` -> `tests/integration/platform_api/` (or closest domain bucket)
- Add subfolders under `tests/integration/`:
  - `infra/` (docker, cache, environment checks)
  - `platform_api/` (platform API integration flows)
  - `cross_service/` (platform ↔ portal contracts)
  - `quality_gates/` (lint/tooling integration tests)

### B. Service tests naming conventions

Use behavior-oriented filenames:

- `test_<subject>_<behavior>.py`
- Avoid meta names: `fixes`, `misc`, `todos`, `remaining`, `round2`, `codex`

Refactor strategy:

- Move tests from temporary bundles into existing domain files when scope matches.
- If scope is novel, create a new explicit file (`test_idempotency_contract.py`, `test_invoice_rounding_rules.py`, etc.).

### C. Duplication policy

Introduce explicit rules:

1. **Allowed duplication:** platform/portal parity tests where separate service contracts must both be validated.
2. **Disallowed duplication:** identical business-logic tests duplicated within same service domain.
3. **Enforcement:** run `scripts/audit_test_layout.py` in CI; fail only for unapproved duplicate-body clusters and disallowed filenames.

## Execution plan

### Phase 0 (non-disruptive inventory)

1. Baseline report artifact from `scripts/audit_test_layout.py`.
2. Tag duplicate clusters as `approved` or `action-required` in a checked-in allowlist (JSON/YAML).

### Phase 1 (root integration cleanup)

1. Move `tests/integration_tests/*` into `tests/integration/` domain subfolders.
2. Add backward-compatible import/path notes in `README` or `docs/development/testing.md`.
3. Remove now-empty `tests/integration_tests/`.

### Phase 2 (platform/portal cleanup)

1. For each suspicious file, classify each test function by target module/behavior.
2. Move function blocks into canonical domain files.
3. Delete emptied temporary bundles.
4. Keep Git history traceable via small, topic-focused commits (one domain at a time).

### Phase 3 (guardrails)

1. Add pre-commit/CI check using `scripts/audit_test_layout.py`.
2. Enforce filename lint rule for banned tokens.
3. Maintain explicit allowlist for intentional parity duplicates.

## Suggested first migration batch

1. `services/platform/tests/billing/test_billing_27_todos.py`
2. `services/platform/tests/billing/test_billing_codex_fixes.py`
3. `services/platform/tests/billing/test_billing_misc_coverage.py`
4. `services/platform/tests/orders/test_idempotency_fixes.py`
5. `services/portal/tests/orders/test_remaining_fixes.py`

These provide high signal and should reduce the most confusing naming quickly.
