# Test Suite Consolidation Plan (Root + Platform + Portal)

## What was audited

- Branch inventory (local + remote refs).
- Root test layout (`tests/`), including split between `tests/integration/` and `tests/integration_tests/`.
- Service-level test layouts:
  - `services/platform/tests/`
  - `services/portal/tests/`
- Potential naming/duplication hotspots using `scripts/audit_test_layout.py`.

## Current state snapshot

- Branches currently visible in this clone:
  - Local: `work`
  - Remote refs: none
- Test file counts:
  - `tests/`: 42 files (28 e2e, 6 integration, 6 integration_tests)
  - `services/platform/tests/`: 242 files
  - `services/portal/tests/`: 60 files
- Exact duplicate test bodies: none found by hash-based scan.
- One duplicate test function name across files:
  - `test_ticket_mobile_responsiveness` appears in both platform and portal e2e tickets suites.

## Key problems to fix

1. **Mixed naming quality**
   - Several test files encode temporary context (`*_fixes.py`, `*_todos.py`, `*_misc_coverage.py`, `*_round2.py`, `*_remaining_fixes.py`) instead of domain behavior.

2. **Root integration split is semantically unclear**
   - `tests/integration/` currently holds infra/static/lint/cross-service checks.
   - `tests/integration_tests/` currently holds API/domain-heavy integration flows.
   - The names are too similar and invite random placement.

3. **Coverage-oriented file names hide intent**
   - Files named `*_coverage.py`, `*_basic.py`, `*_focused.py`, `*_additional.py` often blend unrelated behavior.

4. **No continuous guardrail for test naming drift**
   - There was no lightweight lint/audit utility to repeatedly detect naming drift and obvious exact duplicates.

## Proposed target structure

### Root `tests/`

- Keep `tests/e2e/` exactly where it is.
- Replace dual integration folders with clear intent:
  - `tests/integration/system/` (docker/services/cache/lint/security-hardening style checks)
  - `tests/integration/api/` (cross-service API and workflow integrations)
- Migration approach:
  - Move files from `tests/integration_tests/` into `tests/integration/api/`.
  - Move current `tests/integration/*.py` into `tests/integration/system/` (except API-level files, which go to `api/`).
  - Keep import paths stable via temporary re-export shim modules only if needed for CI transition.

### `services/platform/tests/`

- Keep app-first directory layout.
- Rename/merge temporary buckets into behavior files, for example:
  - `billing/test_billing_27_todos.py` → split into `test_payment_retry_service.py`, `test_efactura_submission.py`, `test_refunds_api.py` (or merge into existing matching files).
  - `billing/test_billing_codex_fixes.py`, `billing/test_billing_misc_coverage.py` → merge into existing behavior files (`test_services.py`, `test_payments_*.py`, `test_invoices_*.py`) by feature.
  - `orders/test_idempotency_fixes.py` → merge into a stable `test_order_idempotency.py` (or existing order flow/idempotency module).

### `services/portal/tests/`

- Keep app-first layout.
- Remove temporary suffixes:
  - `orders/test_order_flow_fixes.py`, `test_remaining_fixes.py`, `test_chaos_monkey_round2.py` → consolidate by behavior into `test_checkout_flow.py`, `test_cart_rate_limits.py`, `test_order_security.py` (or existing equivalents).

## Consolidation workflow (safe + incremental)

1. **Inventory + mapping (no behavior change)**
   - For each flagged file, map every `test_*` function to target module by feature ownership.

2. **Move tests without changing assertions**
   - Use `git mv` and function relocation only.
   - Run targeted test subsets after each batch.

3. **Deduplicate setup/helpers**
   - Extract repeated fixtures/builders into nearest `conftest.py` or helper modules.

4. **Normalize names**
   - Rename tests to behavior-first names (not incident-first names).

5. **Retire empty/placeholder files**
   - Delete files left with no unique behavior.

6. **Gate regressions**
   - Add `scripts/audit_test_layout.py` to CI as non-blocking report first, then blocking for suspicious names after cleanup baseline is accepted.

## How to check duplication going forward

Use:

```bash
python scripts/audit_test_layout.py
python scripts/audit_test_layout.py --json
```

This catches:

- Local and remote branch visibility in current clone.
- Filename drift toward temporary buckets (`fixes`, `todos`, `misc`, etc.).
- Exact duplicate test body clones.
- Reused test function names across files.

For near-duplicate logic (same flow, different constants), add optional tools later (e.g. token-based clone detectors), but this script gives a low-noise baseline now.

## Suggested execution order

1. Root integration directory unification (`tests/integration*`).
2. Portal orders test cleanup (smaller surface).
3. Platform billing + orders cleanup (largest churn).
4. Promote naming audit to CI gate once baseline is stable.
