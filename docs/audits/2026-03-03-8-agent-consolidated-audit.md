# Consolidated 8-Agent Deep Audit Report

**Date**: 2026-03-03
**Agents**: 3 Codex CLI (GPT-5.3-codex) + 5 Claude Deep Code Reviewers (Opus 4.6)
**Scope**: ~54 uncommitted files across infrastructure, provisioning, portal, E2E, and templates

---

## CRITICAL Findings (10)

| # | Finding | File(s) | Agents |
|---|---------|---------|--------|
| **C1** | `VirtualminGateway(server)` — passes `VirtualminServer` instead of `VirtualminConfig`, crashes quota restore | `virtualmin_disaster_recovery.py:296` | Codex G3, Claude B5 |
| **C2** | `deploy_node.py` dry-run creates DB record + consumes node number before checking `--dry-run` flag | `deploy_node.py:214,248` | Codex G2, Claude B4 |
| **C3** | Cloudflare API token serialized cleartext to Django-Q2 queue (docstring says "tokens are NOT passed") | `tasks.py:949-956,986,1020` | Claude B2, B4 |
| **C4** | `calculate_daily_costs_task` crashes every invocation — `timezone.make_aware()` on already-aware datetime | `tasks.py:1292-1295` | Claude B2 |
| **C5** | `DriftCheck.started_at` is `default=None` + NOT NULL — any `bulk_create` or raw SQL crashes with `IntegrityError` | `models.py:835` | Codex G2, Claude B2 |
| **C6** | AWS region `normalized_code` exceeds `max_length=4` — "us-east-1a" (10 chars) causes `DataError` on sync | `provider_sync.py:851` | Claude B2 |
| **C7** | Hetzner `int(server_id)` outside `try/except` in 8 methods — ValueError crashes instead of `Err(...)` | `hcloud_service.py:130,149,165,176,189,202,332,347` | Claude B1 |
| **C8** | Vultr power ops tests broken — hang 300s then fail (mock returns empty dict, polling never exits) | `test_vultr_service.py:128-144` | Claude B1 |
| **C9** | AWS idempotency key uses `deployment-id` while Hetzner/DO/Vultr use `praho-deployment` — retries create duplicate servers on AWS | `aws_service.py:97` | Codex G1, Claude B1 |
| **C10** | Template `deployment_status.html` — `stages.split` splits on whitespace (breaks "SSH Key") + `divisibleby` returns boolean (progress never works) | `deployment_status.html:45-47` | Codex G3, Claude B5 |

## HIGH Findings (18)

| # | Finding | File(s) | Agents |
|---|---------|---------|--------|
| **H1** | TOCTOU in `drift_remediation_approve` — no `select_for_update`, concurrent POSTs double-execute | `views.py:1523,1535` | Codex G1, Claude B3 |
| **H2** | Transient `get_server` errors treated as "server missing" — clears `external_node_id`, orphans infrastructure | `deployment_service.py:223,232` | Codex G1 |
| **H3** | `drift_scan` returns exit code 0 when scans error out (provider/API failures) — breaks CI failure detection | `drift_scan.py:144,214` | Codex G2 |
| **H4** | `retry_deployment` bypasses state machine — directly sets `status="pending"` instead of `transition_to()` | `deployment_service.py:580-582` | Claude B2 |
| **H5** | `stop_node`/`start_node` bypass state machine — direct status assignment | `deployment_service.py:843-844,900-901` | Claude B2 |
| **H6** | `destroy_node` TOCTOU — status check and `transition_to()` not atomic (no `select_for_update`) | `deployment_service.py:461-468` | Claude B2 |
| **H7** | `can_be_destroyed` property missing "stopped" — UI hides destroy button for stopped nodes the service allows | `models.py:636` vs `deployment_service.py:461` | Claude B2 |
| **H8** | SSH key fallback: `get_master_public_key().unwrap()` without `is_err()` check — panics if master key fails | `deployment_service.py:199` | Claude B2 |
| **H9** | AWS `get_server` only catches `ClientError`, not generic `Exception` — network timeouts propagate uncaught | `aws_service.py:151-165` | Claude B1 |
| **H10** | Hetzner doesn't call `normalize_server_status()` while DO/Vultr/AWS do — inconsistent gateway contract | `hcloud_service.py:405` | Claude B1 |
| **H11** | Vultr `delete_firewall` doesn't handle 404 — second delete returns `Err` instead of idempotent `Ok(True)` | `vultr_service.py:325-332` | Claude B1 |
| **H12** | AWS `upload_ssh_key` unconditionally deletes before creating — brief window with no key, unlike other providers | `aws_service.py:229-248` | Claude B1 |
| **H13** | DigitalOcean country derivation wrong — `"nyc1"[:3].upper()` = "NYC" is not an ISO country code | `digitalocean_service.py:270` | Claude B1 |
| **H14** | `manage_node` async path doesn't enforce precondition checks the web UI has (status/action validity) | `manage_node.py:158,219` | Codex G2 |
| **H15** | `cleanup_deployments` marks "destroyed" even when cloud deletion fails — hides orphaned servers/cost leaks | `cleanup_deployments.py:170,177,200` | Codex G2 |
| **H16** | `_execute_with_method` can return `None` — missing `else` branch for unknown `AuthMethod` values | `virtualmin_auth_manager.py:168-176` | Claude B5 |
| **H17** | `_mark_failed` loses audit user context — all failure audit events are anonymous | `deployment_service.py:993-998` | Claude B2 |
| **H18** | HMAC "integration" tests are fully mocked — don't validate real cross-service auth flow | `test_cross_service_hmac.py`, `test_api_client_hmac.py` | Codex G3 |

## MEDIUM Findings (16)

| # | Finding | Agents |
|---|---------|--------|
| **M1** | Node number race — `select_for_update` on filtered rows doesn't lock gaps when no row exists | Codex G1 |
| **M2** | Drift dashboard counts inflated — join multiplication without `distinct=True` | Codex G1 |
| **M3** | Hcloud gateway error handling inconsistent — `int()` casts before `try` | Codex G1 |
| **M4** | `get_next_node_number` duplicate when no rows exist (no retry on IntegrityError) | Claude B2 |
| **M5** | `_sync_vultr_plans` accesses private `_request` method — breaks encapsulation | Claude B2 |
| **M6** | Test `test_supported_providers_list` expects "linode" but config doesn't have it | Claude B2 |
| **M7** | DigitalOcean provider code "do" is 2 chars — breaks 3-letter hostname convention | Claude B2 |
| **M8** | Module-level singleton `get_deployment_service()` not thread-safe | Claude B2 |
| **M9** | Provider registry `_PROVIDER_REGISTRY` is global mutable dict without thread safety | Claude B1 |
| **M10** | Vultr `create_server` sets `os_id: 0` when `request.image` is falsy | Claude B1 |
| **M11** | DO `_resolve_ssh_key_ids` silently drops unresolved key names | Claude B1 |
| **M12** | DO `delete_server` returns `Ok(True)` after polling timeout | Claude B1 |
| **M13** | `normalize_server_status` canonical vocabulary not documented | Claude B1 |
| **M14** | ADR-0028 promises background error detection but implementation excludes `NO_REQUEST_ID` entries | Codex G3 |
| **M15** | Quota restoration skips explicit zero values (truthy checks) | Codex G3 |
| **M16** | Migration `started_at` field `default=None` + NOT NULL inconsistent for non-standard write paths | Codex G2 |

## LOW Findings (6)

| # | Finding | Agents |
|---|---------|--------|
| L1 | AWS test uses realistic-looking key/secret literals — triggers secret scanners | Codex G2 |
| L2 | "All providers implement all methods" test is tautological | Codex G2 |
| L3 | Provider sync bypasses service/gateway abstraction using internals | Codex G1 |
| L4 | Task scheduling setup suppresses all exceptions silently | Codex G1 |
| L5 | Documentation paths point to `/home/claude/...` not `/Users/claudiu/...` | Codex G3 |
| L6 | E2E tests use pytest-style classes (inconsistent with platform style, but acceptable) | Claude B5 |

---

## Unit Test Inventory Summary

| Area | Existing | Needed | Total |
|------|----------|--------|-------|
| `cloud_gateway.py` | 18 | 6 | 24 |
| `hcloud_service.py` | 17 | 22 | 39 |
| `digitalocean_service.py` | 15 | 19 | 34 |
| `vultr_service.py` | 14 (4 broken) | 17 | 31 |
| `aws_service.py` | 17 | 23 | 40 |
| `deployment_service.py` | ~8 | 39 | 47 |
| `tasks.py` | 0 | 28 | 28 |
| `models.py` | ~29 | 14 | 43 |
| `provider_config.py` | 22 | 8 | 30 |
| `provider_sync.py` | ~16 | 11 | 27 |
| Management commands (5) | 0 | 20 | 20 |
| Drift scanner/remediation | ~20 | 8 | 28 |
| Portal/HMAC tests | ~10 | 2 | 12 |
| E2E/server logs | ~12 | 4 | 16 |
| **TOTALS** | **~198** | **~221** | **~419** |

---

## Recommended Fix Priority

1. **C3** (Cloudflare token) — security, quick fix
2. **C4** (daily costs crash) — production blocker
3. **C1** (VirtualminGateway constructor) — disaster recovery broken
4. **C2** (dry-run DB mutation) — data integrity
5. **C7** (Hetzner int conversion) + **C9** (idempotency key) — provider correctness
6. **C8** (Vultr test fix) — unblocks CI
7. **H1-H6** (TOCTOU/state machine) — race conditions
8. Remaining HIGH/MEDIUM findings
9. ~221 unit tests for 90%+ coverage
