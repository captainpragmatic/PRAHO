# ADR-0043: Audit Integrity v2, Retention Enforcement, and the Standalone-SIEM Contract

**Status**: Accepted
**Date**: 2026-07-23
**Deciders**: Platform Engineering
**Related**: ADR-0016 (audit service layer), ADR-0034 (FSM transitions), issues #217, #241, #313, #385

## Context

A full audit-module review found the module's three core promises broken:

1. **Integrity was theater.** Events carried an *unkeyed* SHA-256 over a field
   subset that excluded the evidence (`old_values`/`new_values`/`metadata`) but
   included `user_id`/`ip_address` — so GDPR anonymization produced false
   CRITICALs while an attacker with UPDATE access could recompute hashes or
   strip markers to demote rows to "legacy". Two verifiers lied outright: the
   SIEM-side one read a hash nothing ever wrote ("VERIFIED" vacuously), and a
   crashed verification defaulted to healthy.
2. **Retention did not exist.** Two duplicate engines, no seeded policies, no
   scheduler, a placeholder `archive` action that flipped a metadata flag while
   claiming cold storage, and an `is_mandatory` flag that short-circuited the
   legally mandated deletion instead of protecting the policy.
3. **~2,300 lines of SIEM code had no callers**: outbound transports,
   buffer/flush machinery, a duplicate integration service, a duplicate
   file-integrity service, and two models nothing wrote.

## Decision

### 1. Keyed v2 integrity MACs, no downgrade path

Every `AuditEvent` is stamped at creation with an HMAC-SHA256 over a canonical
JSON payload covering the **evidence**: `action`, `actor_type`, `is_sensitive`,
object identity, `description`, `old_values`, `new_values`, `category`,
`severity`, and `metadata` minus the reserved marker keys
(`integrity_hash`, `integrity_hash_version`, `integrity_key_id`).

- `user_id` and `ip_address` are **deliberately excluded**: GDPR
  anonymization clears them, and v1's coverage of them made every anonymized
  row a false critical. Their absence is compensated by the guard below.
- Keys resolve through the key-derivation registry (domain `audit-integrity`;
  env `AUDIT_INTEGRITY_SECRET` overrides HKDF-over-`SECRET_KEY`). Rotation:
  move the old secret to `AUDIT_INTEGRITY_SECRET_PREVIOUS` — it derives under
  the *same* domain, so stamped history stays valid. Key ids are persisted per
  stamp; verification is constant-time against current + previous keys.
- **Post-cutover, a missing, v1, or unknown marker verifies as COMPROMISED**
  (`AUDIT_INTEGRITY_REQUIRE_V2`, default on). A stripped marker is a downgrade
  attack, not legacy. The migration window (setting off) verifies v1 rows
  under the legacy algorithm.
- Cutover runbook: provision `AUDIT_INTEGRITY_SECRET` → deploy (all v1
  writers gone) → `manage.py restamp_audit_integrity` (pk-batched, resumable,
  idempotent, self-asserting) → `manage.py audit_compliance verify-integrity`.
- #313's chaining/external-anchoring tier remains open; this ships the keyed
  tier.

### 2. Immutability enforced, not described

`AuditEventQuerySet` blocks `update()`/`bulk_update()`/`delete()` and the model
blocks save-on-existing/delete unless the call site entered
`audit_mutation_allowed(reason)`. Legitimate mutators are enumerated: GDPR
anonymize/erase, retention delete/anonymize, password-reset cleanup, integrity
stamping, and the restamp command. Framework FK cascades stay on the plain base
manager **deliberately** — user deletion must not explode on its audit trail,
and `user_id` sits outside the MAC payload. The guard is ORM-layer defense;
raw SQL bypasses it, which is what the MAC exists to catch.

`AuditEvent.content_type` is `on_delete=PROTECT`: running
`remove_stale_contenttypes` against a type with audit history now requires an
explicit retention decision (delete/anonymize the events first) instead of
silently cascading evidence away.

### 3. Honest checks

`verify_audit_integrity` persists a `status="error"` check row *outside* the
failed transaction when it crashes; an empty verification window is a
`warning` with an explicit finding, never silent health. Commands exit
non-zero on compromised/error; the compliance report renders a verification
that failed to run as non-compliant (ISO 27001 A.12.4.2).

### 4. Retention that runs

One engine (`AuditRetentionService`), policy rows seeded by
`setup_audit_retention_policies` (10y mandatory delete for business
operations per Legea contabilității; 5y mandatory anonymize for
privacy/data_protection per GDPR Art. 7 accountability — note this bounds
settings-change history at its category's policy; 2–3y elsewhere), scheduled
weekly by the consolidated scheduler.

- `archive` is **removed**, not implemented: a no-op that claims cold storage
  is worse than absence. Real cold-storage archive is future work.
- `is_mandatory` semantics: DB constraints (`mandatory ⇒ active`, one active
  policy per scope) plus model guards against deactivation/demotion/deletion.
  The action *executes* — mandatory protects the policy, not the data from
  the policy.
- Financial guard is an effective cutoff: per event
  `max(policy retention, 10-year legal minimum)`.
- Anonymization is an explicit invariant: identity fields cleared,
  person-bearing object references replaced with a sentinel, evidence
  stubbed, metadata reduced to an **allowlist**, then re-stamped with a fresh
  v2 MAC. Idempotent across runs.

### 5. Durable file-integrity baselines

`FileIntegrityBaseline` rows replace evictable-cache baselines. Checks diff
baseline vs disk both ways and never mutate baselines;
`run_integrity_check --rebaseline` atomically replaces the set. Deploy
runbook: rebaseline after every release.

### 6. Standalone-SIEM contract

The audit module stands alone. Integration surface: the structured JSON log
stream (`SIEMJSONFormatter`) for any log shipper, and on-demand export
(`audit_compliance export-events`, CEF/LEEF/JSON/Syslog/OCSF renderers in
`apps/audit/siem.py`). Real-time in-app push is deliberately not implemented;
delivery guarantees belong to the log-shipping layer. The dead transport
stack, duplicate services, and orphan models are deleted.

### 7. Coverage guardrails that cannot rot

The model-coverage test now requires a receiver's defining module to reference
the audit API by NAME token (tokenize — comments cannot fake it); every
"audited via X" allowlist justification must cite a mechanism that greps in
`apps/`; the ADR-0016 scanner flags any resurrection of the retired
`audit_service.*` proxy; and a generic `post_transition` receiver audits every
FSM transition outside an explicitly tested skip-list.

## Consequences

- Verification failures are now *visible* (error rows, non-zero exits,
  dashboard counts) — expect alerts from environments where verification was
  silently broken.
- `AUDIT_INTEGRITY_SECRET` must be provisioned and the restamp run per the
  runbook before `AUDIT_INTEGRITY_REQUIRE_V2` environments report clean.
- Anything mutating `AuditEvent` outside the enumerated paths now raises —
  new mutators must adopt `audit_mutation_allowed()` with a reason.
- Retention actually deletes/anonymizes once seeded: environments relying on
  infinite audit history must adjust policies before running the seeder.
