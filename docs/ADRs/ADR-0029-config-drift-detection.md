# ADR-0029: Config Drift Detection & Remediation

**Status:** Proposed
**Date:** 2026-03-03
**Authors:** PRAHO Development Team
**Related:** ADR-0027 (hcloud SDK provisioning)

## Context

ADR-0027 replaced Terraform with direct hcloud SDK calls, making the PRAHO database the single source of truth for infrastructure state. However, there is currently **zero reconciliation** between what the database says and what actually exists in the cloud.

Three layers of drift can occur:

1. **Cloud Provider** -- Someone resizes a server in the Hetzner console, deletes it, or changes firewall rules. The database still shows the old state.
2. **OS/Network** -- The server becomes unreachable (network issue, kernel panic), IP changes, or SSH access is lost.
3. **Application (Virtualmin)** -- An admin adds domains directly in Virtualmin, changes PHP versions, or modifies server configs outside PRAHO.

Without detection, PRAHO's database silently becomes stale. Operations like upgrades, destroy, or new domain placement rely on accurate state and will fail or produce incorrect results when drift exists.

## Decision Drivers

1. **Data accuracy** -- operations must work from correct state
2. **Early warning** -- detect problems before customers report them
3. **Safe remediation** -- fix drift without causing more damage
4. **Auditability** -- full trail of what changed, when, and who approved the fix
5. **Low noise** -- auto-handle trivial drift, only escalate what matters

## Decision

Implement a three-layer config drift detection and remediation system with:

1. **Periodic scanning** via Django-Q2 scheduled tasks (every 15 minutes for active deployments)
2. **Severity-based classification** (CRITICAL / HIGH / MODERATE / LOW / INFO)
3. **Smart auto-resolution** for low-risk drift (update DB to match reality)
4. **Admin approval workflow** for high-risk remediation (with snapshot safety net)
5. **Snapshot-based rollback** for failed remediations

### Design Choices

**Polling over webhooks.** Not all providers support webhooks for all change types. Polling is universal, predictable, and simpler to test. The 15-minute interval balances timeliness against API rate limits (~96 calls/day/deployment).

**Snapshot before remediate.** Cloud snapshots cost approximately EUR 0.01/GB/month. The cost of NOT having a rollback point when remediation fails is server downtime and potential data loss. Every remediation that modifies server state takes a snapshot first.

**Admin approval for HIGH/CRITICAL only.** LOW drift auto-syncs the database silently. MODERATE drift auto-resolves with a notification. This keeps the admin queue focused on decisions that actually need human judgment.

**Separate restart approval.** Server restarts affect all hosted domains. Even within an approved remediation, restart is a separate gate.

**Reuse CloudProviderGateway.** Drift detection and remediation use the same provider abstraction (ADR-0027). Snapshot methods are added to the ABC -- works for all providers that implement it.

**Audit everything.** Every drift detection, auto-resolution, remediation request, approval, execution, and rollback creates an audit event. Full traceability via the existing audit infrastructure (ADR-0016).

### Severity Classification

| Severity | Examples | Auto-action | Admin action |
|----------|---------|-------------|--------------|
| CRITICAL | Server deleted, IP changed, unreachable 3+ consecutive checks | Alert immediately, block operations | Must approve remediation |
| HIGH | Server resized externally, firewall rules changed | Create remediation request | Must approve |
| MODERATE | Virtualmin config changed, extra domains added | Auto-resolve + notify admin | Review notification |
| LOW | Disk/bandwidth stats differ, metadata mismatch | Auto-sync DB silently | None (logged) |
| INFO | No drift detected | None | None |

### New Models

**DriftCheck** -- represents a single scan execution for one deployment.

**DriftReport** -- individual drift finding within a check. One check can produce multiple reports (e.g., server type changed AND firewall rules changed).

**DriftRemediationRequest** -- tracks the approval workflow for fixing HIGH/CRITICAL drift. Links to a DriftReport and records who requested, who approved, snapshot taken, and execution result.

**DriftSnapshot** -- tracks cloud snapshots created for rollback safety. Snapshots auto-expire after 7 days.

### CloudProviderGateway Additions

Four new abstract methods on the existing ABC:

- `create_snapshot(server_id, name) -> Result[str, str]` -- returns snapshot ID
- `restore_snapshot(server_id, snapshot_id) -> Result[bool, str]`
- `list_snapshots(server_id) -> Result[list[dict], str]`
- `delete_snapshot(snapshot_id) -> Result[bool, str]`

### Task Schedule

| Task | Interval | Purpose |
|------|----------|---------|
| `run_drift_scan_task` | Every 15 min | Scan all active deployments |
| `apply_scheduled_remediations_task` | Every 5 min | Execute due remediations |
| `check_remediation_health_task` | Every 5 min | Verify recently remediated deployments |
| `cleanup_old_snapshots_task` | Daily | Delete snapshots older than 7 days |

## Consequences

### Positive

- Infrastructure state in the database stays accurate
- Problems detected before customers report them
- Safe remediation with snapshot rollback
- Full audit trail for compliance
- Low admin noise -- only HIGH/CRITICAL require approval

### Negative

- API rate limit consumption from polling (~96 calls/day/deployment at 15-min intervals)
- Snapshot storage costs (mitigated by 7-day auto-cleanup)
- Added complexity in the infrastructure app (4 new models, 2 new services)

### Neutral

- Existing deployment and destroy workflows are unchanged
- Providers that don't support snapshots can skip remediation (detection still works)

## References

- ADR-0027: hcloud SDK Infrastructure Provisioning
- ADR-0016: Audit Trail Enforcement
- ADR-0020: Async Task Processing Architecture (Django-Q2)
