"""
Drift Remediation Service

Handles the remediation workflow for configuration drift:
- Approve, reject, schedule remediation requests
- Execute remediation with snapshot safety net
- Rollback on failure
"""

from __future__ import annotations

import logging
import socket
import time
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv4_address, validate_ipv6_address
from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.audit_service import InfrastructureAuditContext, InfrastructureAuditService
from apps.infrastructure.cloud_gateway import CloudProviderGateway, get_cloud_gateway
from apps.infrastructure.models import (
    DriftRemediationRequest,
    DriftReport,
    DriftSnapshot,
    NodeDeployment,
    NodeSize,
)
from apps.infrastructure.provider_config import get_provider_token

if TYPE_CHECKING:
    from apps.users.models import User

logger = logging.getLogger(__name__)

# TCP probe timeout for health checks
_DEFAULT_HEALTH_CHECK_TIMEOUT = 10

# Verification loop defaults: a powered-on/resized server needs boot time before
# port 22 answers; the whole verify stage must stay well under Django-Q2's
# 300s worker timeout (rollback still has to fit in the same task).
_DEFAULT_VERIFY_BOOT_GRACE = 30
_DEFAULT_VERIFY_MAX_WAIT = 150
_DEFAULT_VERIFY_POLL_INTERVAL = 10

# Patchable aliases so tests can drive the verification loop with a fake clock.
_sleep = time.sleep
_monotonic = time.monotonic


def _get_health_check_timeout() -> int:
    """Read health check timeout from SettingsService with DB-cache layer."""
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Deferred: avoids circular import

    return SettingsService.get_integer_setting(
        "infrastructure.health_check_timeout_seconds", _DEFAULT_HEALTH_CHECK_TIMEOUT
    )


def _get_verify_boot_grace() -> int:
    """Seconds to wait before the first post-remediation probe."""
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Deferred: avoids circular import

    return max(
        0,
        SettingsService.get_integer_setting(
            "infrastructure.remediation_boot_grace_seconds", _DEFAULT_VERIFY_BOOT_GRACE
        ),
    )


def _get_verify_max_wait() -> int:
    """Total wall-clock budget for the verification stage, grace included."""
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Deferred: avoids circular import

    return max(
        1,
        SettingsService.get_integer_setting(
            "infrastructure.remediation_verify_max_wait_seconds", _DEFAULT_VERIFY_MAX_WAIT
        ),
    )


def _get_verify_poll_interval() -> int:
    """Delay between verification probes."""
    from apps.settings.services import SettingsService  # noqa: PLC0415  # Deferred: avoids circular import

    return max(
        1,
        SettingsService.get_integer_setting(
            "infrastructure.remediation_verify_poll_interval_seconds", _DEFAULT_VERIFY_POLL_INTERVAL
        ),
    )


# Per-task timeout for remediation execution: the apply stage alone can poll
# the provider for ~5 min (e.g. hcloud resize), and verification needs its own
# budget after that — the 300s cluster default would kill a successful resize
# mid-verification. Passed to async_task at every enqueue site.
# Snapshot creation, the apply mutation, and a snapshot restore are EACH bounded
# near 300s by provider action polling, and verification adds its own ~150s
# budget. The task timeout must cover the worst-case sequence (snapshot + apply
# + verify + restore) with margin, or django-q2 kills the worker MID-RESTORE.
EXECUTION_TASK_TIMEOUT_SECONDS = 1500

# Well above the longest possible live execution: a live run can never be
# mistaken for a crashed one.
_DEFAULT_STALE_AFTER_MINUTES = 30


def get_stale_after_minutes() -> int:
    """
    Age after which in_progress/approved remediation state counts as stranded.
    Floored above the longest possible LIVE execution (django-q2 worker timeout
    plus the verification budget) — a misconfigured low value must never let
    the reaper kill, and thereby double-execute, a running remediation.
    """
    import math  # noqa: PLC0415  # Stdlib, local to keep module imports lean

    from apps.settings.services import SettingsService  # noqa: PLC0415  # Deferred: avoids circular import

    floor_minutes = math.ceil(EXECUTION_TASK_TIMEOUT_SECONDS / 60) + 1
    configured = SettingsService.get_integer_setting(
        "infrastructure.remediation_stale_after_minutes", _DEFAULT_STALE_AFTER_MINUTES
    )
    return max(floor_minutes, configured)


# Snapshot expiry in days
SNAPSHOT_EXPIRY_DAYS = 7

# Drift fields with a real automated fix. Everything else must be routed to
# manual intervention — an "apply" for them would be a no-op falsely reported
# as remediated (#224 defect 2).
AUTO_FIXABLE_FIELDS = frozenset({"server_type", "server_status"})


class DriftRemediationService:
    """Handles the remediation workflow: approve, reject, schedule, execute, rollback."""

    def approve_remediation(
        self,
        request_id: int,
        user: User,
    ) -> Result[DriftRemediationRequest, str]:
        """Approve and queue execution asynchronously (single owner of this transition)."""
        from django_q.tasks import async_task  # noqa: PLC0415  # Deferred: avoids circular import

        try:
            req = DriftRemediationRequest.objects.select_related("deployment", "report").get(pk=request_id)
        except DriftRemediationRequest.DoesNotExist:
            return Err(f"Remediation request {request_id} not found")

        if req.action_type != "apply_desired":
            return Err("This drift has no automated fix — resolve it manually and re-scan, or accept the drift")

        # Status flip + task enqueue in one transaction (django-q2 writes to the
        # django_q table, so a failed enqueue rolls the approval back too). The
        # conditional update is the portable claim: a concurrent accept/reject
        # loses cleanly instead of double-transitioning.
        now = timezone.now()
        with transaction.atomic():
            updated = DriftRemediationRequest.objects.filter(pk=request_id, status="pending_approval").update(
                status="approved",
                approved_by=user,
                approved_at=now,
                execution_claimed_at=now,
            )
            if not updated:
                req.refresh_from_db()
                return Err(f"Cannot approve request in status '{req.status}'")

            async_task(
                "apps.infrastructure.tasks.execute_remediation_task",
                request_id,
                task_name=f"remediation_{request_id}",
                timeout=EXECUTION_TASK_TIMEOUT_SECONDS,
            )

        logger.info(f"✅ [DriftRemediation] Request {request_id} approved by {user.email}, execution queued")

        req.refresh_from_db()
        try:
            InfrastructureAuditService.log_drift_remediation_approved(
                req.deployment, req, user, InfrastructureAuditContext(user=user)
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for approval: {e}")

        return Ok(req)

    def reject_remediation(
        self,
        request_id: int,
        user: User,
        reason: str,
    ) -> Result[DriftRemediationRequest, str]:
        """Set status=rejected with reason."""
        try:
            req = DriftRemediationRequest.objects.get(pk=request_id)
        except DriftRemediationRequest.DoesNotExist:
            return Err(f"Remediation request {request_id} not found")

        # Conditional update like every other transition: a stale read must
        # never overwrite a concurrent approve/accept/claim.
        updated = DriftRemediationRequest.objects.filter(pk=request_id, status="pending_approval").update(
            status="rejected", rejected_reason=reason
        )
        if not updated:
            req.refresh_from_db()
            return Err(f"Cannot reject request in status '{req.status}'")
        req.refresh_from_db()

        # Best-effort operational audit: the reject transition is already
        # durably committed (and separately recoverable), so an audit-backend
        # blip must not surface as a 500 out of a successful reject. This is
        # deliberately NOT a mandatory-audit path — cf. the staff dismiss
        # action, whose audit is mandatory and rolls back on failure.
        try:
            InfrastructureAuditService.log_drift_remediation_rejected(
                deployment=req.deployment,
                request=req,
                rejector=user,
                reason=reason,
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for rejection: {e}")

        logger.info(f"✅ [DriftRemediation] Request {request_id} rejected by {user.email}: {reason}")
        return Ok(req)

    def schedule_remediation(
        self,
        request_id: int,
        user: User,
        scheduled_for: datetime,
    ) -> Result[DriftRemediationRequest, str]:
        """Set status=scheduled with datetime."""
        try:
            req = DriftRemediationRequest.objects.get(pk=request_id)
        except DriftRemediationRequest.DoesNotExist:
            return Err(f"Remediation request {request_id} not found")

        if req.action_type != "apply_desired":
            return Err("This drift has no automated fix — scheduling it would execute a no-op")

        # Conditional update: scheduling must never overwrite a row a worker
        # has already claimed in_progress (that would discard the running
        # execution's terminal write and re-execute the provider mutation).
        updated = DriftRemediationRequest.objects.filter(
            pk=request_id, status__in=("pending_approval", "approved")
        ).update(
            status="scheduled",
            scheduled_for=scheduled_for,
            approved_by=user,
            approved_at=timezone.now(),
        )
        if not updated:
            req.refresh_from_db()
            return Err(f"Cannot schedule request in status '{req.status}'")
        req.refresh_from_db()

        # Best-effort operational audit (see reject_remediation): the schedule
        # transition is already committed; an audit failure must not fail it.
        try:
            InfrastructureAuditService.log_drift_remediation_scheduled(
                deployment=req.deployment,
                request=req,
                scheduled_for=str(scheduled_for),
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for scheduling: {e}")

        logger.info(f"✅ [DriftRemediation] Request {request_id} scheduled for {scheduled_for}")
        return Ok(req)

    def accept_drift(  # noqa: PLR0911  # Guarded workflow: one early exit per validation
        self,
        request_id: int,
        user: User,
    ) -> Result[DriftRemediationRequest, str]:
        """
        Accept reality: durably write the observed value back to PRAHO's
        records and mark the drift resolved. Flag-only acceptance would just
        re-mint the identical drift on the next scan, so fields with nothing
        durable to write (see DriftReport.ACCEPTABLE_DRIFT_FIELDS) are refused.
        """
        try:
            req = DriftRemediationRequest.objects.select_related("report", "deployment").get(pk=request_id)
        except DriftRemediationRequest.DoesNotExist:
            return Err(f"Remediation request {request_id} not found")

        report = req.report
        if not report.is_acceptable:
            return Err(
                f"Drift on '{report.field_name}' cannot be accepted — fix it manually and re-scan, "
                "or stop/decommission the deployment"
            )

        with transaction.atomic():
            # Lock order everywhere: deployment -> request. Validation happens
            # AFTER locking so a concurrent approve/heal/reject cannot flip the
            # status between check and write.
            deployment = NodeDeployment.objects.select_for_update().get(pk=req.deployment_id)
            locked_req = DriftRemediationRequest.objects.select_for_update().get(pk=request_id)

            if locked_req.status != "pending_approval":
                return Err(f"Cannot accept drift for request in status '{locked_req.status}'")

            report.refresh_from_db()
            if report.resolved:
                return Err("Drift was resolved in the meantime — nothing left to accept")

            if (
                report.field_name == "server_status"
                and DriftRemediationRequest.objects.filter(deployment=deployment, status="in_progress").exists()
            ):
                return Err("A remediation is executing for this deployment — retry once it settles")

            sync_result = self._sync_accepted_value(deployment, report)
            if sync_result.is_err():
                # A normal return from atomic() COMMITS — force rollback so a
                # partial deployment write can never survive a failed accept.
                transaction.set_rollback(True)
                return Err(sync_result.unwrap_err())

            updated = DriftRemediationRequest.objects.filter(pk=request_id, status="pending_approval").update(
                status="completed",
                action_type="accept_actual",
                completed_at=timezone.now(),
            )
            if not updated:
                # Refresh BEFORE flagging rollback: a query on a needs_rollback
                # connection raises TransactionManagementError.
                req.refresh_from_db()
                transaction.set_rollback(True)
                return Err(f"Cannot accept drift for request in status '{req.status}'")

            finalized = DriftReport.objects.filter(pk=report.pk, resolved=False).update(
                resolved=True,
                resolved_at=timezone.now(),
                resolved_by=user,
                resolution_type="accepted",
            )
            if not finalized:
                # A concurrent heal won — the drift is gone; do not overwrite
                # its resolution or keep our deployment write
                transaction.set_rollback(True)
                return Err("Drift was resolved in the meantime — nothing left to accept")
            report.refresh_from_db()

        req.refresh_from_db()
        logger.info(f"✅ [DriftRemediation] Drift accepted for {req.deployment.hostname} by {user.email}")

        try:
            InfrastructureAuditService.log_drift_accepted(
                req.deployment, report, user, InfrastructureAuditContext(user=user)
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for drift acceptance: {e}")

        return Ok(req)

    def _sync_accepted_value(  # noqa: PLR0911  # Field dispatch: one exit per acceptable field
        self, deployment: NodeDeployment, report: DriftReport
    ) -> Result[bool, str]:
        """Write the accepted actual value back to the deployment record."""
        field = report.field_name
        actual = (report.actual_value or "").strip()

        if field in ("ipv4_address", "ipv6_address"):
            validator = validate_ipv4_address if field == "ipv4_address" else validate_ipv6_address
            try:
                validator(actual)
            except ValidationError:
                return Err(f"Observed value '{actual}' is not a valid address — cannot accept")
            setattr(deployment, field, actual)
            deployment.save(update_fields=[field, "updated_at"])
            return Ok(True)

        if field == "server_type":
            node_size = NodeSize.objects.filter(provider=deployment.provider, provider_type_id=actual).first()
            if node_size is None:
                return Err(f"No NodeSize matches provider type '{actual}' — create it first, then accept again")
            deployment.node_size = node_size
            deployment.save(update_fields=["node_size", "updated_at"])
            return Ok(True)

        if field == "server_status":
            if actual not in ("off", "stopped"):
                return Err(
                    f"Cannot accept transient provider status '{actual}' — only a powered-off "
                    "server can be accepted as stopped"
                )
            try:
                # A stopped deployment leaves scan scope; the recovery task
                # supersedes its remaining drift bookkeeping.
                deployment.transition_to("stopped", "Accepted drift: server powered off at provider")
            except ValidationError as e:
                return Err(str(e))
            return Ok(True)

        return Err(f"Field '{field}' has no durable write-back")

    def execute_remediation(  # noqa: PLR0911  # Multi-step workflow: each gate exits early
        self,
        request: DriftRemediationRequest,
    ) -> Result[bool, str]:
        """
        Execute remediation: snapshot -> apply -> verify -> audit.
        Rollback on failure.
        """
        deployment = request.deployment

        claim_result = self._claim_for_execution(request, deployment)
        if claim_result.is_err():
            return claim_result
        request.refresh_from_db()

        # Pre-flight: refuse work that has no automated fix BEFORE any snapshot,
        # so legacy/manual requests fail fast instead of no-op'ing into a
        # false "remediated" (and a pointless destructive rollback on failure).
        details = request.action_details or {}
        field_name = details.get("field_name", "")
        if request.action_type != "apply_desired" or field_name not in AUTO_FIXABLE_FIELDS:
            self._mark_failed(
                request,
                f"No automated fix available for field '{field_name or 'unknown'}' — manual intervention required",
            )
            return Err(f"No automated fix available for field '{field_name or 'unknown'}'")

        # Step 1: Take snapshot
        snapshot_result = self._take_snapshot(deployment)
        if snapshot_result.is_err():
            self._mark_failed(request, f"Snapshot failed: {snapshot_result.unwrap_err()}")
            return Err(snapshot_result.unwrap_err())

        snapshot = snapshot_result.unwrap()
        request.snapshot_id = snapshot.provider_snapshot_id
        request.save(update_fields=["snapshot_id"])

        # Step 2: Apply remediation
        gateway = self._get_gateway(deployment)
        if gateway is None:
            self._mark_failed(request, "Cannot get cloud gateway")
            return Err("Cannot get cloud gateway")

        apply_result = self._apply_remediation(request, gateway)
        if apply_result.is_err():
            failure = self._resolve_apply_failure(
                request,
                deployment,
                snapshot,
                gateway,
                field_name,
                details.get("expected_value", ""),
                apply_result.unwrap_err(),
            )
            if failure is not None:
                return failure

        # Step 3: Verify the remediated state (provider outcome + reachability)
        health_result = self._verify_remediation(
            deployment,
            gateway,
            field_name,
            details.get("expected_value", ""),
        )
        if health_result.is_err():
            # Err means the provider was OBSERVED in the wrong state — the only
            # verification outcome that justifies a destructive restore.
            return self._rollback_after_failure(
                request, deployment, snapshot, "Health check failed", health_result.unwrap_err()
            )
        inconclusive = health_result.unwrap()
        if inconclusive is not None:
            # Inconclusive (SSH silent, or provider unobservable): restoring the
            # snapshot would be a destructive response to ambiguity — staff check.
            self._mark_failed(request, inconclusive)
            return Err(inconclusive)

        # Step 4: Mark complete (CAS — a reaped/externally-transitioned row is
        # never overwritten, and its report stays open for the next scan)
        finalized = DriftRemediationRequest.objects.filter(pk=request.pk, status="in_progress").update(
            status="completed", completed_at=timezone.now()
        )
        if not finalized:
            request.refresh_from_db()
            logger.warning(
                f"⚠️ [DriftRemediation] Request {request.pk} finished but was externally "
                f"transitioned to '{request.status}' — not marking completed"
            )
            return Err(f"Request was externally transitioned to '{request.status}' during execution")
        request.refresh_from_db()

        # Mark the associated report as resolved — conditionally: a scan may
        # have healed it mid-execution, and "remediated" must not overwrite
        # that independent resolution.
        report = request.report
        resolved_now = DriftReport.objects.filter(pk=report.pk, resolved=False).update(
            resolved=True, resolved_at=timezone.now(), resolution_type="remediated"
        )
        if not resolved_now:
            logger.info(
                f"✅ [DriftRemediation] Report {report.pk} was already resolved externally — "
                "keeping its resolution; request completion stands"
            )

        logger.info(f"✅ [DriftRemediation] Remediation completed for {deployment.hostname}")

        try:
            InfrastructureAuditService.log_drift_remediation_applied(
                deployment, request, True, InfrastructureAuditContext()
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for completion: {e}")

        return Ok(True)

    def _claim_for_execution(
        self,
        request: DriftRemediationRequest,
        deployment: NodeDeployment,
    ) -> Result[bool, str]:
        """
        Atomically claim the request for execution. The conditional update
        (approved -> in_progress) is the portable correctness layer — SQLite's
        select_for_update is a no-op, so row locks alone cannot prevent a
        double claim. The deployment row lock serializes claims per deployment
        on PostgreSQL; the partial-unique in_progress constraint is the DB
        backstop.
        """
        now = timezone.now()
        stale_cutoff = now - timedelta(minutes=get_stale_after_minutes())

        with transaction.atomic():
            locked_deployment = NodeDeployment.objects.select_for_update().get(pk=deployment.pk)

            if locked_deployment.status != "completed":
                reason = f"Deployment {deployment.hostname} left scan scope (status '{locked_deployment.status}')"
                self._retire_approved(request, "superseded", reason)
                return Err(reason)

            report = DriftReport.objects.get(pk=request.report_id)
            if report.resolved:
                self._retire_approved(request, "superseded", "Drift report was resolved after approval")
                return Err("Drift report was resolved after approval — nothing left to remediate")

            details = request.action_details or {}
            fingerprint_stale = (
                details.get("field_name", "") != report.field_name
                or details.get("expected_value", "") != report.expected_value
                or details.get("actual_value", "") != report.actual_value
                # Legacy rows lack the severity key — only compare when present
                or ("severity" in details and details["severity"] != report.severity)
            )
            if fingerprint_stale:
                self._retire_approved(
                    request, "failed", "Drift changed since approval — the next scan mints a fresh request"
                )
                return Err("Drift changed since approval — stale request not executed")

            # Fresh in_progress sibling blocks; a stale one (crashed worker) is
            # reaped inline so a single stuck row can never block the
            # deployment forever.
            blocking = False
            siblings = (
                DriftRemediationRequest.objects.select_for_update()
                .filter(deployment=deployment, status="in_progress")
                .exclude(pk=request.pk)
            )
            for sibling in siblings:
                if sibling.started_at and sibling.started_at >= stale_cutoff:
                    blocking = True
                else:
                    self._mark_failed(
                        sibling,
                        "Remediation stuck in progress — auto-recovered (worker crash suspected)",
                    )
            if blocking:
                return Err("Another remediation is already in progress for this deployment")

            claimed = DriftRemediationRequest.objects.filter(pk=request.pk, status="approved").update(
                status="in_progress", started_at=now
            )
            if not claimed:
                request.refresh_from_db()
                return Err(f"Cannot execute remediation in status '{request.status}'")

        return Ok(True)

    def _retire_approved(self, request: DriftRemediationRequest, new_status: str, reason: str) -> None:
        """Retire an approved-but-unexecutable request (audited — it carried a human approval)."""
        fields = {"status": new_status}
        if new_status == "failed":
            fields["error_message"] = reason
        updated = DriftRemediationRequest.objects.filter(pk=request.pk, status="approved").update(
            **fields, completed_at=timezone.now()
        )
        if not updated:
            return
        request.refresh_from_db()
        try:
            InfrastructureAuditService.log_drift_remediation_failed(
                request.deployment, request, reason, InfrastructureAuditContext()
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for retired approval: {e}")

    def _rollback_after_failure(
        self,
        request: DriftRemediationRequest,
        deployment: NodeDeployment,
        snapshot: DriftSnapshot,
        stage: str,
        error: str,
    ) -> Result[bool, str]:
        """Shared apply/verify failure path: restore the snapshot, mark, audit.

        Last-moment preconditions: the claim-time checks are a snapshot in
        time, not a guard at the destructive action. Re-validate NOW that the
        drift is still unresolved and this request still owns the execution.
        """
        still_in_progress = DriftRemediationRequest.objects.filter(pk=request.pk, status="in_progress").exists()
        report_healed = DriftReport.objects.filter(pk=request.report_id, resolved=True).exists()
        if report_healed or not still_in_progress:
            if report_healed and still_in_progress:
                msg = f"{stage}: {error} — snapshot restore skipped: drift was resolved externally during execution"
                self._mark_failed(request, msg)
            else:
                msg = f"{stage}: {error} — snapshot restore skipped: request no longer owns this execution"
                logger.warning(f"⚠️ [DriftRemediation] {msg} (request {request.pk})")
            return Err(msg)

        logger.error(f"🔥 [DriftRemediation] {stage}, rolling back: {error}")
        rollback_result = self._rollback(deployment, snapshot.provider_snapshot_id)
        if rollback_result.is_err():
            logger.error(f"🔥 [DriftRemediation] Rollback failed: {rollback_result.unwrap_err()}")
            self._mark_rollback_failed(request, f"{stage} and rollback failed: {rollback_result.unwrap_err()}")
        else:
            self._mark_rolled_back(request, f"{stage} (rolled back): {error}")

        try:
            InfrastructureAuditService.log_drift_rollback_triggered(deployment, snapshot, InfrastructureAuditContext())
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for rollback after {stage.lower()}: {e}")

        return Err(error)

    def _take_snapshot(
        self,
        deployment: NodeDeployment,
    ) -> Result[DriftSnapshot, str]:
        """Call gateway.create_snapshot(), create DriftSnapshot record."""
        gateway = self._get_gateway(deployment)
        if gateway is None:
            return Err("Cannot get cloud gateway for snapshot")

        name = f"praho-drift-{deployment.hostname}-{timezone.now().strftime('%Y%m%d%H%M%S')}"
        result = gateway.create_snapshot(deployment.external_node_id, name)

        if result.is_err():
            return Err(f"Snapshot creation failed: {result.unwrap_err()}")

        snapshot = DriftSnapshot.objects.create(
            deployment=deployment,
            provider_snapshot_id=result.unwrap(),
            snapshot_type="pre_remediation",
            status="available",
            expires_at=timezone.now() + timedelta(days=SNAPSHOT_EXPIRY_DAYS),
        )

        logger.info(f"✅ [DriftRemediation] Snapshot created: {snapshot.provider_snapshot_id}")
        return Ok(snapshot)

    def _apply_remediation(
        self,
        request: DriftRemediationRequest,
        gateway: CloudProviderGateway,
    ) -> Result[bool, str]:
        """Execute the actual fix based on request.action_details."""
        details = request.action_details or {}
        field_name = details.get("field_name", "")
        expected_value = details.get("expected_value", "")
        deployment = request.deployment

        if field_name == "server_type" and expected_value:
            result = gateway.resize(deployment.external_node_id, expected_value)
            if result.is_err():
                return Err(f"Resize failed: {result.unwrap_err()}")
            return Ok(True)

        if field_name == "server_status" and expected_value == "running":
            result = gateway.power_on(deployment.external_node_id)
            if result.is_err():
                return Err(f"Power on failed: {result.unwrap_err()}")
            return Ok(True)

        # Defense-in-depth: execute_remediation pre-flights fixability, so an
        # unknown field reaching this point is a bug — never report success.
        return Err(f"No automated fix available for field '{field_name}'")

    def _verify_remediation(
        self,
        deployment: NodeDeployment,
        gateway: CloudProviderGateway,
        field_name: str,
        expected_value: str,
    ) -> Result[str | None, str]:
        """
        Verify the remediated STATE, not just liveness: poll the provider until the
        drifted field reports the expected value, then confirm SSH reachability.
        Bounded by a total wall-clock budget that includes an initial boot grace
        (power-on/resize reboots take time — an instant probe false-negatives and
        triggers a destructive snapshot rollback).

        Tri-state result: Ok(True) = fully verified; Ok(False) = the provider
        confirmed the outcome but reachability is inconclusive — the caller must
        fail WITHOUT a destructive snapshot restore; Err = the provider never
        confirmed the outcome (rollback is justified).
        """
        deadline = _monotonic() + _get_verify_max_wait()

        grace = min(_get_verify_boot_grace(), max(0.0, deadline - _monotonic()))
        if grace > 0:
            _sleep(grace)

        outcome_result = self._await_provider_outcome(deployment, gateway, field_name, expected_value, deadline)
        if outcome_result.is_err():
            return outcome_result

        unobservable = outcome_result.unwrap()
        if unobservable is not None:
            return Ok(unobservable)

        if not deployment.ipv4_address:
            # IPv6-only / address-less deployments cannot be probed; the
            # provider outcome is confirmed, which is all we can verify.
            logger.warning(
                f"⚠️ [DriftRemediation] {deployment.hostname} has no IPv4 address — "
                "skipping reachability probe after confirmed provider outcome"
            )
            return Ok(None)

        health_result = self._verify_health(deployment, deadline)
        if health_result.is_err():
            return Ok(
                f"Provider confirms the remediation of '{field_name}' but {deployment.hostname} "
                "is unreachable on port 22 — manual check required"
            )

        return Ok(None)

    def _resolve_apply_failure(  # noqa: PLR0913  # Destructive-decision context: every parameter is load-bearing
        self,
        request: DriftRemediationRequest,
        deployment: NodeDeployment,
        snapshot: DriftSnapshot,
        gateway: CloudProviderGateway,
        field_name: str,
        expected_value: str,
        error: str,
    ) -> Result[bool, str] | None:
        """Decide what a failed apply actually means before anything destructive.

        An apply Err is NOT proof the mutation failed: the provider may have
        accepted the action while our polling of it errored. Observe actual
        state once — None means the apply in fact landed and the caller should
        continue to verification.
        """
        observed = self._observe_field_once(gateway, deployment, field_name, expected_value)
        if observed is None:
            msg = (
                f"Apply failed and the provider state of '{field_name}' is unobservable — "
                f"manual intervention required (no destructive restore on ambiguity): {error}"
            )
            self._mark_failed(request, msg)
            return Err(msg)
        if observed is False:
            return self._rollback_after_failure(request, deployment, snapshot, "Apply failed", error)
        logger.warning(
            f"⚠️ [DriftRemediation] Apply reported an error but the provider already shows the "
            f"expected state for '{field_name}' on {deployment.hostname} — continuing to "
            f"verification: {error}"
        )
        return None

    def _observe_field_once(
        self,
        gateway: CloudProviderGateway,
        deployment: NodeDeployment,
        field_name: str,
        expected_value: str,
    ) -> bool | None:
        """One provider observation: True = matches, False = observed mismatched, None = unobservable."""
        server_result = gateway.get_server(deployment.external_node_id)
        if server_result.is_err():
            logger.warning(
                f"⚠️ [DriftRemediation] Cannot observe provider state for {deployment.hostname}: "
                f"{server_result.unwrap_err()}"
            )
            return None
        server_info = server_result.unwrap()
        if server_info is None:
            return None
        if field_name == "server_type":
            return bool(server_info.server_type == expected_value)
        if field_name == "server_status":
            return bool(server_info.status == "running")
        return None

    def _await_provider_outcome(
        self,
        deployment: NodeDeployment,
        gateway: CloudProviderGateway,
        field_name: str,
        expected_value: str,
        deadline: float,
    ) -> Result[str | None, str]:
        """Poll gateway.get_server() until the remediated field matches expectations.

        Ok(None): confirmed. Ok(message): provider NEVER observed — ambiguity,
        no restore. Err: provider observed in the wrong state — restore justified.
        """
        if field_name not in ("server_type", "server_status"):
            return Ok(None)

        observed_any = False
        last_observed = "unknown"
        last_error = ""
        while True:
            server_result = gateway.get_server(deployment.external_node_id)
            if server_result.is_err():
                last_error = str(server_result.unwrap_err())
                logger.warning(
                    f"⚠️ [DriftRemediation] get_server failed during verification of {deployment.hostname}: {last_error}"
                )
                server_info = None
            else:
                server_info = server_result.unwrap()
            if server_info is not None:
                observed_any = True
                if field_name == "server_type":
                    last_observed = server_info.server_type
                    if server_info.server_type == expected_value:
                        return Ok(None)
                else:
                    last_observed = server_info.status
                    if server_info.status == "running":
                        return Ok(None)

            remaining = deadline - _monotonic()
            if remaining <= 0:
                if not observed_any:
                    return Ok(
                        f"Provider state of '{field_name}' on {deployment.hostname} could not be "
                        f"observed during verification (last error: {last_error or 'none'}) — "
                        "manual check required"
                    )
                return Err(
                    f"Remediation of '{field_name}' on {deployment.hostname} not confirmed by provider "
                    f"(last observed: {last_observed})"
                )
            _sleep(min(_get_verify_poll_interval(), remaining))

    def _verify_health(
        self,
        deployment: NodeDeployment,
        deadline: float,
    ) -> Result[bool, str]:
        """TCP-probe port 22 until reachable or the verification deadline passes."""
        if not deployment.ipv4_address:
            return Err("No IP address to verify")

        while True:
            remaining = deadline - _monotonic()
            probe_timeout = min(_get_health_check_timeout(), max(1.0, remaining))
            try:
                with socket.create_connection(
                    (str(deployment.ipv4_address), 22),
                    timeout=probe_timeout,
                ):
                    pass
            except (OSError, TimeoutError):
                remaining = deadline - _monotonic()
                if remaining <= 0:
                    return Err(f"Server {deployment.hostname} unreachable on port 22 after remediation")
                _sleep(min(_get_verify_poll_interval(), remaining))
                continue

            return Ok(True)

    def _rollback(
        self,
        deployment: NodeDeployment,
        snapshot_id: str,
    ) -> Result[bool, str]:
        """Restore from snapshot via gateway.restore_snapshot()."""
        gateway = self._get_gateway(deployment)
        if gateway is None:
            return Err("Cannot get cloud gateway for rollback")

        result = gateway.restore_snapshot(deployment.external_node_id, snapshot_id)
        if result.is_err():
            logger.error(f"🔥 [DriftRemediation] Rollback failed: {result.unwrap_err()}")
            return Err(f"Rollback failed: {result.unwrap_err()}")

        logger.info(f"✅ [DriftRemediation] Rolled back {deployment.hostname} from snapshot {snapshot_id}")
        return Ok(True)

    def _get_gateway(self, deployment: NodeDeployment) -> CloudProviderGateway | None:
        """Get the cloud gateway for a deployment's provider."""
        try:
            provider = deployment.provider
            token_result = get_provider_token(provider)
            if token_result.is_err():
                return None
            return get_cloud_gateway(provider.provider_type, token_result.unwrap())
        except Exception as e:
            logger.error(f"🔥 [DriftRemediation] Gateway retrieval failed: {e}")
            return None

    def _finalize_from_in_progress(self, request: DriftRemediationRequest, new_status: str, error: str) -> bool:
        """
        Conditional terminal transition: only an in_progress row may be
        finalized, so a request the recovery task already reaped is never
        overwritten by a slow worker's stale result.
        """
        updated = DriftRemediationRequest.objects.filter(pk=request.pk, status="in_progress").update(
            status=new_status,
            error_message=error[:1000],
            completed_at=timezone.now(),
        )
        request.refresh_from_db()
        if not updated:
            logger.warning(
                f"⚠️ [DriftRemediation] Skipped marking request {request.pk} '{new_status}': "
                f"status is already '{request.status}'"
            )
            return False

        try:
            InfrastructureAuditService.log_drift_remediation_failed(
                request.deployment, request, error, InfrastructureAuditContext()
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for '{new_status}': {e}")
        return True

    def _mark_failed(self, request: DriftRemediationRequest, error: str) -> None:
        """Mark a remediation request as failed."""
        self._finalize_from_in_progress(request, "failed", error)

    def _mark_rolled_back(self, request: DriftRemediationRequest, error: str) -> None:
        """Mark a remediation request as rolled back after failure."""
        self._finalize_from_in_progress(request, "rolled_back", error)

    def _mark_rollback_failed(self, request: DriftRemediationRequest, error: str) -> None:
        """Mark a remediation request as rollback_failed when rollback itself fails."""
        logger.error(f"🔥 [DriftRemediation] Rollback failed for {request.deployment.hostname}: {error}")
        self._finalize_from_in_progress(request, "rollback_failed", error)


# Module-level singleton
_remediation_service: DriftRemediationService | None = None


def get_drift_remediation_service() -> DriftRemediationService:
    """Get global drift remediation service instance."""
    global _remediation_service  # noqa: PLW0603  # Module-level singleton pattern
    if _remediation_service is None:
        _remediation_service = DriftRemediationService()
    return _remediation_service
