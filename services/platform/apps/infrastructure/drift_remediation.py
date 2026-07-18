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

from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.audit_service import InfrastructureAuditContext, InfrastructureAuditService
from apps.infrastructure.cloud_gateway import CloudProviderGateway, get_cloud_gateway
from apps.infrastructure.models import (
    DriftRemediationRequest,
    DriftSnapshot,
)
from apps.infrastructure.provider_config import get_provider_token

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment
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

        if req.status not in ("pending_approval",):
            return Err(f"Cannot reject request in status '{req.status}'")

        req.status = "rejected"
        req.rejected_reason = reason
        req.save(update_fields=["status", "rejected_reason"])

        InfrastructureAuditService.log_drift_remediation_rejected(
            deployment=req.deployment,
            request=req,
            rejector=user,
            reason=reason,
        )

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

        if req.status not in ("pending_approval", "approved"):
            return Err(f"Cannot schedule request in status '{req.status}'")

        if req.action_type != "apply_desired":
            return Err("This drift has no automated fix — scheduling it would execute a no-op")

        req.status = "scheduled"
        req.scheduled_for = scheduled_for
        req.approved_by = user
        req.approved_at = timezone.now()
        req.save(update_fields=["status", "scheduled_for", "approved_by", "approved_at"])

        InfrastructureAuditService.log_drift_remediation_scheduled(
            deployment=req.deployment,
            request=req,
            scheduled_for=str(scheduled_for),
        )

        logger.info(f"✅ [DriftRemediation] Request {request_id} scheduled for {scheduled_for}")
        return Ok(req)

    def accept_drift(
        self,
        request_id: int,
        user: User,
    ) -> Result[DriftRemediationRequest, str]:
        """Update DB to match reality (accept actual state), mark resolved."""
        try:
            req = DriftRemediationRequest.objects.select_related("report", "deployment").get(pk=request_id)
        except DriftRemediationRequest.DoesNotExist:
            return Err(f"Remediation request {request_id} not found")

        if req.status not in ("pending_approval",):
            return Err(f"Cannot accept drift for request in status '{req.status}'")

        report = req.report
        report.resolved = True
        report.resolved_at = timezone.now()
        report.resolved_by = user
        report.resolution_type = "accepted"
        report.save(update_fields=["resolved", "resolved_at", "resolved_by", "resolution_type"])

        req.status = "completed"
        req.action_type = "accept_actual"
        req.completed_at = timezone.now()
        req.save(update_fields=["status", "action_type", "completed_at"])

        logger.info(f"✅ [DriftRemediation] Drift accepted for {req.deployment.hostname} by {user.email}")

        try:
            InfrastructureAuditService.log_drift_accepted(
                req.deployment, report, user, InfrastructureAuditContext(user=user)
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for drift acceptance: {e}")

        return Ok(req)

    def execute_remediation(  # noqa: PLR0911  # Multi-step workflow: each gate exits early
        self,
        request: DriftRemediationRequest,
    ) -> Result[bool, str]:
        """
        Execute remediation: snapshot -> apply -> verify -> audit.
        Rollback on failure.
        """
        deployment = request.deployment

        # Prevent concurrent remediation on same deployment
        with transaction.atomic():
            active = (
                DriftRemediationRequest.objects.select_for_update()
                .filter(deployment=deployment, status="in_progress")
                .exclude(pk=request.pk)
                .exists()
            )
            if active:
                return Err("Another remediation is already in progress for this deployment")

            request.status = "in_progress"
            request.started_at = timezone.now()
            request.save(update_fields=["status", "started_at"])

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
            return self._rollback_after_failure(
                request, deployment, snapshot, "Apply failed", apply_result.unwrap_err()
            )

        # Step 3: Verify the remediated state (provider outcome + reachability)
        health_result = self._verify_remediation(
            deployment,
            gateway,
            field_name,
            details.get("expected_value", ""),
        )
        if health_result.is_err():
            return self._rollback_after_failure(
                request, deployment, snapshot, "Health check failed", health_result.unwrap_err()
            )

        # Step 4: Mark complete
        request.status = "completed"
        request.completed_at = timezone.now()
        request.save(update_fields=["status", "completed_at"])

        # Mark the associated report as resolved
        report = request.report
        report.resolved = True
        report.resolved_at = timezone.now()
        report.resolution_type = "remediated"
        report.save(update_fields=["resolved", "resolved_at", "resolution_type"])

        logger.info(f"✅ [DriftRemediation] Remediation completed for {deployment.hostname}")

        try:
            InfrastructureAuditService.log_drift_remediation_applied(
                deployment, request, True, InfrastructureAuditContext()
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for completion: {e}")

        return Ok(True)

    def _rollback_after_failure(
        self,
        request: DriftRemediationRequest,
        deployment: NodeDeployment,
        snapshot: DriftSnapshot,
        stage: str,
        error: str,
    ) -> Result[bool, str]:
        """Shared apply/verify failure path: restore the snapshot, mark, audit."""
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
    ) -> Result[bool, str]:
        """
        Verify the remediated STATE, not just liveness: poll the provider until the
        drifted field reports the expected value, then confirm SSH reachability.
        Bounded by a total wall-clock budget that includes an initial boot grace
        (power-on/resize reboots take time — an instant probe false-negatives and
        triggers a destructive snapshot rollback).
        """
        deadline = _monotonic() + _get_verify_max_wait()

        grace = min(_get_verify_boot_grace(), max(0.0, deadline - _monotonic()))
        if grace > 0:
            _sleep(grace)

        outcome_result = self._await_provider_outcome(deployment, gateway, field_name, expected_value, deadline)
        if outcome_result.is_err():
            return outcome_result

        return self._verify_health(deployment, deadline)

    def _await_provider_outcome(
        self,
        deployment: NodeDeployment,
        gateway: CloudProviderGateway,
        field_name: str,
        expected_value: str,
        deadline: float,
    ) -> Result[bool, str]:
        """Poll gateway.get_server() until the remediated field matches expectations."""
        if field_name not in ("server_type", "server_status"):
            return Ok(True)

        last_observed = "unknown"
        while True:
            server_result = gateway.get_server(deployment.external_node_id)
            if server_result.is_ok() and server_result.unwrap() is not None:
                server_info = server_result.unwrap()
                if field_name == "server_type":
                    last_observed = server_info.server_type
                    if server_info.server_type == expected_value:
                        return Ok(True)
                else:
                    last_observed = server_info.status
                    if server_info.status == "running":
                        return Ok(True)

            remaining = deadline - _monotonic()
            if remaining <= 0:
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

    def _mark_failed(self, request: DriftRemediationRequest, error: str) -> None:
        """Mark a remediation request as failed."""
        request.status = "failed"
        request.error_message = error[:1000]
        request.completed_at = timezone.now()
        request.save(update_fields=["status", "error_message", "completed_at"])

        try:
            InfrastructureAuditService.log_drift_remediation_failed(
                request.deployment, request, error, InfrastructureAuditContext()
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for failure: {e}")

    def _mark_rolled_back(self, request: DriftRemediationRequest, error: str) -> None:
        """Mark a remediation request as rolled back after failure."""
        request.status = "rolled_back"
        request.error_message = error[:1000]
        request.completed_at = timezone.now()
        request.save(update_fields=["status", "error_message", "completed_at"])

        try:
            InfrastructureAuditService.log_drift_remediation_failed(
                request.deployment, request, error, InfrastructureAuditContext()
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for rollback: {e}")

    def _mark_rollback_failed(self, request: DriftRemediationRequest, error: str) -> None:
        """Mark a remediation request as rollback_failed when rollback itself fails."""
        request.status = "rollback_failed"
        request.error_message = error[:1000]
        request.completed_at = timezone.now()
        request.save(update_fields=["status", "error_message", "completed_at"])

        logger.error(f"🔥 [DriftRemediation] Rollback failed for {request.deployment.hostname}: {error}")

        try:
            InfrastructureAuditService.log_drift_remediation_failed(
                request.deployment, request, error, InfrastructureAuditContext()
            )
        except Exception as e:
            logger.warning(f"⚠️ [DriftRemediation] Failed to log audit for rollback failure: {e}")


# Module-level singleton
_remediation_service: DriftRemediationService | None = None


def get_drift_remediation_service() -> DriftRemediationService:
    """Get global drift remediation service instance."""
    global _remediation_service  # noqa: PLW0603  # Module-level singleton pattern
    if _remediation_service is None:
        _remediation_service = DriftRemediationService()
    return _remediation_service
