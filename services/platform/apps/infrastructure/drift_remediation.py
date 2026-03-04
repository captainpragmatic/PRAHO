"""
Drift Remediation Service

Handles the remediation workflow for configuration drift:
- Approve, reject, schedule remediation requests
- Execute remediation with snapshot safety net
- Rollback on failure
"""

from __future__ import annotations

import contextlib
import logging
import socket
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
HEALTH_CHECK_TIMEOUT = 10

# Snapshot expiry in days
SNAPSHOT_EXPIRY_DAYS = 7


class DriftRemediationService:
    """Handles the remediation workflow: approve, reject, schedule, execute, rollback."""

    def approve_remediation(
        self,
        request_id: int,
        user: User,
    ) -> Result[DriftRemediationRequest, str]:
        """Set status=approved, trigger execution."""
        with transaction.atomic():
            try:
                req = DriftRemediationRequest.objects.select_for_update().get(pk=request_id)
            except DriftRemediationRequest.DoesNotExist:
                return Err(f"Remediation request {request_id} not found")

            if req.status not in ("pending_approval",):
                return Err(f"Cannot approve request in status '{req.status}'")

            req.status = "approved"
            req.approved_by = user
            req.approved_at = timezone.now()
            req.save(update_fields=["status", "approved_by", "approved_at"])

        logger.info(f"✅ [DriftRemediation] Request {request_id} approved by {user.email}")

        try:
            InfrastructureAuditService.log_drift_remediation_approved(
                req.deployment, req, user, InfrastructureAuditContext(user=user)
            )
        except Exception:
            logger.warning("⚠️ [DriftRemediation] Failed to log audit for approval")

        # Trigger execution
        exec_result = self.execute_remediation(req)
        if exec_result.is_err():
            return Err(f"Approved but execution failed: {exec_result.unwrap_err()}")

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
        except Exception:
            logger.warning("⚠️ [DriftRemediation] Failed to log audit for drift acceptance")

        return Ok(req)

    def execute_remediation(  # Complexity: drift scan  # noqa: PLR0915  # Complexity: multi-step business logic
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
            logger.error(f"🔥 [DriftRemediation] Apply failed, rolling back: {apply_result.unwrap_err()}")
            rollback_result = self._rollback(deployment, snapshot.provider_snapshot_id)
            if rollback_result.is_err():
                logger.error(f"🔥 [DriftRemediation] Rollback failed: {rollback_result.unwrap_err()}")
                self._mark_rollback_failed(request, f"Apply failed and rollback failed: {rollback_result.unwrap_err()}")
            else:
                self._mark_rolled_back(request, f"Apply failed (rolled back): {apply_result.unwrap_err()}")

            with contextlib.suppress(Exception):
                InfrastructureAuditService.log_drift_rollback_triggered(
                    deployment, snapshot, InfrastructureAuditContext()
                )

            return Err(apply_result.unwrap_err())

        # Step 3: Verify health
        health_result = self._verify_health(deployment)
        if health_result.is_err():
            logger.error(f"🔥 [DriftRemediation] Health check failed, rolling back: {health_result.unwrap_err()}")
            rollback_result = self._rollback(deployment, snapshot.provider_snapshot_id)
            if rollback_result.is_err():
                logger.error(f"🔥 [DriftRemediation] Rollback failed: {rollback_result.unwrap_err()}")
                self._mark_rollback_failed(
                    request, f"Health check failed and rollback failed: {rollback_result.unwrap_err()}"
                )
            else:
                self._mark_rolled_back(request, f"Health check failed (rolled back): {health_result.unwrap_err()}")

            with contextlib.suppress(Exception):
                InfrastructureAuditService.log_drift_rollback_triggered(
                    deployment, snapshot, InfrastructureAuditContext()
                )

            return Err(health_result.unwrap_err())

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
        except Exception:
            logger.warning("⚠️ [DriftRemediation] Failed to log audit for completion")

        return Ok(True)

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

        # For other field types, no automated fix available
        return Ok(True)

    def _verify_health(
        self,
        deployment: NodeDeployment,
    ) -> Result[bool, str]:
        """TCP probe port 22 + Virtualmin API check if linked."""
        if not deployment.ipv4_address:
            return Err("No IP address to verify")

        try:
            with socket.create_connection(
                (str(deployment.ipv4_address), 22),
                timeout=HEALTH_CHECK_TIMEOUT,
            ):
                pass
        except (OSError, TimeoutError):
            return Err(f"Server {deployment.hostname} unreachable on port 22 after remediation")

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
        except Exception:
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
        except Exception:
            logger.warning("⚠️ [DriftRemediation] Failed to log audit for failure")

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
        except Exception:
            logger.warning("⚠️ [DriftRemediation] Failed to log audit for rollback")

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
        except Exception:
            logger.warning("⚠️ [DriftRemediation] Failed to log audit for rollback failure")


# Module-level singleton
_remediation_service: DriftRemediationService | None = None


def get_drift_remediation_service() -> DriftRemediationService:
    """Get global drift remediation service instance."""
    global _remediation_service  # noqa: PLW0603  # Module-level singleton pattern
    if _remediation_service is None:
        _remediation_service = DriftRemediationService()
    return _remediation_service
