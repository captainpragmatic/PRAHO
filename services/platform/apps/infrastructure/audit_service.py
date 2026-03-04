"""
Infrastructure Audit Service

Provides audit logging for infrastructure operations:
- Node deployment lifecycle events
- Provider and configuration changes
- SSH key management
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from apps.audit.services import AuditService
from apps.common.request_ip import get_safe_client_ip

if TYPE_CHECKING:
    from apps.audit.models import AuditEvent
    from apps.infrastructure.models import (
        CloudProvider,
        DriftRemediationRequest,
        DriftReport,
        DriftSnapshot,
        NodeDeployment,
        NodeRegion,
        NodeSize,
    )
    from apps.users.models import User

logger = logging.getLogger(__name__)


@dataclass
class InfrastructureAuditContext:
    """Context information for infrastructure audit events"""

    user: User | None = None
    request: Any = None
    ip_address: str | None = None
    user_agent: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Extract IP and user agent from request if available"""
        if self.request and not self.ip_address:
            self.ip_address = get_safe_client_ip(self.request)
        if self.request and not self.user_agent:
            self.user_agent = self.request.META.get("HTTP_USER_AGENT", "")


class InfrastructureAuditService:
    """
    Audit service for infrastructure operations.

    Provides methods to log:
    - Deployment lifecycle events
    - Provider/region/size changes
    - SSH key operations
    """

    # Category for all infrastructure events
    CATEGORY = "system_admin"

    # Severity mapping for different event types
    SEVERITY_MAP: ClassVar[dict[str, str]] = {
        "node_deployment_created": "medium",
        "node_deployment_started": "low",
        "node_deployment_completed": "medium",
        "node_deployment_failed": "high",
        "node_deployment_retry": "medium",
        "node_destroy_started": "high",
        "node_destroy_completed": "high",
        "node_destroy_failed": "critical",
        "cloud_provider_created": "medium",
        "cloud_provider_updated": "medium",
        "cloud_provider_deleted": "high",
        "infrastructure_ssh_key_generated": "medium",
        "infrastructure_ssh_key_revoked": "medium",
        "drift_detected": "medium",
        "drift_auto_resolved": "low",
        "drift_remediation_requested": "medium",
        "drift_remediation_approved": "medium",
        "drift_remediation_applied": "medium",
        "drift_remediation_failed": "high",
        "drift_rollback_triggered": "critical",
        "drift_accepted": "low",
        "drift_remediation_rejected": "medium",
        "drift_remediation_scheduled": "medium",
        "drift_scan_started": "low",
        "drift_scan_completed": "low",
        "node_upgrade_started": "medium",
        "node_upgrade_completed": "medium",
        "node_upgrade_failed": "high",
        "node_stop_started": "low",
        "node_stop_completed": "low",
        "node_stop_failed": "medium",
        "node_start_completed": "low",
        "node_start_failed": "medium",
        "node_reboot_completed": "low",
        "node_reboot_failed": "medium",
        "node_maintenance_started": "low",
        "node_maintenance_completed": "low",
        "node_maintenance_failed": "medium",
    }

    @classmethod
    def log_deployment_created(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node deployment creation"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_deployment_created",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Created node deployment: {deployment.hostname}",
            new_values={
                "hostname": deployment.hostname,
                "environment": deployment.environment,
                "node_type": deployment.node_type,
                "provider": deployment.provider.name if deployment.provider else None,
                "region": deployment.region.name if deployment.region else None,
                "node_size": deployment.node_size.name if deployment.node_size else None,
            },
            metadata={
                **context.metadata,
                "initiated_by": str(deployment.initiated_by_id) if deployment.initiated_by_id else None,
            },
        )

    @classmethod
    def log_deployment_started(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log deployment provisioning started"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_deployment_started",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Started provisioning: {deployment.hostname}",
            metadata=context.metadata,
        )

    @classmethod
    def log_deployment_completed(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
        duration_seconds: float | None = None,
    ) -> AuditEvent:
        """Log successful deployment completion"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_deployment_completed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Deployment completed: {deployment.hostname}",
            new_values={
                "ipv4_address": deployment.ipv4_address,
                "ipv6_address": deployment.ipv6_address,
                "virtualmin_server_id": str(deployment.virtualmin_server_id)
                if deployment.virtualmin_server_id
                else None,
            },
            metadata={
                **context.metadata,
                "duration_seconds": duration_seconds,
            },
        )

    @classmethod
    def log_deployment_failed(
        cls,
        deployment: NodeDeployment,
        error_message: str,
        stage: str,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log deployment failure"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_deployment_failed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Deployment failed: {deployment.hostname} at stage '{stage}'",
            severity="high",
            metadata={
                **context.metadata,
                "error_message": error_message[:1000],  # Truncate long errors
                "failed_stage": stage,
                "retry_count": deployment.retry_count,
            },
        )

    @classmethod
    def log_deployment_retry(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log deployment retry attempt"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_deployment_retry",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Retrying deployment: {deployment.hostname} (attempt {deployment.retry_count})",
            metadata={
                **context.metadata,
                "retry_count": deployment.retry_count,
            },
        )

    @classmethod
    def log_destroy_started(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node destruction started"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_destroy_started",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Started destruction: {deployment.hostname}",
            severity="high",
            old_values={
                "hostname": deployment.hostname,
                "ipv4_address": deployment.ipv4_address,
                "status": deployment.status,
            },
            metadata=context.metadata,
        )

    @classmethod
    def log_destroy_completed(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log successful node destruction"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_destroy_completed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Node destroyed: {deployment.hostname}",
            severity="high",
            metadata=context.metadata,
        )

    @classmethod
    def log_destroy_failed(
        cls,
        deployment: NodeDeployment,
        error_message: str,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log destruction failure"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_destroy_failed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Destruction failed: {deployment.hostname}",
            severity="critical",
            metadata={
                **context.metadata,
                "error_message": error_message[:1000],
            },
        )

    @classmethod
    def log_provider_created(
        cls,
        provider: CloudProvider,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log cloud provider creation"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="cloud_provider_created",
            content_object=provider,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Created cloud provider: {provider.name}",
            new_values={
                "name": provider.name,
                "code": provider.code,
                "provider_type": provider.provider_type,
                "is_active": provider.is_active,
            },
            metadata=context.metadata,
        )

    @classmethod
    def log_provider_updated(
        cls,
        provider: CloudProvider,
        old_values: dict[str, Any],
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log cloud provider update"""
        context = context or InfrastructureAuditContext()

        new_values = {
            "name": provider.name,
            "code": provider.code,
            "provider_type": provider.provider_type,
            "is_active": provider.is_active,
        }

        return cls._create_event(
            action="cloud_provider_updated",
            content_object=provider,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Updated cloud provider: {provider.name}",
            old_values=old_values,
            new_values=new_values,
            metadata=context.metadata,
        )

    @classmethod
    def log_size_created(
        cls,
        size: NodeSize,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node size creation"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_size_created",
            content_object=size,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Created node size: {size.name} ({size.provider.name})",
            new_values={
                "name": size.name,
                "provider": size.provider.name,
                "vcpus": size.vcpus,
                "memory_gb": size.memory_gb,
                "disk_gb": size.disk_gb,
                "monthly_cost_eur": str(size.monthly_cost_eur),
            },
            metadata=context.metadata,
        )

    @classmethod
    def log_size_updated(
        cls,
        size: NodeSize,
        old_values: dict[str, Any],
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node size update"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_size_updated",
            content_object=size,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Updated node size: {size.name}",
            old_values=old_values,
            new_values={
                "name": size.name,
                "vcpus": size.vcpus,
                "memory_gb": size.memory_gb,
                "disk_gb": size.disk_gb,
                "monthly_cost_eur": str(size.monthly_cost_eur),
                "is_active": size.is_active,
            },
            metadata=context.metadata,
        )

    @classmethod
    def log_region_toggled(
        cls,
        region: NodeRegion,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log region enabled/disabled"""
        context = context or InfrastructureAuditContext()

        action_desc = "enabled" if region.is_active else "disabled"

        return cls._create_event(
            action="node_region_toggled",
            content_object=region,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Region {action_desc}: {region.name} ({region.provider.name})",
            new_values={
                "is_active": region.is_active,
            },
            metadata=context.metadata,
        )

    @classmethod
    def log_ssh_key_generated(
        cls,
        deployment: NodeDeployment,
        fingerprint: str,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log SSH key generation"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="infrastructure_ssh_key_generated",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"SSH key generated for: {deployment.hostname}",
            new_values={
                "fingerprint": fingerprint,
            },
            metadata=context.metadata,
            is_sensitive=True,
        )

    @classmethod
    def log_ssh_key_revoked(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log SSH key revocation"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="infrastructure_ssh_key_revoked",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"SSH key revoked for: {deployment.hostname}",
            metadata=context.metadata,
            is_sensitive=True,
        )

    # =========================================================================
    # Node lifecycle audit methods (upgrade, stop, start, reboot, maintenance)
    # =========================================================================

    @classmethod
    def log_node_upgrade_started(
        cls,
        deployment: NodeDeployment,
        old_size: NodeSize,
        new_size: NodeSize,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node size upgrade started"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_upgrade_started",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Started node size upgrade: {deployment.hostname} ({old_size.name} → {new_size.name})",
            old_values={"node_size": old_size.name},
            new_values={"node_size": new_size.name},
            metadata=context.metadata,
        )

    @classmethod
    def log_node_upgrade_completed(
        cls,
        deployment: NodeDeployment,
        old_size: NodeSize,
        new_size: NodeSize,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node size upgrade completed"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_upgrade_completed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Node size upgrade completed: {deployment.hostname} ({old_size.name} → {new_size.name})",
            old_values={"node_size": old_size.name},
            new_values={"node_size": new_size.name},
            metadata=context.metadata,
        )

    @classmethod
    def log_node_upgrade_failed(
        cls,
        deployment: NodeDeployment,
        error_message: str,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node size upgrade failure"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_upgrade_failed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Node size upgrade failed: {deployment.hostname}",
            severity="high",
            metadata={
                **context.metadata,
                "error_message": error_message[:1000],
            },
        )

    @classmethod
    def log_node_stop_started(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node stop (power off) started"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_stop_started",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Started stopping node: {deployment.hostname}",
            metadata=context.metadata,
        )

    @classmethod
    def log_node_stop_completed(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node stop (power off) completed"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_stop_completed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Node stopped successfully: {deployment.hostname}",
            metadata=context.metadata,
        )

    @classmethod
    def log_node_stop_failed(
        cls,
        deployment: NodeDeployment,
        error_message: str,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node stop (power off) failure"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_stop_failed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Node stop failed: {deployment.hostname}",
            metadata={
                **context.metadata,
                "error_message": error_message[:1000],
            },
        )

    @classmethod
    def log_node_start_completed(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node start (power on) completed"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_start_completed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Node started successfully: {deployment.hostname}",
            metadata=context.metadata,
        )

    @classmethod
    def log_node_start_failed(
        cls,
        deployment: NodeDeployment,
        error_message: str,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node start (power on) failure"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_start_failed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Node start failed: {deployment.hostname}",
            metadata={
                **context.metadata,
                "error_message": error_message[:1000],
            },
        )

    @classmethod
    def log_node_reboot_completed(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node reboot completed"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_reboot_completed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Node rebooted successfully: {deployment.hostname}",
            metadata=context.metadata,
        )

    @classmethod
    def log_node_reboot_failed(
        cls,
        deployment: NodeDeployment,
        error_message: str,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node reboot failure"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_reboot_failed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Node reboot failed: {deployment.hostname}",
            metadata={
                **context.metadata,
                "error_message": error_message[:1000],
            },
        )

    @classmethod
    def log_node_maintenance_started(
        cls,
        deployment: NodeDeployment,
        playbooks: list[str],
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node maintenance started"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_maintenance_started",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Started maintenance on {deployment.hostname}: {', '.join(playbooks)}",
            metadata={
                **context.metadata,
                "playbooks": playbooks,
            },
        )

    @classmethod
    def log_node_maintenance_completed(
        cls,
        deployment: NodeDeployment,
        playbooks: list[str],
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node maintenance completed"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_maintenance_completed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Maintenance completed on {deployment.hostname}: {', '.join(playbooks)}",
            metadata={
                **context.metadata,
                "playbooks": playbooks,
            },
        )

    @classmethod
    def log_node_maintenance_failed(
        cls,
        deployment: NodeDeployment,
        playbooks: list[str],
        error_message: str,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log node maintenance failure"""
        context = context or InfrastructureAuditContext()

        return cls._create_event(
            action="node_maintenance_failed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Maintenance failed on {deployment.hostname}",
            metadata={
                **context.metadata,
                "playbooks": playbooks,
                "error_message": error_message[:1000],
            },
        )

    # =========================================================================
    # Drift Detection & Remediation audit methods
    # =========================================================================

    @classmethod
    def log_drift_detected(
        cls,
        deployment: NodeDeployment,
        drift_report: DriftReport,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log drift detection event."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_detected",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Drift detected on {deployment.hostname}: {drift_report.field_name} ({drift_report.severity})",
            metadata={
                **context.metadata,
                "field_name": drift_report.field_name,
                "severity": drift_report.severity,
                "expected": drift_report.expected_value[:200],
                "actual": drift_report.actual_value[:200],
            },
        )

    @classmethod
    def log_drift_auto_resolved(
        cls,
        deployment: NodeDeployment,
        drift_report: DriftReport,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log automatic drift resolution."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_auto_resolved",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Drift auto-resolved on {deployment.hostname}: {drift_report.field_name}",
            metadata={
                **context.metadata,
                "field_name": drift_report.field_name,
                "severity": drift_report.severity,
            },
        )

    @classmethod
    def log_drift_remediation_requested(
        cls,
        deployment: NodeDeployment,
        request: DriftRemediationRequest,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log remediation request creation."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_remediation_requested",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Remediation requested for {deployment.hostname}: {request.action_type}",
            metadata={
                **context.metadata,
                "action_type": request.action_type,
                "requires_approval": request.requires_approval,
                "requires_restart": request.requires_restart,
            },
        )

    @classmethod
    def log_drift_remediation_approved(
        cls,
        deployment: NodeDeployment,
        request: DriftRemediationRequest,
        approver: User,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log remediation approval."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_remediation_approved",
            content_object=deployment,
            user=approver,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Remediation approved for {deployment.hostname} by {approver.email}",
            metadata=context.metadata,
        )

    @classmethod
    def log_drift_remediation_applied(
        cls,
        deployment: NodeDeployment,
        request: DriftRemediationRequest,
        result: Any,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log successful remediation execution."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_remediation_applied",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Remediation applied on {deployment.hostname}",
            metadata={
                **context.metadata,
                "action_type": request.action_type,
                "snapshot_id": request.snapshot_id,
            },
        )

    @classmethod
    def log_drift_remediation_failed(
        cls,
        deployment: NodeDeployment,
        request: DriftRemediationRequest,
        error: str,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log remediation failure."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_remediation_failed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Remediation failed on {deployment.hostname}",
            severity="high",
            metadata={
                **context.metadata,
                "error": error[:1000],
            },
        )

    @classmethod
    def log_drift_rollback_triggered(
        cls,
        deployment: NodeDeployment,
        snapshot: DriftSnapshot,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log snapshot rollback triggered."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_rollback_triggered",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Rollback triggered on {deployment.hostname} from snapshot {snapshot.provider_snapshot_id}",
            severity="critical",
            metadata={
                **context.metadata,
                "snapshot_id": snapshot.provider_snapshot_id,
            },
        )

    @classmethod
    def log_drift_accepted(
        cls,
        deployment: NodeDeployment,
        drift_report: DriftReport,
        admin: User,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log drift acceptance (admin chose to keep actual state)."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_accepted",
            content_object=deployment,
            user=admin,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Drift accepted on {deployment.hostname}: {drift_report.field_name} by {admin.email}",
            metadata={
                **context.metadata,
                "field_name": drift_report.field_name,
                "actual_value": drift_report.actual_value[:200],
            },
        )

    @classmethod
    def log_drift_remediation_rejected(
        cls,
        deployment: NodeDeployment,
        request: DriftRemediationRequest,
        rejector: User,
        reason: str = "",
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log remediation rejection."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_remediation_rejected",
            content_object=deployment,
            user=rejector,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Remediation rejected for {deployment.hostname} by {rejector.email}",
            metadata={
                **context.metadata,
                "action_type": request.action_type,
                "reason": reason[:500],
            },
        )

    @classmethod
    def log_drift_remediation_scheduled(
        cls,
        deployment: NodeDeployment,
        request: DriftRemediationRequest,
        scheduled_for: str = "",
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log remediation scheduled for later execution."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_remediation_scheduled",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Remediation scheduled for {deployment.hostname}",
            metadata={
                **context.metadata,
                "action_type": request.action_type,
                "scheduled_for": scheduled_for,
            },
        )

    @classmethod
    def log_drift_scan_started(
        cls,
        deployment: NodeDeployment,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log drift scan started."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_scan_started",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Drift scan started for {deployment.hostname}",
            metadata=context.metadata,
        )

    @classmethod
    def log_drift_scan_completed(
        cls,
        deployment: NodeDeployment,
        drift_count: int = 0,
        context: InfrastructureAuditContext | None = None,
    ) -> AuditEvent:
        """Log drift scan completed."""
        context = context or InfrastructureAuditContext()
        return cls._create_event(
            action="drift_scan_completed",
            content_object=deployment,
            user=context.user,
            ip_address=context.ip_address,
            user_agent=context.user_agent or "",
            description=f"Drift scan completed for {deployment.hostname}: {drift_count} findings",
            metadata={
                **context.metadata,
                "drift_count": drift_count,
            },
        )

    @classmethod
    def _create_event(  # audit trail fields  # noqa: PLR0913  # Business logic parameters
        cls,
        action: str,
        content_object: Any,
        user: User | None = None,
        ip_address: str | None = None,
        user_agent: str = "",
        description: str = "",
        old_values: dict[str, Any] | None = None,
        new_values: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        severity: str | None = None,
        is_sensitive: bool = False,
    ) -> AuditEvent:
        """Create and save an audit event via the central audit service"""
        if severity is None:
            severity = cls.SEVERITY_MAP.get(action, "low")

        audit_metadata = dict(metadata or {})
        audit_metadata["category"] = cls.CATEGORY
        audit_metadata["severity"] = severity
        audit_metadata["is_sensitive"] = is_sensitive
        if user_agent:
            audit_metadata["user_agent"] = user_agent

        event = AuditService.log_simple_event(
            action,
            user=user,
            content_object=content_object,
            description=description,
            old_values=old_values,
            new_values=new_values,
            metadata=audit_metadata,
            ip_address=ip_address,
            actor_type="user" if user else "system",
        )

        logger.info(f"[Audit] {action}: {description}")
        return event


# Module-level singleton
_audit_service: InfrastructureAuditService | None = None


def get_infrastructure_audit_service() -> InfrastructureAuditService:
    """Get global infrastructure audit service instance"""
    global _audit_service  # noqa: PLW0603  # Module-level singleton pattern
    if _audit_service is None:
        _audit_service = InfrastructureAuditService()
    return _audit_service
