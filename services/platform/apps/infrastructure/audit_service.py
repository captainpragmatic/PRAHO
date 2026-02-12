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
from typing import TYPE_CHECKING, Any

from django.utils import timezone

from apps.audit.services import AuditService
from apps.common.request_ip import get_safe_client_ip

if TYPE_CHECKING:
    from django.http import HttpRequest

    from apps.audit.models import AuditEvent
    from apps.infrastructure.models import (
        CloudProvider,
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

    def __post_init__(self):
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
    SEVERITY_MAP = {
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
                "virtualmin_server_id": str(deployment.virtualmin_server_id) if deployment.virtualmin_server_id else None,
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

    @classmethod
    def _create_event(
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
    ) -> Any:
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
    global _audit_service
    if _audit_service is None:
        _audit_service = InfrastructureAuditService()
    return _audit_service
