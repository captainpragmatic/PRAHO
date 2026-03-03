"""
Infrastructure App

Automated infrastructure deployment and management for PRAHO platform.
Handles cloud provider integration, node deployment, and lifecycle management.

Supports:
- Hetzner Cloud (with extensibility for DigitalOcean, AWS, etc.)
- Virtualmin GPL panel installation via Ansible
- Terraform-based infrastructure provisioning

Note: Imports are lazy to avoid Django AppRegistryNotReady issues during testing.
Use `from apps.infrastructure.models import CloudProvider` for direct imports.
"""

from typing import Any

__all__ = [
    "AnsibleResult",
    # Ansible
    "AnsibleService",
    # Models
    "CloudProvider",
    "CostSummary",
    # Cost Tracking
    "CostTrackingService",
    "DeploymentCostBreakdown",
    "DeploymentProgress",
    "DeploymentResult",
    "InfrastructureAuditContext",
    # Audit
    "InfrastructureAuditService",
    "NodeDeployment",
    "NodeDeploymentCostRecord",
    "NodeDeploymentLog",
    # Deployment Orchestration
    "NodeDeploymentService",
    "NodeRegion",
    # Registration
    "NodeRegistrationService",
    "NodeSize",
    "NodeValidationReport",
    # Validation
    "NodeValidationService",
    "PanelType",
    "SSHKeyInfo",
    # SSH Key Management
    "SSHKeyManager",
    "SSHKeyPair",
    "TerraformResult",
    # Terraform
    "TerraformService",
    "ValidationResult",
    "can_deploy_nodes",
    "can_destroy_nodes",
    "can_manage_providers",
    "can_manage_regions",
    "can_manage_sizes",
    # Permissions
    "can_view_infrastructure",
    "get_ansible_service",
    "get_cost_tracking_service",
    "get_deployment_service",
    "get_infrastructure_audit_service",
    "get_registration_service",
    "get_ssh_key_manager",
    "get_terraform_service",
    "get_validation_service",
]


def __getattr__(name: str) -> Any:
    """Lazy import for module attributes to avoid AppRegistryNotReady issues."""
    # Models
    if name in (
        "CloudProvider",
        "NodeRegion",
        "NodeSize",
        "PanelType",
        "NodeDeployment",
        "NodeDeploymentLog",
        "NodeDeploymentCostRecord",
    ):
        from apps.infrastructure import models

        return getattr(models, name)

    # SSH Key Management
    if name in ("SSHKeyManager", "SSHKeyPair", "SSHKeyInfo", "get_ssh_key_manager"):
        from apps.infrastructure import ssh_key_manager

        return getattr(ssh_key_manager, name)

    # Terraform
    if name in ("TerraformService", "TerraformResult", "get_terraform_service"):
        from apps.infrastructure import terraform_service

        return getattr(terraform_service, name)

    # Ansible
    if name in ("AnsibleService", "AnsibleResult", "get_ansible_service"):
        from apps.infrastructure import ansible_service

        return getattr(ansible_service, name)

    # Validation
    if name in (
        "NodeValidationService",
        "NodeValidationReport",
        "ValidationResult",
        "get_validation_service",
    ):
        from apps.infrastructure import validation_service

        return getattr(validation_service, name)

    # Registration
    if name in ("NodeRegistrationService", "get_registration_service"):
        from apps.infrastructure import registration_service

        return getattr(registration_service, name)

    # Deployment Orchestration
    if name in (
        "NodeDeploymentService",
        "DeploymentResult",
        "DeploymentProgress",
        "get_deployment_service",
    ):
        from apps.infrastructure import deployment_service

        return getattr(deployment_service, name)

    # Audit
    if name in (
        "InfrastructureAuditService",
        "InfrastructureAuditContext",
        "get_infrastructure_audit_service",
    ):
        from apps.infrastructure import audit_service

        return getattr(audit_service, name)

    # Permissions
    if name in (
        "can_view_infrastructure",
        "can_deploy_nodes",
        "can_destroy_nodes",
        "can_manage_providers",
        "can_manage_sizes",
        "can_manage_regions",
    ):
        from apps.infrastructure import permissions

        return getattr(permissions, name)

    # Cost Tracking
    if name in (
        "CostTrackingService",
        "CostSummary",
        "DeploymentCostBreakdown",
        "get_cost_tracking_service",
    ):
        from apps.infrastructure import cost_service

        return getattr(cost_service, name)

    raise AttributeError(f"module 'apps.infrastructure' has no attribute '{name}'")
