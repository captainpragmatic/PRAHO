"""
Node Deployment Service

Orchestrates the complete node deployment pipeline:
1. SSH key generation
2. Cloud provider provisioning (hcloud SDK)
3. DNS configuration
4. Ansible configuration
5. Validation
6. Registration
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.ansible_service import AnsibleResult, get_ansible_service
from apps.infrastructure.audit_service import InfrastructureAuditContext, InfrastructureAuditService
from apps.infrastructure.cloud_gateway import (
    STANDARD_FIREWALL_RULES,
    CloudProviderGateway,
    ServerCreateRequest,
    ServerCreateResult,
    get_cloud_gateway,
)
from apps.infrastructure.provider_config import (
    run_provider_command,
)
from apps.infrastructure.registration_service import get_registration_service
from apps.infrastructure.ssh_key_manager import get_ssh_key_manager
from apps.infrastructure.validation_service import NodeValidationReport, get_validation_service
from apps.settings.services import SettingsService

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment, NodeSize
    from apps.users.models import User

logger = logging.getLogger(__name__)


@dataclass
class DeploymentProgress:
    """Tracks progress through deployment stages"""

    stage: str
    percentage: int
    message: str
    started_at: datetime = field(default_factory=timezone.now)
    completed_at: datetime | None = None
    error: str | None = None


@dataclass
class DeploymentResult:
    """Complete result of a deployment operation"""

    success: bool
    deployment_id: int
    hostname: str
    stages_completed: list[str]
    cloud_result: ServerCreateResult | None = None
    ansible_results: list[AnsibleResult] | None = None
    validation_report: NodeValidationReport | None = None
    virtualmin_server_id: Any = None
    error: str | None = None
    duration_seconds: float = 0.0


class NodeDeploymentService:
    """
    Main Deployment Orchestrator

    Manages the complete lifecycle of node deployments:
    - Initial deployment (hcloud SDK + Ansible)
    - Validation and registration
    - Upgrade operations
    - Destruction

    All operations are designed to be resumable and idempotent where possible.
    """

    # Deployment stages with progress percentages
    STAGES: ClassVar[dict[str, tuple[int, str]]] = {
        "init": (0, "Initializing deployment"),
        "ssh_key": (5, "Generating SSH key"),
        "provision_server": (15, "Creating cloud server"),
        "update_deployment": (40, "Updating deployment records"),
        "ansible_base": (50, "Running base configuration"),
        "ansible_panel": (60, "Installing control panel"),
        "ansible_harden": (70, "Hardening server"),
        "ansible_backup": (80, "Configuring backups"),
        "validation": (85, "Validating node"),
        "registration": (95, "Registering node"),
        "complete": (100, "Deployment complete"),
    }

    def __init__(self) -> None:
        """Initialize deployment service with all required sub-services"""
        self._ssh_manager = get_ssh_key_manager()
        self._ansible = get_ansible_service()
        self._validation = get_validation_service()
        self._registration = get_registration_service()

    def deploy_node(  # Complexity: deployment orchestration  # noqa: C901, PLR0911, PLR0912, PLR0915  # Complexity: multi-step business logic
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        cloudflare_api_token: str | None = None,
        user: User | None = None,
        progress_callback: Callable[..., None] | None = None,
    ) -> Result[DeploymentResult, str]:
        """
        Execute complete node deployment pipeline.

        Args:
            deployment: NodeDeployment instance to deploy
            credentials: Provider credentials dict (e.g., {"api_token": "xxx"})
            cloudflare_api_token: Cloudflare API token (optional)
            user: User performing the deployment
            progress_callback: Optional callback for progress updates

        Returns:
            Result with DeploymentResult or error
        """
        start_time = timezone.now()
        stages_completed: list[str] = []
        _cloud_result: ServerCreateResult | None = None  # unused; actual tracking via server_create_result
        ansible_results: list[AnsibleResult] = []
        # Track created cloud resources for cleanup on failure: (resource_type, resource_id)
        created_resources: list[tuple[str, str]] = []
        # gateway is captured here so the except block can access it for cleanup
        gateway: CloudProviderGateway | None = None

        def report_progress(stage: str) -> None:
            if progress_callback and stage in self.STAGES:
                pct, msg = self.STAGES[stage]
                progress_callback(DeploymentProgress(stage=stage, percentage=pct, message=msg))

        def log_deployment(level: str, message: str) -> None:
            """Log to both logger and deployment log"""
            from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
                NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
            )

            getattr(logger, level)(f"[Deployment:{deployment.hostname}] {message}")
            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level=level.upper(),
                message=message,
                phase=stages_completed[-1] if stages_completed else "init",
            )

        try:
            report_progress("init")
            log_deployment("info", "Starting node deployment")

            # Check if deployment is enabled
            if not SettingsService.get_setting("node_deployment.enabled", True):
                return Err("Node deployment is disabled in settings")

            # Atomic lock to prevent concurrent deployments of the same node
            with transaction.atomic():
                from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
                    NodeDeployment as NDModel,  # Circular: cross-app  # Deferred: avoids circular import
                )

                locked = NDModel.objects.select_for_update().filter(pk=deployment.pk).first()
                if not locked or locked.status not in ("pending", "failed"):
                    return Err(f"Cannot deploy node in status '{locked.status if locked else 'unknown'}'")

                # Transition to provisioning (transition_to saves internally)
                try:
                    locked.transition_to("provisioning_node")
                except ValidationError:
                    return Err(f"Cannot transition from '{locked.status}' to 'provisioning_node'")

            # Refresh local instance after atomic block
            deployment.refresh_from_db()

            # Audit: deployment started
            audit_ctx = InfrastructureAuditContext(user=user)
            try:
                InfrastructureAuditService.log_deployment_started(deployment, audit_ctx)
            except Exception:
                logger.warning(f"[Deployment:{deployment.hostname}] Failed to log audit: deployment started")

            # Stage 1: Generate SSH key
            report_progress("ssh_key")
            log_deployment("info", "Generating deployment SSH key")

            key_result = self._ssh_manager.generate_deployment_key(
                deployment,
                user=user,
            )

            if key_result.is_err():
                # Try master key fallback
                master_result = self._ssh_manager.get_master_key()
                if master_result.is_err():
                    self._mark_failed(
                        deployment,
                        f"SSH key generation failed: {key_result.unwrap_err()}",
                        stage="ssh_key",
                        audit_ctx=audit_ctx,
                    )
                    return Err(f"SSH key generation failed: {key_result.unwrap_err()}")
                master_pub_result = self._ssh_manager.get_master_public_key()
                if master_pub_result.is_err():
                    self._mark_failed(
                        deployment,
                        f"SSH key generation failed and master public key unavailable: {master_pub_result.unwrap_err()}",
                        stage="ssh_key",
                        audit_ctx=audit_ctx,
                    )
                    return Err(f"SSH key generation failed: {key_result.unwrap_err()}")
                ssh_public_key = master_pub_result.unwrap()
                log_deployment("warning", "Using master SSH key (fallback)")
            else:
                ssh_public_key = key_result.unwrap().public_key
                log_deployment("info", "SSH key generated successfully")

            stages_completed.append("ssh_key")

            # Stage 2: Provision server via cloud provider gateway
            report_progress("provision_server")

            # Get API token from credentials
            api_token = credentials.get("api_token", "")
            if not api_token:
                self._mark_failed(deployment, "No API token provided", stage="provision_server", audit_ctx=audit_ctx)
                return Err("No API token provided")

            provider_type = deployment.provider.provider_type
            gateway = get_cloud_gateway(provider_type, api_token)

            # Idempotent: skip server creation if external_node_id already set (retry scenario)
            server_create_result: ServerCreateResult | None = None
            if deployment.external_node_id:
                log_deployment("info", f"Server already exists (id={deployment.external_node_id}), skipping creation")
                server_info_result = gateway.get_server(deployment.external_node_id)
                if server_info_result.is_err():
                    # Transient error — do NOT clear external_node_id
                    self._mark_failed(
                        deployment,
                        f"Cannot verify existing server: {server_info_result.unwrap_err()}",
                        stage="provision_server",
                        audit_ctx=audit_ctx,
                    )
                    return Err(f"Cannot verify existing server: {server_info_result.unwrap_err()}")
                elif server_info_result.unwrap() is not None:
                    info = server_info_result.unwrap()
                    assert info is not None  # narrowed by elif above
                    server_create_result = ServerCreateResult(
                        server_id=info.server_id,
                        ipv4_address=info.ipv4_address,
                        ipv6_address=info.ipv6_address,
                    )
                else:
                    log_deployment("warning", "Previously created server not found, creating new one")
                    deployment.external_node_id = ""
                    deployment.save(update_fields=["external_node_id", "updated_at"])

            if not deployment.external_node_id:
                log_deployment("info", f"Creating server via {provider_type} API")

                # Upload SSH key to provider
                ssh_key_name = f"praho-{deployment.hostname}"
                key_upload_result = gateway.upload_ssh_key(ssh_key_name, ssh_public_key)
                if key_upload_result.is_err():
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment)
                    self._mark_failed(
                        deployment,
                        f"SSH key upload failed: {key_upload_result.unwrap_err()}",
                        stage="provision_server",
                    )
                    return Err(f"SSH key upload failed: {key_upload_result.unwrap_err()}")

                created_resources.append(("ssh_key", ssh_key_name))
                log_deployment("info", f"SSH key '{ssh_key_name}' uploaded to provider")

                # Create firewall before server — attach during provisioning
                firewall_name = f"praho-fw-{deployment.hostname}"
                log_deployment("info", f"Creating firewall '{firewall_name}'")
                firewall_result = gateway.create_firewall(
                    name=firewall_name,
                    rules=STANDARD_FIREWALL_RULES,
                    labels={
                        "managed-by": "praho",
                        "deployment-id": str(deployment.correlation_id),
                        "hostname": deployment.hostname,
                    },
                )
                if firewall_result.is_err():
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment)
                    self._mark_failed(
                        deployment,
                        f"Firewall creation failed: {firewall_result.unwrap_err()}",
                        stage="provision_server",
                    )
                    return Err(f"Firewall creation failed: {firewall_result.unwrap_err()}")

                firewall_id = firewall_result.unwrap()
                created_resources.append(("firewall", firewall_id))
                log_deployment("info", f"Firewall '{firewall_name}' created (id={firewall_id})")
                # Persist firewall_id in a structured log entry so destroy_node can retrieve it by ID
                from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
                    NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
                )

                NodeDeploymentLog.objects.create(
                    deployment=deployment,
                    level="INFO",
                    message=f"Firewall resource recorded: {firewall_name}",
                    phase="provision_server",
                    details={"firewall_id": firewall_id, "firewall_name": firewall_name},
                )

                # Create the server via gateway
                create_request = ServerCreateRequest(
                    name=deployment.hostname,
                    server_type=deployment.node_size.provider_type_id if deployment.node_size else "",
                    location=deployment.region.provider_region_id if deployment.region else "",
                    ssh_keys=[ssh_key_name],
                    firewall_ids=[firewall_id],
                    labels={
                        "managed-by": "praho",
                        "praho-deployment": str(deployment.correlation_id),
                        "hostname": deployment.hostname,
                        "environment": deployment.environment,
                    },
                )
                server_result = gateway.create_server(create_request)

                if server_result.is_err():
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment)
                    self._mark_failed(
                        deployment,
                        f"Server creation failed: {server_result.unwrap_err()}",
                        stage="provision_server",
                    )
                    return Err(f"Server creation failed: {server_result.unwrap_err()}")

                server_create_result = server_result.unwrap()
                created_resources.append(("server", server_create_result.server_id))
            stages_completed.append("provision_server")
            log_deployment("info", f"Server created successfully via {provider_type} gateway")

            # Stage 3: Update deployment with server details
            report_progress("update_deployment")

            if not server_create_result or not server_create_result.ipv4_address:
                if gateway is not None and created_resources:
                    self._cleanup_resources(gateway, created_resources, deployment)
                self._mark_failed(deployment, "Server creation did not return an IP address", stage="update_deployment")
                return Err("Server creation did not return an IP address")

            with transaction.atomic():
                deployment.external_node_id = server_create_result.server_id
                deployment.ipv4_address = server_create_result.ipv4_address
                deployment.ipv6_address = server_create_result.ipv6_address or ""
                deployment.save(
                    update_fields=[
                        "external_node_id",
                        "ipv4_address",
                        "ipv6_address",
                        "updated_at",
                    ]
                )
                deployment.transition_to("configuring_dns")

            stages_completed.append("update_deployment")
            log_deployment("info", f"Server provisioned with IP: {deployment.ipv4_address}")

            # Transition to panel installation phase
            deployment.transition_to("installing_panel")

            # Stage 7-10: Run Ansible playbooks (panel-aware)
            panel_type = "virtualmin"
            if hasattr(deployment, "panel_type") and deployment.panel_type:
                panel_type = (
                    deployment.panel_type.panel_type
                    if hasattr(deployment.panel_type, "panel_type")
                    else str(deployment.panel_type)
                )

            playbook_names = self._ansible.get_playbook_order(panel_type)
            stage_keys = ["ansible_base", "ansible_panel", "ansible_harden", "ansible_backup"]
            ansible_playbooks = list(zip(stage_keys, playbook_names, strict=False))

            for stage_name, playbook in ansible_playbooks:
                report_progress(stage_name)
                log_deployment("info", f"Running Ansible playbook: {playbook}")

                playbook_result = self._ansible.run_playbook(
                    deployment=deployment,
                    playbook=playbook,
                )

                if playbook_result.is_err():
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment)
                    self._mark_failed(
                        deployment, f"Ansible {playbook} failed: {playbook_result.unwrap_err()}", stage=stage_name
                    )
                    return Err(f"Ansible {playbook} failed: {playbook_result.unwrap_err()}")

                result = playbook_result.unwrap()
                ansible_results.append(result)

                if not result.success:
                    if gateway is not None and created_resources:
                        self._cleanup_resources(gateway, created_resources, deployment)
                    self._mark_failed(deployment, f"Ansible {playbook} failed: {result.stderr[:500]}", stage=stage_name)
                    return Err(f"Ansible {playbook} failed: {result.stderr[:500]}")

                stages_completed.append(stage_name)
                log_deployment("info", f"Ansible {playbook} completed successfully")

            # Stage 11: Validation
            report_progress("validation")
            deployment.transition_to("validating")
            log_deployment("info", "Validating node health")

            validation_result = self._validation.validate_node(deployment)

            if validation_result.is_err():
                if gateway is not None and created_resources:
                    self._cleanup_resources(gateway, created_resources, deployment)
                self._mark_failed(
                    deployment, f"Validation failed: {validation_result.unwrap_err()}", stage="validation"
                )
                return Err(f"Validation failed: {validation_result.unwrap_err()}")

            validation_report = validation_result.unwrap()

            if not validation_report.all_passed:
                # Warning but continue - some checks might fail initially
                log_deployment("warning", f"Validation: {validation_report.summary}")
            else:
                log_deployment("info", f"Validation passed: {validation_report.summary}")

            stages_completed.append("validation")

            # Stage 12: Registration
            report_progress("registration")
            deployment.transition_to("registering")
            log_deployment("info", "Registering node as VirtualminServer")

            # Generate a random password for Virtualmin admin
            import string  # noqa: PLC0415  # Deferred: avoids circular import

            admin_password = "".join(
                secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*") for _ in range(24)
            )

            registration_result = self._registration.register_node(
                deployment=deployment,
                admin_username="root",
                admin_password=admin_password,
                user=user,
            )

            virtualmin_server_id = None
            if registration_result.is_err():
                log_deployment("warning", f"Registration failed: {registration_result.unwrap_err()}")
                # Continue anyway - registration can be retried
            else:
                server = registration_result.unwrap()
                virtualmin_server_id = server.id
                log_deployment("info", f"Registered as VirtualminServer(id={server.id})")

            stages_completed.append("registration")

            # Stage 13: Complete
            report_progress("complete")
            deployment.completed_at = timezone.now()
            deployment.save(update_fields=["completed_at", "updated_at"])
            deployment.transition_to("completed")

            stages_completed.append("complete")

            duration = (timezone.now() - start_time).total_seconds()
            log_deployment("info", f"Deployment completed successfully in {duration:.1f}s")

            # Audit: deployment completed
            try:
                InfrastructureAuditService.log_deployment_completed(
                    deployment,
                    audit_ctx,
                    duration_seconds=duration,
                )
            except Exception:
                logger.warning(f"[Deployment:{deployment.hostname}] Failed to log audit: deployment completed")

            return Ok(
                DeploymentResult(
                    success=True,
                    deployment_id=deployment.id,
                    hostname=deployment.hostname,
                    stages_completed=stages_completed,
                    cloud_result=server_create_result,
                    ansible_results=ansible_results,
                    validation_report=validation_report,
                    virtualmin_server_id=virtualmin_server_id,
                    duration_seconds=duration,
                )
            )

        except Exception as e:
            logger.exception(f"Deployment failed for {deployment.hostname}: {e}")
            # Best-effort cleanup of any cloud resources created before the failure
            if gateway is not None and created_resources:
                self._cleanup_resources(gateway, created_resources, deployment)
            self._mark_failed(deployment, str(e), audit_ctx=audit_ctx)

            duration = (timezone.now() - start_time).total_seconds()
            return Err(f"Deployment failed: {e}")

    def destroy_node(  # Complexity: deployment orchestration  # noqa: C901, PLR0912, PLR0915  # Complexity: multi-step business logic
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        cloudflare_api_token: str | None = None,
        user: User | None = None,
    ) -> Result[bool, str]:
        """
        Destroy a deployed node.

        Args:
            deployment: NodeDeployment instance to destroy
            credentials: Provider credentials dict
            cloudflare_api_token: Cloudflare API token
            user: User performing the destruction

        Returns:
            Result with success status or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        logger.info(f"[Destroy:{deployment.hostname}] Starting node destruction")

        audit_ctx = InfrastructureAuditContext(user=user)

        try:
            # Atomic check-and-transition to prevent TOCTOU race
            with transaction.atomic():
                from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
                    NodeDeployment as NDModel,  # Circular: cross-app  # Deferred: avoids circular import
                )

                locked = NDModel.objects.select_for_update().get(pk=deployment.pk)
                if locked.status not in ("completed", "failed", "stopped"):
                    return Err(f"Cannot destroy node in status '{locked.status}'")
                locked.transition_to("destroying")

            # Refresh local instance after atomic block
            deployment.refresh_from_db()

            # Audit: destroy started
            try:
                InfrastructureAuditService.log_destroy_started(deployment, audit_ctx)
            except Exception:
                logger.warning(f"[Destroy:{deployment.hostname}] Failed to log audit: destroy started")

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Starting node destruction",
                phase="destroying",
            )

            # Unregister from PRAHO first
            if deployment.virtualmin_server:
                unregister_result = self._registration.unregister_node(
                    deployment=deployment,
                    delete_server=True,
                    user=user,
                )
                if unregister_result.is_err():
                    logger.warning(f"Unregistration failed: {unregister_result.unwrap_err()}")

            # Delete server via cloud provider gateway
            if deployment.external_node_id:
                api_token = credentials.get("api_token", "")
                if not api_token:
                    return Err("No API token provided for server deletion")

                provider_type = deployment.provider.provider_type
                gateway = get_cloud_gateway(provider_type, api_token)
                delete_result = gateway.delete_server(deployment.external_node_id)

                if delete_result.is_err():
                    self._mark_failed(
                        deployment,
                        f"Server deletion failed: {delete_result.unwrap_err()}",
                        stage="destroying",
                        audit_ctx=audit_ctx,
                    )
                    return Err(f"Server deletion failed: {delete_result.unwrap_err()}")

                # Clean up SSH key from provider
                ssh_key_name = f"praho-{deployment.hostname}"
                ssh_delete_result = gateway.delete_ssh_key(ssh_key_name)
                if ssh_delete_result.is_err():
                    logger.warning(
                        f"[Destroy:{deployment.hostname}] SSH key cleanup failed: {ssh_delete_result.unwrap_err()}"
                    )

                # Clean up firewall from provider (best-effort — may not exist on older deployments)
                # Look up firewall_id from deployment log (stored during deploy_node)
                firewall_name = f"praho-fw-{deployment.hostname}"
                fw_log = (
                    NodeDeploymentLog.objects.filter(
                        deployment=deployment,
                        phase="provision_server",
                        message__startswith="Firewall resource recorded:",
                    )
                    .order_by("-created_at")
                    .first()
                )
                firewall_id_to_delete: str | None = (
                    fw_log.details.get("firewall_id") if fw_log and isinstance(fw_log.details, dict) else None
                )
                if firewall_id_to_delete:
                    logger.info(f"[Destroy:{deployment.hostname}] Deleting firewall id={firewall_id_to_delete}")
                    try:
                        fw_delete_result = gateway.delete_firewall(str(firewall_id_to_delete))
                        if fw_delete_result.is_err():
                            logger.warning(
                                f"[Destroy:{deployment.hostname}] Firewall deletion failed (best-effort): "
                                f"{fw_delete_result.unwrap_err()}"
                            )
                        else:
                            logger.info(f"[Destroy:{deployment.hostname}] Firewall '{firewall_name}' deleted")
                    except Exception as fw_exc:
                        logger.warning(
                            f"[Destroy:{deployment.hostname}] Firewall deletion raised exception (best-effort): "
                            f"{fw_exc}"
                        )
                else:
                    logger.warning(
                        f"[Destroy:{deployment.hostname}] No firewall_id found in logs, skipping firewall cleanup"
                    )
            else:
                logger.warning(f"No external_node_id for {deployment.hostname}, skipping cloud deletion")

            # Clean up SSH key from vault
            self._ssh_manager.revoke_deployment_key(deployment, user=user)

            # Mark as destroyed
            deployment.destroyed_at = timezone.now()
            deployment.save(update_fields=["destroyed_at", "updated_at"])
            deployment.transition_to("destroyed")

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node destroyed successfully",
                phase="destroyed",
            )

            # Audit: destroy completed
            try:
                InfrastructureAuditService.log_destroy_completed(deployment, audit_ctx)
            except Exception:
                logger.warning(f"[Destroy:{deployment.hostname}] Failed to log audit: destroy completed")

            logger.info(f"[Destroy:{deployment.hostname}] Node destroyed successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Destruction failed for {deployment.hostname}: {e}")
            self._mark_failed(deployment, str(e), stage="destroying", audit_ctx=audit_ctx)

            # Audit: destroy failed
            try:
                InfrastructureAuditService.log_destroy_failed(deployment, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Destroy:{deployment.hostname}] Failed to log audit: destroy failed")

            return Err(f"Destruction failed: {e}")

    def retry_deployment(
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        cloudflare_api_token: str | None = None,
        user: User | None = None,
    ) -> Result[DeploymentResult, str]:
        """
        Retry a failed deployment.

        Args:
            deployment: Failed NodeDeployment instance
            credentials: Provider credentials dict
            cloudflare_api_token: Cloudflare API token
            user: User performing the retry

        Returns:
            Result with DeploymentResult or error
        """
        if deployment.status != "failed":
            return Err(f"Can only retry failed deployments, current status: {deployment.status}")

        # Increment retry count
        deployment.retry_count += 1
        deployment.save(update_fields=["retry_count", "updated_at"])

        # Reset to pending via state machine (failed -> pending is a valid transition)
        deployment.transition_to("pending")

        logger.info(f"[Retry:{deployment.hostname}] Retrying deployment (attempt {deployment.retry_count})")

        # Audit: deployment retry
        try:
            InfrastructureAuditService.log_deployment_retry(
                deployment,
                InfrastructureAuditContext(user=user),
            )
        except Exception:
            logger.warning(f"[Retry:{deployment.hostname}] Failed to log audit: deployment retry")

        return self.deploy_node(
            deployment=deployment,
            credentials=credentials,
            cloudflare_api_token=cloudflare_api_token,
            user=user,
        )

    def upgrade_node_size(  # Complexity: deployment orchestration  # noqa: PLR0911  # Complexity: multi-step business logic
        self,
        deployment: NodeDeployment,
        new_size: NodeSize,
        credentials: dict[str, str],
        user: User | None = None,
    ) -> Result[bool, str]:
        """
        Upgrade a node to a new size (resize VPS).

        Args:
            deployment: NodeDeployment instance to upgrade
            new_size: New NodeSize to resize to
            credentials: Provider credentials dict
            user: User performing the upgrade

        Returns:
            Result with success status or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        logger.info(f"[Upgrade:{deployment.hostname}] Starting node resize to {new_size.name}")

        if deployment.status != "completed":
            return Err(f"Can only upgrade completed deployments, current status: {deployment.status}")

        if deployment.node_size == new_size:
            return Err("Node is already using the selected size")

        if new_size.provider != deployment.provider:
            return Err("New size must be from the same provider")

        old_size = deployment.node_size
        audit_ctx = InfrastructureAuditContext(user=user)

        try:
            # Log the upgrade start
            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message=f"Starting upgrade from {old_size.name} to {new_size.name}",
                phase="upgrading",
            )

            # Audit: upgrade started
            try:
                InfrastructureAuditService.log_node_upgrade_started(deployment, old_size, new_size, audit_ctx)
            except Exception:
                logger.warning(f"[Upgrade:{deployment.hostname}] Failed to log audit: upgrade started")

            # Use provider-agnostic command execution
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="resize",
                credentials=credentials,
                timeout=300,
                server_id=str(deployment.external_node_id),
                size=new_size.provider_type_id,
            )

            if result.is_err():
                error_msg = f"Resize failed: {result.unwrap_err()}"
                NodeDeploymentLog.objects.create(
                    deployment=deployment,
                    level="ERROR",
                    message=error_msg,
                    phase="upgrading",
                )
                try:
                    InfrastructureAuditService.log_node_upgrade_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Upgrade:{deployment.hostname}] Failed to log audit: upgrade failed")
                return Err(error_msg)

            cmd_result = result.unwrap()
            if not cmd_result.success:
                error_msg = f"Resize failed: {cmd_result.stderr}"
                NodeDeploymentLog.objects.create(
                    deployment=deployment,
                    level="ERROR",
                    message=error_msg,
                    phase="upgrading",
                )
                try:
                    InfrastructureAuditService.log_node_upgrade_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Upgrade:{deployment.hostname}] Failed to log audit: upgrade failed")
                return Err(error_msg)

            # Update deployment with new size
            deployment.node_size = new_size
            deployment.save()

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message=f"Successfully upgraded to {new_size.name}",
                phase="completed",
            )

            # Audit: upgrade completed
            try:
                InfrastructureAuditService.log_node_upgrade_completed(deployment, old_size, new_size, audit_ctx)
            except Exception:
                logger.warning(f"[Upgrade:{deployment.hostname}] Failed to log audit: upgrade completed")

            logger.info(f"[Upgrade:{deployment.hostname}] Node upgraded successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Upgrade failed for {deployment.hostname}: {e}")
            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="ERROR",
                message=str(e),
                phase="upgrading",
            )
            try:
                InfrastructureAuditService.log_node_upgrade_failed(deployment, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Upgrade:{deployment.hostname}] Failed to log audit: upgrade failed")
            return Err(f"Upgrade failed: {e}")

    def run_maintenance(  # Complexity: deployment orchestration  # noqa: C901  # Complexity: multi-step business logic
        self,
        deployment: NodeDeployment,
        playbooks: list[str] | None = None,
        extra_vars: dict[str, Any] | None = None,
        user: User | None = None,
    ) -> Result[list[AnsibleResult], str]:
        """
        Run maintenance playbooks on a deployed node.

        Args:
            deployment: NodeDeployment instance
            playbooks: List of playbook names to run (default: virtualmin_harden.yml)
            extra_vars: Extra variables to pass to Ansible
            user: User performing the maintenance

        Returns:
            Result with list of AnsibleResult or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        if deployment.status != "completed":
            return Err(f"Can only run maintenance on completed deployments, current status: {deployment.status}")

        if not deployment.ipv4_address:
            return Err("Deployment has no IP address")

        # Default to hardening playbook
        if not playbooks:
            playbooks = ["virtualmin_harden.yml"]

        logger.info(f"[Maintenance:{deployment.hostname}] Running playbooks: {playbooks}")

        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="INFO",
            message=f"Starting maintenance: {', '.join(playbooks)}",
            phase="maintenance",
        )

        audit_ctx = InfrastructureAuditContext(user=user)

        # Audit: maintenance started
        try:
            InfrastructureAuditService.log_node_maintenance_started(deployment, playbooks, audit_ctx)
        except Exception:
            logger.warning(f"[Maintenance:{deployment.hostname}] Failed to log audit: maintenance started")

        results = []
        try:
            for playbook in playbooks:
                result = self._ansible.run_playbook(
                    deployment=deployment,
                    playbook=playbook,
                    extra_vars=extra_vars,
                )

                if result.is_err():
                    error_msg = f"Playbook {playbook} failed: {result.unwrap_err()}"
                    NodeDeploymentLog.objects.create(
                        deployment=deployment,
                        level="ERROR",
                        message=error_msg,
                        phase="maintenance",
                    )
                    try:
                        InfrastructureAuditService.log_node_maintenance_failed(
                            deployment, playbooks, error_msg, audit_ctx
                        )
                    except Exception:
                        logger.warning(f"[Maintenance:{deployment.hostname}] Failed to log audit: maintenance failed")
                    return Err(error_msg)

                ansible_result = result.unwrap()
                results.append(ansible_result)

                if not ansible_result.success:
                    error_msg = f"Playbook {playbook} failed: {ansible_result.stderr[:500]}"
                    NodeDeploymentLog.objects.create(
                        deployment=deployment,
                        level="ERROR",
                        message=error_msg,
                        phase="maintenance",
                    )
                    try:
                        InfrastructureAuditService.log_node_maintenance_failed(
                            deployment, playbooks, error_msg, audit_ctx
                        )
                    except Exception:
                        logger.warning(f"[Maintenance:{deployment.hostname}] Failed to log audit: maintenance failed")
                    return Err(error_msg)

                NodeDeploymentLog.objects.create(
                    deployment=deployment,
                    level="INFO",
                    message=f"Playbook {playbook} completed successfully",
                    phase="maintenance",
                )

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Maintenance completed successfully",
                phase="completed",
            )

            # Audit: maintenance completed
            try:
                InfrastructureAuditService.log_node_maintenance_completed(deployment, playbooks, audit_ctx)
            except Exception:
                logger.warning(f"[Maintenance:{deployment.hostname}] Failed to log audit: maintenance completed")

            logger.info(f"[Maintenance:{deployment.hostname}] All playbooks completed")
            return Ok(results)

        except Exception as e:
            logger.exception(f"Maintenance failed for {deployment.hostname}: {e}")
            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="ERROR",
                message=str(e),
                phase="maintenance",
            )
            try:
                InfrastructureAuditService.log_node_maintenance_failed(deployment, playbooks, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Maintenance:{deployment.hostname}] Failed to log audit: maintenance failed")
            return Err(f"Maintenance failed: {e}")

    def stop_node(
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        user: User | None = None,
    ) -> Result[bool, str]:
        """
        Stop (power off) a deployed node.

        Args:
            deployment: NodeDeployment instance
            credentials: Provider credentials dict
            user: User performing the action

        Returns:
            Result with success status or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        logger.info(f"[Stop:{deployment.hostname}] Stopping node")

        if deployment.status not in ("completed", "stopped"):
            return Err(f"Can only stop completed nodes, current status: {deployment.status}")

        if deployment.status == "stopped":
            return Ok(True)  # Already stopped

        audit_ctx = InfrastructureAuditContext(user=user)

        # Audit: stop started
        try:
            InfrastructureAuditService.log_node_stop_started(deployment, audit_ctx)
        except Exception:
            logger.warning(f"[Stop:{deployment.hostname}] Failed to log audit: stop started")

        try:
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="power_off",
                credentials=credentials,
                server_id=str(deployment.external_node_id),
            )

            if result.is_err():
                error_msg = f"Failed to stop node: {result.unwrap_err()}"
                try:
                    InfrastructureAuditService.log_node_stop_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Stop:{deployment.hostname}] Failed to log audit: stop failed")
                return Err(error_msg)

            cmd_result = result.unwrap()
            if not cmd_result.success:
                error_msg = f"Failed to stop node: {cmd_result.stderr}"
                try:
                    InfrastructureAuditService.log_node_stop_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Stop:{deployment.hostname}] Failed to log audit: stop failed")
                return Err(error_msg)

            deployment.transition_to("stopped")

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node stopped (powered off)",
                phase="stopped",
            )

            # Audit: stop completed
            try:
                InfrastructureAuditService.log_node_stop_completed(deployment, audit_ctx)
            except Exception:
                logger.warning(f"[Stop:{deployment.hostname}] Failed to log audit: stop completed")

            logger.info(f"[Stop:{deployment.hostname}] Node stopped successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Stop failed for {deployment.hostname}: {e}")
            try:
                InfrastructureAuditService.log_node_stop_failed(deployment, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Stop:{deployment.hostname}] Failed to log audit: stop failed")
            return Err(f"Stop failed: {e}")

    def start_node(
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        user: User | None = None,
    ) -> Result[bool, str]:
        """
        Start (power on) a stopped node.

        Args:
            deployment: NodeDeployment instance
            credentials: Provider credentials dict
            user: User performing the action

        Returns:
            Result with success status or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        logger.info(f"[Start:{deployment.hostname}] Starting node")

        if deployment.status != "stopped":
            return Err(f"Can only start stopped nodes, current status: {deployment.status}")

        audit_ctx = InfrastructureAuditContext(user=user)

        try:
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="power_on",
                credentials=credentials,
                server_id=str(deployment.external_node_id),
            )

            if result.is_err():
                error_msg = f"Failed to start node: {result.unwrap_err()}"
                try:
                    InfrastructureAuditService.log_node_start_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Start:{deployment.hostname}] Failed to log audit: start failed")
                return Err(error_msg)

            cmd_result = result.unwrap()
            if not cmd_result.success:
                error_msg = f"Failed to start node: {cmd_result.stderr}"
                try:
                    InfrastructureAuditService.log_node_start_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Start:{deployment.hostname}] Failed to log audit: start failed")
                return Err(error_msg)

            deployment.transition_to("completed")

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node started (powered on)",
                phase="completed",
            )

            # Audit: start completed
            try:
                InfrastructureAuditService.log_node_start_completed(deployment, audit_ctx)
            except Exception:
                logger.warning(f"[Start:{deployment.hostname}] Failed to log audit: start completed")

            logger.info(f"[Start:{deployment.hostname}] Node started successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Start failed for {deployment.hostname}: {e}")
            try:
                InfrastructureAuditService.log_node_start_failed(deployment, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Start:{deployment.hostname}] Failed to log audit: start failed")
            return Err(f"Start failed: {e}")

    def reboot_node(
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        user: User | None = None,
    ) -> Result[bool, str]:
        """
        Reboot a deployed node.

        Args:
            deployment: NodeDeployment instance
            credentials: Provider credentials dict
            user: User performing the action

        Returns:
            Result with success status or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        logger.info(f"[Reboot:{deployment.hostname}] Rebooting node")

        if deployment.status != "completed":
            return Err(f"Can only reboot running nodes, current status: {deployment.status}")

        audit_ctx = InfrastructureAuditContext(user=user)

        try:
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="reboot",
                credentials=credentials,
                server_id=str(deployment.external_node_id),
            )

            if result.is_err():
                error_msg = f"Failed to reboot node: {result.unwrap_err()}"
                try:
                    InfrastructureAuditService.log_node_reboot_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Reboot:{deployment.hostname}] Failed to log audit: reboot failed")
                return Err(error_msg)

            cmd_result = result.unwrap()
            if not cmd_result.success:
                error_msg = f"Failed to reboot node: {cmd_result.stderr}"
                try:
                    InfrastructureAuditService.log_node_reboot_failed(deployment, error_msg, audit_ctx)
                except Exception:
                    logger.warning(f"[Reboot:{deployment.hostname}] Failed to log audit: reboot failed")
                return Err(error_msg)

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node rebooted",
                phase="completed",
            )

            # Audit: reboot completed
            try:
                InfrastructureAuditService.log_node_reboot_completed(deployment, audit_ctx)
            except Exception:
                logger.warning(f"[Reboot:{deployment.hostname}] Failed to log audit: reboot completed")

            logger.info(f"[Reboot:{deployment.hostname}] Node rebooted successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Reboot failed for {deployment.hostname}: {e}")
            try:
                InfrastructureAuditService.log_node_reboot_failed(deployment, str(e), audit_ctx)
            except Exception:
                logger.warning(f"[Reboot:{deployment.hostname}] Failed to log audit: reboot failed")
            return Err(f"Reboot failed: {e}")

    def _cleanup_resources(
        self,
        gateway: CloudProviderGateway,
        resources: list[tuple[str, str]],
        deployment: NodeDeployment,
    ) -> None:
        """
        Best-effort cleanup of cloud resources created during a failed deployment.

        Processes resources in reverse creation order (server → firewall → ssh_key)
        so dependencies are respected. Never raises; logs all outcomes.

        Args:
            gateway: The cloud provider gateway to use for deletions
            resources: List of (resource_type, resource_id) tuples in creation order
            deployment: The NodeDeployment instance (used for logging only)
        """
        hostname = deployment.hostname
        logger.info(f"[Deployment:{hostname}] Starting best-effort cleanup of {len(resources)} resource(s)")

        for resource_type, resource_id in reversed(resources):
            try:
                if resource_type == "server":
                    logger.info(f"[Deployment:{hostname}] Cleanup: deleting server id={resource_id}")
                    result = gateway.delete_server(resource_id)
                    if result.is_err():
                        logger.warning(
                            f"[Deployment:{hostname}] Cleanup: server deletion failed: {result.unwrap_err()}"
                        )
                    else:
                        logger.info(f"[Deployment:{hostname}] Cleanup: server id={resource_id} deleted ✅")

                elif resource_type == "firewall":
                    logger.info(f"[Deployment:{hostname}] Cleanup: deleting firewall id={resource_id}")
                    result = gateway.delete_firewall(resource_id)
                    if result.is_err():
                        logger.warning(
                            f"[Deployment:{hostname}] Cleanup: firewall deletion failed: {result.unwrap_err()}"
                        )
                    else:
                        logger.info(f"[Deployment:{hostname}] Cleanup: firewall id={resource_id} deleted ✅")

                elif resource_type == "ssh_key":
                    logger.info(f"[Deployment:{hostname}] Cleanup: deleting SSH key name={resource_id}")
                    result = gateway.delete_ssh_key(resource_id)
                    if result.is_err():
                        logger.warning(
                            f"[Deployment:{hostname}] Cleanup: SSH key deletion failed: {result.unwrap_err()}"
                        )
                    else:
                        logger.info(f"[Deployment:{hostname}] Cleanup: SSH key name={resource_id} deleted ✅")

                else:
                    logger.warning(f"[Deployment:{hostname}] Cleanup: unknown resource type '{resource_type}'")

            except Exception as exc:
                logger.warning(
                    f"[Deployment:{hostname}] Cleanup: exception deleting {resource_type} '{resource_id}': {exc}"
                )

        logger.info(f"[Deployment:{hostname}] Cleanup complete")

    def _mark_failed(
        self,
        deployment: NodeDeployment,
        error_message: str,
        stage: str = "",
        audit_ctx: InfrastructureAuditContext | None = None,
    ) -> None:
        """Mark deployment as failed with error message"""
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentLog,  # Circular: cross-app  # Deferred: avoids circular import
        )

        # Capture the current stage before transitioning to failed
        failed_stage = stage or deployment.status

        try:
            deployment.transition_to("failed")
        except ValidationError:
            # Force-set if transition is somehow invalid (e.g., from destroyed)
            deployment.status = "failed"
            deployment.save(update_fields=["status", "updated_at"])

        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="ERROR",
            message=error_message,
            phase=failed_stage,
        )

        # Audit: deployment failed (with user context if available)
        try:
            InfrastructureAuditService.log_deployment_failed(
                deployment,
                error_message,
                stage=failed_stage,
                context=audit_ctx,
            )
        except Exception:
            logger.warning(f"[Deployment:{deployment.hostname}] Failed to log audit: deployment failed")

        logger.error(f"[Deployment:{deployment.hostname}] Failed at stage '{failed_stage}': {error_message}")


# Module-level singleton
_deployment_service: NodeDeploymentService | None = None


def get_deployment_service() -> NodeDeploymentService:
    """Get global deployment service instance"""
    global _deployment_service  # noqa: PLW0603  # Module-level singleton pattern
    if _deployment_service is None:
        _deployment_service = NodeDeploymentService()
    return _deployment_service
