"""
Node Deployment Service

Orchestrates the complete node deployment pipeline:
1. SSH key generation
2. Terraform provisioning
3. DNS configuration
4. Ansible configuration
5. Validation
6. Registration
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

from django.db import transaction
from django.utils import timezone

from apps.common.types import Err, Ok, Result
from apps.infrastructure.ansible_service import AnsibleResult, get_ansible_service
from apps.infrastructure.provider_config import (
    get_provider_config,
    map_terraform_outputs_to_deployment,
    run_provider_command,
    validate_provider_prerequisites,
)
from apps.infrastructure.registration_service import get_registration_service
from apps.infrastructure.ssh_key_manager import get_ssh_key_manager
from apps.infrastructure.terraform_service import TerraformResult, get_terraform_service
from apps.infrastructure.validation_service import NodeValidationReport, get_validation_service
from apps.settings.services import SettingsService

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment, NodeSize
    from apps.provisioning.virtualmin_models import VirtualminServer
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
    terraform_result: TerraformResult | None = None
    ansible_results: list[AnsibleResult] | None = None
    validation_report: NodeValidationReport | None = None
    virtualmin_server_id: int | None = None
    error: str | None = None
    duration_seconds: float = 0.0


class NodeDeploymentService:
    """
    Main Deployment Orchestrator

    Manages the complete lifecycle of node deployments:
    - Initial deployment (Terraform + Ansible)
    - Validation and registration
    - Upgrade operations
    - Destruction

    All operations are designed to be resumable and idempotent where possible.
    """

    # Deployment stages with progress percentages
    STAGES = {
        "init": (0, "Initializing deployment"),
        "ssh_key": (5, "Generating SSH key"),
        "terraform_init": (10, "Initializing Terraform"),
        "terraform_plan": (20, "Planning infrastructure"),
        "terraform_apply": (30, "Provisioning infrastructure"),
        "update_deployment": (50, "Updating deployment records"),
        "ansible_base": (55, "Running base configuration"),
        "ansible_panel": (65, "Installing control panel"),
        "ansible_harden": (75, "Hardening server"),
        "ansible_backup": (80, "Configuring backups"),
        "validation": (85, "Validating node"),
        "registration": (95, "Registering node"),
        "complete": (100, "Deployment complete"),
    }

    def __init__(self) -> None:
        """Initialize deployment service with all required sub-services"""
        self._ssh_manager = get_ssh_key_manager()
        self._terraform = get_terraform_service()
        self._ansible = get_ansible_service()
        self._validation = get_validation_service()
        self._registration = get_registration_service()

    def deploy_node(
        self,
        deployment: NodeDeployment,
        credentials: dict[str, str],
        cloudflare_api_token: str | None = None,
        user: User | None = None,
        progress_callback: callable | None = None,
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
        from pathlib import Path

        start_time = timezone.now()
        stages_completed: list[str] = []
        terraform_result: TerraformResult | None = None
        ansible_results: list[AnsibleResult] = []
        deploy_dir: Path | None = None  # Track for cleanup on exception

        def report_progress(stage: str) -> None:
            if progress_callback and stage in self.STAGES:
                pct, msg = self.STAGES[stage]
                progress_callback(DeploymentProgress(stage=stage, percentage=pct, message=msg))

        def log_deployment(level: str, message: str) -> None:
            """Log to both logger and deployment log"""
            from apps.infrastructure.models import NodeDeploymentLog

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

            # Validate deployment is in correct state
            if deployment.status not in ("pending", "failed"):
                return Err(f"Cannot deploy node in status '{deployment.status}'")

            # Check if deployment is enabled
            if not SettingsService.get_setting("node_deployment.enabled", True):
                return Err("Node deployment is disabled in settings")

            # Validate provider prerequisites (CLI tools, Terraform, modules)
            provider_type = deployment.provider.provider_type
            prereq_result = validate_provider_prerequisites(provider_type)
            if prereq_result.is_err():
                self._mark_failed(
                    deployment,
                    f"Provider prerequisites check failed: {prereq_result.unwrap_err()}",
                )
                return Err(f"Provider prerequisites check failed: {prereq_result.unwrap_err()}")

            # Transition to provisioning
            if not deployment.transition_to("provisioning_node"):
                return Err(f"Invalid state transition from '{deployment.status}' to 'provisioning_node'")
            deployment.save()

            # Stage 1: Generate SSH key
            report_progress("ssh_key")
            log_deployment("info", "Generating deployment SSH key")

            key_result = self._ssh_manager.generate_deployment_key(
                deployment,
                user=user,
                reason=f"Node deployment: {deployment.hostname}",
            )

            if key_result.is_err():
                # Try master key fallback
                master_result = self._ssh_manager.get_master_key()
                if master_result.is_err():
                    self._mark_failed(deployment, f"SSH key generation failed: {key_result.unwrap_err()}")
                    return Err(f"SSH key generation failed: {key_result.unwrap_err()}")
                ssh_public_key = self._ssh_manager.get_master_public_key().unwrap()
                log_deployment("warning", "Using master SSH key (fallback)")
            else:
                ssh_public_key = key_result.unwrap().public_key
                log_deployment("info", "SSH key generated successfully")

            stages_completed.append("ssh_key")

            # Stage 2: Generate Terraform config
            report_progress("terraform_init")
            log_deployment("info", "Generating Terraform configuration")

            config_result = self._terraform.generate_deployment_config(
                deployment=deployment,
                ssh_public_key=ssh_public_key,
                credentials=credentials,
                cloudflare_api_token=cloudflare_api_token,
            )

            if config_result.is_err():
                self._mark_failed(deployment, f"Terraform config generation failed: {config_result.unwrap_err()}")
                return Err(f"Terraform config generation failed: {config_result.unwrap_err()}")

            deploy_dir = config_result.unwrap()
            log_deployment("info", f"Terraform config generated at: {deploy_dir}")

            # Stage 3: Terraform init
            init_result = self._terraform.init(deploy_dir)
            if not init_result.success:
                self._terraform.cleanup_sensitive_files(deploy_dir)  # SECURITY: Remove credentials
                self._mark_failed(deployment, f"Terraform init failed: {init_result.stderr[:500]}")
                return Err(f"Terraform init failed: {init_result.stderr[:500]}")

            stages_completed.append("terraform_init")
            log_deployment("info", "Terraform initialized successfully")

            # Stage 4: Terraform plan
            report_progress("terraform_plan")
            plan_result = self._terraform.plan(deploy_dir)
            if not plan_result.success:
                self._terraform.cleanup_sensitive_files(deploy_dir)  # SECURITY: Remove credentials
                self._mark_failed(deployment, f"Terraform plan failed: {plan_result.stderr[:500]}")
                return Err(f"Terraform plan failed: {plan_result.stderr[:500]}")

            stages_completed.append("terraform_plan")
            log_deployment("info", "Terraform plan successful")

            # Stage 5: Terraform apply
            report_progress("terraform_apply")
            log_deployment("info", "Applying Terraform configuration")

            apply_result = self._terraform.apply(deploy_dir)
            terraform_result = apply_result

            if not apply_result.success:
                self._terraform.cleanup_sensitive_files(deploy_dir)  # SECURITY: Remove credentials
                self._mark_failed(deployment, f"Terraform apply failed: {apply_result.stderr[:500]}")
                return Err(f"Terraform apply failed: {apply_result.stderr[:500]}")

            stages_completed.append("terraform_apply")
            log_deployment("info", "Infrastructure provisioned successfully")

            # SECURITY: Clean up sensitive tfvars file immediately after terraform apply
            self._terraform.cleanup_sensitive_files(deploy_dir)

            # Stage 6: Update deployment with Terraform outputs
            report_progress("update_deployment")

            outputs = apply_result.outputs
            if not outputs or "ipv4_address" not in outputs:
                self._mark_failed(deployment, "Terraform did not return IP address")
                return Err("Terraform did not return IP address")

            with transaction.atomic():
                # Map terraform outputs to deployment fields using provider config
                provider_type = deployment.provider.provider_type
                map_terraform_outputs_to_deployment(provider_type, outputs, deployment)
                deployment.terraform_state_version = 1
                deployment.transition_to("configuring_dns")
                deployment.save()

            stages_completed.append("update_deployment")
            log_deployment("info", f"Server provisioned with IP: {deployment.ipv4_address}")

            # Transition to Ansible phase
            deployment.transition_to("running_ansible")
            deployment.save()

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
            ansible_playbooks = list(zip(stage_keys, playbook_names))

            for stage_name, playbook in ansible_playbooks:
                report_progress(stage_name)
                log_deployment("info", f"Running Ansible playbook: {playbook}")

                playbook_result = self._ansible.run_playbook(
                    deployment=deployment,
                    playbook=playbook,
                )

                if playbook_result.is_err():
                    self._mark_failed(deployment, f"Ansible {playbook} failed: {playbook_result.unwrap_err()}")
                    return Err(f"Ansible {playbook} failed: {playbook_result.unwrap_err()}")

                result = playbook_result.unwrap()
                ansible_results.append(result)

                if not result.success:
                    self._mark_failed(deployment, f"Ansible {playbook} failed: {result.stderr[:500]}")
                    return Err(f"Ansible {playbook} failed: {result.stderr[:500]}")

                stages_completed.append(stage_name)
                log_deployment("info", f"Ansible {playbook} completed successfully")

            # Stage 11: Validation
            report_progress("validation")
            deployment.transition_to("validating")
            deployment.save()
            log_deployment("info", "Validating node health")

            validation_result = self._validation.validate_node(deployment)

            if validation_result.is_err():
                self._mark_failed(deployment, f"Validation failed: {validation_result.unwrap_err()}")
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
            deployment.save()
            log_deployment("info", "Registering node as VirtualminServer")

            # Generate a random password for Virtualmin admin
            import secrets
            import string

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
            deployment.transition_to("completed")
            deployment.deployed_at = timezone.now()
            deployment.save()

            stages_completed.append("complete")

            duration = (timezone.now() - start_time).total_seconds()
            log_deployment("info", f"Deployment completed successfully in {duration:.1f}s")

            return Ok(
                DeploymentResult(
                    success=True,
                    deployment_id=deployment.id,
                    hostname=deployment.hostname,
                    stages_completed=stages_completed,
                    terraform_result=terraform_result,
                    ansible_results=ansible_results,
                    validation_report=validation_report,
                    virtualmin_server_id=virtualmin_server_id,
                    duration_seconds=duration,
                )
            )

        except Exception as e:
            logger.exception(f"Deployment failed for {deployment.hostname}: {e}")
            # SECURITY: Clean up sensitive tfvars file on exception
            if deploy_dir is not None:
                self._terraform.cleanup_sensitive_files(deploy_dir)
            self._mark_failed(deployment, str(e))

            duration = (timezone.now() - start_time).total_seconds()
            return Err(f"Deployment failed: {e}")

    def destroy_node(
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
        from apps.infrastructure.models import NodeDeploymentLog

        logger.info(f"[Destroy:{deployment.hostname}] Starting node destruction")

        if deployment.status not in ("completed", "failed", "stopped"):
            return Err(f"Cannot destroy node in status '{deployment.status}'")

        try:
            # Transition to destroying
            deployment.transition_to("destroying")
            deployment.save()

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

            # Find Terraform deployment directory
            from pathlib import Path

            deploy_dir = (
                Path(SettingsService.get_setting("node_deployment.terraform_state_path", "/var/lib/praho/terraform"))
                / deployment.hostname
            )

            if not deploy_dir.exists():
                # No Terraform state - might have been manually cleaned
                logger.warning(f"Terraform directory not found: {deploy_dir}")
                deployment.transition_to("destroyed")
                deployment.destroyed_at = timezone.now()
                deployment.save()
                return Ok(True)

            # Regenerate Terraform config with tokens for destroy
            config_result = self._terraform.generate_deployment_config(
                deployment=deployment,
                ssh_public_key="",  # Not needed for destroy
                credentials=credentials,
                cloudflare_api_token=cloudflare_api_token,
            )

            if config_result.is_err():
                return Err(f"Could not regenerate Terraform config: {config_result.unwrap_err()}")

            # Run Terraform destroy
            destroy_result = self._terraform.destroy(deploy_dir)

            if not destroy_result.success:
                self._mark_failed(deployment, f"Terraform destroy failed: {destroy_result.stderr[:500]}")
                return Err(f"Terraform destroy failed: {destroy_result.stderr[:500]}")

            # Clean up SSH key from vault
            self._ssh_manager.revoke_deployment_key(deployment, user=user)

            # Mark as destroyed
            deployment.transition_to("destroyed")
            deployment.destroyed_at = timezone.now()
            deployment.save()

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node destroyed successfully",
                phase="destroyed",
            )

            logger.info(f"[Destroy:{deployment.hostname}] Node destroyed successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Destruction failed for {deployment.hostname}: {e}")
            self._mark_failed(deployment, str(e))
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

        # Reset to pending for fresh start
        deployment.status = "pending"
        deployment.save()

        logger.info(f"[Retry:{deployment.hostname}] Retrying deployment (attempt {deployment.retry_count})")

        return self.deploy_node(
            deployment=deployment,
            credentials=credentials,
            cloudflare_api_token=cloudflare_api_token,
            user=user,
        )

    def upgrade_node_size(
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
        from apps.infrastructure.models import NodeDeploymentLog

        logger.info(f"[Upgrade:{deployment.hostname}] Starting node resize to {new_size.name}")

        if deployment.status != "completed":
            return Err(f"Can only upgrade completed deployments, current status: {deployment.status}")

        if deployment.node_size == new_size:
            return Err("Node is already using the selected size")

        if new_size.provider != deployment.provider:
            return Err("New size must be from the same provider")

        old_size = deployment.node_size

        try:
            # Log the upgrade start
            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message=f"Starting upgrade from {old_size.name} to {new_size.name}",
                phase="upgrading",
            )

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
            return Err(f"Upgrade failed: {e}")

    def run_maintenance(
        self,
        deployment: NodeDeployment,
        playbooks: list[str] | None = None,
        extra_vars: dict | None = None,
        user: User | None = None,
    ) -> Result[list, str]:
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
        from apps.infrastructure.models import NodeDeploymentLog

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
        from apps.infrastructure.models import NodeDeploymentLog

        logger.info(f"[Stop:{deployment.hostname}] Stopping node")

        if deployment.status not in ("completed", "stopped"):
            return Err(f"Can only stop completed nodes, current status: {deployment.status}")

        if deployment.status == "stopped":
            return Ok(True)  # Already stopped

        try:
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="power_off",
                credentials=credentials,
                server_id=str(deployment.external_node_id),
            )

            if result.is_err():
                return Err(f"Failed to stop node: {result.unwrap_err()}")

            cmd_result = result.unwrap()
            if not cmd_result.success:
                return Err(f"Failed to stop node: {cmd_result.stderr}")

            deployment.status = "stopped"
            deployment.save()

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node stopped (powered off)",
                phase="stopped",
            )

            logger.info(f"[Stop:{deployment.hostname}] Node stopped successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Stop failed for {deployment.hostname}: {e}")
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
        from apps.infrastructure.models import NodeDeploymentLog

        logger.info(f"[Start:{deployment.hostname}] Starting node")

        if deployment.status != "stopped":
            return Err(f"Can only start stopped nodes, current status: {deployment.status}")

        try:
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="power_on",
                credentials=credentials,
                server_id=str(deployment.external_node_id),
            )

            if result.is_err():
                return Err(f"Failed to start node: {result.unwrap_err()}")

            cmd_result = result.unwrap()
            if not cmd_result.success:
                return Err(f"Failed to start node: {cmd_result.stderr}")

            deployment.status = "completed"
            deployment.save()

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node started (powered on)",
                phase="completed",
            )

            logger.info(f"[Start:{deployment.hostname}] Node started successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Start failed for {deployment.hostname}: {e}")
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
        from apps.infrastructure.models import NodeDeploymentLog

        logger.info(f"[Reboot:{deployment.hostname}] Rebooting node")

        if deployment.status != "completed":
            return Err(f"Can only reboot running nodes, current status: {deployment.status}")

        try:
            provider_type = deployment.provider.provider_type
            result = run_provider_command(
                provider_type=provider_type,
                operation="reboot",
                credentials=credentials,
                server_id=str(deployment.external_node_id),
            )

            if result.is_err():
                return Err(f"Failed to reboot node: {result.unwrap_err()}")

            cmd_result = result.unwrap()
            if not cmd_result.success:
                return Err(f"Failed to reboot node: {cmd_result.stderr}")

            NodeDeploymentLog.objects.create(
                deployment=deployment,
                level="INFO",
                message="Node rebooted",
                phase="completed",
            )

            logger.info(f"[Reboot:{deployment.hostname}] Node rebooted successfully")
            return Ok(True)

        except Exception as e:
            logger.exception(f"Reboot failed for {deployment.hostname}: {e}")
            return Err(f"Reboot failed: {e}")

    def _mark_failed(self, deployment: NodeDeployment, error_message: str) -> None:
        """Mark deployment as failed with error message"""
        from apps.infrastructure.models import NodeDeploymentLog

        deployment.status = "failed"
        deployment.save()

        NodeDeploymentLog.objects.create(
            deployment=deployment,
            level="ERROR",
            message=error_message,
            phase="failed",
        )

        logger.error(f"[Deployment:{deployment.hostname}] Failed: {error_message}")


# Module-level singleton
_deployment_service: NodeDeploymentService | None = None


def get_deployment_service() -> NodeDeploymentService:
    """Get global deployment service instance"""
    global _deployment_service
    if _deployment_service is None:
        _deployment_service = NodeDeploymentService()
    return _deployment_service
