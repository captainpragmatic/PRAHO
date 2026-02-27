"""
Ansible Service

Wrapper for executing Ansible playbooks for node configuration.
Handles inventory generation, playbook execution, and log capture.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from apps.common.types import Err, Ok, Result
from apps.infrastructure.ssh_key_manager import get_ssh_key_manager
from apps.settings.services import SettingsService

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment

logger = logging.getLogger(__name__)

# Path to ansible files
ANSIBLE_BASE_PATH = Path(__file__).parent.parent.parent / "infrastructure" / "ansible"
PLAYBOOKS_PATH = ANSIBLE_BASE_PATH / "playbooks"


@dataclass
class AnsibleResult:
    """Result of an Ansible operation"""

    success: bool
    playbook: str
    stdout: str
    stderr: str
    return_code: int
    stats: dict[str, Any] = field(default_factory=dict)


class AnsibleService:
    """
    📜 Ansible Service

    Manages Ansible operations for node configuration:
    - Generates dynamic inventory for deployments
    - Runs playbooks (common_base, virtualmin, harden, backup)
    - Captures output and stats
    - Handles SSH key management
    """

    # Panel-aware playbook execution order
    PANEL_PLAYBOOKS: ClassVar[dict[str, list[str]]] = {
        "virtualmin": [
            "common_base.yml",
            "virtualmin.yml",
            "virtualmin_harden.yml",
            "virtualmin_backup.yml",
        ],
        "blesta": [
            "common_base.yml",
            "blesta.yml",
            "blesta_harden.yml",
            "blesta_backup.yml",
        ],
    }

    # Default playbook order (backwards compatibility)
    PLAYBOOK_ORDER = PANEL_PLAYBOOKS["virtualmin"]

    def __init__(self, timeout: int = 1800) -> None:
        """Initialize Ansible service"""
        self.timeout = timeout
        self._ansible_path = self._find_ansible()
        self._ssh_manager = get_ssh_key_manager()

    def _find_ansible(self) -> str:
        """Find ansible-playbook binary"""
        ansible_path = shutil.which("ansible-playbook")
        if not ansible_path:
            for path in ["/usr/local/bin/ansible-playbook", "/usr/bin/ansible-playbook"]:
                if os.path.exists(path):
                    return path
            raise RuntimeError("ansible-playbook not found. Please install Ansible.")
        return ansible_path

    def get_playbook_order(self, panel_type: str = "virtualmin") -> list[str]:
        """Get ordered playbooks for a panel type."""
        return self.PANEL_PLAYBOOKS.get(panel_type, self.PANEL_PLAYBOOKS["virtualmin"])

    def run_all_playbooks(
        self,
        deployment: NodeDeployment,
        extra_vars: dict[str, Any] | None = None,
        panel_type: str = "virtualmin",
    ) -> Result[list[AnsibleResult], str]:
        """
        Run all playbooks in order for a deployment.

        Args:
            deployment: NodeDeployment instance
            extra_vars: Additional variables to pass to playbooks
            panel_type: Panel type to determine playbook order

        Returns:
            Result with list of AnsibleResult or error
        """
        results: list[AnsibleResult] = []
        playbook_order = self.get_playbook_order(panel_type)

        for playbook in playbook_order:
            logger.info(f"📜 [Ansible] Running playbook: {playbook} for {deployment.hostname}")

            result = self.run_playbook(deployment, playbook, extra_vars)

            if result.is_err():
                return Err(f"Playbook {playbook} failed: {result.unwrap_err()}")

            playbook_result = result.unwrap()
            results.append(playbook_result)

            if not playbook_result.success:
                logger.error(f"📜 [Ansible] Playbook {playbook} failed, stopping execution")
                return Err(f"Playbook {playbook} failed: {playbook_result.stderr[:500]}")

        logger.info(f"📜 [Ansible] All {len(results)} playbooks completed successfully")
        return Ok(results)

    def run_playbook(
        self,
        deployment: NodeDeployment,
        playbook: str,
        extra_vars: dict[str, Any] | None = None,
    ) -> Result[AnsibleResult, str]:
        """
        Run a single Ansible playbook.

        Args:
            deployment: NodeDeployment instance
            playbook: Playbook filename (e.g., "virtualmin.yml")
            extra_vars: Additional variables

        Returns:
            Result with AnsibleResult or error
        """
        if not deployment.ipv4_address:
            return Err("Deployment has no IP address")

        playbook_path = PLAYBOOKS_PATH / playbook
        if not playbook_path.exists():
            return Err(f"Playbook not found: {playbook_path}")

        # Get SSH key
        key_result = self._ssh_manager.get_private_key_file(  # type: ignore[call-arg]
            deployment,
            reason=f"Ansible playbook: {playbook}",
        )

        if key_result.is_err():
            # Try master key fallback
            master_result = self._ssh_manager.get_master_key_file()
            if master_result.is_err():
                return Err(f"Could not get SSH key: {key_result.unwrap_err()}")
            key_file = master_result.unwrap()
        else:
            key_file = key_result.unwrap()

        try:
            # Generate inventory
            inventory_file = self._generate_inventory(deployment)

            # Build extra vars
            vars_dict = self._build_vars(deployment, extra_vars)
            vars_json = json.dumps(vars_dict)

            # Build command
            cmd = [
                self._ansible_path,
                "-i",
                str(inventory_file),
                "--private-key",
                str(key_file),
                "-e",
                vars_json,
                str(playbook_path),
            ]

            logger.info(f"📜 [Ansible] Running: {playbook} on {deployment.ipv4_address}")

            # Execute
            result = subprocess.run(  # noqa: PLW1510, S603
                cmd,
                cwd=ANSIBLE_BASE_PATH,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                env={
                    **os.environ,
                    "ANSIBLE_HOST_KEY_CHECKING": "False",
                    "ANSIBLE_STDOUT_CALLBACK": "yaml",
                    "ANSIBLE_FORCE_COLOR": "0",
                },
            )

            success = result.returncode == 0
            log_level = logging.INFO if success else logging.ERROR
            logger.log(log_level, f"📜 [Ansible] Playbook {playbook}: {'success' if success else 'failed'}")

            if not success:
                logger.error(f"📜 [Ansible] stderr: {result.stderr[:1000]}")

            # Parse stats if possible
            stats = self._parse_stats(result.stdout)

            return Ok(
                AnsibleResult(
                    success=success,
                    playbook=playbook,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    return_code=result.returncode,
                    stats=stats,
                )
            )

        except subprocess.TimeoutExpired:
            logger.error(f"🚨 [Ansible] Playbook {playbook} timed out after {self.timeout}s")
            return Ok(
                AnsibleResult(
                    success=False,
                    playbook=playbook,
                    stdout="",
                    stderr=f"Playbook timed out after {self.timeout} seconds",
                    return_code=-1,
                )
            )
        except Exception as e:
            logger.error(f"🚨 [Ansible] Playbook {playbook} failed: {e}")
            return Err(f"Playbook execution failed: {e}")
        finally:
            # Cleanup temporary files
            if key_file.exists():
                key_file.unlink()
            if "inventory_file" in locals() and inventory_file.exists():
                inventory_file.unlink()

    def _generate_inventory(self, deployment: NodeDeployment) -> Path:
        """Generate dynamic inventory file for deployment"""
        inventory_content = f"""# Auto-generated inventory for {deployment.hostname}
[all]
{deployment.hostname} ansible_host={deployment.ipv4_address} ansible_user=root

[all:vars]
ansible_python_interpreter=/usr/bin/python3
"""
        # Write to temp file
        fd, path = tempfile.mkstemp(prefix="ansible_inv_", suffix=".ini")
        with os.fdopen(fd, "w") as f:
            f.write(inventory_content)

        return Path(path)

    def _build_vars(
        self,
        deployment: NodeDeployment,
        extra_vars: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build variables dict for playbook"""
        # Get settings
        backup_enabled = SettingsService.get_setting("node_deployment.backup_enabled", True)
        backup_storage = SettingsService.get_setting("node_deployment.backup_storage", "local")
        backup_retention = SettingsService.get_setting("node_deployment.backup_retention_days", 7)
        backup_schedule = SettingsService.get_setting("node_deployment.backup_schedule", "0 2 * * *")

        vars_dict: dict[str, Any] = {
            # Deployment info
            "deployment_id": str(deployment.id),
            "inventory_hostname": deployment.hostname,
            "inventory_hostname_short": deployment.hostname,
            # Backup settings
            "backup_enabled": backup_enabled,
            "backup_storage": backup_storage,
            "backup_retention_days": backup_retention,
            "backup_schedule": backup_schedule,
            # Force hostname setting
            "virtualmin_force_hostname": True,
        }

        # Add S3 backup settings when S3 storage is configured
        if backup_storage == "s3":
            vars_dict.update(
                {
                    "backup_s3_bucket": SettingsService.get_setting("node_deployment.backup_s3_bucket", ""),
                    "backup_s3_region": SettingsService.get_setting("node_deployment.backup_s3_region", "eu-central-1"),
                    "backup_s3_prefix": SettingsService.get_setting("node_deployment.backup_s3_prefix", "backups/"),
                }
            )

        # Add FQDN if DNS zone is configured
        if deployment.dns_zone:
            vars_dict["inventory_hostname"] = deployment.fqdn

        # Merge extra vars
        if extra_vars:
            vars_dict.update(extra_vars)

        return vars_dict

    def _parse_stats(self, stdout: str) -> dict[str, Any]:
        """Parse Ansible play recap stats from output"""
        stats = {}

        # Look for PLAY RECAP section
        if "PLAY RECAP" in stdout:
            recap_start = stdout.find("PLAY RECAP")
            recap_section = stdout[recap_start:]

            # Try to extract host stats
            # Format: hostname : ok=X changed=Y unreachable=Z failed=W
            import re  # noqa: PLC0415

            match = re.search(
                r"ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)",
                recap_section,
            )
            if match:
                stats = {
                    "ok": int(match.group(1)),
                    "changed": int(match.group(2)),
                    "unreachable": int(match.group(3)),
                    "failed": int(match.group(4)),
                }

        return stats

    def check_playbook_exists(self, playbook: str) -> bool:
        """Check if a playbook file exists"""
        return (PLAYBOOKS_PATH / playbook).exists()

    def list_available_playbooks(self) -> list[str]:
        """List all available playbooks"""
        return [f.name for f in PLAYBOOKS_PATH.glob("*.yml")]


# Module-level singleton
_ansible_service: AnsibleService | None = None


def get_ansible_service() -> AnsibleService:
    """Get global Ansible service instance"""
    global _ansible_service  # noqa: PLW0603
    if _ansible_service is None:
        _ansible_service = AnsibleService()
    return _ansible_service
