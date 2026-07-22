"""
Ansible Service

Wrapper for executing Ansible playbooks for node configuration.
Handles inventory generation, playbook execution, and log capture.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from django.conf import settings

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
    ALLOWED_PLAYBOOKS: ClassVar[frozenset[str]] = frozenset(
        {
            "common_base.yml",
            "virtualmin.yml",
            "virtualmin_harden.yml",
            "virtualmin_backup.yml",
            "blesta.yml",
            "blesta_harden.yml",
            "blesta_backup.yml",
        }
    )

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

    def run_playbook(  # noqa: PLR0911, PLR0912, PLR0915, C901  # Fail-closed boundary checks, SSH-readiness + host-key pinning, guarded temp-file cleanup
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

        if playbook not in self.ALLOWED_PLAYBOOKS:
            return Err(f"Playbook not allowed: {playbook}")

        playbook_path = (PLAYBOOKS_PATH / playbook).resolve()
        if playbook_path.parent != PLAYBOOKS_PATH.resolve():
            return Err(f"Playbook not allowed: {playbook}")
        if not playbook_path.exists():
            return Err(f"Playbook not found: {playbook_path}")

        # Get SSH key
        key_result = self._ssh_manager.get_private_key_file(
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
            # A freshly-created node reports "running" before its OS has booted sshd, so wait
            # until SSH is actually reachable — otherwise ansible fails UNREACHABLE (#node-deploy).
            ssh_wait = self._wait_for_ssh(deployment.ipv4_address)
            if ssh_wait.is_err():
                return Err(ssh_wait.unwrap_err())
            # Managed TOFU is only sound on FIRST use: when the operator's configured
            # known_hosts already covers this node, that pinned key must outrank any
            # fresh network scan — otherwise an active MITM at re-run time silently
            # replaces the trust anchor. Scan-and-pin only for genuinely new nodes.
            known_hosts_file = None
            if not self._configured_known_hosts_covers(deployment.ipv4_address):
                known_hosts_file = self._scan_host_key(deployment.ipv4_address)

            # Generate inventory
            inventory_file = self._generate_inventory(deployment)

            # Build extra vars
            vars_dict = self._build_vars(deployment, extra_vars)
            # Pass vars via a 0600 temp file (`-e @file`), never `-e <json>` on the
            # command line: extra_vars can carry secrets (the Virtualmin API
            # password, #347) that would otherwise leak into the process list.
            # Cleaned up in the finally block.
            vars_file = self._write_vars_file(vars_dict)

            # Build command
            cmd = [
                self._ansible_path,
                "-i",
                str(inventory_file),
                "--private-key",
                str(key_file),
            ]
            # Load group_vars/all.yml explicitly. Ansible does NOT auto-load it for this deploy:
            # group_vars/ is discovered next to the INVENTORY or the PLAYBOOK, but the inventory is
            # a temp file in /tmp and the playbook lives in playbooks/ (group_vars is one level up),
            # so every group var (system_timezone, php_*, webserver_modules, ssh_*, ...) would be
            # UNDEFINED. Listed BEFORE the per-deployment vars file so deployment values still win
            # (ansible extra-vars: later -e overrides earlier).
            group_vars_all = ANSIBLE_BASE_PATH / "group_vars" / "all.yml"
            if group_vars_all.is_file():
                cmd += ["-e", f"@{group_vars_all}"]
            cmd += [
                "-e",
                f"@{vars_file}",
                str(playbook_path),
            ]

            logger.info(f"📜 [Ansible] Running: {playbook} on {deployment.ipv4_address}")

            ansible_env = self._build_ansible_env(known_hosts_file=known_hosts_file)

            # Execute
            result = subprocess.run(  # Safe: shell=False  # noqa: S603  # Safe: shell=False
                cmd,
                cwd=ANSIBLE_BASE_PATH,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                env=ansible_env,
            )

            success = result.returncode == 0
            log_level = logging.INFO if success else logging.ERROR
            logger.log(log_level, f"📜 [Ansible] Playbook {playbook}: {'success' if success else 'failed'}")

            if not success:
                logger.error(
                    f"📜 [Ansible] rc={result.returncode} out_len={len(result.stdout)} err_len={len(result.stderr)}"
                )
                if result.stderr.strip():
                    logger.error(f"📜 [Ansible] stderr: {result.stderr[:1000]}")
                # A task failure (rc=2) puts the actionable detail — which task failed and the
                # fatal msg — in STDOUT with the default callback, even when stderr only carries
                # an unrelated warning. Always surface the stdout tail on failure so an operator
                # sees the reason instead of an empty "playbook failed:".
                logger.error(f"📜 [Ansible] stdout(tail): {result.stdout[-2500:]}")

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
            # Cleanup temp files (key, inventory, vars). Remove the SECRET-bearing vars file FIRST,
            # and guard each unlink independently so one failure can't strand the others (a lingering
            # 0600 credential file matters more than a leftover inventory).
            local_vars = locals()
            for _tmp_name in ("vars_file", "key_file", "inventory_file", "known_hosts_file"):
                _tmp_path = local_vars.get(_tmp_name)
                if isinstance(_tmp_path, Path):
                    try:
                        _tmp_path.unlink(missing_ok=True)
                    except OSError as _cleanup_err:
                        logger.warning(f"⚠️ [Ansible] Could not remove temp file {_tmp_path}: {_cleanup_err}")

    @staticmethod
    def _write_vars_file(vars_dict: dict[str, Any]) -> Path:
        """Write playbook vars to a 0600 temp file so secrets in extra_vars (the
        Virtualmin API password, #347) never reach the ansible command line or
        the host's process list. The caller removes it in its finally block."""
        vars_fd, vars_path_str = tempfile.mkstemp(prefix="praho_ansible_vars_", suffix=".json")
        vars_file = Path(vars_path_str)
        try:
            with os.fdopen(vars_fd, "w") as vars_fh:
                json.dump(vars_dict, vars_fh)
            os.chmod(vars_file, 0o600)
        except Exception:
            # A raise mid-write (non-serializable vars, disk full, chmod failure) would otherwise
            # orphan a partial-secret 0600 file: the caller keys its finally cleanup on the RETURNED
            # path, which never binds when this raises. Clean up our own temp before propagating.
            vars_file.unlink(missing_ok=True)
            raise
        return vars_file

    @staticmethod
    def _build_ansible_env(known_hosts_file: Path | None = None) -> dict[str, str]:
        """Build an environment that always enforces managed SSH host-key trust.

        known_hosts_file: a freshly-scanned+pinned known_hosts for a newly provisioned node
        (managed TOFU). When provided it takes precedence over the configured path.
        """
        ansible_env = {
            **os.environ,
            "ANSIBLE_HOST_KEY_CHECKING": "True",
            "ANSIBLE_SSH_COMMON_ARGS": "-o StrictHostKeyChecking=yes",
            # The community.general.yaml stdout callback was REMOVED in community.general
            # 12.0.0. Its replacement is ansible-core's built-in default callback with
            # result_format=yaml. This env var overrides ansible.cfg, so it must be fixed
            # HERE (not just in ansible.cfg) or deploys fail: "callback plugin has been removed".
            "ANSIBLE_STDOUT_CALLBACK": "default",
            "ANSIBLE_CALLBACK_RESULT_FORMAT": "yaml",
            "ANSIBLE_FORCE_COLOR": "0",
        }
        # Prefer the freshly-scanned host key for a new node; otherwise a configured verified
        # file — but only if it actually exists, so a misconfigured/placeholder path (e.g. an
        # inline .env comment mis-parsed as the value) can't inject garbage into the SSH args.
        known_hosts_path = ""
        if known_hosts_file is not None:
            known_hosts_path = str(known_hosts_file)
        else:
            configured = str(getattr(settings, "PRAHO_SSH_KNOWN_HOSTS_PATH", "")).strip()
            if configured and Path(configured).is_file():
                known_hosts_path = configured
        if known_hosts_path:
            known_hosts_arg = f"-o UserKnownHostsFile={shlex.quote(known_hosts_path)}"
            ansible_env["ANSIBLE_SSH_COMMON_ARGS"] = f"{ansible_env['ANSIBLE_SSH_COMMON_ARGS']} {known_hosts_arg}"
        return ansible_env

    @staticmethod
    def _configured_known_hosts_covers(ip: str) -> bool:
        """True when the operator-configured known_hosts has a key for this node.

        Uses ``ssh-keygen -F`` (handles hashed hostnames) rather than substring
        matching. When the lookup tooling itself fails, returns True — keeping
        the stricter configured anchor is the fail-closed choice; a missing key
        then fails the SSH host-key check loudly instead of silently re-pinning.
        """
        configured = str(getattr(settings, "PRAHO_SSH_KNOWN_HOSTS_PATH", "")).strip()
        if not configured or not Path(configured).is_file():
            return False
        keygen_bin = shutil.which("ssh-keygen") or "ssh-keygen"
        try:
            lookup = subprocess.run(  # noqa: S603  # ssh-keygen -F on a PRAHO-managed file
                [keygen_bin, "-F", ip, "-f", configured],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return True
        return lookup.returncode == 0 and bool(lookup.stdout.strip())

    @staticmethod
    def _wait_for_ssh(ip: str, port: int = 22, timeout: int = 180, interval: float = 3.0) -> Result[bool, str]:
        """Block until the node accepts TCP connections on the SSH port.

        A freshly-created cloud server reports 'running' the moment its VM powers on, but the
        OS needs ~30-60s more to bring up networking and start sshd. Running ansible before then
        fails with an opaque UNREACHABLE. Bounded so a genuinely-unreachable node fails LOUDLY
        with an actionable message rather than hanging or emitting an empty error.
        """
        deadline = time.monotonic() + timeout
        last = "no attempt"
        while time.monotonic() < deadline:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            try:
                sock.connect((ip, port))
                logger.info(f"🔌 [Ansible] SSH reachable on {ip}:{port}")
                return Ok(True)
            except OSError as exc:
                last = type(exc).__name__
            finally:
                sock.close()
            time.sleep(interval)
        return Err(f"Node {ip} not SSH-reachable on port {port} after {timeout}s (last error: {last})")

    @staticmethod
    def _scan_host_key(ip: str) -> Path | None:
        """ssh-keyscan the node's host key into a 0600 temp known_hosts file and pin it for
        this run (managed TOFU for freshly provisioned nodes — the platform has no way to know
        a brand-new node's key in advance). Returns None on failure; the caller then falls back
        to the configured known_hosts. Caller removes the file in its finally block."""
        fd, path_str = tempfile.mkstemp(prefix="praho_known_hosts_", suffix="")
        path = Path(path_str)
        keyscan_bin = shutil.which("ssh-keyscan") or "ssh-keyscan"
        try:
            scan = subprocess.run(  # noqa: S603  # ssh-keyscan on a PRAHO-controlled node IP
                [keyscan_bin, "-T", "10", ip],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if scan.returncode != 0 or not scan.stdout.strip():
                logger.warning(f"⚠️ [Ansible] ssh-keyscan for {ip} produced no host keys")
                os.close(fd)
                path.unlink(missing_ok=True)
                return None
            with os.fdopen(fd, "w") as key_fh:  # takes ownership of fd
                key_fh.write(scan.stdout)
            os.chmod(path, 0o600)
            logger.info(f"🔑 [Ansible] Pinned host key for {ip}")
            return path
        except (OSError, subprocess.SubprocessError) as exc:
            logger.warning(f"⚠️ [Ansible] ssh-keyscan failed for {ip}: {exc}")
            with contextlib.suppress(OSError):  # fd may already be closed if os.fdopen ran
                os.close(fd)
            path.unlink(missing_ok=True)
            return None

    def _generate_inventory(self, deployment: NodeDeployment) -> Path:
        """Generate dynamic inventory file for deployment"""
        inventory_content = f"""# Auto-generated inventory for {deployment.hostname}
[all]
{deployment.hostname} ansible_host={deployment.ipv4_address} ansible_user=root

[all:vars]
ansible_python_interpreter=/usr/bin/python3
"""
        # Write to temp file. Clean up our own temp on a mid-write failure so a raise here can't
        # orphan it — the caller keys its finally cleanup on the RETURNED path, which never binds
        # when this raises (mirrors _write_vars_file, #348 #5).
        fd, path = tempfile.mkstemp(prefix="ansible_inv_", suffix=".ini")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(inventory_content)
        except Exception:
            Path(path).unlink(missing_ok=True)
            raise

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
    global _ansible_service  # noqa: PLW0603  # Module-level singleton pattern
    if _ansible_service is None:
        _ansible_service = AnsibleService()
    return _ansible_service
