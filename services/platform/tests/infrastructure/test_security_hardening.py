"""Regression tests for infrastructure trust-boundary hardening."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import paramiko
from django.test import SimpleTestCase, TestCase, override_settings

from apps.common.performance.connection_pool import SSHConnectionPool
from apps.common.types import Ok
from apps.infrastructure.ansible_service import ANSIBLE_BASE_PATH, AnsibleService
from apps.infrastructure.ssh_key_manager import SSHKeyManager, SSHKeyPair
from apps.infrastructure.validation_service import NodeValidationService


class AnsiblePlaybookBoundaryTests(SimpleTestCase):
    """Only repository-owned playbooks may reach root-level Ansible execution."""

    def _service(self) -> AnsibleService:
        service = object.__new__(AnsibleService)
        service.timeout = 30
        service._ansible_path = "/usr/bin/ansible-playbook"
        service._ssh_manager = MagicMock()
        return service

    def test_path_traversal_is_rejected_before_ssh_key_access(self) -> None:
        service = self._service()
        deployment = MagicMock(ipv4_address="203.0.113.10")

        result = service.run_playbook(deployment, "../ansible.cfg")

        self.assertTrue(result.is_err())
        self.assertIn("not allowed", result.unwrap_err().lower())
        service._ssh_manager.get_private_key_file.assert_not_called()

    @patch("apps.infrastructure.ansible_service.subprocess.run")
    @override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH="/etc/praho/known_hosts")
    def test_ansible_host_key_checking_is_enabled(self, mock_run: MagicMock) -> None:
        service = self._service()
        service._ssh_manager.get_private_key_file.return_value = Ok(Path("nonexistent-praho-key"))
        deployment = MagicMock(ipv4_address="203.0.113.10", hostname="node.example.com")
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        with (
            patch.object(service, "_generate_inventory", return_value=Path("nonexistent-praho-inventory")),
            patch.object(service, "_build_vars", return_value={}),
        ):
            result = service.run_playbook(deployment, "virtualmin_harden.yml")

        self.assertTrue(result.is_ok())
        self.assertEqual(mock_run.call_args.kwargs["env"]["ANSIBLE_HOST_KEY_CHECKING"], "True")
        self.assertIn(
            "UserKnownHostsFile=/etc/praho/known_hosts",
            mock_run.call_args.kwargs["env"]["ANSIBLE_SSH_COMMON_ARGS"],
        )

    def test_repository_ansible_config_does_not_disable_host_key_checking(self) -> None:
        config = (ANSIBLE_BASE_PATH / "ansible.cfg").read_text()

        self.assertIn("host_key_checking = True", config)
        self.assertNotIn("StrictHostKeyChecking=no", config)


class InfrastructureSSHTrustTests(SimpleTestCase):
    """Validation SSH connections must use pre-provisioned known-host trust."""

    @patch("apps.infrastructure.validation_service.paramiko.Ed25519Key.from_private_key")
    @patch("apps.infrastructure.validation_service.paramiko.SSHClient")
    @override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH="/etc/praho/known_hosts")
    def test_validation_rejects_unknown_host_keys(
        self,
        mock_client_class: MagicMock,
        _mock_private_key: MagicMock,
    ) -> None:
        service = object.__new__(NodeValidationService)
        service.timeout = 10
        service._ssh_manager = MagicMock()
        service._ssh_manager.get_deployment_key.return_value = Ok(MagicMock(private_key="private-key"))
        deployment = MagicMock(ipv4_address="203.0.113.10")
        client = mock_client_class.return_value
        stdout = MagicMock()
        stdout.read.return_value = b"node.example.com"
        client.exec_command.return_value = (MagicMock(), stdout, MagicMock())

        result = service._check_ssh(deployment)

        self.assertTrue(result.passed)
        client.load_system_host_keys.assert_called_once_with()
        client.load_host_keys.assert_called_once_with("/etc/praho/known_hosts")
        policy = client.set_missing_host_key_policy.call_args.args[0]
        self.assertIsInstance(policy, paramiko.RejectPolicy)

    @override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH="/etc/praho/known_hosts")
    def test_shared_ssh_pool_rejects_unknown_host_keys(self) -> None:
        pool = object.__new__(SSHConnectionPool)
        pool._paramiko = MagicMock()
        pool.max_connections = 1
        pool.idle_timeout = 30
        pool._connections = {}
        import threading  # noqa: PLC0415

        pool._lock = threading.Lock()
        client = pool._paramiko.SSHClient.return_value

        pool.get_connection("node.example.com", "root", password="secret")

        client.load_system_host_keys.assert_called_once_with()
        client.load_host_keys.assert_called_once_with("/etc/praho/known_hosts")
        client.set_missing_host_key_policy.assert_called_once_with(pool._paramiko.RejectPolicy.return_value)


class SSHKeyLifecycleAuditTests(TestCase):
    """Key creation and revocation must leave sensitive audit evidence."""

    @patch("apps.infrastructure.audit_service.InfrastructureAuditService.log_ssh_key_generated")
    def test_generation_is_audited(self, mock_audit: MagicMock) -> None:
        manager = SSHKeyManager()
        manager._vault = MagicMock()
        manager._vault.store_credential.return_value = Ok(MagicMock(id="credential-id"))
        deployment = MagicMock(hostname="node.example.com", id=42)
        key_pair = SSHKeyPair(public_key="ssh-ed25519 AAAA", private_key="private", fingerprint="SHA256:test")

        with patch.object(manager, "generate_key_pair", return_value=key_pair):
            result = manager.generate_deployment_key(deployment)

        self.assertTrue(result.is_ok())
        mock_audit.assert_called_once()
        self.assertEqual(mock_audit.call_args.args[:2], (deployment, "SHA256:test"))

    @patch("apps.infrastructure.audit_service.InfrastructureAuditService.log_ssh_key_revoked")
    @patch("apps.infrastructure.ssh_key_manager.EncryptedCredential.objects.get")
    def test_revocation_is_audited(self, mock_get: MagicMock, mock_audit: MagicMock) -> None:
        manager = SSHKeyManager()
        deployment = MagicMock(hostname="node.example.com", ssh_key_credential_id="credential-id")
        mock_get.return_value = MagicMock()

        result = manager.delete_deployment_key(deployment)

        self.assertTrue(result.is_ok())
        mock_audit.assert_called_once()
        self.assertEqual(mock_audit.call_args.args[0], deployment)

    def test_private_key_file_preserves_ansible_access_reason(self) -> None:
        manager = SSHKeyManager()
        deployment = MagicMock(hostname="node.example.com")
        key_pair = SSHKeyPair(public_key="ssh-ed25519 AAAA", private_key="private", fingerprint="SHA256:test")

        with patch.object(manager, "get_deployment_key", return_value=Ok(key_pair)) as mock_get_key:
            result = manager.get_private_key_file(deployment, reason="Ansible playbook: virtualmin_harden.yml")

        self.assertTrue(result.is_ok())
        key_file = result.unwrap()
        self.addCleanup(key_file.unlink, missing_ok=True)
        mock_get_key.assert_called_once_with(deployment, None, "Ansible playbook: virtualmin_harden.yml")
