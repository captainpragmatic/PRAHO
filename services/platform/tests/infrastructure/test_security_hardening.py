"""Regression tests for infrastructure trust-boundary hardening."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import paramiko
from django.test import SimpleTestCase, TestCase, override_settings

from apps.common.performance.connection_pool import SSHConnectionPool
from apps.common.types import Err, Ok
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
    def test_ansible_host_key_checking_is_enabled(self, mock_run: MagicMock) -> None:
        service = self._service()
        service._ssh_manager.get_private_key_file.return_value = Ok(Path("nonexistent-praho-key"))
        deployment = MagicMock(ipv4_address="203.0.113.10", hostname="node.example.com")
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # The configured trust anchor must be a real file: _build_ansible_env
        # deliberately skips nonexistent configured paths (#367).
        with tempfile.NamedTemporaryFile("w", suffix="_known_hosts", delete=False) as known_hosts_fh:
            known_hosts_fh.write("# managed known_hosts\n")
            configured_known_hosts = known_hosts_fh.name
        try:
            with (
                override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH=configured_known_hosts),
                patch.object(AnsibleService, "_wait_for_ssh", return_value=Ok(True)),
                patch.object(AnsibleService, "_scan_host_key", return_value=None),
                patch.object(service, "_generate_inventory", return_value=Path("nonexistent-praho-inventory")),
                patch.object(service, "_build_vars", return_value={}),
            ):
                result = service.run_playbook(deployment, "virtualmin_harden.yml")

            self.assertTrue(result.is_ok())
            self.assertEqual(mock_run.call_args.kwargs["env"]["ANSIBLE_HOST_KEY_CHECKING"], "True")
            self.assertIn(
                f"UserKnownHostsFile={configured_known_hosts}",
                mock_run.call_args.kwargs["env"]["ANSIBLE_SSH_COMMON_ARGS"],
            )
        finally:
            Path(configured_known_hosts).unlink(missing_ok=True)

    @patch("apps.infrastructure.ansible_service.subprocess.run")
    @override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH="/etc/praho/known_hosts")
    def test_secret_extra_vars_never_reach_the_command_line(self, mock_run: MagicMock) -> None:
        """#347: extra_vars can carry the Virtualmin API password; it must be
        passed via a 0600 temp file (-e @file), never `-e <json>` on argv, or it
        leaks into the PRAHO host's process list."""
        service = self._service()
        service._ssh_manager.get_private_key_file.return_value = Ok(Path("nonexistent-praho-key"))
        deployment = MagicMock(ipv4_address="203.0.113.10", hostname="node.example.com")
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        secret = "SUPER-SECRET-API-PW-9f3a"  # test literal, not a real credential
        with (
            patch.object(AnsibleService, "_wait_for_ssh", return_value=Ok(True)),
            patch.object(AnsibleService, "_scan_host_key", return_value=None),
            patch.object(service, "_generate_inventory", return_value=Path("nonexistent-praho-inventory")),
            patch.object(service, "_build_vars", return_value={"praho_api_password": secret}),
        ):
            result = service.run_playbook(deployment, "virtualmin.yml", extra_vars={"praho_api_password": secret})

        self.assertTrue(result.is_ok())
        argv = [str(a) for a in mock_run.call_args.args[0]]
        self.assertFalse(any(secret in a for a in argv), f"secret leaked onto the command line: {argv}")
        e_idx = argv.index("-e")
        self.assertTrue(argv[e_idx + 1].startswith("@"), f"expected -e @file, got {argv[e_idx + 1]!r}")

    @patch("apps.infrastructure.ansible_service.subprocess.run")
    def test_write_vars_file_does_not_leak_secret_temp_on_write_failure(self, _mock_run: MagicMock) -> None:
        """#348: if writing the vars file raises mid-write, the partial 0600 secret file must NOT be
        left behind. _write_vars_file cleans up its OWN temp before propagating — the caller's finally
        keys cleanup on the returned path, which never binds when the write raises."""
        service = self._service()
        service._ssh_manager.get_private_key_file.return_value = Ok(Path("nonexistent-praho-key"))
        deployment = MagicMock(ipv4_address="203.0.113.10", hostname="node.example.com")

        tmpdir = Path(tempfile.gettempdir())
        before = set(tmpdir.glob("praho_ansible_vars_*"))
        with (
            # Mock the SSH seams or run_playbook errs on the readiness wait BEFORE
            # ever reaching _write_vars_file — the leak assertion would pass
            # vacuously (and eat the full 180s socket timeout) (#367).
            patch.object(AnsibleService, "_wait_for_ssh", return_value=Ok(True)),
            patch.object(AnsibleService, "_scan_host_key", return_value=None),
            patch.object(service, "_generate_inventory", return_value=Path("nonexistent-praho-inventory")),
            patch.object(service, "_build_vars", return_value={"praho_api_password": "secret-value"}),
            patch("apps.infrastructure.ansible_service.json.dump", side_effect=OSError("disk full")),
        ):
            result = service.run_playbook(deployment, "virtualmin.yml", extra_vars={"praho_api_password": "secret-value"})

        self.assertTrue(result.is_err(), "a vars-file write failure must surface as an Err")
        self.assertIn("disk full", result.unwrap_err(), "the Err must come from the vars-file write, not an SSH wait")
        leaked = set(tmpdir.glob("praho_ansible_vars_*")) - before
        self.assertEqual(leaked, set(), f"partial-secret vars file(s) leaked in tempdir: {leaked}")

    @patch.dict(
        "os.environ",
        {
            "ANSIBLE_SSH_COMMON_ARGS": (
                "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/var/lib/praho/untrusted-known-hosts"
            )
        },
    )
    @override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH="/etc/praho/known_hosts")
    def test_ansible_environment_cannot_weaken_host_key_checking(self) -> None:
        # The configured trust anchor must be a real file: nonexistent configured
        # paths are deliberately skipped so a placeholder value can't inject
        # garbage into the SSH args (#367).
        with tempfile.NamedTemporaryFile("w", suffix="_known_hosts", delete=False) as known_hosts_fh:
            known_hosts_fh.write("# managed known_hosts\n")
            configured_known_hosts = known_hosts_fh.name
        try:
            with override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH=configured_known_hosts):
                ansible_env = AnsibleService._build_ansible_env()

            self.assertNotIn("StrictHostKeyChecking=no", ansible_env["ANSIBLE_SSH_COMMON_ARGS"])
            self.assertNotIn("/var/lib/praho/untrusted-known-hosts", ansible_env["ANSIBLE_SSH_COMMON_ARGS"])
            self.assertIn("StrictHostKeyChecking=yes", ansible_env["ANSIBLE_SSH_COMMON_ARGS"])
            self.assertIn(f"UserKnownHostsFile={configured_known_hosts}", ansible_env["ANSIBLE_SSH_COMMON_ARGS"])
        finally:
            Path(configured_known_hosts).unlink(missing_ok=True)

    def test_build_env_skips_configured_known_hosts_that_does_not_exist(self) -> None:
        """A misconfigured/placeholder path must not inject garbage into SSH args,
        and strict host-key checking must survive the fallback (#367)."""
        with override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH="/nonexistent/praho/known_hosts"):
            ansible_env = AnsibleService._build_ansible_env()

        self.assertNotIn("UserKnownHostsFile", ansible_env["ANSIBLE_SSH_COMMON_ARGS"])
        self.assertIn("StrictHostKeyChecking=yes", ansible_env["ANSIBLE_SSH_COMMON_ARGS"])

    def test_build_env_prefers_fresh_scan_over_configured_when_given(self) -> None:
        """A freshly-pinned known_hosts (managed TOFU for a NEW node) takes
        precedence — run_playbook only supplies one when the configured anchor
        does not already cover the node."""
        with tempfile.NamedTemporaryFile("w", suffix="_known_hosts", delete=False) as known_hosts_fh:
            known_hosts_fh.write("# managed known_hosts\n")
            configured_known_hosts = known_hosts_fh.name
        fresh_scan = Path(tempfile.gettempdir()) / "praho_fresh_scan"
        try:
            with override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH=configured_known_hosts):
                ansible_env = AnsibleService._build_ansible_env(known_hosts_file=fresh_scan)

            self.assertIn(f"UserKnownHostsFile={fresh_scan}", ansible_env["ANSIBLE_SSH_COMMON_ARGS"])
            self.assertNotIn(configured_known_hosts, ansible_env["ANSIBLE_SSH_COMMON_ARGS"])
        finally:
            Path(configured_known_hosts).unlink(missing_ok=True)

    def test_repository_ansible_config_does_not_disable_host_key_checking(self) -> None:
        config = (ANSIBLE_BASE_PATH / "ansible.cfg").read_text()

        self.assertIn("host_key_checking = True", config)
        self.assertNotIn("StrictHostKeyChecking=no", config)


class AnsibleTrustPrecedenceTests(SimpleTestCase):
    """TOFU is only sound on FIRST use — configured trust outranks re-scans."""

    def _service(self) -> AnsibleService:
        service = object.__new__(AnsibleService)
        service.timeout = 30
        service._ansible_path = "/usr/bin/ansible-playbook"
        service._ssh_manager = MagicMock()
        return service

    @patch("apps.infrastructure.ansible_service.subprocess.run")
    def test_configured_trust_outranks_tofu_rescan(self, mock_run: MagicMock) -> None:
        """#367 review: when the operator's known_hosts already covers the node,
        a fresh network scan must NOT outrank it — otherwise an active MITM at
        re-run time silently defeats the pinned key."""
        service = self._service()
        service._ssh_manager.get_private_key_file.return_value = Ok(Path("nonexistent-praho-key"))
        deployment = MagicMock(ipv4_address="203.0.113.10", hostname="node.example.com")
        # Covers-lookup (ssh-keygen -F) and the ansible run share this mock:
        # non-empty stdout + rc=0 means "the configured file covers the node".
        mock_run.return_value = MagicMock(returncode=0, stdout="203.0.113.10 ssh-ed25519 AAAA\n", stderr="")

        with tempfile.NamedTemporaryFile("w", suffix="_known_hosts", delete=False) as known_hosts_fh:
            known_hosts_fh.write("203.0.113.10 ssh-ed25519 AAAAconfigured\n")
            configured_known_hosts = known_hosts_fh.name
        try:
            with (
                override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH=configured_known_hosts),
                patch.object(AnsibleService, "_wait_for_ssh", return_value=Ok(True)),
                patch.object(AnsibleService, "_scan_host_key") as mock_scan,
                patch.object(service, "_generate_inventory", return_value=Path("nonexistent-praho-inventory")),
                patch.object(service, "_build_vars", return_value={}),
            ):
                result = service.run_playbook(deployment, "virtualmin.yml")

            self.assertTrue(result.is_ok())
            mock_scan.assert_not_called()
            self.assertIn(
                f"UserKnownHostsFile={configured_known_hosts}",
                mock_run.call_args.kwargs["env"]["ANSIBLE_SSH_COMMON_ARGS"],
            )
        finally:
            Path(configured_known_hosts).unlink(missing_ok=True)

    def test_uncovered_node_falls_back_to_tofu_scan(self) -> None:
        """A genuinely new node (not in the configured anchor) still gets the
        managed TOFU scan — that is the case #367 exists to fix."""
        service = self._service()
        service._ssh_manager.get_private_key_file.return_value = Ok(Path("nonexistent-praho-key"))
        deployment = MagicMock(ipv4_address="203.0.113.10", hostname="node.example.com")

        with (
            patch.object(AnsibleService, "_configured_known_hosts_covers", return_value=False),
            patch.object(AnsibleService, "_wait_for_ssh", return_value=Ok(True)),
            patch.object(AnsibleService, "_scan_host_key", return_value=None) as mock_scan,
            patch.object(service, "_generate_inventory", return_value=Path("nonexistent-praho-inventory")),
            patch.object(service, "_build_vars", return_value={}),
            patch("apps.infrastructure.ansible_service.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = service.run_playbook(deployment, "virtualmin.yml")

        self.assertTrue(result.is_ok())
        mock_scan.assert_called_once_with("203.0.113.10")

    def test_configured_known_hosts_covers_real_lookup(self) -> None:
        """The covers-check uses real ssh-keygen -F semantics (handles hashed
        hostnames), not naive substring matching."""
        key_line = "203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPrahoTestKeyPrahoTestKeyPrahoTestKeyPra\n"
        with tempfile.NamedTemporaryFile("w", suffix="_known_hosts", delete=False) as known_hosts_fh:
            known_hosts_fh.write(key_line)
            configured_known_hosts = known_hosts_fh.name
        try:
            with override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH=configured_known_hosts):
                self.assertTrue(AnsibleService._configured_known_hosts_covers("203.0.113.10"))
                self.assertFalse(AnsibleService._configured_known_hosts_covers("203.0.113.99"))
            with override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH="/nonexistent/praho/known_hosts"):
                self.assertFalse(AnsibleService._configured_known_hosts_covers("203.0.113.10"))
        finally:
            Path(configured_known_hosts).unlink(missing_ok=True)


class AnsibleSSHSeamTests(SimpleTestCase):
    """Contracts for the SSH-readiness wait and host-key pinning seams."""

    def test_wait_for_ssh_returns_ok_when_port_accepts(self) -> None:
        with patch("apps.infrastructure.ansible_service.socket.socket") as mock_socket:
            mock_socket.return_value.connect.return_value = None
            result = AnsibleService._wait_for_ssh("203.0.113.10", timeout=1, interval=0.01)
        self.assertTrue(result.is_ok())

    def test_wait_for_ssh_fails_loudly_after_deadline(self) -> None:
        with patch("apps.infrastructure.ansible_service.socket.socket") as mock_socket:
            mock_socket.return_value.connect.side_effect = OSError("refused")
            result = AnsibleService._wait_for_ssh("203.0.113.10", timeout=0.05, interval=0.01)
        self.assertTrue(result.is_err())
        self.assertIn("not SSH-reachable", result.unwrap_err())

    def test_scan_host_key_pins_key_with_0600(self) -> None:
        scanned = "203.0.113.10 ssh-ed25519 AAAAtestkey\n"
        path: Path | None = None
        try:
            with patch("apps.infrastructure.ansible_service.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout=scanned, stderr="")
                path = AnsibleService._scan_host_key("203.0.113.10")
            self.assertIsNotNone(path)
            assert path is not None  # narrow for the type checker
            self.assertEqual(path.read_text(), scanned)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        finally:
            if path is not None:
                path.unlink(missing_ok=True)

    def test_scan_host_key_failure_leaves_no_temp_file(self) -> None:
        tmp_dir = Path(tempfile.gettempdir())
        before = set(tmp_dir.glob("praho_known_hosts_*"))
        with patch("apps.infrastructure.ansible_service.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="scan failed")
            path = AnsibleService._scan_host_key("203.0.113.10")
        self.assertIsNone(path)
        self.assertEqual(set(tmp_dir.glob("praho_known_hosts_*")) - before, set())


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

    @patch("apps.infrastructure.validation_service.paramiko.Ed25519Key.from_private_key")
    @patch("apps.infrastructure.validation_service.paramiko.SSHClient")
    @override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH="/etc/praho/known_hosts")
    def test_host_key_mismatch_reading_webmin_cert_surfaces_as_mitm(
        self,
        mock_client_class: MagicMock,
        _mock_private_key: MagicMock,
    ) -> None:
        """HIGH-1: a changed SSH host key while reading the Webmin cert is the
        MITM signal this verified-SSH path exists to catch — it must return a
        distinct, MITM-scoped error, not generic connection friction."""
        service = object.__new__(NodeValidationService)
        service.timeout = 10
        service._ssh_manager = MagicMock()
        service._ssh_manager.get_deployment_key.return_value = Ok(MagicMock(private_key="private-key"))
        deployment = MagicMock(ipv4_address="203.0.113.10", hostname="node.example.com")
        client = mock_client_class.return_value
        client.connect.side_effect = paramiko.BadHostKeyException("203.0.113.10", MagicMock(), MagicMock())

        result = service.get_webmin_certificate_fingerprint(deployment)

        self.assertTrue(result.is_err())
        self.assertIn("MITM", result.unwrap_err())

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

    @patch("apps.infrastructure.validation_service.paramiko.Ed25519Key.from_private_key")
    @patch("apps.infrastructure.validation_service.paramiko.SSHClient")
    def test_webmin_certificate_pin_is_read_over_trusted_ssh(
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
        stdout.read.return_value = b"sha256 Fingerprint=" + b"AA:" * 31 + b"BB\n"
        stdout.channel.recv_exit_status.return_value = 0
        client.exec_command.return_value = (MagicMock(), stdout, MagicMock())

        result = service.get_webmin_certificate_fingerprint(deployment)

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        self.assertEqual(result.unwrap(), "aa" * 31 + "bb")
        client.exec_command.assert_called_once_with(
            "openssl s_client -connect 127.0.0.1:10000 </dev/null 2>/dev/null "
            "| openssl x509 -noout -fingerprint -sha256",
            timeout=10,
        )
        client.close.assert_called_once_with()

    def test_webmin_certificate_pin_fails_closed_without_node_address(self) -> None:
        service = object.__new__(NodeValidationService)
        service.timeout = 10
        service._ssh_manager = MagicMock()

        result = service.get_webmin_certificate_fingerprint(MagicMock(ipv4_address=None))

        self.assertEqual(result, Err("Node has no IP address assigned"))


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

    def test_private_key_file_does_not_leak_secret_temp_on_write_failure(self) -> None:
        """#348 (sibling of #5): if writing the PRIVATE KEY to its temp file raises, the partial key
        file must NOT be left behind — get_private_key_file cleans up its own temp before returning
        Err. The caller never sees a path to clean, so the leak would otherwise be permanent."""
        manager = SSHKeyManager()
        deployment = MagicMock(hostname="node.example.com")
        key_pair = SSHKeyPair(public_key="ssh-ed25519 AAAA", private_key="PRIVATE", fingerprint="SHA256:test")

        tmpdir = Path(tempfile.gettempdir())
        before = set(tmpdir.glob("praho_ssh_*.key"))
        with (
            patch.object(manager, "get_deployment_key", return_value=Ok(key_pair)),
            patch("apps.infrastructure.ssh_key_manager.os.fdopen", side_effect=OSError("disk full")),
        ):
            result = manager.get_private_key_file(deployment)

        self.assertTrue(result.is_err())
        leaked = set(tmpdir.glob("praho_ssh_*.key")) - before
        self.assertEqual(leaked, set(), f"partial private-key file(s) leaked in tempdir: {leaked}")
