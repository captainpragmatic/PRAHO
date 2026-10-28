"""Imported archive transport uses only explicit keys and exact host/port trust."""

import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from unittest.mock import MagicMock, patch

import paramiko
from django.test import SimpleTestCase, override_settings

from apps.common.types import Err, Retriability, retriability_of
from apps.infrastructure.ansible_service import AnsibleService
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_pair_restore import run_pair_step


class ImportedBackupTransportTests(SimpleTestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.key = Path(self.directory.name) / "private-key"
        self.key.write_text("fixture identity, never used by a real SSH process")
        self.key.chmod(0o600)
        self.trust = Path(self.directory.name) / "known_hosts"
        host_key = paramiko.RSAKey.generate(2048)
        self.trust.write_text(f"[imported.example.test]:9876 {host_key.get_name()} {host_key.get_base64()}\n")
        self.server = cast(VirtualminServer, SimpleNamespace(hostname="imported.example.test", ssh_port=9876, node_deployment=None))
        self.service = object.__new__(AnsibleService)
        self.service.timeout = 30
        self.service._ansible_path = "/usr/bin/ansible-playbook"
        self.service._ssh_manager = MagicMock()
        self.config = override_settings(VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH=str(self.key), PRAHO_SSH_KNOWN_HOSTS_PATH=str(self.trust))
        self.config.enable()
        self.addCleanup(self.config.disable)

    def test_imported_fetch_uses_exact_identity_and_cleans_only_owned_files(self) -> None:
        captured = {}

        def execute(command, **options):
            inventory = Path(command[command.index("-i") + 1])
            captured["inventory"] = json.loads(inventory.read_text())
            captured["path"] = inventory
            captured["env"] = options["env"]
            return subprocess.CompletedProcess(command, 0, "BACKUP_SHA256=" + "a" * 64, "")

        with patch("apps.infrastructure.ansible_service.subprocess.run", side_effect=execute) as run:
            result = self.service.run_server_playbook(self.server, "virtualmin_backup_fetch.yml", {"archive_name": "fixture"})
        self.assertTrue(result.is_ok())
        self.assertTrue(result.unwrap().success)
        self.assertEqual(run.call_count, 1)
        host = captured["inventory"]["all"]["hosts"]["backup_target"]
        self.assertEqual((host["ansible_host"], host["ansible_port"], host["ansible_user"]), (self.server.hostname, 9876, "root"))
        options = captured["env"]["ANSIBLE_SSH_ARGS"]
        for required in ("IdentitiesOnly=yes", "IdentityAgent=none", "ControlMaster=no", "BatchMode=yes", "PasswordAuthentication=no", "StrictHostKeyChecking=yes"):
            self.assertIn(required, options)
        self.assertFalse(captured["path"].exists())
        self.assertTrue(self.key.exists())
        self.assertTrue(self.trust.exists())
        self.service._ssh_manager.get_private_key_file.assert_not_called()

    def test_missing_key_refuses_before_execution(self) -> None:
        self.key.unlink()
        with patch("apps.infrastructure.ansible_service.subprocess.run") as run:
            result = self.service.run_server_playbook(self.server, "virtualmin_backup_fetch.yml")
        self.assertTrue(result.is_err())
        self.assertIn("key", result.unwrap_err().lower())
        run.assert_not_called()

    def test_malformed_enrolled_host_key_is_a_definite_local_refusal(self) -> None:
        from apps.infrastructure.imported_backup_transport import server_transport_ready  # noqa: PLC0415

        self.trust.write_text("[imported.example.test]:9876 ssh-rsa invalid-key\n")
        result = server_transport_ready(self.server)
        self.assertTrue(result.is_err())
        self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)

    def test_managed_key_failure_never_consults_imported_identity(self) -> None:
        self.server.node_deployment = SimpleNamespace(ipv4_address="203.0.113.10")
        self.service._ssh_manager.get_private_key_file.return_value = Err("Missing managed identity")
        with patch("apps.infrastructure.ansible_service.imported_identity") as imported, patch("apps.infrastructure.ansible_service.subprocess.run") as run:
            result = self.service.run_server_playbook(self.server, "virtualmin_backup_fetch.yml")
        self.assertTrue(result.is_err())
        self.assertIn("enrolled authentication key", result.unwrap_err())
        imported.assert_not_called()
        run.assert_not_called()

    def test_trust_for_another_port_is_not_accepted(self) -> None:
        self.trust.write_text(self.trust.read_text().replace(":9876", ":22"))
        with patch("apps.infrastructure.ansible_service.subprocess.run") as run:
            result = self.service.run_server_playbook(self.server, "virtualmin_backup_fetch.yml")
        self.assertTrue(result.is_err())
        self.assertIn("trust", result.unwrap_err().lower())
        run.assert_not_called()

    def test_timeout_preserves_operator_configuration(self) -> None:
        with patch("apps.infrastructure.ansible_service.subprocess.run", side_effect=subprocess.TimeoutExpired("ansible", 30)):
            result = self.service.run_server_playbook(self.server, "virtualmin_backup_push.yml")
        self.assertTrue(result.is_ok())
        self.assertFalse(result.unwrap().success)
        self.assertTrue(self.key.exists())
        self.assertTrue(self.trust.exists())

    def test_imported_transport_cannot_run_hardening_or_override_connection(self) -> None:
        with patch("apps.infrastructure.ansible_service.subprocess.run") as run:
            self.assertTrue(self.service.run_server_playbook(self.server, "ssh-hardening.yml").is_err())
            self.assertTrue(self.service.run_server_playbook(self.server, "virtualmin_remote_cleanup.yml", {"ansible_user": "other"}).is_err())
        run.assert_not_called()

    def test_local_refusal_after_readiness_stays_definite_in_all_recovery_wrappers(self) -> None:
        token = "0b5f1c7e-3c1d-4f0a-9a52-6d1b3a8c2e44"
        variables = {"chain_action": "cancel", "chain_domain": "example.test", "chain_domain_id": "17", "chain_token": token}
        service = VirtualminBackupService(self.server)
        refusal = Err("Key removed before dispatch", retriability=Retriability.NOT_RETRIABLE)
        with patch("apps.infrastructure.ansible_service.AnsibleService.run_server_playbook", return_value=refusal), patch("apps.infrastructure.ansible_service.AnsibleService._find_ansible", return_value="ansible-playbook"), patch("apps.settings.services.SettingsService.get_setting", side_effect=lambda key, default=None: default):
            results = (
                service.run_chain_step(variables, token=token, mode="base", domain_id="17"),
                run_pair_step(self.server, variables, token=token, domain_id="17", timeout_seconds=30),
                service.remove_staged_archive("virtualmin_backup_" + "a" * 32 + ".tar.gz"),
            )
        for result in results:
            self.assertTrue(result.is_err())
            self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
