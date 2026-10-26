"""Persist verified SSH transport state without changing legacy node access."""

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import paramiko
from django.test import SimpleTestCase, override_settings

from apps.common.ssh import configure_strict_host_key_checking
from apps.infrastructure.ansible_service import AnsibleService
from apps.infrastructure.cloud_gateway import node_firewall_rules
from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.ssh_transport import recover_connection_port, resolve_node_host_keys, trusted_node_known_hosts
from apps.infrastructure.validation_service import NodeValidationService
from apps.provisioning.virtualmin_models import VirtualminServer


class NodeSSHStateTests(SimpleTestCase):
    def test_legacy_nodes_keep_bootstrap_port_and_require_trust_enrollment(self) -> None:
        deployment = NodeDeployment()
        self.assertEqual(deployment.ssh_port, 22)
        self.assertEqual(deployment.ssh_host_keys, "")

    def test_unmanaged_servers_keep_their_explicit_port(self) -> None:
        server = VirtualminServer()
        # Same absent-related-row cache populated by select_related in a DB read.
        server._state.fields_cache["node_deployment"] = None
        self.assertEqual(server.ssh_port, 22)
        self.assertEqual(server.effective_ssh_port, 22)
        server.ssh_port = 2222
        self.assertEqual(server.effective_ssh_port, 2222)

    def test_linked_deployment_is_the_authority_after_a_cutover(self) -> None:
        server = VirtualminServer()
        server.node_deployment = NodeDeployment(ssh_port=9876)
        self.assertEqual(server.effective_ssh_port, 9876)
        server.node_deployment.ssh_port = 22
        self.assertEqual(server.effective_ssh_port, 22)


class NodeSSHPinTests(SimpleTestCase):
    def test_operator_bundle_preserves_multiple_keys_with_the_same_algorithm(self) -> None:
        keys = [paramiko.RSAKey.generate(2048) for _ in range(2)]
        lines = [f"{key.get_name()} {key.get_base64()} operator-{index}" for index, key in enumerate(keys)]
        with TemporaryDirectory() as directory:
            path = Path(directory) / "operators"
            path.write_text("\n".join(lines))
            with override_settings(PRAHO_SSH_OPERATOR_PUBLIC_KEYS_FILE=str(path)):
                self.assertEqual(AnsibleService.operator_public_keys(), tuple(lines))
                path.write_text("\n".join(line.replace(" ", "\t  ") for line in lines))
                self.assertEqual(AnsibleService.operator_public_keys(), tuple(lines))

    def test_recursive_hardening_receives_the_validated_operator_snapshot(self) -> None:
        from apps.common.types import Ok  # noqa: PLC0415 -- Ansible subprocess boundary fixture.

        service = AnsibleService()
        snapshot = ("approved-public-key-snapshot",)
        deployment = NodeDeployment()
        with patch.object(service, "run_playbook", return_value=Ok(MagicMock(success=True))) as run:
            self.assertTrue(service._ensure_ssh_policy(deployment, operator_public_keys=snapshot).is_ok())
        run.assert_called_once_with(deployment, "ssh-hardening.yml", operator_public_keys=snapshot)

    def test_a_preloaded_ambient_key_cannot_outrank_the_enrolled_pin(self) -> None:
        key = paramiko.RSAKey.generate(2048)
        client = paramiko.SSHClient()
        client._system_host_keys.add("192.0.2.1", key.get_name(), key)
        with self.assertRaisesMessage(ValueError, "fresh client"):
            configure_strict_host_key_checking(
                client, host_keys=f"{key.get_name()} {key.get_base64()}",
                hostnames=("192.0.2.1",), port=9876,
            )

    def test_enrolled_identity_is_shared_across_hostname_and_ports(self) -> None:
        key = paramiko.RSAKey.generate(2048)
        client = paramiko.SSHClient()
        with patch.object(client, "load_system_host_keys") as ambient:
            configure_strict_host_key_checking(
                client, host_keys=f"{key.get_name()} {key.get_base64()}",
                hostnames=("192.0.2.1", "node.example.com"), port=9876,
            )
        ambient.assert_not_called()
        for alias in ("192.0.2.1", "node.example.com", "[192.0.2.1]:9876", "[node.example.com]:9876"):
            pinned = client.get_host_keys().lookup(alias)
            self.assertIsNotNone(pinned)
            self.assertEqual(pinned[key.get_name()].get_base64(), key.get_base64())
        self.assertIsInstance(client._policy, paramiko.RejectPolicy)

    def test_missing_or_invalid_enrollment_never_uses_ambient_trust(self) -> None:
        for keys in ("", "ssh-ed25519 invalid", "ssh-dss AAAA"):
            with self.subTest(keys=keys), self.assertRaises(ValueError):
                configure_strict_host_key_checking(
                    paramiko.SSHClient(), host_keys=keys, hostnames=("192.0.2.1",), port=9876,
                )


class NodeSSHConsumerTests(SimpleTestCase):
    def test_quick_health_checks_the_verified_port(self) -> None:
        deployment = NodeDeployment(ipv4_address="192.0.2.1", ssh_port=9876)
        service = NodeValidationService()
        with patch.object(service, "_is_port_open", return_value=True) as probe:
            self.assertTrue(service.quick_health_check(deployment))
        self.assertIn(("192.0.2.1", 9876), [call.args for call in probe.call_args_list])
        self.assertNotIn(("192.0.2.1", 22), [call.args for call in probe.call_args_list])


class NodeSSHEnrollmentTests(SimpleTestCase):
    def setUp(self) -> None:
        self.key = paramiko.RSAKey.generate(2048)
        self.public_key = f"{self.key.get_name()} {self.key.get_base64()}"
        self.deployment = NodeDeployment(
            id=1, hostname="dev-sha-tst-de-tst1-001", dns_zone="example.com",
            external_node_id="vm-original", ipv4_address="192.0.2.1", ssh_host_keys=None,
        )

    @override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH="")
    def test_legacy_node_without_operator_pin_never_reenrolls_from_network(self) -> None:
        self.deployment.ssh_host_keys = ""
        scan = MagicMock()
        with self.assertRaisesMessage(ValueError, "operator-verified"):
            trusted_node_known_hosts(self.deployment, scan)
        scan.assert_not_called()

    def test_fresh_node_cannot_be_validated_before_bootstrap_enrollment(self) -> None:
        with self.assertRaisesMessage(ValueError, "bootstrap host-key enrollment"):
            resolve_node_host_keys(self.deployment)

    def test_virtualmin_legacy_identity_imports_only_the_verified_configured_pin(self) -> None:
        self.deployment.ssh_host_keys = ""
        server = VirtualminServer()
        server.node_deployment = self.deployment
        with TemporaryDirectory() as directory:
            configured = Path(directory) / "known_hosts"
            configured.write_text(f"192.0.2.1 {self.public_key}\n")
            with (
                override_settings(PRAHO_SSH_KNOWN_HOSTS_PATH=str(configured)),
                patch("apps.infrastructure.ssh_transport.NodeDeployment.objects.filter") as records,
            ):
                records.return_value.update.return_value = 1
                self.assertEqual(server.enrolled_ssh_host_keys, self.public_key)
            self.assertEqual(records.call_args.kwargs["ssh_host_keys"], "")
            self.assertEqual(self.deployment.ssh_host_keys, self.public_key)

    def test_both_validation_clients_resolve_legacy_pins_before_connecting(self) -> None:
        self.deployment.ssh_host_keys = ""
        service = NodeValidationService()
        service._ssh_manager = MagicMock()
        from apps.common.types import Ok  # noqa: PLC0415 -- Test-only transport fixture.

        service._ssh_manager.get_deployment_key.return_value = Ok(MagicMock(private_key="fixture"))
        for operation in (service._check_ssh, service.get_webmin_certificate_fingerprint):
            with (
                self.subTest(operation=operation.__name__),
                patch("apps.infrastructure.validation_service.resolve_node_host_keys", side_effect=ValueError("operator pin required")) as resolve,
                patch("apps.infrastructure.validation_service.paramiko.SSHClient") as client,
            ):
                operation(self.deployment)
                resolve.assert_called_once_with(self.deployment)
                client.return_value.connect.assert_not_called()

    def test_fresh_enrollment_pins_once_and_cleans_the_raw_scan(self) -> None:
        with TemporaryDirectory() as directory:
            scanned = Path(directory) / "scan"
            scanned.write_text(f"192.0.2.1 {self.public_key}\n")
            with patch("apps.infrastructure.ssh_transport.NodeDeployment.objects.filter") as records:
                records.return_value.update.return_value = 1
                rendered = trusted_node_known_hosts(self.deployment, MagicMock(return_value=scanned))
            try:
                content = rendered.read_text()
                self.assertIn("[192.0.2.1]:22", content)
                self.assertIn("[192.0.2.1]:9876", content)
                self.assertIn(self.deployment.fqdn, content)
                self.assertIn(self.public_key, content)
                self.assertEqual(self.deployment.ssh_host_keys, self.public_key)
                self.assertFalse(scanned.exists())
                self.assertEqual(records.call_args.kwargs["external_node_id"], "vm-original")
                self.assertIsNone(records.call_args.kwargs["ssh_host_keys"])
            finally:
                rendered.unlink()

    def test_changed_identity_cannot_overwrite_the_winning_pin(self) -> None:
        with TemporaryDirectory() as directory:
            scanned = Path(directory) / "scan"
            scanned.write_text(f"192.0.2.1 {self.public_key}\n")
            with patch("apps.infrastructure.ssh_transport.NodeDeployment.objects.filter") as records:
                records.return_value.update.return_value = 0
                with self.assertRaisesMessage(ValueError, "identity changed"):
                    trusted_node_known_hosts(self.deployment, MagicMock(return_value=scanned))
            self.assertIsNone(self.deployment.ssh_host_keys)
            self.assertFalse(scanned.exists())

    def test_enrolled_node_never_scans_or_updates_trust_again(self) -> None:
        self.deployment.ssh_host_keys = self.public_key
        scan = MagicMock()
        with patch("apps.infrastructure.ssh_transport.NodeDeployment.objects.filter") as records:
            rendered = trusted_node_known_hosts(self.deployment, scan)
        rendered.unlink()
        scan.assert_not_called()
        records.assert_not_called()

    def test_pending_rollback_cannot_persist_a_reachable_new_port(self) -> None:
        self.deployment.ssh_host_keys = self.public_key
        with (
            patch("apps.infrastructure.ssh_transport.socket.create_connection"),
            patch("apps.infrastructure.ssh_transport.subprocess.run") as run,
        ):
            run.return_value.returncode = 73
            with self.assertRaisesMessage(ValueError, "active or unrecovered"):
                recover_connection_port(self.deployment, Path("key"), Path("pins"))
        self.assertEqual(self.deployment.ssh_port, 22)

    def test_authenticated_recovery_is_ephemeral_until_transition_commits(self) -> None:
        self.deployment.ssh_host_keys = self.public_key
        with (
            patch("apps.infrastructure.ssh_transport.socket.create_connection"),
            patch("apps.infrastructure.ssh_transport.subprocess.run") as run,
        ):
            run.return_value.returncode = 0
            run.return_value.stdout = "0\n"
            self.assertEqual(recover_connection_port(self.deployment, Path("key"), Path("pins")), 9876)
        self.assertEqual(self.deployment.ssh_port, 22)

    def test_full_port_validation_checks_the_verified_port(self) -> None:
        deployment = NodeDeployment(ipv4_address="192.0.2.1", ssh_port=9876)
        service = NodeValidationService()
        with patch.object(service, "_is_port_open", return_value=True) as probe:
            service._check_ports(deployment)
        self.assertIn(("192.0.2.1", 9876), [call.args for call in probe.call_args_list])
        self.assertNotIn(("192.0.2.1", 22), [call.args for call in probe.call_args_list])


class NodeSSHFirewallTests(SimpleTestCase):
    def test_both_ssh_ports_and_webmin_are_scoped_to_the_same_sources(self) -> None:
        sources = ["192.0.2.1/32", "2001:db8::1/128"]
        rules = node_firewall_rules(sources)
        admin = {rule.port: rule.source_ips for rule in rules if rule.port in {"22", "9876", "10000"}}
        self.assertEqual(admin, dict.fromkeys(("22", "9876", "10000"), sources))
        for rule in rules:
            if rule.port in {"80", "443"}:
                self.assertEqual(rule.source_ips, ["0.0.0.0/0", "::/0"])

    def test_missing_or_world_open_administrator_sources_are_refused(self) -> None:
        for sources in ([], ["0.0.0.0/0"], ["::/0"]):
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                node_firewall_rules(sources)
