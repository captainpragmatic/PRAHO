"""Native acceptance cannot silently prepare with discarded or unbound credentials."""

import importlib.util
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase

from apps.common.credential_vault import get_credential_vault
from apps.infrastructure.models import NodeDeployment
from apps.infrastructure.native_lab import native_authority, native_run_lock
from apps.infrastructure.native_workflow import bind_native_fixture


class NativeWorkflowBoundaryTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR).parents[1] / "tests/virtualmin_lab/native/provider_vm.py"
        spec = importlib.util.spec_from_file_location("hosting_native_driver_workflow", path)
        cls.driver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.driver)

    def test_prepare_refuses_without_actual_platform_fixture_and_keeps_manifest(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            run = str(uuid4())
            key = Ed25519PrivateKey.generate()
            public = (
                key.public_key()
                .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
                .decode()
            )
            (root / (run + ".key")).write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
                )
            )
            (root / (run + ".key")).chmod(0o600)
            (root / (run + ".known_hosts")).write_text("192.0.2.13 " + public + "\n")
            path = root / "manifest.json"
            manifest = {
                "schema": 1,
                "owner": "praho-quota-776",
                "provider": "hetzner",
                "run": run,
                "phase": "created",
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "server_id": 13,
                "ssh_key_id": 17,
                "firewall_id": 19,
                "ipv4": "192.0.2.13",
                "ssh_port": 22,
                "admin_cidr": "192.0.2.17/32",
                "host_public_key": public,
            }
            path.write_text(json.dumps(manifest))
            path.chmod(0o600)
            provider = SimpleNamespace(
                labels={"praho-native-run": run, "praho-native-owner": "praho-quota-776"},
                public_net=SimpleNamespace(ipv4=SimpleNamespace(ip="192.0.2.13")),
            )
            with (
                patch.object(self.driver, "client") as client,
                patch.object(self.driver, "ssh") as ssh,
                patch.object(
                    self.driver.subprocess,
                    "run",
                    return_value=CompletedProcess([], 0, "", ""),
                ),
                patch.object(self.driver.shutil, "which", return_value="/approved/ansible-playbook"),
            ):
                client.return_value.servers.get_by_id.return_value = provider
                stdin = SimpleNamespace(write=lambda value: None, channel=SimpleNamespace(shutdown_write=lambda: None))
                stdout = SimpleNamespace(read=lambda size: b"", channel=SimpleNamespace(recv_exit_status=lambda: 0))
                ssh.return_value.exec_command.return_value = stdin, stdout, io.BytesIO(b"")
                with self.assertRaisesRegex(ValueError, "Platform.*fixture"):
                    self.driver.provision(path)
            self.assertEqual(json.loads(path.read_text())["phase"], "created")

    def test_management_command_refuses_developer_or_ci_settings_before_any_writes(self):
        with self.assertRaisesRegex(CommandError, "dedicated native settings"):
            call_command("hosting_native_workflow", "prepare", "--manifest", "/missing/native-manifest.json")


class NativeWorkflowFixtureTests(TestCase):
    def test_fixture_is_idempotent_encrypted_and_refuses_provider_retarget(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            run = str(uuid4())
            key = Ed25519PrivateKey.generate()
            public = (
                key.public_key()
                .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
                .decode()
            )
            private = key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()
            )
            (root / (run + ".key")).write_bytes(private)
            (root / (run + ".key")).chmod(0o600)
            path = root / "manifest.json"
            contents = {
                "schema": 1,
                "owner": "praho-quota-776",
                "provider": "hetzner",
                "run": run,
                "phase": "created",
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "server_id": 13,
                "ssh_key_id": 17,
                "firewall_id": 19,
                "ipv4": "192.0.2.13",
                "ssh_port": 22,
                "admin_cidr": "192.0.2.17/32",
                "host_public_key": public,
            }
            path.write_text(json.dumps(contents))
            path.chmod(0o600)
            first = bind_native_fixture(native_authority(path), dns_zone="example.com")
            with (
                native_run_lock(native_authority(path)),
                self.assertRaisesRegex(ValueError, "Another controller"),
                native_run_lock(native_authority(path)),
            ):
                self.fail("Two native controllers acquired the same manifest")
            stored = get_credential_vault().get_credential(
                service_type="virtualmin", service_identifier=first.fqdn, reason="Native fixture regression"
            )
            self.assertTrue(stored.is_ok(), stored)
            username, password, metadata = stored.unwrap()
            self.assertNotEqual(username, "root")
            self.assertTrue(password)
            self.assertEqual(metadata["native_run"], run)
            self.assertNotIn(password, path.read_text())
            self.assertNotIn(private.decode(), path.read_text())
            second = bind_native_fixture(native_authority(path), dns_zone="example.com")
            self.assertEqual(first.pk, second.pk)
            self.assertEqual(NodeDeployment.objects.filter(correlation_id=run).count(), 1)
            self.assertEqual(first.ssh_key_credential_id, second.ssh_key_credential_id)
            self.assertEqual(
                get_credential_vault()
                .get_credential(
                    service_type="virtualmin", service_identifier=first.fqdn, reason="Native fixture replay"
                )
                .unwrap()[1],
                password,
            )
            changed = json.loads(path.read_text())
            changed["server_id"] = 14
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "resource changed"):
                bind_native_fixture(native_authority(path), dns_zone="example.com")
