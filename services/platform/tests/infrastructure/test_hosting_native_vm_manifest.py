"""The destructive native lab accepts only its exact private owned manifest."""

import importlib.util
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from uuid import uuid4

from django.conf import settings
from django.test import SimpleTestCase


class NativeVMManifestTests(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        path = Path(settings.BASE_DIR).parents[1] / "tests/virtualmin_lab/native/provider_vm.py"
        spec = importlib.util.spec_from_file_location("hosting_native_vm", path)
        cls.vm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.vm)

    def test_reboot_wait_retries_a_connection_the_rebooting_host_drops(self):
        # paramiko raises a bare EOFError when sshd goes away mid-handshake; that is the reboot, not a failure.
        answers = iter([EOFError(), "old-boot", "new-boot"])

        def remote(*_args, **_kwargs):
            answer = next(answers)
            if isinstance(answer, BaseException):
                raise answer
            return answer

        with (
            patch.object(self.vm, "owned_server", return_value=({}, Mock())),
            patch.object(self.vm, "remote", side_effect=remote),
            patch.object(self.vm.Event, "wait"),
        ):
            self.vm.reboot_and_wait(Path("vm.json"), "old-boot")
        self.assertEqual(next(answers, "drained"), "drained")

    def test_private_manifest_pins_provider_ownership_and_expiry(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "vm.json"
            run = str(uuid4())
            contents = {
                "schema": 1,
                "run": run,
                "owner": "praho-quota-776",
                "provider": "hetzner",
                "phase": "created",
                "expires_at": "2026-11-04T00:00:00+00:00",
                "server_id": 13,
                "ssh_key_id": 17,
                "firewall_id": 19,
                "ipv4": "192.0.2.13",
            }
            path.write_text(json.dumps(contents))
            path.chmod(0o600)
            self.assertEqual(self.vm.read_manifest(path)["run"], run)
            self.assertTrue(
                self.vm.owned_resource(contents, {"praho-native-run": run, "praho-native-owner": "praho-quota-776"})
            )
            self.assertFalse(
                self.vm.owned_resource(
                    contents, {"praho-native-run": str(uuid4()), "praho-native-owner": "praho-quota-776"}
                )
            )
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                self.vm.read_manifest(path)
            path.chmod(0o600)
            link = Path(directory) / "alias.json"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                self.vm.read_manifest(link)
            contents["owner"] = "somebody-else"
            path.write_text(json.dumps(contents))
            with self.assertRaises(ValueError):
                self.vm.read_manifest(path)

    def test_admin_cidr_must_be_explicit_and_never_world_open(self):
        self.assertEqual(self.vm.admin_cidr("192.0.2.17/32"), "192.0.2.17/32")
        for value in ("", "0.0.0.0/0", "::/0", "192.0.2.1;echo bad", "192.0.2.1/8"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.vm.admin_cidr(value)

    def test_fresh_intent_persists_private_authority_without_creating_provider_resources(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "fresh.json"
            with (
                patch.dict(
                    os.environ,
                    {
                        "PRAHO_NATIVE_ADMIN_CIDR": "192.0.2.17/32",
                        "PRAHO_NATIVE_LOCATION": "fsn1",
                        "PRAHO_NATIVE_SERVER_TYPE": "cx33",
                    },
                ),
                patch.object(self.vm, "client", side_effect=AssertionError("Intent must make no provider call")),
            ):
                self.vm.fresh_intent(path)
            self.assertTrue(path.is_file(), "Fresh intent did not durably bind its local authority")
            manifest = self.vm.read_manifest(path)
            self.assertEqual(manifest["origin"], "platform_fresh")
            self.assertEqual(manifest["phase"], "fresh-intent")
            self.assertIsNone(manifest["server_id"])
            self.assertIsNone(manifest["ssh_key_id"])
            self.assertIsNone(manifest["ipv4"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            key, trust = self.vm.paths(path, manifest)
            self.assertEqual(key.stat().st_mode & 0o777, 0o600)
            self.assertTrue(key.read_text().startswith("-----BEGIN OPENSSH PRIVATE KEY-----"))
            self.assertEqual(trust.read_text(), "")
            self.assertNotIn("PRIVATE KEY", path.read_text())

    def test_registration_resume_cannot_certify_the_fresh_provider_dns_path(self):
        manifest = {
            "server_id": 13,
            "platform_deployment_id": 17,
            "fqdn": "fixture.example.test",
            "approved_dns_zone": "example.test",
            "ipv4": "192.0.2.13",
        }
        with self.assertRaises(ValueError):
            self.vm.validate_fresh_deployment_proof(manifest)
        proof = {
            "source": "NodeDeploymentService.deploy_node",
            "server_id": 13,
            "deployment_id": 17,
            "fqdn": manifest["fqdn"],
            "dns_zone": "example.test",
            "dns_answer": "192.0.2.13",
            "provider_created": True,
            "verified_at": "2026-11-03T12:00:00+00:00",
            "controls_digest": "a" * 64,
        }
        manifest["fresh_deployment"] = proof
        with self.assertRaisesRegex(ValueError, "self-attestation"):
            self.vm.validate_fresh_deployment_proof(manifest)
        for key, value in (
            ("source", "retry_deployment"),
            ("server_id", 19),
            ("dns_answer", "192.0.2.99"),
            ("provider_created", False),
            ("controls_digest", "unknown"),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.vm.validate_fresh_deployment_proof({**manifest, "fresh_deployment": {**proof, key: value}})
