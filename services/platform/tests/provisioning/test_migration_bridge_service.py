"""Installing, verifying and removing the cutover bridge (ADR-0061 P2.5)."""

from __future__ import annotations

import base64
import json
from copy import deepcopy
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from django.utils import timezone

from apps.common.types import Err, Ok
from apps.infrastructure.models import NodeDeployment
from apps.provisioning import migration_bridge_service as bridge
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.provisioning.acme_fakes import issue_chain
from tests.provisioning.test_virtualmin_migration_barrier_wiring import RECORD, TOKEN
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase

DOMAIN_ID = "42"


class BridgeServiceCase(MigrationTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.migration = self._start()
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            pre_migration_snapshot={
                "domain": self.account.domain,
                "status": "active",
                "remote": {
                    "domain": self.account.domain,
                    "enabled": True,
                    "username": self.account.virtualmin_username,
                    "attributes": {"ID": DOMAIN_ID},
                },
            }
        )
        self.migration.refresh_from_db()
        record = deepcopy(RECORD)
        record["enabled"][0]["name"] = self.account.domain
        self.migration.barrier_state = {"record": record, "token": TOKEN}
        VirtualminServer.objects.filter(pk=self.target.pk).update(ipv4_address="95.217.0.20")
        self.target.refresh_from_db()
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.account.domain)]))
               .add_extension(x509.SubjectAlternativeName([x509.DNSName(self.account.domain)]), False)
               .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
        self.origin_certificate = issue_chain(csr, 90)
        self.frontend_certificate = issue_chain(csr, 30)
        self.frontends = [{"public_certificate": self.frontend_certificate,
                           "names": [self.account.domain, f"www.{self.account.domain}"]}]
        self.runner = Mock()
        self.runner.run_playbook.side_effect = self._answer
        runner_patch = patch("apps.provisioning.migration_bridge_service._runner", return_value=self.runner)
        runner_patch.start()
        self.addCleanup(runner_patch.stop)

    def _answer(self, deployment, playbook, variables, **kwargs):
        del deployment, playbook, kwargs
        action = variables["bridge_action"]
        if action == "fetch_crontab":
            Path(variables["bridge_crontab_spool"]).write_text("private original cron")
        payload = {"identity": str(self.migration.pk), "vhosts": self.frontends} if action == "prepare" else self.origin_certificate
        encoded = base64.b64encode(json.dumps({"identity": str(self.migration.pk), "action": action, "payload": payload}).encode()).decode()
        return Ok(Mock(success=True, stdout=f"BRIDGE_RESULT={encoded}"))

    def _variables(self) -> dict:
        return self.runner.run_playbook.call_args.args[2]


class BridgeRunTests(BridgeServiceCase):
    def test_install_uses_the_source_deployment_and_the_domains_certificate(self) -> None:
        self.assertEqual(bridge.install_bridge(self.migration), Ok("installed"))

        call = self.runner.run_playbook.call_args
        self.assertEqual(call.args[0], self.server.node_deployment)
        self.assertEqual(call.args[1], bridge.BRIDGE_PLAYBOOK)
        self.assertEqual(call.kwargs["timeout_seconds"], bridge.BRIDGE_TIMEOUT_SECONDS)
        self.assertEqual(self._variables()["bridge_action"], "install")
        self.assertEqual(self._variables()["bridge_id"], str(self.migration.pk))
        self.assertEqual(self._variables()["bridge_target_ipv4"], self.target.ipv4_address)
        self.assertEqual(self._variables()["bridge_origin_certificate"], self.origin_certificate)
        self.assertEqual([call.args[2]["bridge_action"] for call in self.runner.run_playbook.call_args_list],
                         ["prepare", "origin_install", "origin_verify", "install"])
        self.assertEqual(self.runner.run_playbook.call_args_list[1].args[0], self.target.node_deployment)

    def test_verify_and_remove_name_their_action(self) -> None:
        for action, expected in (("verify", "verified"), ("remove", "removed")):
            with self.subTest(action=action):
                self.runner.run_playbook.reset_mock()
                self.assertEqual(getattr(bridge, f"{action}_bridge")(self.migration), Ok(expected))
                expected_action = "origin_remove" if action == "remove" else action
                self.assertEqual(self._variables()["bridge_action"], expected_action)

    def test_target_preparation_failure_never_installs_a_public_source_bridge(self) -> None:
        def answer(deployment, playbook, variables, **kwargs):
            if variables["bridge_action"] == "origin_install":
                return Err("target unavailable")
            return self._answer(deployment, playbook, variables, **kwargs)
        self.runner.run_playbook.side_effect = answer

        result = bridge.install_bridge(self.migration)

        self.assertTrue(result.is_err())
        self.assertNotIn("install", [call.args[2]["bridge_action"] for call in self.runner.run_playbook.call_args_list])

    def test_a_result_for_another_migration_is_not_accepted(self) -> None:
        payload = base64.b64encode(json.dumps({"identity": "another migration", "action": "verify", "payload": ""}).encode()).decode()
        self.runner.run_playbook.side_effect = None
        self.runner.run_playbook.return_value = Ok(Mock(success=True, stdout=f"BRIDGE_RESULT={payload}"))

        self.assertTrue(bridge.verify_bridge(self.migration).is_err())

    def test_a_non_object_result_is_an_uncertain_error(self) -> None:
        payload = base64.b64encode(b"[]").decode()
        self.runner.run_playbook.side_effect = None
        self.runner.run_playbook.return_value = Ok(Mock(success=True, stdout=f"BRIDGE_RESULT={payload}"))

        self.assertTrue(bridge.verify_bridge(self.migration).is_err())

    def test_target_activation_refuses_before_the_point_of_no_return(self) -> None:
        result = bridge.activate_target(self.migration)

        self.assertTrue(result.is_err())
        self.assertIn("commit", result.unwrap_err())
        self.runner.run_playbook.assert_not_called()

    def test_retiring_activation_data_needs_only_target_identity_and_keeps_source_unreachable(self) -> None:
        self.migration.pre_migration_snapshot = {}
        self.migration.barrier_state = {}
        NodeDeployment.objects.filter(virtualmin_server=self.server).delete()
        self.assertEqual(bridge.retire_target_activation_data(self.migration), Ok("retired"))
        call = self.runner.run_playbook.call_args
        self.assertEqual(call.args[0], self.target.node_deployment)
        self.assertEqual(call.args[2], {"bridge_action": "retire_activation", "bridge_id": str(self.migration.pk),
                                        "bridge_domain": self.account.domain})

    def test_preparation_returns_verified_earliest_certificate_deadline(self) -> None:
        result = bridge.prepare_bridge(self.migration).unwrap()
        expected = x509.load_pem_x509_certificate(self.frontend_certificate.encode()).not_valid_after_utc
        self.assertEqual(result.certificate_not_after, expected)
        self.assertEqual(result.origin_certificate, self.origin_certificate)
        self.assertEqual(result.dns_names, tuple(sorted((self.account.domain, f"www.{self.account.domain}"))))

    def test_http_only_preparation_has_the_origin_certificate_deadline(self) -> None:
        self.frontends = [{"names": [self.account.domain]}]
        result = bridge.prepare_bridge(self.migration).unwrap()
        expected = x509.load_pem_x509_certificate(self.origin_certificate.encode()).not_valid_after_utc
        self.assertEqual(result.certificate_not_after, expected)

    def test_successful_cleanup_passes_only_the_exact_original_source_cron_record(self) -> None:
        self.migration.barrier_state = {"record": RECORD, "token": TOKEN}
        removed = bridge.remove_bridge(self.migration, source_removed=True)
        self.assertEqual(removed, Ok("removed"))
        source_call = self.runner.run_playbook.call_args_list[0].args[2]
        self.assertEqual(source_call["cleanup_source_record"], f"/var/lib/praho/migration/migration-{DOMAIN_ID}.{TOKEN}.crontab")

    def test_preparation_stages_original_cron_privately_before_commit_and_activation_never_contacts_source(self) -> None:
        paths = []

        def answer(deployment, playbook, variables, **kwargs):
            if variables["bridge_action"] == "fetch_crontab":
                path = Path(variables["bridge_crontab_spool"])
                self.assertEqual(variables["bridge_crontab_source"], f"/var/lib/praho/migration/migration-{DOMAIN_ID}.{TOKEN}.crontab")
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                path.write_text("private original cron")
                paths.append(path)
            return self._answer(deployment, playbook, variables, **kwargs)

        self.runner.run_playbook.side_effect = answer
        self.assertTrue(bridge.prepare_bridge(self.migration).is_ok())

        self.assertEqual([call.args[2]["bridge_action"] for call in self.runner.run_playbook.call_args_list],
                         ["prepare", "origin_install", "origin_verify", "fetch_crontab", "stage_activation"])
        self.assertEqual(self.runner.run_playbook.call_args_list[-1].args[0], self.target.node_deployment)
        self.assertFalse(paths[0].exists())
        self.assertNotIn("private original cron", repr(self.runner.run_playbook.call_args_list))
        self.migration.cutover_committed_at = timezone.now()
        self.runner.run_playbook.reset_mock()

        def source_lost(deployment, playbook, variables, **kwargs):
            if deployment == self.server.node_deployment:
                return Err("source disappeared after commit")
            return self._answer(deployment, playbook, variables, **kwargs)

        self.runner.run_playbook.side_effect = source_lost
        self.assertEqual(bridge.activate_target(self.migration), Ok("activated"))
        self.assertEqual([call.args[2]["bridge_action"] for call in self.runner.run_playbook.call_args_list], ["activate"])
        self.assertNotIn("bridge_crontab_spool", self._variables())


class BridgeRefusalTests(BridgeServiceCase):
    def test_a_manually_registered_source_is_refused_before_running(self) -> None:
        NodeDeployment.objects.filter(virtualmin_server=self.server).delete()
        self.migration.refresh_from_db()

        result = bridge.install_bridge(self.migration)

        self.assertIsInstance(result, Err)
        self.runner.run_playbook.assert_not_called()

    def test_without_the_node_domain_id_nothing_runs(self) -> None:
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            pre_migration_snapshot={"domain": self.account.domain, "remote": {"attributes": {}}}
        )
        self.migration.refresh_from_db()

        result = bridge.install_bridge(self.migration)

        self.assertIsInstance(result, Err)
        self.runner.run_playbook.assert_not_called()

    def test_a_failed_playbook_is_an_error(self) -> None:
        self.runner.run_playbook.side_effect = None
        self.runner.run_playbook.return_value = Ok(Mock(success=False))

        self.assertIsInstance(bridge.install_bridge(self.migration), Err)

    def test_an_unrunnable_playbook_is_an_error(self) -> None:
        self.runner.run_playbook.side_effect = None
        self.runner.run_playbook.return_value = Err("ssh refused")

        result = bridge.install_bridge(self.migration)

        self.assertIsInstance(result, Err)
        self.assertIn("ssh refused", result.unwrap_err())
