"""Installing, verifying and removing the cutover bridge (ADR-0061 P2.5)."""

from __future__ import annotations

from unittest.mock import Mock, patch

from apps.common.types import Err, Ok
from apps.infrastructure.models import NodeDeployment
from apps.provisioning import migration_bridge_service as bridge
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminServer
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
        VirtualminServer.objects.filter(pk=self.target.pk).update(ipv4_address="95.217.0.20")
        self.target.refresh_from_db()
        self.runner = Mock()
        self.runner.run_playbook.return_value = Ok(Mock(success=True))
        runner_patch = patch("apps.provisioning.migration_bridge_service._runner", return_value=self.runner)
        runner_patch.start()
        self.addCleanup(runner_patch.stop)

    def _variables(self) -> dict:
        return self.runner.run_playbook.call_args.args[2]


class BridgeRunTests(BridgeServiceCase):
    def test_install_uses_the_source_deployment_and_the_domains_certificate(self) -> None:
        self.assertEqual(bridge.install_bridge(self.migration), Ok("installed"))

        call = self.runner.run_playbook.call_args
        self.assertEqual(call.args[0], self.server.node_deployment)
        self.assertEqual(call.args[1], bridge.BRIDGE_PLAYBOOK)
        self.assertEqual(call.kwargs["timeout_seconds"], bridge.BRIDGE_TIMEOUT_SECONDS)
        self.assertEqual(
            self._variables(),
            {
                "bridge_action": "install",
                "bridge_domain": self.account.domain,
                "bridge_domain_id": DOMAIN_ID,
                "bridge_target_ipv4": self.target.ipv4_address,
                "bridge_target_port": 80,
                "bridge_certificate": f"/etc/ssl/virtualmin/{DOMAIN_ID}/ssl.cert",
                "bridge_certificate_key": f"/etc/ssl/virtualmin/{DOMAIN_ID}/ssl.key",
            },
        )

    def test_verify_and_remove_name_their_action(self) -> None:
        for action, expected in (("verify", "verified"), ("remove", "removed")):
            with self.subTest(action=action):
                self.runner.run_playbook.reset_mock()
                self.assertEqual(getattr(bridge, f"{action}_bridge")(self.migration), Ok(expected))
                self.assertEqual(self._variables()["bridge_action"], action)


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
        self.runner.run_playbook.return_value = Ok(Mock(success=False))

        self.assertIsInstance(bridge.install_bridge(self.migration), Err)

    def test_an_unrunnable_playbook_is_an_error(self) -> None:
        self.runner.run_playbook.return_value = Err("ssh refused")

        result = bridge.install_bridge(self.migration)

        self.assertIsInstance(result, Err)
        self.assertIn("ssh refused", result.unwrap_err())
