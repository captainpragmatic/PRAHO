"""Managed routing is finalized only after every retained bridge has been removed."""

from unittest.mock import patch
from uuid import uuid4

from django.urls import reverse

from apps.common.types import Err, Ok
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.account_hostname_service import withdraw_drained_node
from apps.provisioning.virtualmin_drain_service import NodeDrainService
from apps.provisioning.virtualmin_migration_models import MigrationBridge, NodeDrain, VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class ManagedDrainTests(MigrationTestBase):
    def test_managed_staff_page_explains_cleanup_without_manual_routing_confirmation(self):
        self.completed(bridge_state="active")
        self.client.force_login(self.staff)
        with patch(
            "apps.infrastructure.dns_agreement.authoritative_agreement", side_effect=AssertionError("request DNS")
        ):
            response = self.client.get(reverse("provisioning:node_drain", args=[self.server.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "finalized automatically")
        self.assertNotContains(response, 'name="routing_confirmed"')

    def test_non_live_names_are_withdrawn_without_retiring_their_labels(self):
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="error")  # fsm-bypass: non-live fixture
        name = AccountHostname.objects.create(
            account=self.account,
            target_server=self.server,
            label="a1b2c3d4",
            zone="accounts.example.net",
            records={"A": {"id": "r1"}},
        )
        with patch("apps.provisioning.account_hostname_service._withdraw", return_value=Err("provider unavailable")):
            self.assertTrue(withdraw_drained_node(self.server).is_err())
        name.refresh_from_db()
        self.assertEqual(name.target_server_id, self.server.pk)
        with patch("apps.provisioning.account_hostname_service._withdraw", return_value=Ok(None)):
            self.assertTrue(withdraw_drained_node(self.server).is_ok())
        name.refresh_from_db()
        self.assertIsNone(name.target_server_id)
        self.assertIsNone(name.retired_at)
        self.assertEqual(name.label, "a1b2c3d4")

    def completed(self, bridge_state="torn_down", contract="cutover"):
        migration = self._start()
        drain = NodeDrain.objects.create(
            server=self.server, status="completed", task_token=uuid4(), accounts_total=1, accounts_migrated=1
        )
        VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=True)
        VirtualminMigration.objects.filter(pk=migration.pk).update(  # fsm-bypass: completed drain fixture
            status="completed", contract=contract, drain=drain
        )
        self.account.server = self.target
        self.account.save(update_fields=["server", "updated_at"])
        bridge = MigrationBridge.objects.create(
            migration=migration,
            source_server=self.server,
            target_server=self.target,
            domain=self.account.domain,
        )
        bridge.activate()
        if bridge_state == "torn_down":
            bridge.start_removing_source()
            bridge.tear_down()
        bridge.save()
        return drain

    def test_managed_drain_is_automatically_finalized_after_teardown(self):
        drain = self.completed()
        result = NodeDrainService.finalize_managed_drain(drain.pk)
        self.assertTrue(result.is_ok(), result)
        drain.refresh_from_db()
        self.server.refresh_from_db()
        self.assertTrue(drain.routing_confirmed)
        self.assertEqual(self.server.status, "disabled")
        self.assertFalse(self.server.is_draining)

    def test_live_bridge_keeps_source_excluded_and_requires_cleanup(self):
        drain = self.completed(bridge_state="active")
        self.assertTrue(NodeDrainService.finalize_managed_drain(drain.pk).is_err())
        drain.refresh_from_db()
        self.assertFalse(drain.routing_confirmed)

    def test_legacy_routing_requires_the_existing_manual_confirmation(self):
        drain = self.completed(contract="legacy")
        self.assertTrue(NodeDrainService.finalize_managed_drain(drain.pk).is_err())
        drain.refresh_from_db()
        self.assertFalse(drain.routing_confirmed)
