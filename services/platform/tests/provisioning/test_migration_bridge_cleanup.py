"""Retention belongs to the bridge, with durable progress across worker restarts."""

from datetime import timedelta
from unittest.mock import patch

from django.utils import timezone

from apps.common.types import Err, Ok, Retriability
from apps.infrastructure.dns_agreement import Agreement
from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.migration_barrier import BarrierStep
from apps.provisioning.migration_bridge_cleanup import cleanup_bridge, reclaim_bridges
from apps.provisioning.virtualmin_migration_models import (
    MigrationBridge,
    VirtualminMigration,
    account_has_active_operation,
)
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.provisioning.test_virtualmin_migration_barrier_wiring import BarrierCase
from tests.provisioning.test_virtualmin_migration_bridge import BridgeCase


class BridgeCleanupTests(BridgeCase):
    def setUp(self):
        super().setUp()
        self.retire_guard = self.enterContext(
            patch(
                "apps.provisioning.account_hostname_service.retire_removed_node_name",
                return_value=Ok(None),
                create=True,
            )
        )
        self.enterContext(
            patch("apps.provisioning.migration_routing.routing_agreement", return_value=Agreement(True, 300))
        )

    def test_a_busy_native_api_cohort_defers_delete_recovery_without_failing_the_bridge(self):
        bridge, migration = self.due()
        bridge.evidence["delete_issued"] = True
        bridge.save(update_fields=["evidence", "updated_at"])
        with (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
            patch(
                "apps.provisioning.virtualmin_migration_service.run_barrier",
                return_value=Ok(BarrierStep("busy", "operation_running")),
            ),
            patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"),
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "retrying")
        bridge.refresh_from_db()
        self.assertEqual(bridge.status, "removing_source")
        self.assertNotIn("delete-domain", self._programs("source"))

    def test_an_uncertain_source_delete_parks_before_transport_teardown(self):
        bridge, migration = self.due()
        self.effects[("source", "delete-domain")] = Err("response lost", retriability=Retriability.UNKNOWN)
        with (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
            patch("apps.provisioning.migration_bridge_service.remove_bridge") as remove,
        ):
            result = cleanup_bridge(str(migration.pk))
        self.assertEqual(result["action"], "failed")
        bridge.refresh_from_db()
        self.assertTrue(bridge.evidence["delete_issued"])
        self.assertEqual(bridge.status, "failed")
        remove.assert_not_called()

    def test_terminated_accounts_are_reclaimed_before_the_retention_deadline(self):
        bridge, migration = self.due()
        bridge.evidence["next_run"] = (timezone.now() + timedelta(hours=48)).isoformat()
        bridge.save(update_fields=["evidence", "updated_at"])
        MigrationBridge.objects.filter(pk=bridge.pk).update(updated_at=timezone.now() - timedelta(minutes=10))
        VirtualminAccount.objects.filter(pk=self.account.pk).update(
            status="terminated"
        )  # fsm-bypass: terminated fixture
        with patch("apps.provisioning.migration_bridge_cleanup.async_task") as dispatch:
            self.assertEqual(reclaim_bridges(), 1)
        self.assertEqual(dispatch.call_args.args[1], str(migration.pk))

    def due(self):
        self.target.ipv4_address = "95.217.0.20"
        self.target.save(update_fields=["ipv4_address"])
        bridge, migration = self._bridge()
        bridge.activate()
        bridge.evidence = {
            "expires_at": (timezone.now() - timedelta(seconds=1)).isoformat(),
            "dns_names": [self.account.domain],
            "frontend_dns_before": {self.account.domain: {"ttl": 300}},
            "routing": {
                self.account.domain: {"ttl": 300, "confirmed_at": (timezone.now() - timedelta(seconds=600)).isoformat()}
            },
        }
        bridge.save()
        VirtualminMigration.objects.filter(pk=migration.pk).update(  # fsm-bypass: completed cutover fixture
            status="completed", cutover_committed_at=timezone.now(), dns_converged_at=timezone.now()
        )
        self.account.server = self.target
        self.account.save(update_fields=["server", "updated_at"])
        self.source_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, enabled=False)
        AccountHostname.objects.create(
            account=self.account, target_server=self.target, label="a1b2c3d4", zone="accounts.example.net"
        )
        return bridge, migration

    def test_remove_content_then_bridge_and_keep_account_operations_available(self):
        bridge, migration = self.due()
        self.assertFalse(account_has_active_operation(self.account))

        def removed(_migration, *, source_removed):
            self.assertTrue(source_removed)
            self.assertIsNone(self.source_gateway.domain_state_of(self.account.domain))
            return Ok("removed")

        with (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
            patch("apps.provisioning.migration_bridge_service.remove_bridge", side_effect=removed) as remove,
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "torn_down")
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "torn_down")
        bridge.refresh_from_db()
        self.assertEqual(bridge.status, "torn_down")
        self.assertTrue(bridge.evidence["ttl_restored"])
        self.assertEqual(remove.call_count, 1)
        self.assertEqual(self._programs("source").count("delete-domain"), 1)

    def test_private_source_guard_cleanup_is_after_native_absence_and_bridge_pem_teardown(self):
        bridge, migration = self.due()
        order = []

        def retire(account, server):
            self.assertEqual((account.pk, server.pk), (self.account.pk, self.server.pk))
            self.assertIsNone(self.source_gateway.domain_state_of(self.account.domain))
            order.append("guard")
            return Ok(None)

        def transport(*args, **kwargs):
            order.append("bridge")
            return Ok("removed")

        self.retire_guard.side_effect = retire
        with (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
            patch("apps.provisioning.migration_bridge_service.remove_bridge", side_effect=transport),
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "torn_down")
        self.assertEqual(order, ["bridge", "guard"])
        bridge.refresh_from_db()
        self.assertTrue(bridge.evidence["source_guard_retired"])

    def test_interrupted_source_guard_cleanup_keeps_transport_progress_and_retries_without_false_completion(self):
        bridge, migration = self.due()
        self.retire_guard.return_value = Err("node offline", retriability=Retriability.UNKNOWN)
        with (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
            patch("apps.provisioning.migration_bridge_service.remove_bridge", return_value=Ok("removed")) as transport,
            patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"),
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "retrying")
            transport.assert_called_once()
            bridge.refresh_from_db()
            self.assertTrue(bridge.evidence["source_removed"])
            self.assertTrue(bridge.evidence["bridge_removed"])
            self.assertFalse(bridge.evidence.get("source_guard_retired"))
            self.assertFalse(bridge.evidence.get("ttl_restored"))
            self.assertEqual(bridge.status, "removing_source")
            self.retire_guard.return_value = Ok(None)
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "torn_down")
            transport.assert_called_once()
        self.assertEqual(self._programs("source").count("delete-domain"), 1)
        self.assertEqual(self.retire_guard.call_count, 2)

    def test_lease_loss_during_private_cleanup_cannot_record_private_completion_or_restore_ttls(self):
        bridge, migration = self.due()

        def stolen(*args, **kwargs):
            current = MigrationBridge.objects.get(pk=bridge.pk)
            current.evidence = {**current.evidence, "lease_token": "other-worker"}
            current.save(update_fields=["evidence", "updated_at"])
            return Ok(None)

        self.retire_guard.side_effect = stolen
        with (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
            patch("apps.provisioning.migration_bridge_service.remove_bridge", return_value=Ok("removed")) as transport,
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "busy")
        transport.assert_called_once()
        bridge.refresh_from_db()
        self.assertTrue(bridge.evidence["bridge_removed"])
        self.assertFalse(bridge.evidence.get("source_guard_retired"))
        self.assertFalse(bridge.evidence.get("ttl_restored"))

    def test_different_source_owner_is_never_deleted(self):
        bridge, migration = self.due()
        self.source_gateway.seed_domain(self.account.domain, username="anothercustomer", enabled=True)
        with (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
        ):
            result = cleanup_bridge(str(migration.pk))
        bridge.refresh_from_db()
        self.assertEqual(result["action"], "failed")
        self.assertEqual(bridge.status, "failed")
        self.assertNotIn("delete-domain", self._programs("source"))

    def test_window_and_dns_disagreement_keep_the_source_copy(self):
        bridge, migration = self.due()
        bridge.evidence["expires_at"] = (timezone.now() + timedelta(hours=1)).isoformat()
        bridge.save()
        with patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup"):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "waiting")
        self.assertNotIn("delete-domain", self._programs("source"))

    def test_a_lease_stolen_during_listing_prevents_source_deletion(self):
        bridge, migration = self.due()

        def listing():
            current = MigrationBridge.objects.get(pk=bridge.pk)
            current.evidence = {**current.evidence, "lease_token": "another-worker"}
            current.save(update_fields=["evidence", "updated_at"])
            return self.original_calls["source"]("list-domains", {"multiline": ""})

        self.effects[("source", "list-domains")] = listing
        with (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
            patch("apps.provisioning.migration_bridge_service.remove_bridge") as remove,
        ):
            result = cleanup_bridge(str(migration.pk))
        self.assertEqual(result["action"], "busy")
        self.assertNotIn("delete-domain", self._programs("source"))
        remove.assert_not_called()

    def test_an_absent_source_does_not_decrement_an_already_refreshed_domain_count(self):
        _bridge, migration = self.due()
        self.source_gateway.call("delete-domain", {"domain": self.account.domain})
        VirtualminServer.objects.filter(pk=self.server.pk).update(current_domains=1)
        with (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement", return_value=Agreement(True)),
            patch("apps.provisioning.migration_bridge_service.verify_bridge", return_value=Ok("verified")),
            patch("apps.provisioning.migration_bridge_service.remove_bridge", return_value=Ok("removed")),
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "torn_down")
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 1)

    def test_termination_with_verified_withdrawal_cleans_up_without_a_live_hostname(self):
        bridge, migration = self.due()
        VirtualminAccount.objects.filter(pk=self.account.pk).update(
            status="terminated"
        )  # fsm-bypass: termination fixture
        AccountHostname.objects.filter(account=self.account).update(
            retired_at=timezone.now(), target_server=None, records={}
        )
        with (
            patch("apps.infrastructure.dns_agreement.authoritative_agreement") as probe,
            patch("apps.provisioning.migration_bridge_service.verify_bridge") as verify,
            patch("apps.provisioning.migration_bridge_service.remove_bridge", return_value=Ok("removed")),
        ):
            result = cleanup_bridge(str(migration.pk))
        self.assertEqual(result["action"], "torn_down")
        probe.assert_not_called()
        verify.assert_not_called()
        bridge.refresh_from_db()
        self.assertEqual(bridge.status, "torn_down")

    def test_pending_termination_withdrawal_keeps_cleanup_retryable(self):
        bridge, migration = self.due()
        VirtualminAccount.objects.filter(pk=self.account.pk).update(
            status="terminated"
        )  # fsm-bypass: termination fixture
        AccountHostname.objects.filter(account=self.account).update(retired_at=timezone.now())
        with (
            patch("apps.provisioning.migration_bridge_cleanup.schedule_bridge_cleanup") as retry,
            patch("apps.provisioning.migration_bridge_service.remove_bridge") as remove,
        ):
            self.assertEqual(cleanup_bridge(str(migration.pk))["action"], "retrying")
        bridge.refresh_from_db()
        self.assertEqual(bridge.status, "active")
        retry.assert_called_once()
        remove.assert_not_called()
        self.assertNotIn("delete-domain", self._programs("source"))


class TargetGuardRetirementTests(BarrierCase):
    def restored(self):
        migration, token = self._held("compensating", contract="cutover", restore_issued=True)
        self.target_gateway.seed_domain(self.account.domain, username=self.account.virtualmin_username, enabled=False)
        AccountHostname.objects.create(
            account=self.account,
            target_server=self.server,
            label="a1b2c3d4",
            zone="accounts.example.net",
            retired_at=timezone.now(),
        )
        return migration, token

    def test_compensation_retires_only_the_removed_target_after_verified_native_absence(self):
        migration, token = self.restored()

        def retire(account, server):
            self.assertEqual((account.pk, server.pk), (self.account.pk, self.target.pk))
            self.assertIsNone(self.target_gateway.domain_state_of(self.account.domain))
            return Ok(None)

        with (
            patch(
                "apps.provisioning.virtualmin_migration_service.run_barrier", return_value=Ok(BarrierStep("ok", "idle"))
            ),
            patch(
                "apps.provisioning.account_hostname_service.retire_removed_node_name", side_effect=retire, create=True
            ) as retire_guard,
        ):
            VirtualminMigrationService()._remove_target_copy(migration, token)
        retire_guard.assert_called_once()

    def test_failed_target_guard_retirement_remains_retryable_after_native_parent_is_already_absent(self):
        migration, token = self.restored()
        with (
            patch(
                "apps.provisioning.virtualmin_migration_service.run_barrier", return_value=Ok(BarrierStep("ok", "idle"))
            ),
            patch(
                "apps.provisioning.account_hostname_service.retire_removed_node_name",
                return_value=Err("private cleanup unproven", retriability=Retriability.UNKNOWN),
                create=True,
            ) as retire_guard,
        ):
            with self.assertRaisesRegex(ValueError, "private|neutral|guard"):
                VirtualminMigrationService()._remove_target_copy(migration, token)
            self.assertIsNone(self.target_gateway.domain_state_of(self.account.domain))
            retire_guard.return_value = Ok(None)
            VirtualminMigrationService()._remove_target_copy(migration, token)
        self.assertEqual(self._programs("target").count("delete-domain"), 1)
        self.assertEqual(retire_guard.call_count, 2)
