"""Real database evidence must survive failures without accepting obsolete results."""

import json
from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from django.utils import timezone
from django_q.models import Schedule

from apps.common.status_models import NodeResourceHourlySummary, SystemCheckState
from apps.common.status_observations import (
    Observation,
    PublicValue,
    ResourceValues,
    claim_check,
    finish_check,
    prune_hourly_summaries,
)
from apps.common.tasks import setup_system_status_scheduled_tasks
from apps.common.types import Ok
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminServerManagementService
from apps.provisioning.virtualmin_tasks import health_check_virtualmin_servers


class ObservationTests(TestCase):
    def test_removed_node_is_a_local_refusal_before_api_access(self) -> None:
        node = self.node()
        VirtualminServer.objects.filter(pk=node.pk).delete()
        with patch("apps.provisioning.virtualmin_service.VirtualminProvisioningService.test_server_connection") as probe:
            result = VirtualminServerManagementService().health_check_server(node)
        self.assertTrue(result.is_err())
        probe.assert_not_called()

    def test_retention_prunes_only_expired_hours_in_bounded_batches(self) -> None:
        node = self.node()
        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        NodeResourceHourlySummary.objects.bulk_create([
            NodeResourceHourlySummary(node=node, hour=now - timedelta(days=31, hours=index)) for index in range(1001)
        ])
        current = NodeResourceHourlySummary.objects.create(node=node, hour=now - timedelta(days=30))
        with patch("apps.common.status_observations.timezone.now", return_value=now):
            self.assertEqual(prune_hourly_summaries(), 1000)
            self.assertEqual(prune_hourly_summaries(), 1)
        self.assertEqual(list(NodeResourceHourlySummary.objects.values_list("pk", flat=True)), [current.pk])

    def node(self) -> VirtualminServer:
        return VirtualminServer.objects.create(name="Status node", hostname="node.example.test", api_username="api",
                                                encrypted_api_password=b"")

    def test_success_belongs_to_the_verified_configuration(self) -> None:
        claim = claim_check("email", identity="a" * 64)
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertTrue(finish_check(claim, identity="a" * 64, observation=Observation("green", "connected")))
        state = SystemCheckState.objects.get(check_key="email")
        self.assertEqual(state.verified_generation, state.configuration_generation)
        self.assertIsNotNone(state.last_success_at)

    def test_changed_configuration_rejects_old_success(self) -> None:
        claim = claim_check("email", identity="a" * 64)
        self.assertIsNotNone(claim)
        assert claim is not None
        self.assertFalse(finish_check(claim, identity="b" * 64, observation=Observation("green", "connected")))
        self.assertIsNone(SystemCheckState.objects.get(check_key="email").last_success_at)

    def test_overlapping_refresh_does_not_create_another_claim(self) -> None:
        first = claim_check("email", identity="a" * 64)
        self.assertIsNotNone(first)
        self.assertIsNone(claim_check("email", identity="a" * 64))
        self.assertEqual(SystemCheckState.objects.filter(check_key="email").count(), 1)

    def test_expired_owner_cannot_publish_after_replacement(self) -> None:
        first = claim_check("email", identity="a" * 64)
        self.assertIsNotNone(first)
        assert first is not None
        SystemCheckState.objects.filter(pk=first.state_id).update(lease_until=timezone.now() - timedelta(seconds=1))
        second = claim_check("email", identity="a" * 64)
        self.assertIsNotNone(second)
        assert second is not None
        self.assertTrue(finish_check(second, identity="a" * 64, observation=Observation("red", "rejected")))
        self.assertFalse(finish_check(first, identity="a" * 64, observation=Observation("green", "connected")))
        self.assertEqual(SystemCheckState.objects.get(pk=first.state_id).level, "red")

    def test_a_failure_keeps_prior_verification_of_the_same_configuration(self) -> None:
        first = claim_check("email", identity="a" * 64)
        assert first is not None
        finish_check(first, identity="a" * 64, observation=Observation("green", "connected"))
        success = SystemCheckState.objects.get(pk=first.state_id).last_success_at
        second = claim_check("email", identity="a" * 64)
        assert second is not None
        finish_check(second, identity="a" * 64, observation=Observation("red", "unavailable"))
        row = SystemCheckState.objects.get(pk=first.state_id)
        self.assertEqual(row.last_success_at, success)
        self.assertEqual(row.verified_generation, row.configuration_generation)

    def test_duplicate_scheduled_slot_and_manual_refresh_do_not_add_samples(self) -> None:
        node = self.node()
        instant = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
        with patch("apps.common.status_observations.timezone.now", return_value=instant):
            for scheduled in (True, True, False):
                claim = claim_check("virtualmin", node_id=node.id, identity="a" * 64)
                assert claim is not None
                finish_check(claim, identity="a" * 64,
                             observation=Observation("green", "connected", resources=ResourceValues(20, None, 40), scheduled=scheduled))
        row = NodeResourceHourlySummary.objects.get(node=node)
        self.assertEqual(row.cpu_count, 1)
        self.assertEqual(row.cpu_sum, 20)
        self.assertEqual(row.disk_peak, 40)
        self.assertEqual(row.memory_count, 0)
        self.assertIsNone(row.memory_peak)

    def test_deleted_node_cannot_be_recreated_by_a_late_observation(self) -> None:
        node = self.node()
        claim = claim_check("virtualmin", node_id=node.id, identity="a" * 64)
        assert claim is not None
        node.delete()
        self.assertFalse(finish_check(claim, identity="a" * 64, observation=Observation("green", "connected")))
        self.assertEqual(SystemCheckState.objects.count(), 0)

    def test_public_details_reject_secret_keys(self) -> None:
        claim = claim_check("email", identity="a" * 64)
        assert claim is not None
        with self.assertRaises(ValueError):
            finish_check(claim, identity="a" * 64,
                         observation=Observation("green", "connected", {"password": "must-never-persist"}))

    def test_public_details_reject_nested_response_payloads(self) -> None:
        claim = claim_check("email", identity="a" * 64)
        assert claim is not None
        payload = cast(dict[str, PublicValue], {"message": {"raw_response": "private"}})
        with self.assertRaises(ValueError):
            finish_check(claim, identity="a" * 64, observation=Observation("green", "connected", payload))
        self.assertIsNone(SystemCheckState.objects.get(pk=claim.state_id).observed_at)

    def test_node_configuration_changed_during_api_call_does_not_publish_health(self) -> None:
        node = self.node()

        def replace_configuration(_server):
            VirtualminServer.objects.filter(pk=node.pk).update(api_username="replacement")
            return Ok({"healthy": True, "data": {"output": "disk_total: 100\ndisk_free: 80\n"}})

        with patch("apps.provisioning.virtualmin_service.VirtualminProvisioningService.test_server_connection", side_effect=replace_configuration):
            VirtualminServerManagementService().health_check_server(node)
        node.refresh_from_db()
        self.assertIsNone(node.last_health_check)

    def test_ten_minute_schedule_reconciles_existing_daily_row_without_changing_counters(self) -> None:
        Schedule.objects.create(name="system_status_check", func="apps.common.tasks.system_status_check", schedule_type=Schedule.DAILY)
        Schedule.objects.create(name="counter_cull", func="apps.common.tasks.cull_counters", schedule_type=Schedule.DAILY)
        setup_system_status_scheduled_tasks()
        row = Schedule.objects.get(name="system_status_check")
        self.assertEqual(row.schedule_type, Schedule.MINUTES)
        self.assertEqual(row.minutes, 10)
        self.assertEqual(Schedule.objects.get(name="counter_cull").schedule_type, Schedule.DAILY)

    def test_health_write_failure_cannot_publish_green_verification(self) -> None:
        node = self.node()
        with patch("apps.provisioning.virtualmin_service.VirtualminProvisioningService.test_server_connection", return_value=Ok({"healthy": True})), patch.object(VirtualminServer, "save", side_effect=RuntimeError("injected write failure")):
            result = VirtualminServerManagementService().health_check_server(node)
        self.assertTrue(result.is_err())
        row = SystemCheckState.objects.get(check_key="virtualmin", node=node)
        self.assertNotEqual(row.level, "green")
        self.assertIsNone(row.verified_generation)

    def test_health_task_does_not_store_raw_api_payloads_in_queue_results(self) -> None:
        node = self.node()
        node.status = "active"
        node.save(update_fields=["status"])
        cache.clear()
        with patch("apps.provisioning.virtualmin_tasks.VirtualminServerManagementService.health_check_server", return_value=Ok({"data": {"output": "raw-private-provider-payload"}})), patch("apps.provisioning.virtualmin_tasks.reclaim_stalled_virtualmin_operations", return_value={}):
            result = health_check_virtualmin_servers()
        self.assertEqual(result["results"]["healthy_servers"], 1)
        self.assertNotIn("raw-private-provider-payload", json.dumps(result))
