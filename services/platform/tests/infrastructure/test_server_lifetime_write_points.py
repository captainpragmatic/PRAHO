"""Deploy, cleanup and teardown open, confirm, discard and close server lifetimes as the server comes and goes."""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone
from freezegun import freeze_time

from apps.common.types import Err, Ok, Retriability
from apps.infrastructure import server_lifetimes
from apps.infrastructure.cloud_gateway import ServerCreateResult, SSHKeyResult
from apps.infrastructure.cost_service import CostTrackingService
from apps.infrastructure.deployment_lifecycle import claim_operation, provider_token_fingerprint
from apps.infrastructure.models import NodeDeployment, NodeDeploymentLog, NodeServerLifetime, NodeSize
from apps.infrastructure.node_maintenance_models import NodeMaintenanceExecution
from tests.helpers.teardown_provider import attach_teardown_provider
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment, _make_service
from tests.infrastructure.test_node_teardown import TOKEN, Harness, cloud_gateway, dns_gateway


def _gateway(create: Any) -> MagicMock:
    gateway = MagicMock()
    gateway.upload_owned_ssh_key.return_value = Ok(SSHKeyResult(key_id="key-1", name="praho-key"))
    gateway.create_firewall.return_value = Ok("fw-1")
    gateway.create_server.return_value = create
    gateway.delete_server.return_value = Ok(True)
    gateway.delete_firewall.return_value = Ok(True)
    gateway.delete_ssh_key.return_value = Ok(True)
    gateway.delete_ssh_key_by_id.return_value = Ok(True)
    return gateway


def _deploy(deployment: NodeDeployment, gateway: MagicMock, *, dns_fails: bool = True) -> Any:
    created = gateway.create_server.return_value
    if created.is_ok():
        attach_teardown_provider(
            gateway, deployment, server_id=created.unwrap().server_id, ssh_key_ids=("key-1",)
        )
    service = _make_service()
    service._ssh_manager.generate_deployment_key.return_value = Ok(MagicMock(public_key="ssh-rsa AAAA"))
    # Stop right after provisioning: the DNS step fails, which is not under test here.
    service._configure_dns = MagicMock(return_value=Err("dns stops the pipeline here"))
    service._resolve_dns_config = MagicMock(return_value=Ok(("dns-token", "zone")))
    with (
        patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
        patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=gateway),
    ):
        return service.deploy_node(deployment=deployment, credentials={"api_token": "test-token"})


def _lifetimes(deployment: NodeDeployment) -> list[tuple[str, bool, bool]]:
    """(server id, open, legacy) per lifetime, oldest first."""
    return [
        (lt.server_id, lt.ended_at is None, lt.legacy)
        for lt in NodeServerLifetime.objects.filter(deployment=deployment).order_by("started_at", "created_at")
    ]


class DeployWritePointTests(TestCase):
    def test_a_created_server_gets_a_confirmed_lifetime(self) -> None:
        deployment = _create_deployment("pending")
        gateway = _gateway(Ok(ServerCreateResult(server_id="srv-1", ipv4_address="1.2.3.4")))
        gateway.delete_server.return_value = Err("kept for this test")  # Cleanup keeps the server.
        _deploy(deployment, gateway)
        self.assertEqual(_lifetimes(deployment), [("srv-1", True, False)])

    def test_a_refused_create_bills_nothing(self) -> None:
        deployment = _create_deployment("pending")
        _deploy(deployment, _gateway(Err("invalid server type", retriability=Retriability.NOT_RETRIABLE)))
        self.assertEqual(_lifetimes(deployment), [])

    def test_a_lost_create_outcome_stays_billed_until_teardown_proves_it_gone(self) -> None:
        deployment = _create_deployment("pending")
        _deploy(deployment, _gateway(Err("read timed out", retriability=Retriability.RETRIABLE)))
        self.assertEqual(_lifetimes(deployment), [("", True, False)])

    def test_a_replaced_stale_server_keeps_the_window_recorded_in_the_row(self) -> None:
        deployment = _create_deployment("pending", external_node_id="old-vm")
        started = timezone.now() - timedelta(hours=5)
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            started_at=started, server_create_state="created", provider_token_fingerprint=provider_token_fingerprint("test-token")
        )
        deployment.refresh_from_db()
        gateway = _gateway(Ok(ServerCreateResult(server_id="srv-2", ipv4_address="1.2.3.4")))
        gateway.get_server.return_value = Ok(None)  # The stored server is gone.
        gateway.delete_server.return_value = Err("kept for this test")
        _deploy(deployment, gateway)
        self.assertEqual(_lifetimes(deployment), [("", False, True), ("srv-2", True, False)])
        legacy = NodeServerLifetime.objects.get(deployment=deployment, legacy=True)
        self.assertEqual(legacy.started_at, started)

    def test_a_refused_create_keeps_the_only_window_of_an_earlier_unknown_create(self) -> None:
        # A row from before lifetimes whose earlier create outcome is unknown: that server may exist, and this
        # attempt's window is the only one that can bill it.
        deployment = _create_deployment("pending")
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            server_create_state="unknown", provider_token_fingerprint=provider_token_fingerprint("test-token")
        )
        deployment.refresh_from_db()
        _deploy(deployment, _gateway(Err("invalid server type", retriability=Retriability.NOT_RETRIABLE)))
        self.assertEqual(_lifetimes(deployment), [("", True, False)])

    def test_cleanup_stops_when_the_operation_loses_the_row(self) -> None:
        deployment = _create_deployment("pending")
        gateway = _gateway(Ok(ServerCreateResult(server_id="srv-1", ipv4_address="")))

        def taken_over(_server_id: str) -> Any:
            NodeDeployment.objects.filter(pk=deployment.pk).update(operation_token=uuid.uuid4())
            return Ok(True)

        gateway.delete_server.side_effect = taken_over
        _deploy(deployment, gateway)
        gateway.delete_server.assert_called_once()
        gateway.delete_firewall.assert_not_called()
        gateway.delete_ssh_key.assert_not_called()

    def test_cleanup_that_deletes_the_new_server_closes_its_lifetime(self) -> None:
        deployment = _create_deployment("pending")
        _deploy(deployment, _gateway(Ok(ServerCreateResult(server_id="srv-1", ipv4_address=""))))
        self.assertEqual(_lifetimes(deployment), [("srv-1", False, False)])


class CompensationServerFieldsTests(TestCase):
    """Cleanup that proves the new server gone clears the row's server id and addresses with it."""

    def _deploy_with_addresses(self, gateway: MagicMock) -> NodeDeployment:
        deployment = _create_deployment("pending")
        planted: list[tuple[str, str | None, str | None]] = []

        def dns_after_provision(*_args: Any, **_kwargs: Any) -> Any:
            row = NodeDeployment.objects.get(pk=deployment.pk)
            planted.append((row.external_node_id, row.ipv4_address, row.ipv6_address))
            return Err("dns stops the pipeline here")

        attach_teardown_provider(gateway, deployment, server_id="srv-1", ssh_key_ids=("key-1",))
        service = _make_service()
        service._ssh_manager.generate_deployment_key.return_value = Ok(MagicMock(public_key="ssh-rsa AAAA"))
        service._configure_dns = MagicMock(side_effect=dns_after_provision)
        service._resolve_dns_config = MagicMock(return_value=Ok(("dns-token", "zone")))
        with (
            patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value=True),
            patch("apps.infrastructure.deployment_service.get_cloud_gateway", return_value=gateway),
        ):
            result = service.deploy_node(deployment=deployment, credentials={"api_token": "test-token"})
        self.assertTrue(result.is_err(), result)
        # The provisioned row held the server before cleanup ran.
        self.assertEqual(planted, [("srv-1", "1.2.3.4", "2001:db8::1")])
        deployment.refresh_from_db()
        return deployment

    @staticmethod
    def _created() -> Any:
        return Ok(ServerCreateResult(server_id="srv-1", ipv4_address="1.2.3.4", ipv6_address="2001:db8::1"))

    def test_cleanup_that_deletes_the_server_clears_its_id_and_addresses(self) -> None:
        deployment = self._deploy_with_addresses(_gateway(self._created()))

        self.assertEqual(deployment.status, "failed")
        self.assertEqual((deployment.external_node_id, deployment.ipv4_address, deployment.ipv6_address), ("", None, None))
        self.assertEqual(_lifetimes(deployment), [("srv-1", False, False)])

    def test_cleanup_whose_server_delete_fails_keeps_its_id_and_addresses(self) -> None:
        gateway = _gateway(self._created())
        gateway.delete_server.return_value = Err("provider refused deletion")

        deployment = self._deploy_with_addresses(gateway)

        self.assertEqual(deployment.status, "failed")
        self.assertEqual(
            (deployment.external_node_id, deployment.ipv4_address, deployment.ipv6_address),
            ("srv-1", "1.2.3.4", "2001:db8::1"),
        )
        self.assertEqual(_lifetimes(deployment), [("srv-1", True, False)])

    def test_destroying_a_cleaned_failed_row_still_deletes_its_labelled_server(self) -> None:
        deployment = _create_deployment("failed")
        NodeDeployment.objects.filter(pk=deployment.pk).update(
            server_create_state="created", provider_token_fingerprint=provider_token_fingerprint(TOKEN)
        )
        deployment.refresh_from_db()
        self.assertEqual((deployment.external_node_id, deployment.server_create_state), ("", "created"))
        gateway = cloud_gateway()
        attach_teardown_provider(gateway, deployment, server_id="srv-left")

        with (
            patch("apps.infrastructure.node_teardown.get_cloud_gateway", return_value=gateway),
            patch("apps.infrastructure.deployment_service.get_dns_gateway", return_value=dns_gateway()),
            patch("apps.infrastructure.deployment_service.SettingsService.get_setting", return_value="dns-tok"),
        ):
            result = _make_service().destroy_node(deployment, credentials={"api_token": TOKEN})

        self.assertTrue(result.is_ok(), result)
        gateway.delete_server.assert_called_once_with("srv-left")
        deployment.refresh_from_db()
        self.assertEqual(deployment.status, "destroyed")


class TeardownWritePointTests(TestCase):
    def test_teardown_closes_every_open_lifetime_including_an_unconfirmed_one(self) -> None:
        h = Harness()
        NodeServerLifetime.objects.create(
            deployment=h.deployment, correlation_id=h.deployment.correlation_id, server_id="srv-1", node_size=h.deployment.node_size, monthly_cost_eur=3,
            started_at=timezone.now() - timedelta(hours=2),
        )
        NodeServerLifetime.objects.create(
            deployment=h.deployment, correlation_id=h.deployment.correlation_id, server_id="", node_size=h.deployment.node_size, monthly_cost_eur=3,
            started_at=timezone.now() - timedelta(hours=1),
        )
        self.assertTrue(h.destroy().is_ok())
        self.assertEqual(h.row().status, "destroyed")
        self.assertFalse(NodeServerLifetime.objects.filter(deployment=h.deployment, ended_at__isnull=True).exists())


class ResizeWritePointTests(TestCase):
    def test_preparation_reuses_a_window_at_an_earlier_size_after_recording_failure(self) -> None:
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(node_size=self.bigger)
        self.deployment.refresh_from_db()
        self.assertNotEqual(self.lifetime.node_size_id, self.deployment.node_size_id)
        prepared = server_lifetimes.prepare_lifetime_for_resize(self.deployment, "srv-1", self.bigger)
        self.assertEqual(prepared, self.lifetime.pk)
        self.assertTrue(server_lifetimes.split_lifetime_for_resize(prepared, "srv-1", self.bigger))
        self.assertEqual(self.deployment.server_lifetimes.filter(ended_at__isnull=True).get().node_size_id, self.bigger.pk)

    @freeze_time("2026-11-02T12:00:00Z")
    def test_preparation_captures_a_window_starting_exactly_at_dispatch(self) -> None:
        self.lifetime.delete()
        start = timezone.now()
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(started_at=start)
        self.deployment.refresh_from_db()
        prepared = server_lifetimes.prepare_lifetime_for_resize(self.deployment, "srv-1", self.deployment.node_size)
        self.assertIsNotNone(prepared)
        with freeze_time(start + timedelta(hours=1)):
            self.assertTrue(server_lifetimes.split_lifetime_for_resize(prepared, "srv-1", self.bigger))
        old = self.deployment.server_lifetimes.get(pk=prepared)
        self.assertEqual((old.started_at, old.ended_at), (start, start + timedelta(hours=1)))
        recorded = CostTrackingService().calculate_deployment_costs(self.deployment, start, start + timedelta(hours=1)).unwrap()
        self.assertEqual(recorded.cost_eur.quantize(Decimal("0.0001")),
                         (Decimal("3.29") / 730).quantize(Decimal("0.0001")))

    def test_preparation_failure_rolls_back_issuance_without_a_provider_call(self) -> None:
        self.lifetime.delete()
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(started_at=timezone.now() - timedelta(days=1))
        self.deployment.refresh_from_db()
        service = _make_service()
        service._check_resize_orderable = MagicMock(return_value=Ok(True))

        def prepared_then_failed(*args: Any) -> None:
            self.assertIsNotNone(server_lifetimes.prepare_lifetime_for_resize(*args))
            self.assertTrue(self.deployment.server_lifetimes.exists())
            raise RuntimeError("prepare failed")

        with (
            patch("apps.infrastructure.deployment_service.prepare_lifetime_for_resize", side_effect=prepared_then_failed),
            patch("apps.infrastructure.deployment_service.run_provider_command") as provider,
        ):
            result = service.upgrade_node_size(self.deployment, self.bigger, {"api_token": "test-token"})
        self.assertTrue(result.is_err(), result)
        provider.assert_not_called()
        execution = NodeMaintenanceExecution.objects.get(deployment=self.deployment)
        self.assertEqual((execution.phase, execution.issued_at, execution.internal_result.get("code")),
                         ("failed", None, "not_run"))
        self.assertFalse(self.deployment.server_lifetimes.exists())

    def test_prepared_window_is_reused_and_never_reopened_after_server_absence(self) -> None:
        self.lifetime.delete()
        start = timezone.now() - timedelta(days=2)
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(started_at=start, server_create_state="created")
        self.deployment.refresh_from_db()
        prepared = server_lifetimes.prepare_lifetime_for_resize(self.deployment, "srv-1", self.deployment.node_size)
        self.assertIsNotNone(prepared)
        self.assertEqual(server_lifetimes.prepare_lifetime_for_resize(
            self.deployment, "srv-1", self.deployment.node_size), prepared)
        lease = claim_operation(self.deployment.pk, from_states=("completed",), to_status="destroying", kind="teardown").unwrap()
        self.deployment.refresh_from_db()
        self.assertEqual(server_lifetimes.close_server_lifetimes(lease, self.deployment), 1)
        # Physical absence was proved, but dependency cleanup has not cleared this identity yet.
        self.assertEqual(self.deployment.external_node_id, "srv-1")
        self.assertIsNone(self.deployment.destroyed_at)
        self.assertFalse(server_lifetimes.split_lifetime_for_resize(prepared, "srv-1", self.bigger))
        self.assertIsNone(server_lifetimes.prepare_lifetime_for_resize(
            self.deployment, "srv-1", self.deployment.node_size))
        self.assertEqual(self.deployment.server_lifetimes.count(), 1)
        self.assertFalse(self.deployment.server_lifetimes.filter(ended_at__isnull=True).exists())

    def test_preparation_uses_current_catalogue_rate_and_rejects_changed_attempt(self) -> None:
        self.lifetime.delete()
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(started_at=timezone.now() - timedelta(days=1))
        self.deployment.refresh_from_db()
        stale_size = self.deployment.node_size
        NodeSize.objects.filter(pk=stale_size.pk).update(monthly_cost_eur=Decimal("9.99"))
        prepared = server_lifetimes.prepare_lifetime_for_resize(self.deployment, "srv-1", stale_size)
        self.assertEqual(NodeServerLifetime.objects.get(pk=prepared).monthly_cost_eur, Decimal("9.99"))
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(correlation_id=uuid.uuid4())
        with self.assertRaisesMessage(ValueError, "binding changed"):
            server_lifetimes.prepare_lifetime_for_resize(self.deployment, "srv-1", stale_size)
        self.assertEqual(self.deployment.server_lifetimes.count(), 1)

    def test_refused_resize_preserves_old_rate_accounting(self) -> None:
        self.lifetime.delete()
        start = timezone.now() - timedelta(days=2)
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(started_at=start)
        self.deployment.refresh_from_db()
        costs = CostTrackingService()
        before = costs.calculate_deployment_costs(self.deployment, start, start + timedelta(hours=24)).unwrap().cost_eur
        service = _make_service()
        service._check_resize_orderable = MagicMock(return_value=Ok(True))
        with patch("apps.infrastructure.deployment_service.run_provider_command", return_value=Err("provider refused")):
            self.assertTrue(service.upgrade_node_size(self.deployment, self.bigger, {"api_token": "test-token"}).is_err())
        after = costs.calculate_deployment_costs(self.deployment, start, start + timedelta(hours=24)).unwrap().cost_eur
        self.assertEqual(after.quantize(Decimal("0.0001")), before.quantize(Decimal("0.0001")))
        self.assertEqual(self.deployment.server_lifetimes.count(), 1)

    @freeze_time("2026-11-02T12:00:00Z")
    def test_first_resize_while_destroying_preserves_historical_rate(self) -> None:
        self.lifetime.delete()
        start = timezone.now() - timedelta(days=3)
        end = start + timedelta(hours=24)
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(started_at=start, server_create_state="created")
        self.deployment.refresh_from_db()
        costs = CostTrackingService()
        before = costs.calculate_deployment_costs(self.deployment, start, end).unwrap().cost_eur
        self.assertGreater(before, 0)
        self.assertFalse(self.deployment.server_lifetimes.exists())

        def destroying_before_reply(**_kwargs: Any) -> Any:
            # Inject a legacy recording interleaving; current native admission blocks ordinary public overlap.
            NodeDeployment.objects.filter(pk=self.deployment.pk).update(status="destroying")
            return Ok(MagicMock(success=True, stderr=""))

        service = _make_service()
        service._check_resize_orderable = MagicMock(return_value=Ok(True))
        with patch("apps.infrastructure.deployment_service.run_provider_command", side_effect=destroying_before_reply):
            result = service.upgrade_node_size(self.deployment, self.bigger, {"api_token": "test-token"})
        self.assertTrue(result.is_ok(), result)
        self.deployment.refresh_from_db()
        self.assertEqual((self.deployment.status, self.deployment.external_node_id), ("destroying", "srv-1"))
        after = costs.calculate_deployment_costs(self.deployment, start, end).unwrap().cost_eur
        self.assertEqual(after.quantize(Decimal("0.0001")), before.quantize(Decimal("0.0001")))
        self.assertEqual(self.deployment.node_size_id, self.bigger.pk)
        old, new = self.deployment.server_lifetimes.order_by("started_at")
        self.assertEqual((old.monthly_cost_eur, new.monthly_cost_eur), (Decimal("3.29"), Decimal("13.99")))
        self.assertEqual(old.ended_at, new.started_at)
        self.assertIsNone(new.ended_at)

    def setUp(self) -> None:
        self.deployment = _create_deployment("completed", external_node_id="srv-1")
        self.lifetime = NodeServerLifetime.objects.create(
            deployment=self.deployment, correlation_id=self.deployment.correlation_id, server_id="srv-1", node_size=self.deployment.node_size,
            monthly_cost_eur=Decimal("3.29"), started_at=timezone.now() - timedelta(days=3),
        )
        self.bigger = NodeSize.objects.create(
            provider=self.deployment.provider, name="BIG", display_name="Big", provider_type_id="cpx32", vcpus=4,
            memory_gb=8, disk_gb=160, hourly_cost_eur=Decimal("0.0200"), monthly_cost_eur=Decimal("13.99"),
        )
        self.bigger.available_regions.add(self.deployment.region)

    def resize(self) -> Any:
        service = _make_service()
        service._check_resize_orderable = MagicMock(return_value=Ok(True))
        with patch(
            "apps.infrastructure.deployment_service.run_provider_command",
            return_value=Ok(MagicMock(success=True, stderr="")),
        ):
            return service.upgrade_node_size(self.deployment, self.bigger, {"api_token": "test-token"})

    def test_a_resize_keeps_the_old_rate_for_the_hours_before_it(self) -> None:
        self.assertTrue(self.resize().is_ok())
        rows = list(NodeServerLifetime.objects.filter(deployment=self.deployment).order_by("started_at"))
        self.assertEqual(
            [(lt.server_id, lt.monthly_cost_eur, lt.ended_at is None) for lt in rows],
            [("srv-1", Decimal("3.29"), False), ("srv-1", Decimal("13.99"), True)],
        )

    def test_the_first_resize_of_a_row_without_lifetimes_keeps_its_window_at_the_old_rate(self) -> None:
        self.lifetime.delete()
        started = timezone.now() - timedelta(days=5)
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(started_at=started)
        self.deployment.refresh_from_db()
        old_rate = self.deployment.node_size.monthly_cost_eur
        self.assertTrue(self.resize().is_ok())
        rows = list(NodeServerLifetime.objects.filter(deployment=self.deployment).order_by("started_at"))
        self.assertEqual(
            [(lt.server_id, lt.monthly_cost_eur, lt.legacy, lt.ended_at is None) for lt in rows],
            [("srv-1", old_rate, True, False), ("srv-1", Decimal("13.99"), False, True)],
        )
        self.assertEqual(rows[0].started_at, started)

    def test_a_teardown_during_the_first_resize_opens_no_lifetime(self) -> None:
        self.lifetime.delete()
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(started_at=timezone.now() - timedelta(days=5))
        self.deployment.refresh_from_db()

        def torn_down_meanwhile(**_kwargs: Any) -> Any:
            gone = timezone.now()
            # Model the real teardown's physical-absence checkpoint as well as its final row settlement.
            NodeServerLifetime.objects.filter(deployment=self.deployment, ended_at__isnull=True).update(ended_at=gone)
            NodeDeployment.objects.filter(pk=self.deployment.pk).update(
                status="destroyed", external_node_id="", destroyed_at=gone
            )
            return Ok(MagicMock(success=True, stderr=""))

        service = _make_service()
        service._check_resize_orderable = MagicMock(return_value=Ok(True))
        with patch("apps.infrastructure.deployment_service.run_provider_command", side_effect=torn_down_meanwhile):
            service.upgrade_node_size(self.deployment, self.bigger, {"api_token": "test-token"})
        self.assertFalse(
            NodeServerLifetime.objects.filter(deployment=self.deployment, ended_at__isnull=True).exists()
        )

    def test_a_cost_window_failure_after_a_done_resize_is_not_an_upgrade_failure(self) -> None:
        with patch(
            "apps.infrastructure.deployment_service.split_lifetime_for_resize", side_effect=RuntimeError("db hiccup")
        ):
            result = self.resize()
        self.assertTrue(result.is_ok(), result)
        self.deployment.refresh_from_db()
        self.assertEqual(self.deployment.node_size_id, self.bigger.pk)
        self.assertTrue(
            NodeDeploymentLog.objects.filter(
                deployment=self.deployment, level="WARNING", message__contains="cost window"
            ).exists()
        )

    def test_a_resize_that_finishes_after_a_re_deploy_leaves_the_new_attempt_alone(self) -> None:
        def replaced_meanwhile(**_kwargs: Any) -> Any:
            # Teardown and re-deploy ran during the provider call: a new attempt with its own size.
            NodeDeployment.objects.filter(pk=self.deployment.pk).update(
                correlation_id=uuid.uuid4(), external_node_id="srv-2"
            )
            return Ok(MagicMock(success=True, stderr=""))

        old_size_id = self.deployment.node_size_id
        service = _make_service()
        service._check_resize_orderable = MagicMock(return_value=Ok(True))
        with patch("apps.infrastructure.deployment_service.run_provider_command", side_effect=replaced_meanwhile):
            service.upgrade_node_size(self.deployment, self.bigger, {"api_token": "test-token"})
        self.assertEqual(NodeDeployment.objects.get(pk=self.deployment.pk).node_size_id, old_size_id)
