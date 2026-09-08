"""Placement contracts for Round 3; RED/GREEN labels refer to dcdb9003."""

from __future__ import annotations

from unittest.mock import patch
from uuid import UUID, uuid4

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.common.types import Err
from apps.infrastructure.models import NodeDeployment
from apps.provisioning.virtualmin_drain_service import NodeDrainService
from apps.provisioning.virtualmin_migration_models import NodeDrain, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class PlacementTests(MigrationTestBase):
    def _configure(self, server: VirtualminServer, **fields: object) -> None:
        VirtualminServer.objects.filter(pk=server.pk).update(**fields)
        server.refresh_from_db()

    def _candidate(  # noqa: PLR0913  # Keyword-only fixture builder
        self,
        name: str,
        *,
        weight: int = 100,
        load: int = 0,
        region: str = "",
        tags: list[str] | None = None,
        identifier: UUID | None = None,
    ) -> VirtualminServer:
        server = VirtualminServer.objects.create(
            id=identifier or uuid4(),
            name=name,
            hostname=f"{name}.example.com",
            api_username="placement-test",
            weight=weight,
            current_domains=load,
            region=region,
            tags=tags or [],
            last_health_check=timezone.now(),
        )
        deployment = self.target.node_deployment
        number = NodeDeployment.objects.count() + 1
        NodeDeployment.objects.create(
            provider=deployment.provider,
            node_size=deployment.node_size,
            region=deployment.region,
            panel_type=deployment.panel_type,
            hostname=f"prd-sha-het-de-fsn1-{number:03}",
            node_number=number,
            ipv4_address=f"203.0.113.{number}",
            virtualmin_server=server,
        )
        return server

    def test_default_selection_freezes_least_loaded_behavior(self) -> None:
        """GREEN pin: empty policy and equal weights select the exact least-loaded server."""
        self.settings_values["provisioning.placement_required_tags"] = []
        self.settings_values["provisioning.placement_excluded_tags"] = []
        self.assertEqual(self.server.weight, self.target.weight)
        self.assertLess(self.target.current_domains, self.server.current_domains)
        result = VirtualminProvisioningService()._select_best_server()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), self.target)

    def test_weight_is_strict_priority(self) -> None:
        """RED: current implementation chooses the lower-load target."""
        self._configure(self.server, weight=200, current_domains=50)
        result = VirtualminProvisioningService()._select_best_server()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), self.server)

    def test_region_precedes_weight_and_load_case_insensitively(self) -> None:
        """RED: preferred_region is not accepted."""
        self._configure(self.server, region="RO", current_domains=50)
        self._configure(self.target, region="de", weight=1000)
        result = VirtualminProvisioningService()._select_best_server(preferred_region="rO")
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), self.server)

    def test_region_falls_back_when_local_server_cannot_host(self) -> None:
        """RED: preferred_region is not accepted; every unavailable-local case must fall back."""
        self._configure(self.server, region="ro")
        self._configure(self.target, region="de")
        for fields in (
            {"current_domains": self.server.max_domains},
            {"health_check_error": "unreachable"},
            {"is_draining": True},
        ):
            with self.subTest(fields=fields):
                self._configure(self.server, current_domains=10, health_check_error="", is_draining=False)
                self._configure(self.server, **fields)
                result = VirtualminProvisioningService()._select_best_server(preferred_region="RO")
                self.assertTrue(result.is_ok(), result)
                self.assertEqual(result.unwrap(), self.target)

    def test_empty_or_absent_matching_region_keeps_global_pool(self) -> None:
        """RED: preferred_region is not accepted."""
        self._configure(self.server, region="ro", weight=200)
        self._configure(self.target, region="de")
        for region in ("", "unknown"):
            with self.subTest(region=region):
                result = VirtualminProvisioningService()._select_best_server(preferred_region=region)
                self.assertTrue(result.is_ok(), result)
                self.assertEqual(result.unwrap(), self.server)

    def test_required_tags_are_union_of_request_and_setting(self) -> None:
        """RED: required_tags is not accepted; neither source may replace the other."""
        self.settings_values["provisioning.placement_required_tags"] = ["managed"]
        self._configure(self.server, tags=["ssd", "managed"])
        for tags in (["ssd"], ["managed"], ["SSD", "managed"]):
            with self.subTest(tags=tags):
                self._configure(self.target, tags=tags)
                result = VirtualminProvisioningService()._select_best_server(required_tags=["ssd"])
                self.assertTrue(result.is_ok(), result)
                self.assertEqual(result.unwrap(), self.server)

    def test_setting_required_tags_apply_without_parameters(self) -> None:
        """RED: the lower-load untagged target is currently selected."""
        self.settings_values["provisioning.placement_required_tags"] = ["managed", "ssd"]
        self._configure(self.server, tags=["managed", "ssd"])
        result = VirtualminProvisioningService()._select_best_server()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), self.server)

    def test_excluded_tags_are_hard_filters(self) -> None:
        """RED: excluded tags are currently ignored."""
        self.settings_values["provisioning.placement_excluded_tags"] = ["quarantine", "retiring"]
        self._configure(self.target, tags=["retiring"])
        result = VirtualminProvisioningService()._select_best_server()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), self.server)

    def test_excluded_tag_wins_over_required_tag(self) -> None:
        """RED: conflicting policy currently still selects a server."""
        self.settings_values["provisioning.placement_required_tags"] = ["ssd"]
        self.settings_values["provisioning.placement_excluded_tags"] = ["ssd"]
        self._configure(self.server, tags=["ssd"])
        self._configure(self.target, tags=["ssd"])
        self.assertTrue(VirtualminProvisioningService()._select_best_server().is_err())

    def test_explicit_exclusions_remove_the_best_server(self) -> None:
        """RED: exclude_server_ids is not accepted."""
        result = VirtualminProvisioningService()._select_best_server(exclude_server_ids=[self.target.pk])
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), self.server)

    def test_queryset_excludes_draining_servers_before_recheck(self) -> None:
        """RED queryset pin: R2's can_host_domain defense is deliberately bypassed."""
        self._configure(self.target, is_draining=True)
        with patch.object(VirtualminServer, "can_host_domain", autospec=True, return_value=True) as check:
            result = VirtualminProvisioningService()._select_best_server()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), self.server)
        self.assertEqual([call.args[0].pk for call in check.call_args_list], [self.server.pk])

    def test_final_candidate_admission_is_rechecked(self) -> None:
        """GREEN pin: a candidate rejected at the final check is skipped."""
        with patch.object(
            VirtualminServer,
            "can_host_domain",
            autospec=True,
            side_effect=lambda server: server.pk != self.target.pk,
        ) as check:
            result = VirtualminProvisioningService()._select_best_server()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), self.server)
        self.assertEqual([call.args[0].pk for call in check.call_args_list], [self.target.pk, self.server.pk])

    def test_eligible_targets_prioritize_weight_then_load(self) -> None:
        """RED: eligible_targets currently returns insertion/query order."""
        heavy = self._candidate("heavy", weight=200, load=50)
        lighter = self._candidate("lighter", weight=200, load=10)
        self.assertEqual(
            VirtualminMigrationService.eligible_targets(self.account),
            [lighter, heavy, self.target],
        )

    def test_eligible_targets_partition_region_with_fallback(self) -> None:
        """RED: eligible_targets does not accept preferred_region."""
        self._configure(self.target, region="DE", weight=1000)
        local = self._candidate("local", region="RO", load=50)
        service = VirtualminMigrationService()
        self.assertEqual(service.eligible_targets(self.account, preferred_region="ro"), [local, self.target])
        self._configure(local, health_check_error="unreachable")
        self.assertEqual(service.eligible_targets(self.account, preferred_region="ro"), [self.target])

    def test_eligible_targets_apply_all_required_and_no_excluded_tags(self) -> None:
        """RED: migration target discovery currently ignores tag policy."""
        self.settings_values["provisioning.placement_required_tags"] = ["managed", "ssd"]
        self.settings_values["provisioning.placement_excluded_tags"] = ["quarantine", "retiring"]
        self._configure(self.target, tags=["managed"])
        excluded = self._candidate("excluded", weight=1000, tags=["managed", "ssd", "retiring"])
        allowed = self._candidate("allowed", tags=["managed", "ssd"])
        self.assertEqual(VirtualminMigrationService.eligible_targets(self.account), [allowed])
        self._configure(excluded, tags=["managed", "ssd"])
        self.assertEqual(VirtualminMigrationService.eligible_targets(self.account), [excluded, allowed])

    def test_eligible_targets_preserve_hard_admission_and_reservations(self) -> None:
        """GREEN pin: source, unmanaged, unhealthy, inactive, full and reserved nodes stay out."""
        VirtualminServer.objects.create(
            name="unmanaged", hostname="unmanaged.example.com", api_username="test",
            last_health_check=timezone.now(),
        )
        service = VirtualminMigrationService()
        for fields in (
            {"health_check_error": "unreachable"},
            {"is_draining": True},
            {"current_domains": self.target.max_domains},
            {"status": "disabled"},
        ):
            with self.subTest(fields=fields):
                # fsm-bypass: reset VirtualminServer's status CharField for admission fixtures.
                self._configure(self.target, status="active", health_check_error="", is_draining=False, current_domains=0)
                # fsm-bypass: exercise inactive VirtualminServer CharField admission.
                self._configure(self.target, **fields)
                self.assertEqual(service.eligible_targets(self.account), [])
        # fsm-bypass: restore the active target before testing the last available slot.
        self._configure(self.target, status="active", max_domains=1, current_domains=0)
        self.assertEqual(service.eligible_targets(self.account), [self.target])
        migration = VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=self.target,
        )
        self.assertEqual(service.eligible_targets(self.account), [])
        # fsm-bypass: emulate a terminal migration releasing its capacity reservation.
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="completed")
        self.assertEqual(service.eligible_targets(self.account), [self.target])

    def test_equal_weight_and_load_use_uuid_tiebreak(self) -> None:
        """RED: query order currently wins instead of the explicit UUID tiebreak."""
        self._configure(self.target, weight=1)
        larger = self._candidate("a-larger", identifier=UUID(int=2))
        smaller = self._candidate("z-smaller", identifier=UUID(int=1))
        self.assertEqual(
            VirtualminMigrationService.eligible_targets(self.account),
            [smaller, larger, self.target],
        )
        self._configure(self.server, weight=1)
        result = VirtualminProvisioningService()._select_best_server()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap(), smaller)

    def test_drain_selects_target_in_source_region(self) -> None:
        """RED: drain currently selects the lower-load remote target."""
        self._configure(self.server, region="RO")
        self._configure(self.target, region="ro", current_domains=50)
        self._candidate("remote", region="DE", weight=1000)
        drain = NodeDrain.objects.create(server=self.server, initiated_by=self.staff)
        with patch.object(
            VirtualminMigrationService, "start_migration", return_value=Err("boundary stop")
        ) as start:
            self.assertEqual(NodeDrainService._migrate(drain, self.account), "boundary stop")
        start.assert_called_once_with(
            self.account, self.target, initiated_by=self.staff, reason="drain", enqueue=False
        )


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class PlacementSettingTests(TestCase):
    keys = ("provisioning.placement_required_tags", "provisioning.placement_excluded_tags")

    def test_catalog_and_json_list_round_trip(self) -> None:
        """RED: catalog keys do not exist; valid JSON lists must remain lists."""
        for key in self.keys:
            with self.subTest(key=key):
                definition = CATALOG_BY_KEY[key]
                self.assertEqual(definition.default, [])
                self.assertEqual(definition.data_type, "list")
                self.assertEqual(definition.input_kind, "chips")
                self.assertEqual(definition.validation, {"item_type": "string"})
                for value, expected in (('["ssd", "managed"]', ["ssd", "managed"]), ([], [])):
                    result = SettingsService.update_setting(key, value)
                    self.assertTrue(result.is_ok(), result)
                    self.assertEqual(result.unwrap().get_typed_value(), expected)

    def test_invalid_tag_values_cannot_create_or_replace_policy(self) -> None:
        """RED: undeclared settings currently accept invalid policy values."""
        for key in self.keys:
            for value in ({}, 1, True, None, '"ssd"', [1], [True], [None], [{}], [["ssd"]]):
                with self.subTest(key=key, value=value):
                    SystemSetting.objects.filter(key=key).delete()
                    result = SettingsService.update_setting(key, value)
                    self.assertTrue(result.is_err(), result)
                    self.assertFalse(SystemSetting.objects.filter(key=key).exists())
                    valid = SettingsService.update_setting(key, ["ssd"])
                    self.assertTrue(valid.is_ok(), valid)
                    result = SettingsService.update_setting(key, value)
                    self.assertTrue(result.is_err(), result)
                    row = SystemSetting.objects.get(key=key)
                    self.assertEqual(row.get_typed_value(), ["ssd"])
