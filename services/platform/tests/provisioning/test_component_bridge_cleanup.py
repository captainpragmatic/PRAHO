"""Completed component bridges retire selected source content without whole-domain deletion."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.utils import timezone

from apps.provisioning.component_bridge_cleanup import (
    _retirement_variables,
    bridge_cleanup_refusal,
    cleanup_component_bridge,
    cleanup_variables,
    source_retirement_refusal,
)
from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from tests.provisioning.test_component_migration_admission import ComponentAdmissionTestBase


class ComponentBridgeCleanupTests(ComponentAdmissionTestBase):
    def setUp(self):
        super().setUp()
        self.migration = self.start(self.approve(self.review()))
        # fsm-bypass: actual worker completed ownership/activation/routing before retention elapsed.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status="completed",
            cutover_committed_at=timezone.now(),
            archive_sha256="a" * 64,
            barrier_state={
                "component_source_sealed": True,
                "component_target_sealed": True,
                "component_target_activation_complete": True,
            },
        )
        self.account.server = self.target
        self.account.save(update_fields=["server"])
        self.migration.refresh_from_db()
        self.token = uuid4()
        self.bridge = MigrationBridge.objects.create(
            migration=self.migration,
            source_server=self.server,
            target_server=self.target,
            domain=self.account.domain,
            evidence={
                "lease_token": self.token.hex,
                "lease_until": (timezone.now() + timedelta(minutes=5)).isoformat(),
                "component_source_retained": True,
            },
        )
        self.bridge.activate()
        self.bridge.save()
        self.events = []
        self.enterContext(patch("apps.provisioning.migration_routing.observe_frontends", return_value=({}, [])))
        self.run = self.enterContext(
            patch(
                "apps.provisioning.component_bridge_cleanup.run_bridge_operation",
                side_effect=lambda _migration, _token, action, **_kw: self.events.append(action),
            )
        )
        self.retire = self.enterContext(
            patch(
                "apps.provisioning.component_bridge_cleanup._retire_source",
                side_effect=lambda _bridge, _token: self.events.append("retire-source"),
            )
        )
        self.artifacts = self.enterContext(
            patch(
                "apps.provisioning.component_bridge_cleanup._retire_target_artifacts",
                side_effect=lambda _bridge, _token: self.events.append("target-artifacts"),
            )
        )

    def test_selected_retirement_keeps_native_source_obligation_and_never_calls_delete_domain(self):
        service = SimpleNamespace(_command=MagicMock())
        result = cleanup_component_bridge(self.bridge, self.token.hex, service)
        self.assertEqual(result, {"action": "torn_down"})
        self.assertEqual(self.events, ["verify", "remove", "retire-source", "origin_remove", "target-artifacts"])
        service._command.assert_not_called()
        self.bridge.refresh_from_db()
        self.assertEqual(self.bridge.status, "torn_down")
        self.assertTrue(self.bridge.evidence["source_components_removed"])
        self.assertTrue(self.bridge.evidence["source_services_retained"])
        self.assertFalse(hasattr(self.migration.component_source_obligation, "release"))

    def test_cleanup_uses_its_own_lease_after_worker_lease_is_released_and_optional_name_is_absent(self):
        self.assertIsNone(self.migration.lease_token)
        values = cleanup_variables(self.migration, self.token, "verify", self.bridge.pk)
        self.assertIsNone(bridge_cleanup_refusal(self.server, values))
        self.assertIsNotNone(bridge_cleanup_refusal(self.target, values))
        values["bridge_target_ipv4"] = "192.0.2.99"
        self.assertIsNotNone(bridge_cleanup_refusal(self.server, values))

    def test_expired_cleanup_lease_never_calls_a_native_operation(self):
        self.bridge.evidence["lease_until"] = (timezone.now() - timedelta(seconds=1)).isoformat()
        self.bridge.save(update_fields=["evidence"])
        self.assertEqual(cleanup_component_bridge(self.bridge, self.token.hex, None), {"action": "busy"})
        self.assertEqual(self.events, [])

    def test_origin_and_source_retirement_require_exact_completed_predecessors(self):
        values = cleanup_variables(self.migration, self.token, "origin_remove", self.bridge.pk)
        self.assertIsNotNone(bridge_cleanup_refusal(self.target, values))
        source = _retirement_variables(self.bridge, self.token.hex)
        self.assertIsNotNone(source_retirement_refusal(self.server, source))
        self.bridge.start_removing_source()
        self.bridge.evidence["bridge_removed"] = True
        self.bridge.save()
        self.assertIsNone(source_retirement_refusal(self.server, source))
        source["component_request"]["owner"] = "foreigncustomer"
        self.assertIsNotNone(source_retirement_refusal(self.server, source))
