"""Billing convergence takes its own lease without replaying component activation."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.utils import timezone

from apps.provisioning.component_target_transport import target_operation_refusal, target_operation_variables
from apps.provisioning.migration_enabled_state import reconcile_committed_target
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from tests.provisioning.test_component_migration_admission import ComponentAdmissionTestBase


class ComponentCurrentPolicyTests(ComponentAdmissionTestBase):
    def setUp(self):
        super().setUp()
        self.migration = self.start(self.approve(self.review()))
        # fsm-bypass: independently completed native activation, waiting for customer DNS.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status="repointing",
            cutover_committed_at=timezone.now(),
            archive_sha256="a" * 64,
            barrier_state={
                "component_source_sealed": True,
                "component_target_sealed": True,
                "component_target_receipt_sha256": "b" * 64,
                "component_target_activation_complete": True,
                "target_domain_id": "987654321",
                "target_activation": {
                    "complete": True,
                    "server_id": str(self.target.pk),
                    "domain_id": "987654321",
                    "owner": self.account.virtualmin_username,
                },
            },
        )
        self.account.server = self.target
        self.account.save(update_fields=["server"])
        type(self.service).objects.filter(pk=self.service.pk).update(status="suspended")
        self.remote = {"enabled": True}
        self.enterContext(
            patch("apps.provisioning.migration_enabled_state._target", side_effect=lambda _migration: dict(self.remote))
        )

        def native(migration, token, action, *, enabled):
            self.assertEqual(action, "target_policy")
            values = target_operation_variables(migration, token, action, enabled=enabled)
            self.assertIsNone(target_operation_refusal(self.target, values))
            self.remote["enabled"] = enabled
            return {"phase": "active", "target_domain_id": "987654321"}

        self.native = self.enterContext(
            patch("apps.provisioning.component_target_transport.run_target_operation", side_effect=native)
        )

    def test_current_policy_claims_and_releases_its_own_lease_with_default_task_budget(self):
        result = reconcile_committed_target(str(self.service.pk), task_budget_seconds=600)
        self.assertEqual(result, {"success": True, "action": "migration_policy", "enabled": False})
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")
        self.migration.refresh_from_db()
        self.assertIsNone(self.migration.lease_token)
        self.assertEqual(self.migration.status, "repointing")
        self.native.assert_called_once()

    def test_active_worker_lease_keeps_policy_writer_out_of_native_operations(self):
        token = uuid4()
        self.assertTrue(self.migration.acquire_lease(token, timedelta(minutes=5)))
        result = reconcile_committed_target(str(self.service.pk), task_budget_seconds=600)
        self.assertEqual(result, {"success": True, "action": "operation_active"})
        self.native.assert_not_called()
        self.migration.refresh_from_db()
        self.assertEqual(self.migration.lease_token, token)

    def test_current_policy_can_converge_a_proven_target_parked_for_routing_review(self):
        # fsm-bypass: public DNS uncertainty parks only the completed target's routing phase.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status="needs_review", parked_phase="repointing"
        )
        self.assertTrue(reconcile_committed_target(str(self.service.pk), task_budget_seconds=600)["success"])
        self.native.assert_called_once()

    def test_uncertain_activation_has_no_background_enable_permission(self):
        # fsm-bypass: activation itself has not completed and cannot be bypassed.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status="needs_review", parked_phase="activating"
        )
        self.assertIsNone(reconcile_committed_target(str(self.service.pk), task_budget_seconds=600))
        self.native.assert_not_called()
