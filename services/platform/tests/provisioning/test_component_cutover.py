"""Component ownership publication follows durable target and source compensation seals."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from tests.provisioning.test_component_migration_admission import ComponentAdmissionTestBase


class ComponentCutoverTests(ComponentAdmissionTestBase):
    def setUp(self):
        super().setUp()
        self.migration = self.start(self.approve(self.review()))
        self.token = uuid4()
        self.assertTrue(self.migration.acquire_lease(self.token, timedelta(minutes=5)))
        # fsm-bypass: independent source export, held restoration and origin TLS proof completed.
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(
            status="verifying",
            archive_sha256="a" * 64,
            barrier_state={
                "target_domain_id": "987654321",
                "component_target_receipt_sha256": "b" * 64,
                "component_bridge_verified": True,
            },
        )
        self.migration.refresh_from_db()
        self.events = []

    def source(self, migration, token, action):
        self.assertEqual(token, self.token)
        current = VirtualminMigration.objects.get(pk=migration.pk)
        self.events.append(action)
        if action == "source_commit":
            self.assertTrue(current.barrier_state["component_source_seal_intent"])
            self.assertTrue(current.barrier_state["component_target_sealed"])
            self.assertIsNone(current.cutover_committed_at)
        return {"phase": "committed" if action == "source_commit" else "held"}

    def target_operation(self, migration, token, action):
        self.assertEqual(token, self.token)
        current = VirtualminMigration.objects.get(pk=migration.pk)
        self.events.append(action)
        if action == "target_seal":
            self.assertTrue(current.barrier_state["component_source_seal_intent"])
            self.assertIsNone(current.cutover_committed_at)
        return {"target_receipt_sha256": "b" * 64}

    def publish(self):
        from apps.provisioning.component_cutover import commit_component_cutover  # noqa: PLC0415

        with (
            patch("apps.provisioning.component_cutover.run_source_operation", side_effect=self.source),
            patch("apps.provisioning.component_cutover.run_target_operation", side_effect=self.target_operation),
        ):
            commit_component_cutover(VirtualminMigrationService(), self.migration, self.token)

    def test_ownership_moves_only_after_both_native_seals_and_preserves_source_obligation(self):
        obligation = self.migration.component_source_obligation_id
        self.publish()
        self.migration.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual(self.events, ["source_verify", "target_verify", "target_seal", "source_commit"])
        self.assertEqual(self.migration.status, "activating")
        self.assertIsNotNone(self.migration.cutover_committed_at)
        self.assertEqual(self.account.server_id, self.target.pk)
        self.assertEqual(self.migration.component_source_obligation_id, obligation)
        self.assertFalse(hasattr(self.migration.component_source_obligation, "release"))
        bridge = MigrationBridge.objects.get(migration=self.migration)
        self.assertEqual(bridge.source_server_id, self.server.pk)
        self.assertEqual(bridge.target_server_id, self.target.pk)
        self.assertTrue(bridge.evidence["component_source_retained"])

    def test_cancel_before_intent_never_seals_a_native_copy(self):
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(cancel_requested=True)
        with self.assertRaisesRegex(ValueError, "cancel"):
            self.publish()
        self.assertEqual(self.events, [])
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)

    def test_lost_source_seal_response_keeps_target_and_resumes_forward_even_after_cancel(self):
        original = self.source

        def uncertain(migration, token, action):
            receipt = original(migration, token, action)
            if action == "source_commit":
                raise TimeoutError("Lost source seal reply")
            return receipt

        self.source = uncertain
        with self.assertRaises(TimeoutError):
            self.publish()
        self.migration.refresh_from_db()
        self.assertTrue(self.migration.barrier_state["component_source_seal_intent"])
        self.assertTrue(self.migration.barrier_state["component_target_sealed"])
        self.assertIsNone(self.migration.cutover_committed_at)
        self.source = original
        VirtualminMigration.objects.filter(pk=self.migration.pk).update(cancel_requested=True)
        self.events.clear()
        self.publish()
        self.assertEqual(self.events, ["target_seal", "source_commit"])
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.target.pk)

    def test_connection_drift_after_native_seals_keeps_ownership_unpublished(self):
        original = self.source

        def moved_network(migration, token, action):
            receipt = original(migration, token, action)
            if action == "source_commit":
                type(self.target).objects.filter(pk=self.target.pk).update(ipv4_address="192.0.2.99")
            return receipt

        self.source = moved_network
        with self.assertRaisesRegex(ValueError, "addresses"):
            self.publish()
        self.migration.refresh_from_db()
        self.account.refresh_from_db()
        self.assertTrue(self.migration.barrier_state["component_source_sealed"])
        self.assertTrue(self.migration.barrier_state["component_target_sealed"])
        self.assertIsNone(self.migration.cutover_committed_at)
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertFalse(MigrationBridge.objects.exists())

    def test_cancellation_arriving_after_seal_intent_cannot_reopen_the_source(self):
        original = self.target_operation

        def cancel_during_seal(migration, token, action):
            receipt = original(migration, token, action)
            if action == "target_seal":
                VirtualminMigration.objects.filter(pk=migration.pk).update(cancel_requested=True)
            return receipt

        self.target_operation = cancel_during_seal
        self.publish()
        self.migration.refresh_from_db()
        self.account.refresh_from_db()
        self.assertTrue(self.migration.cancel_requested)
        self.assertIsNotNone(self.migration.cutover_committed_at)
        self.assertEqual(self.account.server_id, self.target.pk)
