"""The migration bridge's states and admission (ADR-0061 P2.5).

A bridge is pending, then active, then finishing the retained source removal, then torn down. It can
fail before teardown, and a bridge that is not torn down refuses a new move for the same account.
"""

from __future__ import annotations

from django.db import IntegrityError, transaction
from django_fsm import ConcurrentTransition, TransitionNotAllowed

from apps.provisioning.virtualmin_migration_models import MigrationBridge, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class BridgeCase(MigrationTestBase):
    def _bridge(self) -> tuple[MigrationBridge, VirtualminMigration]:
        migration = self._start()
        bridge = MigrationBridge.objects.create(
            migration=migration,
            source_server=self.server,
            target_server=self.target,
            domain=self.account.domain,
        )
        return bridge, migration


class BridgeStateTests(BridgeCase):
    def test_the_bridge_follows_pending_active_removing_source_torn_down(self) -> None:
        bridge, _ = self._bridge()
        self.assertEqual(bridge.status, "pending")

        bridge.activate()
        bridge.save()
        self.assertEqual(bridge.status, "active")
        self.assertIsNotNone(bridge.activated_at)

        bridge.start_removing_source()
        bridge.save()
        self.assertEqual(bridge.status, "removing_source")

        bridge.tear_down()
        bridge.save()
        bridge.refresh_from_db()
        self.assertEqual(bridge.status, "torn_down")
        self.assertIsNotNone(bridge.torn_down_at)

    def test_an_out_of_order_transition_is_refused_without_changing_the_row(self) -> None:
        bridge, _ = self._bridge()

        with self.assertRaises(TransitionNotAllowed):
            bridge.tear_down()

        self.assertEqual(MigrationBridge.objects.get(pk=bridge.pk).status, "pending")

    def test_a_bridge_can_fail_from_every_state_before_teardown_and_is_then_terminal(self) -> None:
        stages: dict[str, tuple[str, ...]] = {
            "pending": (),
            "active": ("activate",),
            "removing_source": ("activate", "start_removing_source"),
        }
        for stage, steps in stages.items():
            with self.subTest(stage=stage), transaction.atomic():
                bridge, _ = self._bridge()
                for step in steps:
                    getattr(bridge, step)()
                    bridge.save()
                bridge.fail()
                bridge.save()
                bridge.refresh_from_db()
                self.assertEqual(bridge.status, "failed")
                with self.assertRaises(TransitionNotAllowed):
                    bridge.activate()
                transaction.set_rollback(True)

    def test_a_stale_instance_cannot_save_a_competing_transition(self) -> None:
        bridge, _ = self._bridge()
        first = MigrationBridge.objects.get(pk=bridge.pk)
        stale = MigrationBridge.objects.get(pk=bridge.pk)
        first.activate()
        first.save()

        stale.activate()
        with self.assertRaises(ConcurrentTransition):
            stale.save()

    def test_one_bridge_per_migration(self) -> None:
        _bridge, migration = self._bridge()

        with self.assertRaises(IntegrityError), transaction.atomic():
            MigrationBridge.objects.create(
                migration=migration,
                source_server=self.server,
                target_server=self.target,
                domain=self.account.domain,
            )


class BridgeAdmissionTests(BridgeCase):
    def _finished_bridge(self, state: str) -> None:
        bridge, migration = self._bridge()
        if state != "pending":
            if state == "failed":
                bridge.fail()
            else:
                bridge.activate()
                if state in {"removing_source", "torn_down"}:
                    bridge.start_removing_source()
                if state == "torn_down":
                    bridge.tear_down()
        bridge.save()
        # The move that owned the bridge is over; only the bridge itself can still block a new one.
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="completed")

    def test_a_bridge_that_is_not_torn_down_refuses_a_new_move(self) -> None:
        for state in ("pending", "active", "removing_source", "failed"):
            with self.subTest(state=state), transaction.atomic():
                self._finished_bridge(state)

                result = VirtualminMigrationService().start_migration(
                    self.account, self.target, initiated_by=None, enqueue=False
                )

                self.assertTrue(result.is_err(), result)
                self.assertIn("bridge", result.unwrap_err())
                transaction.set_rollback(True)

    def test_a_torn_down_bridge_does_not_block_a_new_move(self) -> None:
        self._finished_bridge("torn_down")

        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=None, enqueue=False
        )

        self.assertTrue(result.is_ok(), result)
