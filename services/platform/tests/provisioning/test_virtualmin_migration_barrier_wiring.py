"""Wiring the node write barrier into a cutover migration (ADR-0061 P2.4).

A cutover migration records the barrier's evidence before the fence, applies and verifies it, and
compensates by releasing exactly that record. A legacy migration keeps the plain disable-domain
quiesce. Cancelling a drain mid-flight requests compensation instead of refusing; a migration parked
for review still needs an operator.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.utils import timezone

from apps.common.types import Ok
from apps.provisioning.migration_barrier import BarrierStep
from apps.provisioning.virtualmin_drain_service import NodeDrainService
from apps.provisioning.virtualmin_migration_models import NodeDrain, VirtualminMigration
from apps.provisioning.virtualmin_migration_service import (
    RESUME_POLICY,
    MigrationLeaseLostError,
    VirtualminMigrationService,
)
from apps.provisioning.virtualmin_models import VirtualminServer
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase

DOMAIN = "customer.example.com"
TOKEN = "11111111-1111-1111-1111-111111111111"

RECORD = {
    "has_crontab": True,
    "crontab_sha": "a" * 64,
    "active_sha": "b" * 64,
    "enabled": [{"name": DOMAIN, "enabled": True}],
    "databases": ["customer_db"],
    "accounts": [
        {
            "user": "customer",
            "host": "localhost",
            "locked": False,
            "plugin": "",
            "auth_sha": "c" * 64,
            "grants_sha": "d" * 64,
        }
    ],
}


def _ok(action: str, reason: str, payload: dict | None = None) -> BarrierStep:
    return BarrierStep(outcome="ok", reason=reason, payload={**(payload or {}), "action": action})


class BarrierCase(MigrationTestBase):
    def _held(self, status: str, **fields: object) -> tuple[VirtualminMigration, object]:
        migration = self._start()
        token = uuid4()
        VirtualminMigration.objects.filter(pk=migration.pk).update(
            status=status, lease_token=token, worker_lease_expires_at=timezone.now() + timedelta(hours=1), **fields
        )
        migration.refresh_from_db()
        return migration, token

    def _cutover(self, status: str = "quiescing") -> tuple[VirtualminMigration, object]:
        return self._held(
            status,
            contract="cutover",
            pre_migration_snapshot={
                "domain": DOMAIN,
                "status": "active",
                "remote": {"domain": DOMAIN, "enabled": True, "username": "customer", "attributes": {"ID": "42"}},
            },
        )


class RecordAndApplyTests(BarrierCase):
    def test_a_cutover_records_applies_and_verifies_the_barrier_in_that_order(self) -> None:
        migration, token = self._cutover()
        calls: list[str] = []

        def run(_server: VirtualminServer, variables: dict) -> object:
            action = variables["barrier_action"]
            calls.append(action)
            return Ok(_ok(action, "recorded" if action == "record" else "applied", RECORD if action == "record" else None))

        with patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=run):
            VirtualminMigrationService()._quiesce(migration, token)

        self.assertEqual(calls, ["record", "apply", "verify"])
        migration.refresh_from_db()
        self.assertEqual(migration.status, "backing_up")
        self.assertEqual(migration.barrier_state["record"]["active_sha"], "b" * 64)
        self.assertIsNotNone(migration.source_disabled_at)

    def test_barrier_evidence_cannot_be_written_after_the_lease_moves(self) -> None:
        migration, _token = self._cutover()
        stale = uuid4()

        def run(_server: VirtualminServer, variables: dict) -> object:
            action = variables["barrier_action"]
            return Ok(_ok(action, "ok", RECORD if action == "record" else None))

        with (
            patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=run),
            self.assertRaises(MigrationLeaseLostError),
        ):
            VirtualminMigrationService()._barrier_quiesce(migration, stale)

        migration.refresh_from_db()
        self.assertEqual(migration.barrier_state, {})

    def test_a_recorded_barrier_is_persisted_before_the_fence_is_applied(self) -> None:
        migration, token = self._cutover()

        def run(_server: VirtualminServer, variables: dict) -> object:
            if variables["barrier_action"] == "apply":
                stored = VirtualminMigration.objects.get(pk=migration.pk).barrier_state
                self.assertEqual(stored["record"]["databases"], ["customer_db"], "the record must exist before apply")
            action = variables["barrier_action"]
            return Ok(_ok(action, "ok", RECORD if action == "record" else None))

        with patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=run):
            VirtualminMigrationService()._quiesce(migration, token)

    def test_a_refused_barrier_compensates_instead_of_backing_up(self) -> None:
        migration, token = self._cutover()

        with patch(
            "apps.provisioning.virtualmin_migration_service.run_barrier",
            return_value=Ok(BarrierStep(outcome="refused", reason="mail_feature", payload={})),
        ):
            VirtualminMigrationService()._quiesce(migration, token)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")
        self.assertIsNone(migration.source_disabled_at)

    def test_a_legacy_migration_quiesces_without_the_barrier(self) -> None:
        migration, token = self._held("quiescing", contract="legacy")

        with patch(
            "apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=AssertionError("barrier")
        ):
            VirtualminMigrationService()._quiesce(migration, token)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "backing_up")
        self.assertIn("disable-domain", self._programs("source"))


class CompensationTests(BarrierCase):
    def _with_record(self) -> tuple[VirtualminMigration, object]:
        migration, token = self._held(
            "quiescing",
            contract="cutover",
            barrier_state={"record": RECORD, "token": TOKEN},
            pre_migration_snapshot={
                "domain": DOMAIN,
                "status": "active",
                "remote": {"domain": DOMAIN, "enabled": True, "username": "customer", "attributes": {"ID": "42"}},
            },
        )
        return migration, token

    def test_compensation_releases_the_barrier_from_the_persisted_record(self) -> None:
        migration, token = self._with_record()
        seen: dict[str, str] = {}

        def run(_server: VirtualminServer, variables: dict) -> object:
            seen.update(
                {
                    "action": variables["barrier_action"],
                    "previous": variables["barrier_previous_token"],
                    "accounts": variables["barrier_accounts"],
                }
            )
            return Ok(_ok("release", "released"))

        with patch("apps.provisioning.virtualmin_migration_service.run_barrier", side_effect=run):
            VirtualminMigrationService()._rollback(migration, token, target_delete_allowed=False)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")
        self.assertEqual(seen["action"], "release")
        self.assertEqual(seen["previous"], TOKEN)
        self.assertTrue(seen["accounts"])

    def test_a_release_that_does_not_hold_parks_for_review(self) -> None:
        migration, token = self._with_record()

        with patch(
            "apps.provisioning.virtualmin_migration_service.run_barrier",
            return_value=Ok(BarrierStep(outcome="failed", reason="release_failed", payload={})),
        ):
            VirtualminMigrationService()._rollback(migration, token, target_delete_allowed=False)

        migration.refresh_from_db()
        self.assertEqual((migration.status, migration.parked_phase), ("compensating", "compensating"))
        self.assertIn("Barrier release not confirmed", migration.error_detail)


class CancelTests(BarrierCase):
    def _drain(self, migration: VirtualminMigration) -> NodeDrain:
        drain = NodeDrain.objects.create(server=self.server, status="running", accounts_total=1)
        NodeDrain.objects.filter(pk=drain.pk).update(current_migration=migration)
        VirtualminServer.objects.filter(pk=self.server.pk).update(is_draining=True)
        drain.refresh_from_db()
        return drain

    def test_cancelling_a_drain_mid_migration_requests_compensation(self) -> None:
        migration, _ = self._held("backing_up", contract="cutover")
        drain = self._drain(migration)

        result = NodeDrainService.cancel_drain(drain)

        self.assertTrue(result.is_ok(), result)
        migration.refresh_from_db()
        drain.refresh_from_db()
        self.assertTrue(migration.cancel_requested)
        self.assertTrue(drain.cancel_requested)
        self.server.refresh_from_db()
        self.assertTrue(self.server.is_draining, "the node is not re-admitted while the account is still there")

    def test_a_migration_parked_for_review_still_needs_an_operator(self) -> None:
        migration, _ = self._held("needs_review", contract="cutover")
        drain = self._drain(migration)

        result = NodeDrainService.cancel_drain(drain)

        self.assertTrue(result.is_err())
        self.assertIn("in-flight migration", result.unwrap_err())

    def test_a_cancelled_migration_stops_before_the_next_step(self) -> None:
        migration, token = self._held("quiescing", contract="legacy", cancel_requested=True)

        VirtualminMigrationService().execute(migration, token)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")

    def test_a_cancelled_cutover_restores_the_ttl_and_releases_the_barrier(self) -> None:
        migration, token = self._held(
            "quiescing",
            contract="cutover",
            cancel_requested=True,
            barrier_state={"record": RECORD, "token": TOKEN},
            pre_migration_snapshot={
                "domain": DOMAIN,
                "status": "active",
                "remote": {"domain": DOMAIN, "enabled": True, "username": "customer", "attributes": {"ID": "42"}},
            },
        )

        with patch(
            "apps.provisioning.virtualmin_migration_service.run_barrier", return_value=Ok(_ok("release", "released"))
        ):
            VirtualminMigrationService().execute(migration, token)

        migration.refresh_from_db()
        self.assertEqual(migration.status, "rolled_back")


class ResumeTests(MigrationTestBase):
    def test_lowering_the_ttl_is_a_continue_not_a_review(self) -> None:
        self.assertEqual(RESUME_POLICY["lowering_ttl"], "continue")
