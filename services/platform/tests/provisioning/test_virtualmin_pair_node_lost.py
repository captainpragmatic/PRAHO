"""A pair restore parked on a node that is gone can be released without the node, but only when it is gone.

Like a chain job, a pair restore in attention is normally released by asking the node to lift its
barrier ("Confirm stopped"). A failed or decommissioned node cannot answer, so the operator may declare it
lost: the job fails, its token is rotated so a late runner can publish nothing, the chain is discarded, and
the decision is audited. Any other node state still needs the node to confirm.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import patch

from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.provisioning import virtualmin_pair_restore as pair
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_backup_service import VirtualminBackupService
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.users.models import User
from tests.provisioning.test_virtualmin_account_exclusion import ExclusionCase
from tests.provisioning.test_virtualmin_chain_interruption import DOMAIN_ID
from tests.provisioning.test_virtualmin_chain_state import ChainFixtures
from tests.provisioning.test_virtualmin_pair_restore import node_result

ARCHIVES = ["virtualmin_backup_" + "a" * 32 + ".tar.gz", "virtualmin_backup_" + "b" * 32 + ".tar.gz"]


class PairNodeLostTests(ChainFixtures, ExclusionCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.staff = User.objects.create_user(
            email="pair-lost@example.com", password="pair-lost-test-password", staff_role="admin"
        )
        self.client.force_login(self.staff)
        VirtualminAccount.objects.filter(pk=self.account.pk).update(
            status="suspended", status_message="Pair restore in progress", chain_epoch=3
        )
        self.token = uuid.uuid4()
        self.job = VirtualminProvisioningJob.objects.create(
            operation="restore_domain",
            account=self.account,
            server=self.server,
            status="attention",
            execution_token=self.token,
            parameters={
                "restore_mode": "pair",
                "pair_token": str(uuid.uuid4()),
                "virtualmin_domain_id": DOMAIN_ID,
                "pair_node_step": "dispatching",
                "pair_archives": ARCHIVES,
            },
        )
        self.url = reverse("provisioning:virtualmin_job_node_lost", args=[self.job.pk])
        self.page = reverse("provisioning:virtualmin_job_status", args=[self.job.pk])

    def declare_lost(self) -> Any:
        with patch.object(VirtualminBackupService, "remove_staged_archive") as node, patch("django_q.tasks.async_task"):
            response = self.client.post(self.url, {"note": "datacentre fire"})
        node.assert_not_called()  # the request never waits on the node
        self.job.refresh_from_db()
        self.account.refresh_from_db()
        return response

    def test_a_node_that_is_still_usable_cannot_be_declared_lost(self) -> None:
        for server_status in ("active", "maintenance", "disabled"):
            with self.subTest(server_status=server_status):
                VirtualminServer.objects.filter(pk=self.server.pk).update(status=server_status)
                self.declare_lost()
                self.assertEqual(self.job.status, "attention")
                self.assertEqual(self.job.execution_token, self.token)
                self.assertTrue(account_has_active_operation(self.account))

    def test_a_failed_server_releases_the_job_and_rotates_its_token(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        self.declare_lost()
        self.assertEqual(self.job.status, "failed")
        self.assertIn("Node lost", self.job.status_message)
        self.assertIn("pair-lost@example.com", self.job.status_message)
        self.assertNotEqual(self.job.execution_token, self.token)
        self.assertFalse(account_has_active_operation(self.account))
        self.assertEqual(self.account.chain_epoch, 4, "the chain is discarded and the epoch moves on")
        self.assertIsNone(self.account.chain_base)

    def test_the_account_no_longer_claims_a_restore_is_in_progress(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        self.declare_lost()
        self.assertEqual(self.account.status, "suspended", "reconcile, not this action, decides when it is enabled")
        self.assertNotIn("in progress", self.account.status_message)
        self.assertIn("node", self.account.status_message.lower())

    def test_a_destroyed_deployment_counts_as_decommissioned(self) -> None:
        from apps.infrastructure.models import NodeDeployment  # noqa: PLC0415

        self.deployment("completed")
        for status, allowed in (("completed", False), ("destroying", True), ("destroyed", True)):
            with self.subTest(deployment=status):
                NodeDeployment.objects.update(status=status)
                self.server.refresh_from_db()
                self.declare_lost()
                self.assertEqual(self.job.status, "failed" if allowed else "attention")
                self.assertEqual(self.job.execution_token != self.token, allowed, "only a released job loses its token")
                VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(status="attention", execution_token=self.token)

    def test_a_late_runner_of_a_lost_pair_restore_can_finish_nothing(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        self.declare_lost()
        self.assertFalse(VirtualminProvisioningJob.owns_execution(self.job.pk, self.token))
        self.assertEqual(VirtualminProvisioningJob.finish_execution(self.job.pk, self.token, "completed", ""), 0)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "failed")

    def test_the_resolution_is_audited_with_who_and_why(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        self.declare_lost()
        event = AuditEvent.objects.get(action="virtualmin_provisioning_job_failed", object_id=str(self.job.pk))
        self.assertEqual(event.user_id, self.staff.pk, "the staff member is the actor")
        self.assertIn("datacentre fire", event.new_values["status_message"])
        self.assertIn("Node lost", event.new_values["status_message"])

    def test_the_node_is_released_in_the_background_unless_the_deployment_is_destroyed(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        with patch("django_q.tasks.async_task") as queued:
            self.client.post(self.url)
        self.assertEqual(
            [call.args for call in queued.call_args_list],
            [("apps.provisioning.virtualmin_tasks.release_lost_pair_node", str(self.job.pk))],
        )
        VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(status="attention")
        self.deployment("destroyed")
        with patch("django_q.tasks.async_task") as queued:
            self.client.post(self.url)
        queued.assert_not_called()

    def test_the_cleanup_task_removes_every_staged_archive(self) -> None:
        from apps.common.types import Err, Ok  # noqa: PLC0415

        VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(status="failed")
        removed: list[str] = []
        with (
            patch.object(pair, "run_pair_step", return_value=node_result("released", "barrier_removed", ran=False, checkpoints=())),
            patch.object(
                VirtualminBackupService,
                "remove_staged_archive",
                autospec=True,
                side_effect=lambda service, name: removed.append(name) or Ok(None),
            ),
        ):
            self.assertTrue(virtualmin_tasks.remove_pair_job_archives(str(self.job.pk))["success"])
        self.assertEqual(removed, ARCHIVES)
        with (
            patch.object(pair, "run_pair_step", return_value=node_result("released", "barrier_removed", ran=False, checkpoints=())),
            patch.object(VirtualminBackupService, "remove_staged_archive", return_value=Err("unreachable")),
        ):
            outcome = virtualmin_tasks.remove_pair_job_archives(str(self.job.pk))
        self.assertFalse(outcome["success"])
        self.job.refresh_from_db()
        self.assertIn("cleanup failed", self.job.status_message)

    def test_a_plain_restore_still_cannot_be_resolved_this_way(self) -> None:
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(parameters={"backup_id": "b-1"})
        self.declare_lost()
        self.assertEqual(self.job.status, "attention")

    def test_the_status_page_offers_node_lost_only_when_it_is_allowed(self) -> None:
        before = self.client.get(self.page).content.decode()
        self.assertIn(reverse("provisioning:virtualmin_job_resolve", args=[self.job.pk]), before)
        self.assertNotIn(self.url, before)
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        after = self.client.get(self.page).content.decode()
        self.assertIn(self.url, after)


class LostNodeReleaseTests(ChainFixtures, ExclusionCase):
    """A node declared lost that is still reachable is released before anything else touches its staging."""

    def setUp(self) -> None:
        super().setUp()
        self.account = self._account()
        self.staff = User.objects.create_user(
            email="pair-lost-release@example.com", password="pair-lost-test-password", staff_role="admin"
        )
        self.client.force_login(self.staff)
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="suspended", chain_epoch=3)
        self.job = VirtualminProvisioningJob.objects.create(
            operation="restore_domain",
            account=self.account,
            server=self.server,
            status="attention",
            execution_token=uuid.uuid4(),
            parameters={
                "restore_mode": "pair",
                "pair_token": str(uuid.uuid4()),
                "virtualmin_domain_id": DOMAIN_ID,
                "pair_node_step": "dispatching",
                "pair_archives": ARCHIVES,
            },
        )
        self.url = reverse("provisioning:virtualmin_job_node_lost", args=[self.job.pk])
        VirtualminServer.objects.filter(pk=self.server.pk).update(status="failed")
        VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(status="failed")
        self.events: list[str] = []
        self.reconciles: list[str] = []
        self.scheduled: list[tuple[Any, ...]] = []
        for target, effect in (
            ("django_q.tasks.schedule", lambda *args, **kwargs: self.scheduled.append((args, kwargs))),
            (
                "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async",
                self.reconciles.append,
            ),
        ):
            patcher = patch(target, side_effect=effect)
            patcher.start()
            self.addCleanup(patcher.stop)

    def release_outcome(self, outcome: Any) -> Any:
        def run(server: Any, variables: dict[str, Any], **kwargs: Any) -> Any:
            self.events.append(f"node {variables['pair_action']}")
            return outcome

        return patch.object(pair, "run_pair_step", side_effect=run)

    def removal(self) -> Any:
        from apps.common.types import Ok  # noqa: PLC0415

        return patch.object(
            VirtualminBackupService,
            "remove_staged_archive",
            side_effect=lambda name: self.events.append(f"remove {name[18:20]}") or Ok(None),
        )

    def test_the_release_runs_before_the_archives_are_removed_and_queues_a_reconcile(self) -> None:
        released = node_result("released", "barrier_removed", ran=False, checkpoints=())
        with self.release_outcome(released), self.removal():
            outcome = virtualmin_tasks.release_lost_pair_node(str(self.job.pk))
        self.assertTrue(outcome["success"] and outcome["released"], outcome)
        self.assertEqual(self.events, ["node release", "remove aa", "remove bb"], "lock, cancel marker, barrier, then cleanup")
        self.assertEqual(self.reconciles, [str(self.account.service_id)])
        self.assertEqual(self.scheduled, [])

    def test_an_unreachable_node_keeps_its_archives_and_retries_later(self) -> None:
        from apps.common.types import Err, Retriability  # noqa: PLC0415

        with self.release_outcome(Err("unreachable", retriability=Retriability.UNKNOWN)), self.removal():
            outcome = virtualmin_tasks.release_lost_pair_node(str(self.job.pk))
        self.assertFalse(outcome["success"])
        self.assertEqual(self.events, ["node release"], "nothing is removed from a node that was not released")
        ((args, kwargs),) = self.scheduled
        self.assertEqual(args, ("apps.provisioning.virtualmin_tasks.release_lost_pair_node", str(self.job.pk), 2))
        self.assertEqual(kwargs["schedule_type"], "O")
        self.assertEqual(self.reconciles, [])

    def test_the_retries_stop_after_a_day_and_raise_an_alert(self) -> None:
        from apps.common.types import Err, Retriability  # noqa: PLC0415

        with self.release_outcome(Err("unreachable", retriability=Retriability.UNKNOWN)):
            outcome = virtualmin_tasks.release_lost_pair_node(str(self.job.pk), virtualmin_tasks.PAIR_RELEASE_MAX_ATTEMPTS)
        self.assertTrue(outcome["abandoned"])
        self.assertEqual(self.scheduled, [])
        self.assertTrue(AuditEvent.objects.filter(action="virtualmin_pair_release_abandoned").exists())

    def test_the_cleanup_task_alone_takes_the_node_lock_first(self) -> None:
        from apps.common.types import Err, Retriability  # noqa: PLC0415

        with self.release_outcome(Err("unreachable", retriability=Retriability.UNKNOWN)), self.removal():
            outcome = virtualmin_tasks.remove_pair_job_archives(str(self.job.pk))
        self.assertFalse(outcome["success"])
        self.assertEqual(self.events, ["node release"])

    def test_declaring_the_node_lost_queues_a_reconcile_at_once(self) -> None:
        VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(
            status="attention",
            parameters={**self.job.parameters, "pair_node_step": "failed", "pair_checkpoints": [{"step": "barrier_up"}]},
        )
        with patch("django_q.tasks.async_task"):
            self.client.post(self.url, {"note": "gone"})
        self.assertEqual(self.reconciles, [str(self.account.service_id)])

    def test_an_account_still_held_stays_disabled_after_node_lost(self) -> None:
        VirtualminProvisioningJob.objects.filter(pk=self.job.pk).update(
            status="attention",
            parameters={
                **self.job.parameters,
                "pair_node_step": "failed",
                "pair_checkpoints": [{"step": "barrier_up"}, {"step": "after_base"}],
                "safety_backup_id": "safety-1",
            },
        )
        with patch("django_q.tasks.async_task"):
            self.client.post(self.url, {"note": "gone"})
        self.account.refresh_from_db()
        self.assertEqual((self.account.restore_hold, self.account.restore_hold_safety_backup_id), ("half_restored", "safety-1"))
        # The reconcile that was queued finds the hold and leaves the account suspended.
        with patch("apps.provisioning.virtualmin_service.VirtualminProvisioningService.unsuspend_account") as unsuspend:
            result = virtualmin_tasks.reconcile_virtualmin_service_state(str(self.account.service_id))
        unsuspend.assert_not_called()
        self.assertEqual(result["action"], "operation_active")
