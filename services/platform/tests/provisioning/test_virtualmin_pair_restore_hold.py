"""A staff-resolved pair restore that had started restoring leaves the domain disabled until staff decide.

"Confirm stopped" releases the barrier, but the domain may be half-restored. Reconcile and the divergence
backstop must not bring it live; only "Re-enable as is" or the completion of the safety backup's restore
clears the hold. A stop before any restore step needs no hold.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.common.types import Ok
from apps.provisioning import virtualmin_pair_restore as pair
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_backup_service import RestoreConfig, VirtualminBackupService
from apps.provisioning.virtualmin_migration_models import account_blocks_reconcile
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.users.models import User
from tests.provisioning.test_virtualmin_pair_restore import (
    BASE_ARCHIVE,
    DIFF_ARCHIVE,
    DOMAIN_ID,
    PairRestoreCase,
    node_result,
)

STOPPED_AFTER_BASE = [{"step": "barrier_up"}, {"step": "after_base"}]


class HoldCase(PairRestoreCase):
    def parked(self, **parameters: Any) -> VirtualminProvisioningJob:
        job = self.admit().unwrap()
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
            status="attention",
            parameters={
                **job.parameters,
                "virtualmin_domain_id": DOMAIN_ID,
                "pair_node_step": "failed",
                "pair_checkpoints": STOPPED_AFTER_BASE,
                "safety_backup_id": "safety-1",
                "pair_archives": [BASE_ARCHIVE, DIFF_ARCHIVE],
                **parameters,
            },
        )
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="suspended")
        job.refresh_from_db()
        return job

    def resolve(self, job: VirtualminProvisioningJob) -> Any:
        released = node_result("released", "barrier_removed", ran=False, checkpoints=())
        with (
            patch.object(pair, "run_pair_step", return_value=released),
            patch.object(VirtualminBackupService, "remove_staged_archive", return_value=Ok(None)),
        ):
            return pair.resolve_pair_job(job, resolved_by="staff@example.com", note="checked")

    def reload(self) -> VirtualminAccount:
        return VirtualminAccount.objects.get(pk=self.account.pk)


class HoldSetTests(HoldCase):
    def test_confirming_stopped_after_a_restore_step_holds_the_account_and_queues_no_reconcile(self) -> None:
        self.assertTrue(self.resolve(self.parked()).is_ok())
        account = self.reload()
        self.assertEqual((account.restore_hold, account.restore_hold_safety_backup_id), ("half_restored", "safety-1"))
        self.assertEqual(account.status, "suspended")
        self.assertEqual(self.reconciles, [], "a routine pass must not bring a half-restored site live")
        self.assertTrue(account_blocks_reconcile(account))

    def test_a_stop_before_any_restore_step_needs_no_hold(self) -> None:
        job = self.parked(pair_checkpoints=[{"step": "barrier_up"}])
        self.assertTrue(self.resolve(job).is_ok())
        self.assertEqual(self.reload().restore_hold, "")
        self.assertEqual(self.reconciles, [str(self.account.service_id)])

    def test_a_result_that_never_arrived_is_treated_as_restored(self) -> None:
        job = self.parked(pair_node_step="dispatching", pair_checkpoints=None)
        self.assertTrue(self.resolve(job).is_ok())
        self.assertEqual(self.reload().restore_hold, "half_restored")

    def test_the_evidence_rule(self) -> None:
        cases = {
            "never dispatched": ({}, False),
            "node refused": ({"pair_node_step": "refused"}, False),
            "barrier only": ({"pair_node_step": "failed", "pair_checkpoints": [{"step": "barrier_up"}]}, False),
            "after base": ({"pair_node_step": "failed", "pair_checkpoints": STOPPED_AFTER_BASE}, True),
            "base restore failed": (
                {"pair_node_step": "failed", "pair_checkpoints": [{"step": "barrier_up"}, {"step": "base_failed"}]},
                True,
            ),
            "dispatched, no result": ({"pair_node_step": "dispatching"}, True),
        }
        for label, (parameters, expected) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(pair.pair_restore_may_have_restored(parameters), expected)


class HoldHonouredTests(HoldCase):
    def setUp(self) -> None:
        super().setUp()
        self.resolve(self.parked())

    def test_reconcile_leaves_the_held_account_alone(self) -> None:
        with patch("apps.provisioning.virtualmin_service.VirtualminProvisioningService.unsuspend_account") as unsuspend:
            result = virtualmin_tasks.reconcile_virtualmin_service_state(str(self.account.service_id))
        self.assertEqual(result["action"], "operation_active")
        unsuspend.assert_not_called()
        self.assertEqual(self.reload().status, "suspended")

    def test_the_divergence_backstop_does_not_requeue_it(self) -> None:
        outcome = virtualmin_tasks.reconcile_divergent_services_task()
        self.assertEqual(outcome["queued"], 0)
        self.assertEqual(self.reconciles, [])

    def test_the_backstop_cap_is_not_spent_on_held_accounts(self) -> None:
        # Another suspended account behind the held one is still found.
        other_service = self._service_for_hold()
        VirtualminAccount.objects.create(
            service=other_service,
            server=self.server,
            domain="other-held.example.com",
            virtualmin_username="otherheld",
            status="suspended",
            praho_customer_id=self.customer.pk,
        )
        outcome = virtualmin_tasks.reconcile_divergent_services_task()
        self.assertEqual(self.reconciles, [str(other_service.pk)])
        self.assertEqual(outcome["queued"], 1)

    def _service_for_hold(self) -> Any:
        from apps.provisioning.models import Service  # noqa: PLC0415

        return Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="other-held.example.com",
            domain="other-held.example.com",
            username="otherheld",
            price=self.service.price,
            status="active",
        )

    def test_the_safety_backup_cannot_be_deleted_while_the_hold_stands(self) -> None:
        reason = VirtualminBackupService._deletion_pin("safety-1", self.reload())
        self.assertIsNotNone(reason)
        self.assertIn("half-restored", str(reason))
        self.assertIsNone(VirtualminBackupService._deletion_pin("some-other-backup", self.reload()))


class HoldReleaseTests(HoldCase):
    def setUp(self) -> None:
        super().setUp()
        self.resolve(self.parked())
        self.staff = User.objects.create_user(email="hold-staff@example.com", password="hold-staff-password", staff_role="admin")
        self.client.force_login(self.staff)

    def test_re_enable_as_is_clears_the_hold_queues_reconcile_and_is_audited(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("provisioning:virtualmin_account_hold_reenable", args=[self.account.pk]))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.reload().restore_hold, "")
        self.assertEqual(self.reconciles, [str(self.account.service_id)])
        self.assertTrue(
            AuditEvent.objects.filter(action="virtualmin_restore_hold_decision", description__contains="re_enabled_as_is").exists()
        )

    def test_the_decisions_are_post_only(self) -> None:
        for name in ("virtualmin_account_hold_reenable", "virtualmin_account_hold_restore_safety"):
            with self.subTest(name=name):
                url = reverse(f"provisioning:{name}", args=[self.account.pk])
                self.assertEqual(self.client.get(url).status_code, 405)
        self.assertEqual(self.reload().restore_hold, "half_restored")

    def test_restoring_the_safety_backup_keeps_the_hold_until_that_restore_completes(self) -> None:
        job = VirtualminProvisioningJob.objects.create(
            operation="restore_domain",
            account=self.account,
            server=self.server,
            status="pending",
            parameters={"backup_id": "safety-1", "force_restore": True},
        )
        with patch.object(VirtualminBackupManagementService, "create_restore_job", return_value=Ok(job)) as create:
            response = self.client.post(reverse("provisioning:virtualmin_account_hold_restore_safety", args=[self.account.pk]))
        self.assertEqual(response.status_code, 302)
        config = create.call_args.kwargs["config"]
        self.assertEqual((config.backup_id, config.force_restore), ("safety-1", True))
        self.assertIsInstance(config, RestoreConfig)
        self.assertEqual(self.reload().restore_hold, "half_restored", "restoring is not finished yet")
        self.assertEqual(self.reconciles, [])
        # The restore completes: the hold ends and reconcile is queued.
        with self.captureOnCommitCallbacks(execute=True):
            virtualmin_tasks._release_hold_after_safety_restore(job, dict(job.parameters))
        self.assertEqual(self.reload().restore_hold, "")
        self.assertEqual(self.reconciles, [str(self.account.service_id)])

    def test_a_restore_of_another_backup_does_not_end_the_hold(self) -> None:
        job = VirtualminProvisioningJob.objects.create(
            operation="restore_domain", account=self.account, server=self.server, status="completed", parameters={"backup_id": "older"}
        )
        virtualmin_tasks._release_hold_after_safety_restore(job, dict(job.parameters))
        self.assertEqual(self.reload().restore_hold, "half_restored")

    def test_a_pair_restore_does_not_end_the_hold(self) -> None:
        job = VirtualminProvisioningJob.objects.create(
            operation="restore_domain",
            account=self.account,
            server=self.server,
            status="completed",
            parameters={"restore_mode": "pair", "backup_id": "safety-1"},
        )
        virtualmin_tasks._release_hold_after_safety_restore(job, dict(job.parameters))
        self.assertEqual(self.reload().restore_hold, "half_restored")

    def test_the_job_page_warns_about_the_half_restored_data_and_names_the_safety_backup(self) -> None:
        job = self.parked()
        page = self.client.get(reverse("provisioning:virtualmin_job_status", args=[job.pk])).content.decode()
        self.assertIn("may be half-restored", page)
        self.assertIn("safety-1", page)

    def test_the_account_page_offers_both_decisions_while_held(self) -> None:
        page = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk])).content.decode()
        self.assertIn(reverse("provisioning:virtualmin_account_hold_reenable", args=[self.account.pk]), page)
        self.assertIn(reverse("provisioning:virtualmin_account_hold_restore_safety", args=[self.account.pk]), page)
        self.assertIn("Restore the safety backup safety-1", page)
