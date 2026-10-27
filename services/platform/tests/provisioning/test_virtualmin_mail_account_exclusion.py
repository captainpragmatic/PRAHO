"""Durable mail intent reserves destructive admission without holding ordinary billing policy."""

from unittest.mock import patch
from uuid import uuid4

from apps.provisioning.account_hostname_models import AccountHostname
from apps.provisioning.account_name_certificates import _name_under_operation
from apps.provisioning.virtualmin_backup_service import RestoreConfig
from apps.provisioning.virtualmin_mail_models import VirtualminMailConfiguration, VirtualminMailOperation
from apps.provisioning.virtualmin_migration_models import account_blocks_reconcile, account_has_active_operation
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService, VirtualminProvisioningService
from tests.provisioning.test_virtualmin_migration_service import MigrationTestBase


class MailOperationExclusionTests(MigrationTestBase):
    def setUp(self):
        super().setUp()
        self.mail = VirtualminMailConfiguration.objects.create(account=self.account)

    def operation(self, status="queued"):
        return VirtualminMailOperation.objects.create(
            configuration=self.mail,
            requested_customer=self.customer,
            requested_by=self.staff,
            submission_id=uuid4(),
            intent="enable",
            target_generation="a" * 64,
            consent_digest="b" * 64,
            confirmed_plan={"version": 1},
            status=status,
        )

    def test_a_later_move_cannot_claim_an_account_with_pending_mail_intent(self):
        operation = self.operation()
        self.events.clear()
        result = VirtualminMigrationService().start_migration(
            self.account, self.target, initiated_by=self.staff, enqueue=False
        )
        self.assertTrue(result.is_err(), "A later move must respect durable mail ownership before native work")
        self.assertEqual(self.events, [])
        self.assertTrue(VirtualminMailOperation.objects.filter(pk=operation.pk, status="queued").exists())

    def test_all_open_mail_attempts_exclude_destructive_admission(self):
        for status in ("queued", "running", "awaiting_dns", "needs_review"):
            with self.subTest(status=status):
                operation = self.operation(status)
                try:
                    self.assertTrue(account_has_active_operation(self.account))
                    self.assertFalse(account_blocks_reconcile(self.account), "Mail intent must not park billing policy")
                finally:
                    operation.delete()

    def test_delete_refuses_mail_ownership_before_dispatch_or_domain_removal(self):
        self.account.protected_from_deletion = False
        self.account.save(update_fields=["protected_from_deletion"])
        operation = self.operation("needs_review")
        self.events.clear()
        result = VirtualminProvisioningService(self.server).delete_account(self.account)
        self.assertTrue(result.is_err(), result)
        self.assertIn("active", result.unwrap_err())
        self.assertEqual(self.events, [])
        self.assertTrue(VirtualminMailOperation.objects.filter(pk=operation.pk).exists())
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "active")

    def test_backup_and_restore_cannot_enqueue_over_waiting_mail_work(self):
        self.operation("awaiting_dns")
        management = VirtualminBackupManagementService(self.server)
        self.events.clear()
        with patch("django_q.tasks.async_task") as enqueue:
            results = (
                management.create_backup_job(self.account),
                management.create_restore_job(self.account, RestoreConfig(backup_id="b-1"), target_server=self.target),
            )
        for result in results:
            self.assertTrue(result.is_err(), result)
            self.assertIn("active", result.unwrap_err())
        enqueue.assert_not_called()
        self.assertEqual(self.events, [])

    def test_terminal_attempts_release_admission(self):
        for status in ("completed", "failed", "cancelled"):
            with self.subTest(status=status):
                self.operation(status)
                self.assertFalse(account_has_active_operation(self.account))

    def test_a_mail_worker_may_ignore_only_its_own_attempt(self):
        operation = self.operation()
        self.assertFalse(account_has_active_operation(self.account, ignore_mail_operation_id=operation.pk))
        self.assertTrue(account_has_active_operation(self.account, ignore_mail_operation_id=uuid4()))

    def test_waiting_mail_intent_does_not_deadlock_its_certificate_prerequisite(self):
        name = AccountHostname.objects.create(
            account=self.account, target_server=self.server, label="mailwait", zone="accounts.example.test"
        )
        for status in ("queued", "awaiting_dns", "running", "needs_review"):
            with self.subTest(status=status):
                operation = self.operation(status)
                try:
                    self.assertEqual(_name_under_operation(name), status in {"running", "needs_review"})
                    self.assertTrue(account_has_active_operation(self.account))
                finally:
                    operation.delete()
