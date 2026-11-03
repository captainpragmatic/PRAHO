"""Real node-policy claims and public backup admission wait on the same server."""

from threading import Event

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import TransactionTestCase, override_settings

from apps.provisioning.hosting_node_execution import claim_hosting_operation, record_hosting_inspection
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_security import connection_identity
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from tests.common.postgres_locking import backend_pid, database_worker, wait_for_blocker
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@override_settings(
    Q_CLUSTER={"name": "hosting-policy-admission", "orm": "default", "retry": 100000}, DISABLE_AUDIT_SIGNALS=True
)
class HostingNodeAdmissionTests(MaintenanceAdmissionFixture, TransactionTestCase):
    def setUp(self):
        super().setUp()
        if connection.vendor != "postgresql":
            self.skipTest("Independent PostgreSQL row-lock proof is required")
        self.inventory = {"identity": connection_identity(self.node), "helper_bundle_digest": "a" * 64}
        self.review = record_hosting_inspection(self.node, self.inventory)

    def test_waited_public_backup_refuses_new_policy_claim_without_publishing_job(self):
        writer = backend_pid()
        start = Event()

        def admit_backup():
            assert start.wait(10)
            return VirtualminBackupManagementService(self.node).create_backup_job(self.account)

        with database_worker(admit_backup) as (pid, pending):
            with transaction.atomic():
                run = claim_hosting_operation(
                    self.review, self.inventory, self.actor, "prepare_helpers", "Owned helper release"
                )
                start.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_virtualmin_servers")
            result = pending.result(timeout=30)
        self.assertTrue(result.is_err(), result)
        self.assertIn("hosting-policy", result.unwrap_err())
        self.assertEqual(NodeHostingPolicy.objects.get(server=self.node).operation, run.pk)
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_waited_policy_claim_refuses_committed_public_backup(self):
        writer = backend_pid()
        start = Event()

        def claim_policy():
            assert start.wait(10)
            try:
                claim_hosting_operation(
                    self.review, self.inventory, self.actor, "prepare_helpers", "Owned helper release"
                )
            except ValidationError as error:
                return str(error)
            return None

        with database_worker(claim_policy) as (pid, pending):
            with transaction.atomic():
                backup = VirtualminBackupManagementService(self.node).create_backup_job(self.account)
                self.assertTrue(backup.is_ok(), backup)
                start.set()
                wait_for_blocker(pid, writer, pending, table="provisioning_virtualmin_servers")
            refusal = pending.result(timeout=30)
        self.assertIsNotNone(refusal)
        self.assertIn("hosting-account operation", refusal)
        self.assertFalse(NodeHostingPolicy.objects.filter(server=self.node).exists())
        self.assertEqual(VirtualminProvisioningJob.objects.filter(status="pending").count(), 1)
