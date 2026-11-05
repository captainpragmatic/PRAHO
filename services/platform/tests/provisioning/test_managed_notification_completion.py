"""Successful managed quota receipts cannot stand in for fresh native mail proof."""

from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone

from apps.common.types import Ok
from apps.provisioning.hosting_limit_execution import freeze_migration_limits
from apps.provisioning.hosting_limit_execution_models import HostingLimitExecution
from apps.provisioning.hosting_node_policy import NOTIFICATION_EMITTERS
from apps.provisioning.hosting_node_policy_models import NodeHostingPolicy
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_gateway import VirtualminGateway
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_security import connection_identity
from apps.provisioning.virtualmin_service import VirtualminAccountCreationData, VirtualminProvisioningService
from tests.mocks.virtualmin_mock import MockVirtualminGateway
from tests.provisioning.test_managed_single_restore_limits import ManagedSingleRestoreFixture


class ManagedNotificationCompletionTests(ManagedSingleRestoreFixture, TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.policy = NodeHostingPolicy.objects.get(server=self.server)
        self.notification_proof = {
            "schema": 1,
            "policy_version": "hosting-node-v1",
            "identity": connection_identity(self.server),
            "installation": self.identity["installation"],
            "emitters": dict.fromkeys(NOTIFICATION_EMITTERS, True),
            "operator_alerts_preserved": True,
            "tenant_mail_preserved": True,
        }
        self.policy.notification_owner = "platform"
        self.policy.notifications_verified_at = timezone.now()
        self.policy.notification_evidence = self.notification_proof
        self.policy.save(update_fields=["notification_owner", "notifications_verified_at", "notification_evidence"])
        self.mail_safe = True
        self.lose_mail_guard = False
        self.inspections = []

    def inspect(self, server, action, request):
        self.assertFalse(connection.in_atomic_block, "Mail inspection must not hold financial/native DB locks")
        self.assertEqual(
            (server.pk, action, request), (self.server.pk, "inspect", {"identity": connection_identity(server)})
        )
        self.inspections.append(server.pk)
        proof = deepcopy(self.notification_proof)
        proof["emitters"]["quota_warnings"] = self.mail_safe
        return {"identity": proof["identity"], "notifications": proof}

    def node_restore(self, server, variables, **kwargs):
        restored = super().node_restore(server, variables, **kwargs)
        if self.lose_mail_guard:
            self.mail_safe = False
        return restored

    def test_managed_restore_retains_attention_when_archive_completion_loses_mail_safety(self):
        self.lose_mail_guard = True
        with patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect):
            job, outcome = self.execute_restore()
        self.assertEqual(outcome["status"], "attention", outcome)
        self.assertEqual(job.status, "attention")
        self.assertEqual(len(self.node_variables), 1)
        self.assertEqual(len(self.quota_requests), 1, "The actual quota child must complete before the mail refusal")
        self.assertEqual(self.inspections, [self.server.pk, self.server.pk])
        self.assertTrue(HostingLimitExecution.objects.filter(job__account=self.account, phase="completed").exists())
        self.assertEqual(self.account.status, "suspended")
        self.assertNotIn("enable-domain", self.api_calls)

    def test_same_managed_restore_completes_with_current_quota_and_mail_evidence(self):
        with patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect):
            job, outcome = self.execute_restore()
        self.assertEqual((outcome["status"], job.status), ("completed", "completed"))
        self.assertEqual(len(self.quota_requests), 1)
        self.assertEqual(self.inspections, [self.server.pk, self.server.pk])
        self.assertEqual(self.account.status, "suspended")

    def public_create(self):
        service = Service.objects.create(
            customer=self.customer,
            service_plan=ServicePlan.objects.get(pk=self.application.target_plan_id),
            currency=self.currency,
            service_name="managed-mail-create.example.test",
            domain="managed-mail-create.example.test",
            username="managedmail",
            price=10,
            status="active",
        )
        gateway = MockVirtualminGateway(server_hostname=self.server.hostname)
        original = gateway.call

        def call(program, params=None, **kwargs):
            result = original(program, params, **kwargs)
            if program == "create-domain" and result.is_ok() and self.lose_mail_guard:
                self.mail_safe = False
            return result

        def probe(execution):
            receipt = self.fresh_receipt(1024)
            receipt["identity"] = {**self.identity, "domain": execution.job.account.domain}
            return receipt

        def apply(server, action, request):
            self.assertEqual(action, "apply")
            receipt = self.fresh_receipt(request["disk_limit_kib"] // 1024, request)
            receipt["identity"] = {**self.identity, **request["identity"]}
            return receipt

        with (
            patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=gateway),
            patch.object(gateway, "call", side_effect=call),
            patch.object(
                gateway,
                "test_connection",
                return_value=Ok({"healthy": True, "data": {"available_disk_mb": 100 * 1024}}),
            ),
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", side_effect=probe),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=apply),
            patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect),
        ):
            result = VirtualminProvisioningService(self.server).create_virtualmin_account(
                VirtualminAccountCreationData(service=service, domain=service.domain, server=self.server)
            )
        account = VirtualminAccount.objects.get(service=service)
        job = VirtualminProvisioningJob.objects.get(account=account, operation="create_domain")
        return result, account, job, gateway

    def test_fresh_managed_create_does_not_activate_when_mail_policy_is_unsafe(self):
        self.lose_mail_guard = True
        result, account, job, gateway = self.public_create()
        self.assertTrue(result.is_err(), result)
        self.assertIn("notification", result.unwrap_err())
        self.assertEqual((account.status, job.status), ("error", "attention"))
        self.assertEqual(self.inspections, [self.server.pk])
        self.assertIsNone(job.execution_token, "Keep the actual initial-create nullable claim")
        self.assertIsNotNone(gateway.domain_state_of(account.domain), "An accepted domain must not be deleted")
        self.assertFalse(gateway.get_calls("delete-domain"))
        self.assertFalse(gateway.get_calls("enable-domain"))
        self.assertTrue(HostingLimitExecution.objects.filter(job__account=account, phase="completed").exists())

    def test_same_fresh_managed_create_completes_without_inventing_a_token(self):
        result, account, job, gateway = self.public_create()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual((account.status, job.status), ("active", "completed"))
        self.assertTrue(account.quota_managed)
        self.assertEqual(self.inspections, [self.server.pk])
        self.assertIsNone(job.execution_token)
        self.assertEqual(len(gateway.get_calls("create-domain")), 1)

    def test_native_owned_managed_create_does_not_invent_a_notification_handover(self):
        self.policy.notification_owner = "native"
        self.policy.save(update_fields=["notification_owner"])
        self.lose_mail_guard = True
        result, account, job, _gateway = self.public_create()
        self.assertTrue(result.is_ok(), result)
        self.assertEqual((account.status, job.status), ("active", "completed"))
        self.assertTrue(account.quota_managed)
        self.assertEqual(self.inspections, [])

    def test_staged_migration_target_cannot_enable_after_quotas_pass_but_mail_fails(self):
        source = VirtualminServer.objects.create(hostname="prior-source.example.test", status="disabled")
        frozen = freeze_migration_limits(self.account)
        self.account.server = source
        self.account.save(update_fields=["server", "updated_at"])
        token = uuid4()
        migration = VirtualminMigration.objects.create(
            account=self.account,
            source_server=source,
            target_server=self.server,
            status="activating",
            lease_token=token,
            worker_lease_expires_at=timezone.now() + timedelta(hours=1),
            pre_migration_snapshot={"status": "active", "hosting_limits": frozen},
        )
        self.mail_safe = False
        commands = []

        def api(gateway, program, params=None, **kwargs):
            commands.append(program)
            raise RuntimeError("A target activation command escaped before fresh mail verification")

        with (
            patch(
                "apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=self.fresh_receipt(1024)
            ),
            patch(
                "apps.provisioning.hosting_limit_transport.run_quota_operation",
                side_effect=lambda server, action, request: self.fresh_receipt(
                    request["disk_limit_kib"] // 1024, request
                ),
            ),
            patch("apps.provisioning.hosting_node_transport.run_node_operation", side_effect=self.inspect),
            patch.object(VirtualminGateway, "call", autospec=True, side_effect=api),
            self.assertRaisesRegex(ValueError, "notification"),
        ):
            VirtualminMigrationService()._activate(migration, token)
        self.assertEqual(commands, [])
        self.assertEqual(self.inspections, [self.server.pk])
        self.assertEqual(VirtualminAccount.objects.get(pk=self.account.pk).server_id, source.pk)
        self.assertEqual(migration.account.server_id, self.server.pk, "Retain the caller's staged target instance")
