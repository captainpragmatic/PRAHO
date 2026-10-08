"""Coverage additions for provisioning signal effects using the real ORM broker."""

from __future__ import annotations

from typing import cast

from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.audit.models import AuditEvent
from apps.provisioning.models import ProvisioningTask, Service, ServiceGroup, ServicePlanPrice
from apps.provisioning.security_utils import SecureTaskParameters
from apps.provisioning.signals import _trigger_automatic_virtualmin_provisioning
from apps.provisioning.virtualmin_models import VirtualminAccount
from apps.provisioning.virtualmin_tasks import reconcile_virtualmin_service_state
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class ProvisioningSupportSignalTests(VirtualminTaskTestBase):
    def reconciliation_packages(self) -> list[dict[str, object]]:
        packages = [cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()]
        return [
            package
            for package in packages
            if package["func"] == "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state"
        ]

    def test_service_transition_persists_audit_and_signed_payload_after_commit(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            self.service.suspend("Support maintenance")
            self.service.save(update_fields=["status", "suspended_at", "suspension_reason"])
            self.assertEqual(self.reconciliation_packages(), [])
        self.assertEqual(Service.objects.get(pk=self.service.pk).status, "suspended")
        packages = self.reconciliation_packages()
        self.assertEqual(len(packages), 1)
        self.assertEqual(packages[0]["args"], (str(self.service.pk),))
        event = AuditEvent.objects.get(action="service_status_changed", object_id=str(self.service.pk))
        self.assertEqual(event.new_values, {"status": "suspended"})
        self.assertTrue(event.metadata["requires_billing_update"])
        self.assertEqual(event.metadata["customer_id"], str(self.customer.pk))

    def test_raw_service_save_keeps_fixture_state_without_enqueuing_reconciliation(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            self.service.suspend("Imported fixture")
            self.service.save_base(raw=True, update_fields=["status", "suspended_at", "suspension_reason"])
        self.assertEqual(Service.objects.get(pk=self.service.pk).status, "suspended")
        self.assertEqual(self.reconciliation_packages(), [])

    def test_task_update_records_retry_state_in_persisted_audit(self) -> None:
        task = ProvisioningTask.objects.create(service=self.service, task_type="backup_service")
        task.status = "failed"
        task.retry_count = 2
        task.save(update_fields=["status", "retry_count"])
        saved = ProvisioningTask.objects.get(pk=task.pk)
        self.assertEqual(saved.status, "failed")
        self.assertEqual(saved.retry_count, 2)
        event = AuditEvent.objects.get(action="provisioning_task_updated", object_id=str(task.pk))
        self.assertEqual(event.new_values["retry_count"], 2)
        self.assertEqual(event.new_values["status"], "failed")
        self.assertEqual(event.metadata["model"], "ProvisioningTask")

    def test_retail_price_update_audits_currency_and_exact_cents(self) -> None:
        price, _ = ServicePlanPrice.objects.update_or_create(
            service_plan=self.plan, currency=self.currency, defaults={"monthly_price_cents": 1234, "setup_cents": 567}
        )
        previous_events = set(AuditEvent.objects.values_list("pk", flat=True))
        price.monthly_price_cents = 2345
        price.save(update_fields=["monthly_price_cents"])
        event = AuditEvent.objects.exclude(pk__in=previous_events).get(
            action="update", content_type__model="serviceplanprice", object_id=str(price.pk)
        )
        self.assertEqual(event.new_values["currency"], "RON")
        self.assertEqual(event.new_values["monthly_price_cents"], 2345)
        self.assertEqual(event.new_values["setup_cents"], 567)
        self.assertEqual(ServicePlanPrice.objects.get(pk=price.pk).monthly_price_cents, 2345)

    def test_disabled_audit_allows_task_creation_and_update_without_events(self) -> None:
        with self.settings(DISABLE_AUDIT_SIGNALS=True):
            task = ProvisioningTask.objects.create(service=self.service, task_type="backup_service")
            task.retry_count = 1
            task.save(update_fields=["retry_count"])
        self.assertEqual(ProvisioningTask.objects.get(pk=task.pk).retry_count, 1)
        self.assertFalse(
            AuditEvent.objects.filter(
                action__in=["provisioning_task_created", "provisioning_task_updated"], object_id=str(task.pk)
            ).exists()
        )

    def test_group_deletion_audits_its_final_state(self) -> None:
        group = ServiceGroup.objects.create(customer=self.customer, name="Support bundle", group_type="bundle")
        group_id = group.pk
        group.delete()
        self.assertFalse(ServiceGroup.objects.filter(pk=group_id).exists())
        event = AuditEvent.objects.get(action="service_group_deleted", object_id=str(group_id))
        self.assertEqual(event.old_values["name"], "Support bundle")
        self.assertEqual(event.old_values["customer_id"], str(self.customer.pk))

    def test_existing_account_blocks_a_racing_automatic_creation(self) -> None:
        Service.objects.filter(pk=self.service.pk).update(domain="tenant.example.com")
        self.service = Service.objects.get(pk=self.service.pk)
        self.account.domain = self.service.domain
        self.account.save(update_fields=["domain"])
        queued_before = OrmQ.objects.count()
        _trigger_automatic_virtualmin_provisioning(self.service)
        self.assertEqual(list(VirtualminAccount.objects.filter(service=self.service)), [self.account])
        self.assertEqual(OrmQ.objects.count(), queued_before)
        self.assertFalse(
            AuditEvent.objects.filter(
                action="virtualmin_auto_provisioning_scheduled", object_id=str(self.service.pk)
            ).exists()
        )
        self.account.delete()
        service = Service.objects.get(pk=self.service.pk)
        with self.captureOnCommitCallbacks(execute=True):
            _trigger_automatic_virtualmin_provisioning(service)
        packages = [cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()]
        provisioning = [
            package
            for package in packages
            if package["func"] == "apps.provisioning.virtualmin_tasks.provision_virtualmin_account"
        ]
        self.assertEqual(len(provisioning), 1)
        secure = cast("tuple[SecureTaskParameters, ...]", provisioning[0]["args"])[0]
        self.assertEqual(secure.decrypt()["domain"], "tenant.example.com")
        self.assertTrue(
            AuditEvent.objects.filter(
                action="virtualmin_auto_provisioning_scheduled", object_id=str(service.pk)
            ).exists()
        )

    def test_nonhosting_service_and_missing_domain_do_not_enqueue_automatic_creation(self) -> None:
        self.account.delete()
        queued_before = OrmQ.objects.count()
        self.plan.plan_type = "domain"
        self.plan.save(update_fields=["plan_type"])
        self.assertFalse(self.service.requires_hosting_account())
        reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertFalse(VirtualminAccount.objects.filter(service=self.service).exists())
        self.assertEqual(OrmQ.objects.count(), queued_before)
        self.plan.plan_type = "shared_hosting"
        self.plan.save(update_fields=["plan_type"])
        self.service.domain = ""
        self.service.save(update_fields=["domain"])
        self.assertFalse(self.service.requires_hosting_account())
        reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertEqual(Service.objects.get(pk=self.service.pk).domain, "")
        self.assertFalse(VirtualminAccount.objects.filter(service=self.service).exists())
        self.assertEqual(OrmQ.objects.count(), queued_before)
