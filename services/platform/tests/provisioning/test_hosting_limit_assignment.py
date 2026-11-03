"""Assigned customer allowances survive catalog edits before native provisioning."""

from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

from django.core.exceptions import ValidationError
from django.db import transaction

from apps.audit.models import AuditEvent
from apps.customers.models import Customer
from apps.provisioning.hosting_limit_assignments import request_service_plan_change
from apps.provisioning.hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from apps.provisioning.models import Service, ServicePlan, VirtualminAccount
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.settings.services import SettingsService
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class AssignedHostingLimitsTests(VirtualminTaskTestBase):
    def test_explicit_assignment_pins_stored_defaults_before_later_setting_edits(self) -> None:
        self.assertTrue(SettingsService.update_setting("virtualmin.domain_quota_default_mb", 37).is_ok())
        self.assertTrue(SettingsService.update_setting("virtualmin.bandwidth_quota_default_mb", 53).is_ok())
        submission = uuid4()
        arguments = {
            "service": self.service,
            "target_plan_id": self.plan.pk,
            "expected_revision": 1,
            "submission_id": submission,
            "reason": "Explicit resource assignment using current defaults",
            "authority": {"kind": "staff_resource_override"},
        }
        with transaction.atomic():
            application = request_service_plan_change(**arguments)
        self.assertEqual(application.disk_allowance_mib, 37)
        self.assertEqual(application.bandwidth_allowance_mib, 53)
        self.assertTrue(SettingsService.update_setting("virtualmin.domain_quota_default_mb", 97).is_ok())
        self.assertTrue(SettingsService.update_setting("virtualmin.bandwidth_quota_default_mb", 101).is_ok())
        with transaction.atomic():
            replay = request_service_plan_change(**arguments)
        self.assertEqual(replay.pk, application.pk)
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual(limits.revision, 2)
        self.assertEqual(limits.disk_source, "stored_default")
        self.assertEqual(limits.bandwidth_source, "stored_default")
        VirtualminProvisioningService(self.server)._apply_default_quotas(self.account)
        self.account.refresh_from_db()
        self.assertEqual(self.account.disk_quota_mb, 37)
        self.assertEqual(self.account.effective_disk_quota_mb, 41)
        self.assertEqual(self.account.bandwidth_quota_mb, 53)

    def test_accepted_assignment_history_cannot_be_rewritten(self) -> None:
        with transaction.atomic():
            application = request_service_plan_change(
                service=self.service,
                target_plan_id=self.plan.pk,
                expected_revision=1,
                submission_id=uuid4(),
                reason="Explicit accepted assignment",
                authority={"kind": "staff_resource_override"},
            )
        application.reason = "rewritten history"
        with self.assertRaises(ValidationError):
            application.save(update_fields=["reason"])
        with self.assertRaises(ValidationError):
            HostingLimitApplication.objects.filter(pk=application.pk).update(reason="rewritten history")
        application.refresh_from_db()
        self.assertEqual(application.reason, "Explicit accepted assignment")

    def test_stale_owner_cannot_assign_limits_after_transfer(self) -> None:
        replacement = ServicePlan.objects.create(name="Larger", plan_type="shared_hosting", price_monthly=20)
        other = Customer.objects.create(name="New owner", customer_type="company", status="active")
        Service.objects.filter(pk=self.service.pk).update(customer=other)
        with transaction.atomic(), self.assertRaises(ValidationError):
            request_service_plan_change(
                service=self.service,
                target_plan_id=replacement.pk,
                expected_revision=1,
                submission_id=uuid4(),
                reason="Old authorization",
                authority={"kind": "staff_resource_override"},
            )
        current = Service.objects.get(pk=self.service.pk)
        self.assertEqual(current.customer_id, other.pk)
        self.assertEqual(current.service_plan_id, self.plan.pk)

    def test_returning_to_original_owner_invalidates_old_assignment_revision(self) -> None:
        other = Customer.objects.create(name="Intermediate owner", customer_type="company", status="active")
        Service.objects.filter(pk=self.service.pk).update(customer=other)
        Service.objects.filter(pk=self.service.pk).update(customer=self.customer)
        with transaction.atomic(), self.assertRaises(ValidationError):
            request_service_plan_change(
                service=self.service,
                target_plan_id=self.plan.pk,
                expected_revision=1,
                submission_id=uuid4(),
                reason="Old authorization",
                authority={"kind": "staff_resource_override"},
            )
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).revision, 3)

    def test_assignment_is_idempotent_and_keeps_billing_and_applied_state(self) -> None:
        replacement = ServicePlan.objects.create(
            name="Larger", plan_type="shared_hosting", price_monthly=20, disk_space_gb=20, bandwidth_gb=100
        )
        submission = uuid4()
        terms = {
            "service": self.service,
            "target_plan_id": replacement.pk,
            "expected_revision": 1,
            "submission_id": submission,
            "reason": "Approved support exception",
            "authority": {"kind": "staff_resource_override", "ticket_id": "123"},
        }
        with transaction.atomic():
            first = request_service_plan_change(**terms)
            second = request_service_plan_change(**terms)
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(HostingLimitApplication.objects.filter(service=self.service).count(), 1)
        limits = ServiceHostingLimits.objects.get(service=self.service)
        self.assertEqual(limits.revision, 2)
        self.assertEqual(limits.disk_allowance_mib, 20480)
        self.assertEqual(limits.bandwidth_allowance_mib, 102400)
        self.assertIsNone(limits.applied_revision)
        current = Service.objects.get(pk=self.service.pk)
        self.assertEqual(current.service_plan_id, replacement.pk)
        self.assertEqual(current.price, Decimal("10.00"))
        # An unrelated save from before the assignment cannot restore the old FK.
        self.service.admin_notes = "unrelated edit"
        self.service.save()
        current.refresh_from_db()
        self.assertEqual(current.service_plan_id, replacement.pk)
        self.assertEqual(current.admin_notes, "unrelated edit")
        current.admin_notes = "after refresh"
        current.save()

    def test_bulk_create_pins_allowances_without_reading_the_plan_per_row(self) -> None:
        services = [
            Service(
                customer=self.customer,
                service_plan=self.plan,
                currency=self.currency,
                service_name=f"bulk-{number}",
                username=f"bulk{number}",
                billing_cycle="monthly",
                price=10,
            )
            for number in range(3)
        ]
        # One initial-allowance audit INSERT adds one fixed query to the two bulk INSERTs.
        with self.assertNumQueries(8):
            Service.objects.bulk_create(services, 10)
        self.assertEqual(ServiceHostingLimits.objects.filter(service__in=services).count(), 3)
        audit = AuditEvent.objects.get(
            content_type__model="servicehostinglimits",
            description="Initial hosting allowance assignments",
            new_values__assignments__0__service_id=services[0].pk,
        )
        self.assertEqual(
            {item["service_id"] for item in audit.new_values["assignments"]}, {item.pk for item in services}
        )

    def test_plain_save_cannot_change_the_resource_plan(self) -> None:
        replacement = ServicePlan.objects.create(name="Other", plan_type="shared_hosting", price_monthly=20)
        self.service.service_plan = replacement
        with self.assertRaises(ValidationError):
            self.service.save(update_fields=["service_plan", "updated_at"])
        self.service.refresh_from_db()
        self.assertEqual(self.service.service_plan_id, self.plan.pk)

    def test_queryset_cannot_change_the_resource_plan(self) -> None:
        replacement = ServicePlan.objects.create(name="Other", plan_type="shared_hosting", price_monthly=20)
        with self.assertRaises(ValidationError):
            Service.objects.filter(pk=self.service.pk).update(service_plan=replacement)
        self.service.refresh_from_db()
        self.assertEqual(self.service.service_plan_id, self.plan.pk)

    def test_delayed_creation_keeps_the_original_allowance_and_headroom(self) -> None:
        plan = ServicePlan.objects.create(
            name="Assigned 5 GiB",
            plan_type="shared_hosting",
            price_monthly=Decimal("10.00"),
            disk_space_gb=5,
            bandwidth_gb=20,
        )
        service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name="Assigned limits",
            domain="assigned.example.test",
            username="assigned_limits",
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="pending",
        )
        account = VirtualminAccount.objects.create(
            service=service,
            server=self.server,
            domain=service.domain,
            virtualmin_username=service.username,
            status="provisioning",
            praho_customer_id=self.customer.pk,
            praho_service_id=service.pk,
        )
        plan.disk_space_gb = 40
        plan.bandwidth_gb = 200
        plan.save(update_fields=["disk_space_gb", "bandwidth_gb", "updated_at"])
        # Reload every relationship: a stale cached Plan must not make this test pass.
        account = VirtualminAccount.objects.get(pk=account.pk)
        self.assertEqual(account.service.service_plan.disk_space_gb, 40)
        with patch(
            "apps.settings.services.SettingsService.get_stored_setting",
            side_effect=lambda name: 1000 if name.endswith("domain_quota_default_mb") else 10000,
        ):
            VirtualminProvisioningService(self.server)._apply_default_quotas(account)
        account.refresh_from_db()
        self.assertEqual(account.disk_quota_mb, 5120)
        self.assertEqual(account.bandwidth_quota_mb, 20480)
        self.assertEqual(account.effective_disk_quota_mb, 5632)
