"""The real staff exception cannot invalidate an accepted commercial change."""

from uuid import uuid4

from django.test import TestCase
from django.urls import reverse

from apps.provisioning.hosting_limit_models import HostingLimitApplication, ServiceHostingLimits
from apps.tickets.models import Ticket
from apps.users.models import User
from tests.billing.test_plan_change_settlement import _PlanChangeSettlementFixture


class PlanChangeStaffOverrideTests(_PlanChangeSettlementFixture, TestCase):
    def test_actual_resource_override_refuses_an_awaiting_payment_change(self) -> None:
        change, _, _, target = self.payable_change()
        staff = User.objects.create_user(email="plan-exception-admin@example.test", staff_role="admin")
        ticket = Ticket.objects.create(customer=self.customer, title="Resource exception", description="Reviewed")
        self.client.force_login(staff)
        result = self.client.post(reverse("provisioning:service_resource_override", args=[self.service.pk]), {
            "target_plan": target.pk, "ticket": ticket.pk, "reason": "Exceptional capacity",
            "submission_id": str(uuid4()), "expected_revision": 1, "billing_unchanged": "on",
        })
        self.assertEqual(result.status_code, 409, result.content)
        self.assertEqual(ServiceHostingLimits.objects.get(service=self.service).revision, 1)
        self.assertFalse(HostingLimitApplication.objects.filter(service=self.service).exists())
        change.refresh_from_db()
        self.assertEqual(change.status, "awaiting_payment")
