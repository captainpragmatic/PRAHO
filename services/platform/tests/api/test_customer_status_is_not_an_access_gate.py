"""A customer's status describes its lifecycle; it does not decide who may use the Portal.

Platform refused every customer-scoped call unless the customer was ``active``. Staff-created
customers start as ``prospect`` and nothing moved them on, so their people could sign in but not
price a cart, pay or open a ticket. Access is the member's user and membership, and soft deletion.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.customers.models import Customer
from apps.users.models import CustomerMembership
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

User = get_user_model()

LIFECYCLE_STATUSES = ("prospect", "active", "inactive", "suspended")


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class CustomerStatusIsNotAnAccessGateTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        self.owner = User.objects.create_user(email="owner@example.test", password="test-password")
        self.customer = Customer.objects.create(name="Lifecycle SRL", customer_type="company")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_active=True)

    def _set_status(self, status: str) -> None:
        Customer.objects.filter(pk=self.customer.pk).update(status=status)
        self.assertEqual(Customer.all_objects.get(pk=self.customer.pk).status, status)  # the fixture holds

    def _list_team(self) -> int:
        body = {"customer_id": self.customer.pk, "user_id": self.owner.pk}
        return self.portal_post("/api/customers/users/", body).status_code

    def _switch_to(self) -> bool:
        body = {"customer_id": self.customer.pk, "user_id": self.owner.pk}
        response = self.portal_post("/api/users/verify-customer-access/", body)
        self.assertEqual(response.status_code, 200, response.content)
        return bool(response.json()["data"]["has_access"])

    def test_every_lifecycle_status_reaches_customer_scoped_endpoints(self) -> None:
        for status in LIFECYCLE_STATUSES:
            with self.subTest(status=status):
                self._set_status(status)
                self.assertEqual(self._list_team(), 200)

    def test_every_lifecycle_status_can_be_switched_to(self) -> None:
        for status in LIFECYCLE_STATUSES:
            with self.subTest(status=status):
                self._set_status(status)
                self.assertTrue(self._switch_to())

    def test_a_deleted_customer_is_refused_in_any_status(self) -> None:
        for status in LIFECYCLE_STATUSES:
            with self.subTest(status=status):
                Customer.all_objects.filter(pk=self.customer.pk).update(status=status, deleted_at=timezone.now())
                self.assertIsNotNone(Customer.all_objects.get(pk=self.customer.pk).deleted_at)
                self.assertIn(self._list_team(), (401, 403))
                self.assertFalse(self._switch_to())

    def test_an_inactive_membership_is_still_refused(self) -> None:
        CustomerMembership.objects.filter(customer=self.customer, user=self.owner).update(is_active=False)
        self._set_status("active")
        self.assertIn(self._list_team(), (401, 403))
        self.assertFalse(self._switch_to())


class StaffOrderCreateListsEveryStatusTests(TestCase):
    """Staff can place an order for a prospect: the first order is what a prospect is waiting for."""

    def test_the_order_form_offers_customers_in_every_lifecycle_status(self) -> None:
        staff = User.objects.create_user("order-staff@example.test", is_staff=True, staff_role="admin")
        self.client.force_login(staff)
        for status in LIFECYCLE_STATUSES:
            customer = Customer.objects.create(name=f"Order {status}", primary_email=f"{status}@example.test")
            Customer.objects.filter(pk=customer.pk).update(status=status)
        response = self.client.get("/orders/create/")
        self.assertEqual(response.status_code, 200)
        offered = {customer.status for customer in response.context["customers"]}
        self.assertEqual(offered, set(LIFECYCLE_STATUSES))
