"""
Tests for user_management_views security fixes.
Verifies @staff_required decorator and server-side delete confirmation.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.customers.models import Customer
from apps.users.models import CustomerMembership

User = get_user_model()


class UserManagementStaffRequiredTests(TestCase):
    """Verify all user management views require staff access."""

    def setUp(self):
        self.non_staff_user = User.objects.create_user(
            email="customer@example.com",
            password="testpass123",
        )
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            company_name="Test Co",
            primary_email="test@co.com",
            customer_type="company",
        )
        self.target_user = User.objects.create_user(
            email="target@example.com",
            password="testpass123",
        )
        self.membership = CustomerMembership.objects.create(
            customer=self.customer,
            user=self.target_user,
            role="viewer",
        )
        self.client = Client()

    def _assert_non_staff_blocked(self, url, method="get"):
        """Non-staff user should be redirected (302) from staff-only views."""
        self.client.force_login(self.non_staff_user)
        response = self.client.get(url) if method == "get" else self.client.post(url, {})
        self.assertIn(response.status_code, [302, 403])

    def test_add_user_requires_staff(self):
        url = reverse("customers:add_user", kwargs={"customer_id": self.customer.id})
        self._assert_non_staff_blocked(url)

    def test_create_user_requires_staff(self):
        url = reverse("customers:create_user", kwargs={"customer_id": self.customer.id})
        self._assert_non_staff_blocked(url)

    def test_change_role_requires_staff(self):
        url = reverse(
            "customers:change_user_role",
            kwargs={"customer_id": self.customer.id, "membership_id": self.membership.id},
        )
        self._assert_non_staff_blocked(url, method="post")

    def test_toggle_status_requires_staff(self):
        url = reverse(
            "customers:toggle_user_status",
            kwargs={"customer_id": self.customer.id, "user_id": self.target_user.id},
        )
        self._assert_non_staff_blocked(url, method="post")

    def test_remove_user_requires_staff(self):
        url = reverse(
            "customers:remove_user",
            kwargs={"customer_id": self.customer.id, "membership_id": self.membership.id},
        )
        self._assert_non_staff_blocked(url, method="post")

    def test_staff_can_access_add_user(self):
        """Staff user should be able to access add_user view."""
        self.client.force_login(self.staff_user)
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=self.customer.id)
            url = reverse("customers:add_user", kwargs={"customer_id": self.customer.id})
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200)


class CustomerDeleteConfirmationTests(TestCase):
    """Verify server-side delete confirmation (confirm_name must match)."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            company_name="Test Co",
            primary_email="test@co.com",
            customer_type="company",
        )
        self.client = Client()
        self.url = reverse("customers:delete", kwargs={"customer_id": self.customer.id})

    def test_delete_requires_confirm_name(self):
        """POST without matching confirm_name should fail."""
        self.client.force_login(self.staff_user)
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=self.customer.id)
            response = self.client.post(self.url, {"confirm_name": "Wrong Name"})
            self.assertEqual(response.status_code, 200)  # Re-renders form
            self.customer.refresh_from_db()
            self.assertFalse(self.customer.is_deleted)

    def test_delete_with_correct_name_succeeds(self):
        """POST with matching confirm_name should soft-delete."""
        self.client.force_login(self.staff_user)
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=self.customer.id)
            response = self.client.post(self.url, {"confirm_name": "Test Customer"})
            self.assertEqual(response.status_code, 302)
            self.customer.refresh_from_db()
            self.assertTrue(self.customer.is_deleted)
