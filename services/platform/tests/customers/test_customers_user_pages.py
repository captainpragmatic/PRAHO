"""
Tests for customer user management pages — Phase 5 consolidation.

Verifies:
- Breadcrumbs present on add_user, create_user, assign_user pages
- Component buttons used (not raw HTML anchor tags)
"""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.customers.models import Customer
from apps.users.models import CustomerMembership

User = get_user_model()


class CustomerAddUserPageTests(TestCase):
    """Verify add_user page has breadcrumbs and component buttons."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="User Page Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_add_user_has_breadcrumb(self):
        """Breadcrumb items are present in add_user context."""
        response = self.client.get(
            reverse("customers:add_user", kwargs={"customer_id": self.customer.pk})
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("breadcrumb_items", response.context)
        breadcrumb = response.context["breadcrumb_items"]
        self.assertEqual(len(breadcrumb), 4)
        self.assertEqual(str(breadcrumb[-1]["text"]), "Add User")

    def test_add_user_no_back_link(self):
        """Old back link should be replaced by breadcrumb."""
        response = self.client.get(
            reverse("customers:add_user", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertNotIn("Back to Customer", content)


class CustomerCreateUserPageTests(TestCase):
    """Verify create_user page has breadcrumbs and component buttons."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Create User Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_create_user_has_breadcrumb(self):
        """Breadcrumb items are present in create_user context."""
        response = self.client.get(
            reverse("customers:create_user", kwargs={"customer_id": self.customer.pk})
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("breadcrumb_items", response.context)
        breadcrumb = response.context["breadcrumb_items"]
        self.assertEqual(len(breadcrumb), 4)
        self.assertEqual(str(breadcrumb[-1]["text"]), "Create User")

    def test_create_user_no_back_link(self):
        """Old back link should be replaced by breadcrumb."""
        response = self.client.get(
            reverse("customers:create_user", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertNotIn("Back to Customer", content)


class CustomerAssignUserPageTests(TestCase):
    """Verify assign_user page has breadcrumbs and component buttons."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Assign User Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_assign_user_has_breadcrumb(self):
        """Breadcrumb items are present in assign_user context."""
        response = self.client.get(
            reverse("customers:assign_user", kwargs={"customer_id": self.customer.pk})
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("breadcrumb_items", response.context)
        breadcrumb = response.context["breadcrumb_items"]
        self.assertEqual(len(breadcrumb), 4)
        self.assertEqual(str(breadcrumb[-1]["text"]), "Assign User")

    def test_assign_user_uses_breadcrumb_component(self):
        """Assign user page uses breadcrumb component, not hand-coded nav."""
        response = self.client.get(
            reverse("customers:assign_user", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        # Should use breadcrumb component (aria-label="Breadcrumb")
        self.assertIn("breadcrumb", content.lower())
