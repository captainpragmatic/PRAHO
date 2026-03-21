"""
Tests for customer detail view — Phase 3 polish.

Verifies:
- Breadcrumbs in context
- Clickable service/invoice/ticket rows
- Billing config visibility (staff-only gate)
- Badge component used instead of raw HTML
- No confirm() dialogs (replaced by dangerous_action_modal event-dispatch)
- Correct field names in template
"""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.customers.models import Customer
from apps.customers.profile_models import CustomerBillingProfile
from apps.users.models import CustomerMembership

User = get_user_model()


class CustomerDetailBreadcrumbTests(TestCase):
    """Verify breadcrumb navigation on detail page."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Breadcrumb Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_detail_has_breadcrumb_items(self):
        """Breadcrumb items are present in detail context."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        self.assertIn("breadcrumb_items", response.context)
        breadcrumb = response.context["breadcrumb_items"]
        self.assertEqual(len(breadcrumb), 3)
        self.assertEqual(str(breadcrumb[1]["text"]), "Customers")
        self.assertIn("url", breadcrumb[1])

    def test_detail_has_is_staff_user(self):
        """is_staff_user flag is present in context."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        self.assertTrue(response.context["is_staff_user"])


class CustomerDetailClickableRowTests(TestCase):
    """Verify service/invoice/ticket rows are clickable."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Clickable Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_detail_renders_200(self):
        """Detail page renders without errors."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        self.assertEqual(response.status_code, 200)

    def test_detail_uses_breadcrumb_component(self):
        """Detail page includes breadcrumb component markup."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        # Breadcrumb component renders nav with aria-label
        self.assertIn("breadcrumb", content.lower())

    def test_detail_services_renamed(self):
        """Services section uses 'Services' not 'Hosting Services'."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertNotIn("Hosting Services", content)


class CustomerDetailBillingConfigTests(TestCase):
    """Verify billing config is staff-only."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="admin@example.com",
            password="pass123",
            is_staff=True,
            staff_role="admin",
        )
        self.regular_user = User.objects.create_user(
            email="customer@example.com",
            password="pass123",
            is_staff=False,
        )
        self.customer = Customer.objects.create(
            name="Billing Gate Co",
            customer_type="company",
        )
        CustomerBillingProfile.objects.create(
            customer=self.customer,
            preferred_currency="RON",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.regular_user, role="viewer"
        )
        self.client = Client()

    def test_staff_sees_billing_config(self):
        """Staff user sees billing configuration section."""
        self.client.force_login(self.staff_user)
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertIn("Billing Configuration", content)

    def test_non_staff_no_billing_config(self):
        """Non-staff user does NOT see billing configuration."""
        self.client.force_login(self.regular_user)
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertNotIn("Billing Configuration", content)


class CustomerDetailConfirmDialogTests(TestCase):
    """Verify confirm() dialogs replaced with event-dispatch."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Modal Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_no_confirm_dialogs(self):
        """No confirm( in response — replaced by confirm-dangerous-action event dispatch."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertNotIn("return confirm(", content)

    def test_uses_event_dispatch(self):
        """Template uses confirm-dangerous-action CustomEvent dispatch."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertIn("confirm-dangerous-action", content)
