"""
Tests for customer edit view — Phase 4 improvements.

Verifies:
- invoice_delivery_method removed from form
- Breadcrumb present in edit context
- Staff configuration separator visible
- Edit page renders without errors
"""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.customers.forms import CustomerEditForm
from apps.customers.models import Customer
from apps.users.models import CustomerMembership

User = get_user_model()


class CustomerEditFormFieldTests(TestCase):
    """Verify invoice_delivery_method is removed from the edit form."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Edit Test Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )

    def test_no_invoice_delivery_method_in_form(self):
        """invoice_delivery_method field should not exist in form."""
        form = CustomerEditForm(self.customer)
        self.assertNotIn("invoice_delivery_method", form.fields)

    def test_form_still_has_billing_fields(self):
        """Other billing fields should still be present."""
        form = CustomerEditForm(self.customer)
        self.assertIn("payment_terms", form.fields)
        self.assertIn("credit_limit", form.fields)
        self.assertIn("preferred_currency", form.fields)
        self.assertIn("auto_payment_enabled", form.fields)


class CustomerEditBreadcrumbTests(TestCase):
    """Verify breadcrumb navigation on edit page."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Breadcrumb Edit Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_edit_has_breadcrumb_items(self):
        """Breadcrumb items are present in edit context."""
        response = self.client.get(
            reverse("customers:edit", kwargs={"customer_id": self.customer.pk})
        )
        self.assertIn("breadcrumb_items", response.context)
        breadcrumb = response.context["breadcrumb_items"]
        self.assertEqual(len(breadcrumb), 4)
        self.assertEqual(str(breadcrumb[1]["text"]), "Customers")
        self.assertIn("url", breadcrumb[2])

    def test_edit_renders_200(self):
        """Edit page renders without errors."""
        response = self.client.get(
            reverse("customers:edit", kwargs={"customer_id": self.customer.pk})
        )
        self.assertEqual(response.status_code, 200)


class CustomerEditTemplateTests(TestCase):
    """Verify edit template content after Phase 4 changes."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Template Test Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_no_invoice_delivery_method_in_template(self):
        """Template should not render invoice_delivery_method field."""
        response = self.client.get(
            reverse("customers:edit", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertNotIn("invoice_delivery_method", content)
        self.assertNotIn("Invoice Delivery Method", content)

    def test_staff_configuration_separator_visible(self):
        """Staff Configuration separator is visible in edit page."""
        response = self.client.get(
            reverse("customers:edit", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertIn("Staff Configuration", content)

    def test_breadcrumb_component_rendered(self):
        """Breadcrumb component markup is present in edit page."""
        response = self.client.get(
            reverse("customers:edit", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertIn("breadcrumb", content.lower())

    def test_no_back_link(self):
        """Old back link should be replaced by breadcrumb."""
        response = self.client.get(
            reverse("customers:edit", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertNotIn("Back to customer details", content)
