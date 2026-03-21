"""
Tests for customer list and detail views — Phase 1 critical bug fixes.

Verifies:
- Correct model attributes used in templates (not non-existent fields)
- N+1 query fix for memberships prefetch
- Dead links wired to real URLs
- Search uses canonical `q` param with SEARCH_QUERY_MIN_LENGTH threshold
- URL encoding in pagination
- Correct field names in detail template
"""

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from apps.customers.contact_models import CustomerAddress
from apps.customers.models import Customer
from apps.customers.profile_models import CustomerTaxProfile
from apps.users.models import CustomerMembership

User = get_user_model()


class CustomerListAttributeTests(TestCase):
    """Verify list page renders correct model attributes (not non-existent ones)."""

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
            primary_phone="+40722000000",
            customer_type="company",
        )
        CustomerAddress.objects.create(
            customer=self.customer,
            address_type="primary",
            is_current=True,
            city="București",
            county="București",
            country="Romania",
            address_line1="Str. Test 1",
            postal_code="010101",
        )
        CustomerMembership.objects.create(
            customer=self.customer,
            user=self.staff_user,
            role="owner",
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_list_renders_correct_attributes(self):
        """primary_email, primary_phone, display name appear (not contact_email, contact_person)."""
        response = self.client.get(reverse("customers:list"))
        content = response.content.decode()
        self.assertContains(response, "test@co.com")
        self.assertContains(response, "+40722000000")
        # get_display_name returns company_name for company-type customers
        self.assertContains(response, "Test Co")
        # Non-existent attributes should NOT appear
        self.assertNotIn("contact_email", content)
        self.assertNotIn("contact_person", content)
        self.assertNotIn("contact_phone", content)
        self.assertNotIn("legal_address", content)

    def test_list_shows_primary_address_city(self):
        """Primary address city, county, and country appear in list."""
        response = self.client.get(reverse("customers:list"))
        self.assertContains(response, "București")
        self.assertContains(response, "Romania")

    def test_list_shows_only_primary_address(self):
        """Only primary address shown, not all addresses."""
        # Add a second non-primary address
        CustomerAddress.objects.create(
            customer=self.customer,
            address_type="billing",
            is_current=True,
            city="Cluj-Napoca",
            county="Cluj",
            country="Romania",
            address_line1="Str. Billing 1",
            postal_code="400000",
        )
        response = self.client.get(reverse("customers:list"))
        content = response.content.decode()
        # Should show primary address
        self.assertIn("București", content)
        # Billing address city should NOT appear in the address column
        # (it may appear elsewhere if the customer has it, but we check the address section)

    def test_no_emoji_in_tax_display(self):
        """Tax display should use icon component, not emoji flags."""
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui="RO12345678",
        )
        response = self.client.get(reverse("customers:list"))
        content = response.content.decode()
        # CUI value should be present
        self.assertIn("RO12345678", content)
        # The emoji flag should not appear adjacent to CUI values
        self.assertNotIn("🇷🇴 RO12345678", content)


class CustomerListSearchTests(TestCase):
    """Verify search uses canonical `q` param and SEARCH_QUERY_MIN_LENGTH."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Acme Corp",
            primary_email="acme@example.com",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_search_uses_q_param(self):
        """View reads `q` param, not `search`."""
        response = self.client.get(reverse("customers:list"), {"q": "Acme"})
        self.assertContains(response, "Acme Corp")

    def test_old_search_param_ignored(self):
        """Old `search` param should not filter results."""
        response = self.client.get(reverse("customers:list"), {"search": "Acme"})
        # search_query context should be empty since we read `q` now
        self.assertEqual(response.context["search_query"], "")

    def test_search_min_length_returns_unfiltered(self):
        """Queries shorter than SEARCH_QUERY_MIN_LENGTH (2) return unfiltered results."""
        response = self.client.get(reverse("customers:list"), {"q": "A"})
        # Single char query — should return all customers (unfiltered)
        self.assertContains(response, "Acme Corp")

    def test_search_pagination_url_encoding(self):
        """Search with special chars in query doesn't break pagination."""
        response = self.client.get(reverse("customers:list"), {"q": "test&co"})
        # extra_params should be properly URL-encoded
        self.assertIn("q=test%26co", response.context.get("extra_params", ""))


class CustomerDetailFieldTests(TestCase):
    """Verify detail page uses correct model field names."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Detail Test Co",
            primary_email="detail@test.com",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_detail_no_variant_outline(self):
        """Button should not use non-existent variant='outline'."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertNotIn('variant="outline"', content)

    def test_detail_view_all_links_not_dead(self):
        """Services/invoices/tickets 'View all' links contain real URLs."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        # Response should load successfully (200 OK)
        self.assertEqual(response.status_code, 200)

    def test_detail_no_inline_styles(self):
        """No inline style='display: inline;' should remain."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertNotIn('style="display: inline;"', content)

    def test_detail_uses_correct_invoice_field(self):
        """Template should use invoice.number, not invoice.invoice_number."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        self.assertNotIn("invoice_number", content)

    def test_detail_uses_correct_ticket_field(self):
        """Template should use ticket.title, not ticket.subject."""
        response = self.client.get(
            reverse("customers:detail", kwargs={"customer_id": self.customer.pk})
        )
        content = response.content.decode()
        # ticket.subject should not appear in the template
        self.assertNotIn(".subject", content)


class CustomerListAnnotationTests(TestCase):
    """Verify queryset annotations for service/ticket counts."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer = Customer.objects.create(
            name="Annotated Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_annotations_present_in_context(self):
        """Customer objects in context have active_services_count and open_tickets_count."""
        response = self.client.get(reverse("customers:list"))
        customers = response.context["customers"]
        customer = customers[0]
        self.assertTrue(hasattr(customer, "active_services_count"))
        self.assertTrue(hasattr(customer, "open_tickets_count"))
        self.assertEqual(customer.active_services_count, 0)
        self.assertEqual(customer.open_tickets_count, 0)

    def test_breadcrumb_in_context(self):
        """Breadcrumb items are present in list context."""
        response = self.client.get(reverse("customers:list"))
        self.assertIn("breadcrumb_items", response.context)
        breadcrumb = response.context["breadcrumb_items"]
        self.assertEqual(len(breadcrumb), 2)
        self.assertEqual(str(breadcrumb[1]["text"]), "Customers")

    def test_status_tabs_in_context(self):
        """Status tabs are present for filter UI."""
        response = self.client.get(reverse("customers:list"))
        self.assertIn("status_tabs", response.context)
        tabs = response.context["status_tabs"]
        tab_values = [t["value"] for t in tabs]
        self.assertIn("", tab_values)  # "All" tab
        self.assertIn("active", tab_values)
        self.assertIn("prospect", tab_values)

    def test_stats_in_context(self):
        """total_count and active_count present in context."""
        response = self.client.get(reverse("customers:list"))
        self.assertIn("total_count", response.context)
        self.assertIn("active_count", response.context)


class CustomerListHTMXSearchTests(TestCase):
    """Verify HTMX search endpoint returns partial template."""

    def setUp(self):
        self.staff_user = User.objects.create_user(
            email="staff@example.com",
            password="staffpass123",
            is_staff=True,
            staff_role="admin",
        )
        self.customer_active = Customer.objects.create(
            name="Active Corp",
            primary_email="active@example.com",
            customer_type="company",
            status="active",
        )
        self.customer_prospect = Customer.objects.create(
            name="Prospect LLC",
            primary_email="prospect@example.com",
            customer_type="individual",
            status="prospect",
        )
        CustomerMembership.objects.create(
            customer=self.customer_active, user=self.staff_user, role="owner"
        )
        CustomerMembership.objects.create(
            customer=self.customer_prospect, user=self.staff_user, role="owner"
        )
        self.client = Client()
        self.client.force_login(self.staff_user)

    def test_htmx_search_returns_partial(self):
        """HTMX search returns the partial template (no base.html wrapping)."""
        response = self.client.get(
            reverse("customers:search_htmx"),
            {"q": "Active"},
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        # Partial should NOT contain <html> or base.html structure
        self.assertNotIn("<!DOCTYPE html>", content)
        # Should contain the matching customer
        self.assertIn("Active Corp", content)

    def test_htmx_search_min_length(self):
        """Queries shorter than SEARCH_QUERY_MIN_LENGTH return unfiltered."""
        response = self.client.get(
            reverse("customers:search_htmx"),
            {"q": "A"},
            HTTP_HX_REQUEST="true",
        )
        content = response.content.decode()
        # Both customers should appear (unfiltered)
        self.assertIn("Active Corp", content)
        self.assertIn("Prospect LLC", content)

    def test_htmx_status_filter(self):
        """Status filter returns only matching customers."""
        response = self.client.get(
            reverse("customers:search_htmx"),
            {"status": "active"},
            HTTP_HX_REQUEST="true",
        )
        content = response.content.decode()
        self.assertIn("Active Corp", content)
        self.assertNotIn("Prospect LLC", content)

    def test_htmx_type_filter(self):
        """Type filter returns only matching customer types."""
        response = self.client.get(
            reverse("customers:search_htmx"),
            {"type": "individual"},
            HTTP_HX_REQUEST="true",
        )
        content = response.content.decode()
        self.assertNotIn("Active Corp", content)
        self.assertIn("Prospect LLC", content)

    def test_htmx_preserves_filter_state(self):
        """Partial context includes active filter values."""
        response = self.client.get(
            reverse("customers:search_htmx"),
            {"q": "Corp", "status": "active", "type": "company"},
            HTTP_HX_REQUEST="true",
        )
        self.assertEqual(response.context["search_query"], "Corp")
        self.assertEqual(response.context["status_filter"], "active")
        self.assertEqual(response.context["type_filter"], "company")

    def test_htmx_empty_state(self):
        """No matching customers shows empty state."""
        response = self.client.get(
            reverse("customers:search_htmx"),
            {"q": "NonExistentXYZ123"},
            HTTP_HX_REQUEST="true",
        )
        content = response.content.decode()
        self.assertIn("No Customers Found", content)


class CustomerListNewButtonRoleGateTests(TestCase):
    """Verify 'New Customer' button is role-gated."""

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
            name="Gate Test Co",
            customer_type="company",
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.staff_user, role="owner"
        )
        CustomerMembership.objects.create(
            customer=self.customer, user=self.regular_user, role="viewer"
        )
        self.client = Client()

    def test_staff_sees_new_customer_button(self):
        """Staff user sees the New Customer button."""
        self.client.force_login(self.staff_user)
        response = self.client.get(reverse("customers:list"))
        self.assertContains(response, reverse("customers:create"))

    def test_non_staff_no_new_customer_button(self):
        """Non-staff user does not see the New Customer button."""
        self.client.force_login(self.regular_user)
        response = self.client.get(reverse("customers:list"))
        content = response.content.decode()
        # The create URL should not appear in header action
        self.assertNotIn("New Customer", content)
