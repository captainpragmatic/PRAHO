"""
Portal Customer Views Tests — team, tax profile, addresses.

Uses SimpleTestCase (no business DB) and mocks the Platform API client,
following the established Portal testing pattern.
"""

from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from django.urls import reverse

SESSION_DEFAULTS = {
    "customer_id": "1",
    "user_id": 10,
    "email": "owner@example.com",
    "selected_customer_id": "1",
    "user_memberships": [
        {"customer_id": 1, "customer_name": "Test Co", "role": "owner"},
    ],
    "user_memberships_fetched_at": 9999999999,
}


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class TeamViewTests(SimpleTestCase):
    """Test the team list view."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    @patch("apps.customers.views.api_client")
    def test_team_view_renders_members(self, mock_api):
        """Team view renders 200 with member list."""
        mock_api.get_customer_users.return_value = {
            "success": True,
            "users": [
                {
                    "id": 10,
                    "email": "owner@example.com",
                    "first_name": "O",
                    "last_name": "W",
                    "role": "owner",
                    "is_active": True,
                },
                {
                    "id": 20,
                    "email": "viewer@test.com",
                    "first_name": "V",
                    "last_name": "R",
                    "role": "viewer",
                    "is_active": True,
                },
            ],
        }
        self._set_session()
        response = self.client.get(reverse("customers:team"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "owner@example.com")
        self.assertContains(response, "viewer@test.com")

    @patch("apps.customers.views.api_client")
    def test_team_view_empty_state(self, mock_api):
        """Team view shows empty state when no members."""
        mock_api.get_customer_users.return_value = {"success": True, "users": []}
        self._set_session()
        response = self.client.get(reverse("customers:team"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No team members yet")

    @patch("apps.customers.views.api_client")
    def test_team_view_owner_sees_invite_button(self, mock_api):
        """Owner role sees the Invite Member button."""
        mock_api.get_customer_users.return_value = {"success": True, "users": []}
        self._set_session()
        response = self.client.get(reverse("customers:team"))
        self.assertContains(response, "Invite Member")

    @patch("apps.customers.views.api_client")
    def test_team_view_viewer_no_invite_button(self, mock_api):
        """Viewer role does not see the Invite Member button."""
        mock_api.get_customer_users.return_value = {"success": True, "users": []}
        self._set_session(
            user_memberships=[
                {"customer_id": 1, "customer_name": "Test Co", "role": "viewer"},
            ]
        )
        response = self.client.get(reverse("customers:team"))
        self.assertNotContains(response, "Invite Member")


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class AddressViewTests(SimpleTestCase):
    """Test the addresses list and add views."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    @patch("apps.customers.views.api_client")
    def test_addresses_view_renders_list(self, mock_api):
        """Addresses view renders 200 with address list."""
        mock_api.get_customer_addresses.return_value = {
            "success": True,
            "addresses": [
                {
                    "id": 1,
                    "address_type": "billing",
                    "address_line1": "Str. Test 1",
                    "city": "București",
                    "country": "Romania",
                    "is_current": True,
                },
            ],
        }
        self._set_session()
        response = self.client.get(reverse("customers:addresses"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Str. Test 1")
        self.assertContains(response, "Billing")

    @patch("apps.customers.views.api_client")
    def test_addresses_view_empty_state(self, mock_api):
        """Addresses view shows empty state."""
        mock_api.get_customer_addresses.return_value = {"success": True, "addresses": []}
        self._set_session()
        response = self.client.get(reverse("customers:addresses"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "No addresses yet")

    @patch("apps.customers.views.api_client")
    def test_address_add_renders_form(self, mock_api):
        """Address add view renders the form on GET."""
        self._set_session()
        response = self.client.get(reverse("customers:address_add"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Street Address")
        self.assertContains(response, "Address Type")

    @patch("apps.customers.views.api_client")
    def test_address_add_post_success(self, mock_api):
        """Successful address add redirects to address list."""
        mock_api.add_customer_address.return_value = {"success": True}
        self._set_session()
        response = self.client.post(
            reverse("customers:address_add"),
            data={
                "address_type": "billing",
                "address_line1": "Str. Nouă 5",
                "city": "Cluj",
                "county": "Cluj",
                "country": "RO",
                "postal_code": "400000",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("addresses", response.url)


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class NavigationTests(SimpleTestCase):
    """Test that navigation links appear correctly."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    @patch("apps.customers.views.api_client")
    @patch("apps.users.views.api_client")
    def test_company_profile_has_quick_links(self, mock_users_api, mock_cust_api):
        """Company profile page has quick links to Team, Tax, Addresses."""
        mock_users_api.post.return_value = {
            "success": True,
            "customer": {
                "company_name": "Test Co",
                "primary_email": "test@example.com",
                "billing_profile": {},
                "tax_profile": {},
            },
        }
        self._set_session()
        response = self.client.get(reverse("users:company_profile"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Team Members")
        self.assertContains(response, "Tax Profile")
        self.assertContains(response, "Addresses")

    @patch("apps.customers.views.api_client")
    def test_team_view_has_back_to_company_link(self, mock_api):
        """Team view links back to company profile."""
        mock_api.get_customer_users.return_value = {"success": True, "users": []}
        self._set_session()
        response = self.client.get(reverse("customers:team"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Back to Company")


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class CompanyProfileEditTests(SimpleTestCase):
    """Test that the company profile edit page works correctly."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    @patch("apps.users.views.api_client")
    def test_edit_form_renders_billing_fields(self, mock_api):
        """Edit form renders billing address fields with correct names."""
        mock_api.post.return_value = {
            "success": True,
            "customer": {
                "company_name": "Test Co",
                "primary_email": "test@co.ro",
                "billing_profile": {"address_street": "Str. Test 1", "address_city": "Cluj"},
                "tax_profile": {"vat_number": "RO123"},
            },
        }
        self._set_session()
        response = self.client.get(reverse("users:company_profile_edit"))
        self.assertEqual(response.status_code, 200)
        # Verify correct field names are used (billing_street, not street_address)
        self.assertContains(response, 'name="billing_street"')
        self.assertContains(response, 'name="billing_city"')
        self.assertContains(response, 'name="billing_state"')

    @patch("apps.users.views.api_client")
    def test_edit_form_no_admin_fields(self, mock_api):
        """Edit form does not expose admin-only fields."""
        mock_api.post.return_value = {
            "success": True,
            "customer": {
                "company_name": "Test Co",
                "primary_email": "test@co.ro",
                "billing_profile": {},
                "tax_profile": {},
            },
        }
        self._set_session()
        response = self.client.get(reverse("users:company_profile_edit"))
        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        # Admin fields must NOT be present
        self.assertNotIn("payment_terms", content)
        self.assertNotIn("credit_limit", content)
        self.assertNotIn("preferred_currency", content)
