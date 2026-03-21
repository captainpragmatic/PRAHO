"""
Portal Customer Views Tests — team, tax profile, addresses.

Uses SimpleTestCase (no business DB) and mocks the Platform API client,
following the established Portal testing pattern.
"""

import time
from typing import Any
from unittest.mock import patch

from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse

from apps.api_client.services import PlatformAPIError

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
                    "user_id": 10,
                    "email": "owner@example.com",
                    "first_name": "O",
                    "last_name": "W",
                    "role": "owner",
                    "is_active": True,
                },
                {
                    "user_id": 20,
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
class TeamRoleViewTests(SimpleTestCase):
    """Test the team role-change endpoint (POST)."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    @patch("apps.customers.views.api_client")
    def test_role_change_success_redirects(self, mock_api):
        """Successful role change redirects to team page."""
        mock_api.change_customer_user_role.return_value = {"success": True}
        self._set_session()
        response = self.client.post(
            reverse("customers:team_role", kwargs={"target_user_id": 20}),
            data={"role": "billing"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("team", response.url)
        mock_api.change_customer_user_role.assert_called_once()

    @patch("apps.customers.views.api_client")
    def test_role_change_api_error_redirects(self, mock_api):
        """API error on role change still redirects to team page with error message."""
        mock_api.change_customer_user_role.side_effect = PlatformAPIError("server error")
        self._set_session()
        response = self.client.post(
            reverse("customers:team_role", kwargs={"target_user_id": 20}),
            data={"role": "billing"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("team", response.url)


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class TeamRemoveViewTests(SimpleTestCase):
    """Test the team member removal endpoint (POST)."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    @patch("apps.customers.views.api_client")
    def test_remove_member_success_redirects(self, mock_api):
        """Successful removal redirects to team page."""
        mock_api.remove_customer_user.return_value = {"success": True}
        self._set_session()
        response = self.client.post(
            reverse("customers:team_remove", kwargs={"target_user_id": 20}),
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("team", response.url)
        mock_api.remove_customer_user.assert_called_once()

    @patch("apps.customers.views.api_client")
    def test_remove_member_api_error_redirects(self, mock_api):
        """API error on removal still redirects to team page."""
        mock_api.remove_customer_user.side_effect = PlatformAPIError("not found")
        self._set_session()
        response = self.client.post(
            reverse("customers:team_remove", kwargs={"target_user_id": 20}),
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("team", response.url)


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class AddressDeleteViewTests(SimpleTestCase):
    """Test the address deletion endpoint (POST)."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    @patch("apps.customers.views.api_client")
    def test_address_delete_success_redirects(self, mock_api):
        """Successful address deletion redirects to addresses page."""
        mock_api.delete_customer_address.return_value = {"success": True}
        self._set_session()
        response = self.client.post(
            reverse("customers:address_delete", kwargs={"address_id": 5}),
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("addresses", response.url)
        mock_api.delete_customer_address.assert_called_once()

    @patch("apps.customers.views.api_client")
    def test_address_delete_api_error_redirects(self, mock_api):
        """API error on deletion still redirects to addresses page."""
        mock_api.delete_customer_address.side_effect = PlatformAPIError("not found")
        self._set_session()
        response = self.client.post(
            reverse("customers:address_delete", kwargs={"address_id": 5}),
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


# ---------------------------------------------------------------------------
# F4: hx-confirm replaced with native onclick confirm
# ---------------------------------------------------------------------------


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class TeamRemoveConfirmTests(SimpleTestCase):
    """F4: Destructive remove button uses native JS confirm, not inert hx-confirm."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    @patch("apps.customers.views.api_client")
    def test_remove_button_has_native_confirm(self, mock_api):
        """Destructive action button uses native JS confirm, not inert hx-confirm."""
        mock_api.get_customer_users.return_value = {
            "success": True,
            "users": [
                {
                    "user_id": 10,
                    "email": "owner@test.com",
                    "first_name": "O",
                    "last_name": "W",
                    "role": "owner",
                    "is_active": True,
                    "is_primary": True,
                    "created_at": "2024-01-01T00:00:00",
                },
                {
                    "user_id": 20,
                    "email": "viewer@test.com",
                    "first_name": "V",
                    "last_name": "W",
                    "role": "viewer",
                    "is_active": True,
                    "is_primary": False,
                    "created_at": "2024-01-01T00:00:00",
                },
            ],
        }
        self._set_session()
        response = self.client.get(reverse("customers:team"))
        content = response.content.decode()
        self.assertIn("return confirm(", content)
        self.assertNotIn("hx-confirm", content)


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class AddressDeleteConfirmTests(SimpleTestCase):
    """F4: Destructive delete button uses native JS confirm, not inert hx-confirm."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    @patch("apps.customers.views.api_client")
    def test_delete_button_has_native_confirm(self, mock_api):
        """Destructive action button uses native JS confirm, not inert hx-confirm."""
        mock_api.get_customer_addresses.return_value = {
            "success": True,
            "addresses": [
                {
                    "id": 1,
                    "address_type": "billing",
                    "is_current": True,
                    "address_line1": "St 1",
                    "city": "Bucharest",
                    "county": "B",
                    "country": "Romania",
                    "postal_code": "010101",
                },
            ],
        }
        self._set_session()
        response = self.client.get(reverse("customers:addresses"))
        content = response.content.decode()
        self.assertIn("return confirm(", content)
        self.assertNotIn("hx-confirm", content)


# ---------------------------------------------------------------------------
# F6: Admin role can edit tax profile
# ---------------------------------------------------------------------------


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class TaxProfileViewTests(SimpleTestCase):
    """F6: Admin role must be allowed to edit the tax profile."""

    def setUp(self) -> None:
        self.client = Client()

    def _set_session(self, role: str = "admin") -> None:
        session = self.client.session
        session["user_id"] = 10
        session["customer_id"] = "1"
        session["selected_customer_id"] = 1
        session["user_memberships"] = [{"customer_id": 1, "role": role}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    def _do_post_tax_profile(self, mock_api: Any, role: str) -> None:
        """Helper: set session with role and POST to tax_profile."""
        self._set_session(role=role)
        mock_api.update_customer_tax_profile.return_value = {"success": True}
        mock_api.post.return_value = {"success": True, "tax_profile": {}}
        self.client.post(
            reverse("customers:tax_profile"),
            {"cui": "12345678", "is_vat_payer": "on"},
        )

    @patch("apps.customers.views.api_client")
    def test_admin_role_can_edit_tax_profile(self, mock_api: Any) -> None:
        """Admin role should be able to edit tax profile (POST)."""
        self._do_post_tax_profile(mock_api, role="admin")
        mock_api.update_customer_tax_profile.assert_called_once()

    @patch("apps.customers.views.api_client")
    def test_owner_role_can_edit_tax_profile(self, mock_api: Any) -> None:
        """Owner role should still be able to edit tax profile."""
        self._do_post_tax_profile(mock_api, role="owner")
        mock_api.update_customer_tax_profile.assert_called_once()

    @patch("apps.customers.views.api_client")
    def test_billing_role_can_edit_tax_profile(self, mock_api: Any) -> None:
        """Billing role should still be able to edit tax profile."""
        self._do_post_tax_profile(mock_api, role="billing")
        mock_api.update_customer_tax_profile.assert_called_once()

    @patch("apps.customers.views.api_client")
    def test_viewer_role_cannot_edit_tax_profile(self, mock_api: Any) -> None:
        """Viewer role must NOT be allowed to edit tax profile (can_edit=False)."""
        self._set_session(role="viewer")
        mock_api.post.return_value = {"success": True, "tax_profile": {}}
        self.client.post(
            reverse("customers:tax_profile"),
            {"cui": "12345678", "is_vat_payer": "on"},
        )
        mock_api.update_customer_tax_profile.assert_not_called()

# ---------------------------------------------------------------------------
# F7: Role allowlist on invite / role-change
# ---------------------------------------------------------------------------


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class TeamRoleValidationTests(SimpleTestCase):
    """F7: Invalid roles must be rejected on both invite and role-change endpoints."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    @patch("apps.customers.views.api_client")
    def test_role_change_invalid_role_rejected(self, mock_api):
        """Submitting an invalid role to team_role does not call the API."""
        self._set_session()
        response = self.client.post(
            reverse("customers:team_role", kwargs={"target_user_id": 20}),
            {"role": "superadmin"},
        )
        self.assertEqual(response.status_code, 302)
        mock_api.change_customer_user_role.assert_not_called()

    @patch("apps.customers.views.api_client")
    def test_role_change_valid_role_proceeds(self, mock_api):
        """Submitting a valid role to team_role calls the API."""
        mock_api.change_customer_user_role.return_value = {"success": True}
        self._set_session()
        response = self.client.post(
            reverse("customers:team_role", kwargs={"target_user_id": 20}),
            {"role": "billing"},
        )
        self.assertEqual(response.status_code, 302)
        mock_api.change_customer_user_role.assert_called_once()

    @patch("apps.customers.views.api_client")
    def test_invite_invalid_role_rejected(self, mock_api):
        """Submitting an invalid role to team_invite does not call the API."""
        self._set_session()
        self.client.post(
            reverse("customers:team_invite"),
            {
                "email": "new@example.com",
                "first_name": "New",
                "last_name": "User",
                "role": "superadmin",
            },
        )
        # Should re-render the form, not call create_customer_user
        mock_api.create_customer_user.assert_not_called()

    @patch("apps.customers.views.api_client")
    def test_invite_valid_role_proceeds(self, mock_api):
        """Submitting a valid role to team_invite calls the API."""
        mock_api.create_customer_user.return_value = {"success": True}
        self._set_session()
        self.client.post(
            reverse("customers:team_invite"),
            {
                "email": "new@example.com",
                "first_name": "New",
                "last_name": "User",
                "role": "tech",
            },
        )
        mock_api.create_customer_user.assert_called_once()


# ---------------------------------------------------------------------------
# F14: Address form valid types
# ---------------------------------------------------------------------------


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class AddressFormTypesTests(SimpleTestCase):
    """F14: Address form must offer only valid address types matching the model."""

    def _set_session(self, **overrides):
        session = self.client.session
        for k, v in {**SESSION_DEFAULTS, **overrides}.items():
            session[k] = v
        session.save()

    def test_address_form_has_valid_address_types(self):
        """Address form offers only valid address types matching the model."""
        self._set_session()
        response = self.client.get(reverse("customers:address_add"))
        content = response.content.decode()
        # Valid types present
        self.assertIn('value="primary"', content)
        self.assertIn('value="billing"', content)
        self.assertIn('value="delivery"', content)
        self.assertIn('value="legal"', content)
        # Invalid types absent
        self.assertNotIn('value="shipping"', content)
        self.assertNotIn('value="other"', content)
