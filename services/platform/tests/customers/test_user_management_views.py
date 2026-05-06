"""
Tests for user_management_views security fixes.
Verifies @staff_required decorator and server-side delete confirmation.
"""

from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from apps.customers.models import Customer
from apps.users.models import CustomerMembership
from apps.users.services import SecureCustomerUserService

User = get_user_model()

# Tests that exercise cache-based rate limits need a real cache, not DummyCache.
LOCMEM_TEST_CACHE = getattr(settings, "LOCMEM_TEST_CACHE", {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "test-cache-isolated",
    },
})


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


class CustomerCreateUserInviteEmailTests(TestCase):
    """Verify invite email is sent when staff creates a new user."""

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
        self.url = reverse("customers:create_user", kwargs={"customer_id": self.customer.id})

    @patch("apps.customers.user_management_views.SecureCustomerUserService._send_welcome_email_secure")
    def test_create_user_sends_invite_email(self, mock_send_email):
        """Creating a new user should trigger an invite email."""
        mock_send_email.return_value = True
        self.client.force_login(self.staff_user)
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=self.customer.id)
            response = self.client.post(self.url, {
                "email": "invited@example.com",
                "first_name": "Invited",
                "last_name": "User",
                "role": "viewer",
            })
            self.assertEqual(response.status_code, 302)
            self.assertTrue(User.objects.filter(email="invited@example.com").exists())
            new_user = User.objects.get(email="invited@example.com")
            mock_send_email.assert_called_once()
            call_args = mock_send_email.call_args
            self.assertEqual(call_args[0], (new_user, self.customer))
            self.assertIn("request_ip", call_args[1])

    @patch("apps.customers.user_management_views.SecureCustomerUserService._send_welcome_email_secure")
    def test_create_user_warns_on_email_failure(self, mock_send_email):
        """User is still created when invite email fails, with a warning message."""
        mock_send_email.return_value = False
        self.client.force_login(self.staff_user)
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=self.customer.id)
            response = self.client.post(self.url, {
                "email": "noemail@example.com",
                "first_name": "No",
                "last_name": "Email",
                "role": "viewer",
            }, follow=True)
            self.assertTrue(User.objects.filter(email="noemail@example.com").exists())
            messages_list = list(response.context["messages"])
            warning_messages = [m for m in messages_list if m.level_tag == "warning"]
            self.assertTrue(len(warning_messages) >= 1)


class CustomerCreateUserSecurityTests(TestCase):
    """Verify enumeration protection, validation, and rollback on user creation."""

    def setUp(self):
        cache.clear()
        self.staff_user = User.objects.create_user(
            email="staff@example.com", password="staffpass", is_staff=True, staff_role="admin"
        )
        self.customer = Customer.objects.create(
            name="Security Customer", company_name="Sec Co", primary_email="sec@co.com", customer_type="company"
        )
        self.client = Client()
        self.url = reverse("customers:create_user", kwargs={"customer_id": self.customer.id})

    def _post(self, data):
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=self.customer.id)
            return self.client.post(self.url, data, follow=True)

    def test_existing_user_in_other_customer_returns_generic_message(self):
        """Cross-tenant existing user must NOT be revealed — generic message only."""
        User.objects.create_user(email="elsewhere@example.com", password="pass123")
        self.client.force_login(self.staff_user)
        response = self._post({"email": "elsewhere@example.com", "role": "viewer"})
        messages_list = [str(m) for m in response.context["messages"]]
        self.assertTrue(any("Cannot create" in m for m in messages_list))
        # Must not say "already" — that would reveal the user exists somewhere.
        self.assertFalse(any("already" in m.lower() for m in messages_list))

    def test_existing_user_in_this_customer_returns_specific_message(self):
        """Existing member of THIS customer is allowed-info — specific message OK."""
        existing = User.objects.create_user(email="member@example.com", password="pass123")
        CustomerMembership.objects.create(customer=self.customer, user=existing, role="viewer")
        self.client.force_login(self.staff_user)
        response = self._post({"email": "member@example.com", "role": "viewer"})
        messages_list = [str(m) for m in response.context["messages"]]
        self.assertTrue(any("already a member" in m for m in messages_list))

    def test_invalid_email_format_rejected_before_db_write(self):
        """validate_email_secure rejects malformed addresses with no DB writes."""
        baseline = User.objects.count()
        self.client.force_login(self.staff_user)
        response = self._post({"email": "notanemail", "role": "viewer"})
        messages_list = [str(m) for m in response.context["messages"]]
        self.assertTrue(any("valid email" in m.lower() or "invalid" in m.lower() for m in messages_list))
        self.assertEqual(User.objects.count(), baseline)


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class SendWelcomeInviteRateLimitTests(TestCase):
    """Per-user cache guard inside SecureCustomerUserService.send_welcome_invite."""

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(email="invitee@example.com")
        self.user.set_unusable_password()
        self.user.save()
        self.customer = Customer.objects.create(
            name="Rate Co", company_name="Rate Co", primary_email="rate@co.com", customer_type="company"
        )

    @patch("apps.users.services.SecureCustomerUserService._send_welcome_email_secure")
    def test_rate_limit_blocks_after_threshold(self, mock_send):
        """After 3 successful sends in an hour, the 4th call is rate-limited and returns False."""
        mock_send.return_value = True
        for _ in range(3):
            self.assertTrue(SecureCustomerUserService.send_welcome_invite(self.user, self.customer))
        # 4th call must be rejected by the cache guard before the helper is called.
        self.assertFalse(SecureCustomerUserService.send_welcome_invite(self.user, self.customer))
        self.assertEqual(mock_send.call_count, 3)

    @patch("apps.users.services.SecureCustomerUserService._send_welcome_email_secure")
    def test_failed_send_does_not_consume_quota(self, mock_send):
        """If the underlying send returns False, the cache counter is NOT incremented."""
        mock_send.return_value = False
        for _ in range(5):
            self.assertFalse(SecureCustomerUserService.send_welcome_invite(self.user, self.customer))
        # All 5 attempts hit the helper; the guard only counts successful sends.
        self.assertEqual(mock_send.call_count, 5)


class CustomerResendInviteTests(TestCase):
    """Recovery endpoint for users whose initial invite email failed."""

    def setUp(self):
        cache.clear()
        self.staff_user = User.objects.create_user(
            email="staff@example.com", password="staffpass", is_staff=True, staff_role="admin"
        )
        self.customer = Customer.objects.create(
            name="Resend Co", company_name="Resend Co", primary_email="resend@co.com", customer_type="company"
        )
        self.invitee = User.objects.create_user(email="invitee@example.com")
        self.invitee.set_unusable_password()
        self.invitee.save()
        CustomerMembership.objects.create(customer=self.customer, user=self.invitee, role="viewer")
        self.client = Client()
        self.url = reverse(
            "customers:resend_invite",
            kwargs={"customer_id": self.customer.id, "user_id": self.invitee.id},
        )

    def _post(self):
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=self.customer.id)
            return self.client.post(self.url, follow=True)

    @patch("apps.users.services.SecureCustomerUserService._send_welcome_email_secure")
    def test_resend_invite_for_invitee_with_unusable_password_succeeds(self, mock_send):
        mock_send.return_value = True
        self.client.force_login(self.staff_user)
        response = self._post()
        mock_send.assert_called_once()
        messages_list = [str(m) for m in response.context["messages"]]
        self.assertTrue(any("resent" in m.lower() for m in messages_list))

    @patch("apps.users.services.SecureCustomerUserService._send_welcome_email_secure")
    def test_resend_invite_blocked_for_user_with_usable_password(self, mock_send):
        """Users who already set a password should use password-reset, not resend-invite."""
        self.invitee.set_password("realpassword")
        self.invitee.save()
        self.client.force_login(self.staff_user)
        response = self._post()
        mock_send.assert_not_called()
        messages_list = [str(m) for m in response.context["messages"]]
        self.assertTrue(any("password reset" in m.lower() for m in messages_list))

    @patch("apps.users.services.SecureCustomerUserService._send_welcome_email_secure")
    def test_resend_invite_blocked_for_user_not_in_this_customer(self, mock_send):
        """Staff cannot re-invite a user who isn't a member of this customer."""
        outsider = User.objects.create_user(email="outsider@example.com")
        outsider.set_unusable_password()
        outsider.save()
        url = reverse(
            "customers:resend_invite",
            kwargs={"customer_id": self.customer.id, "user_id": outsider.id},
        )
        self.client.force_login(self.staff_user)
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=self.customer.id)
            response = self.client.post(url, follow=True)
        mock_send.assert_not_called()
        messages_list = [str(m) for m in response.context["messages"]]
        self.assertTrue(any("not a member" in m for m in messages_list))


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
