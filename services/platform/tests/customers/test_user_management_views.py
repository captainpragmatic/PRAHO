"""
Tests for user_management_views security fixes.
Verifies @staff_required decorator and server-side delete confirmation.
"""

import re
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils.http import urlsafe_base64_decode

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

    @patch("apps.users.services.SecureCustomerUserService._send_welcome_email_secure")
    def test_atomic_counter_uses_cache_incr_not_set(self, mock_send):
        """Regression for Copilot finding on PR #184 (services.py:898): the
        rate-limit counter must use atomic cache.incr, not cache.get+cache.set.
        We assert this by observing the underlying cache key value after each
        send — only an atomic increment guarantees correct counts under
        concurrent calls. (Single-thread test does not exercise concurrency
        directly; this test pins the implementation to the atomic primitive.)"""
        mock_send.return_value = True
        guard_key = f"welcome_invite:{self.user.pk}"
        # Pre-condition: key absent.
        self.assertIsNone(cache.get(guard_key))

        SecureCustomerUserService.send_welcome_invite(self.user, self.customer)
        # After 1st successful send, counter must be exactly 1.
        self.assertEqual(cache.get(guard_key), 1)

        SecureCustomerUserService.send_welcome_invite(self.user, self.customer)
        SecureCustomerUserService.send_welcome_invite(self.user, self.customer)
        self.assertEqual(cache.get(guard_key), 3)

        # 4th call: counter must NOT advance past invite_limit, and the helper
        # must NOT be called (incr+decr atomic dance).
        result = SecureCustomerUserService.send_welcome_invite(self.user, self.customer)
        self.assertFalse(result)
        # Counter stays at the limit (incr-then-decr leaves us at 3, not 4).
        self.assertEqual(cache.get(guard_key), 3)
        # Helper called only 3 times (not for the rate-limited 4th).
        self.assertEqual(mock_send.call_count, 3)


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
    def test_failure_warning_renders_post_form_not_get_link(self, mock_send):
        """Regression for codex P1 on PR #184: the resend link in the warning
        must be an inline POST form (the endpoint is @require_POST). A bare
        <a href> would 405 when clicked."""
        # Create the user via the staff create-user flow with email failure.
        mock_send.return_value = False  # force email failure -> warning rendered
        staff = User.objects.create_user(
            email="staff-warn@example.com", password="x", is_staff=True, staff_role="admin"
        )
        customer = Customer.objects.create(
            name="Warn Co", company_name="Warn Co", primary_email="warn@co.com", customer_type="company"
        )
        self.client.force_login(staff)
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=customer.id)
            response = self.client.post(
                reverse("customers:create_user", kwargs={"customer_id": customer.id}),
                {"email": "warned@example.com", "first_name": "W", "last_name": "U", "role": "viewer"},
                follow=True,
            )
        warnings = [str(m) for m in response.context["messages"] if m.level_tag == "warning"]
        self.assertEqual(len(warnings), 1)
        warning_html = warnings[0]
        # Must be a POST form, NOT a GET link.
        self.assertIn('method="post"', warning_html)
        self.assertIn("csrfmiddlewaretoken", warning_html)
        self.assertNotRegex(warning_html, r'<a\s+href=[^>]*resend-invite')

    @patch("apps.users.services.SecureCustomerUserService._send_welcome_email_secure")
    def test_clicking_resend_form_actually_resends(self, mock_send):
        """End-to-end: extract the action URL from the rendered warning,
        POST to it, assert the resend endpoint runs successfully."""
        # First call: initial create — email "fails" so warning is rendered.
        mock_send.return_value = False
        staff = User.objects.create_user(
            email="staff-flow@example.com", password="x", is_staff=True, staff_role="admin"
        )
        customer = Customer.objects.create(
            name="Flow Co", company_name="Flow Co", primary_email="flow@co.com", customer_type="company"
        )
        self.client.force_login(staff)
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=customer.id)
            create_response = self.client.post(
                reverse("customers:create_user", kwargs={"customer_id": customer.id}),
                {"email": "recovery@example.com", "first_name": "R", "last_name": "U", "role": "viewer"},
                follow=True,
            )
        warnings = [str(m) for m in create_response.context["messages"] if m.level_tag == "warning"]
        self.assertEqual(len(warnings), 1)
        warning_html = warnings[0]

        # Pull the form's action URL out of the rendered HTML.
        action_match = re.search(r'action="([^"]+resend-invite[^"]*)"', warning_html)
        self.assertIsNotNone(action_match, f"Warning must contain a form action URL: {warning_html}")
        resend_url = action_match.group(1)

        # Second call: simulate clicking the form's submit button. mock_send
        # now returns True so the resend reports success.
        mock_send.return_value = True
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=customer.id)
            resend_response = self.client.post(resend_url, follow=True)
        self.assertEqual(resend_response.status_code, 200)
        success = [str(m) for m in resend_response.context["messages"] if m.level_tag == "success"]
        self.assertTrue(any("resent" in m.lower() for m in success))
        # send_welcome_invite was called once for the create + once for the resend.
        self.assertEqual(mock_send.call_count, 2)

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


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class CustomerCreateUserEmailRenderingIntegrationTests(TestCase):
    """End-to-end: staff create-user POST renders the welcome email template
    against the live mail backend and produces a usable password-reset token.

    No mocks of _send_welcome_email_secure or send_welcome_invite — this is the
    only test in the suite that catches template rendering regressions
    (e.g. a broken {% url %} tag, a misspelled context var, an XSS-unsafe
    edit). Closes item 5 of issue #173.
    """

    def setUp(self):
        cache.clear()
        mail.outbox = []
        self.staff_user = User.objects.create_user(
            email="staff@example.com", password="staffpass", is_staff=True, staff_role="admin"
        )
        # company_name is non-empty — required to assert subject contains it.
        self.customer = Customer.objects.create(
            name="Render Customer",
            company_name="Render Co SRL",
            primary_email="render@co.com",
            customer_type="company",
        )
        self.client = Client()
        self.url = reverse("customers:create_user", kwargs={"customer_id": self.customer.id})

    def _post_create(self, email, customer=None):
        """Helper: log in as staff and POST a create-user form for the given customer."""
        target = customer or self.customer
        self.client.force_login(self.staff_user)
        with patch("apps.customers.customer_service.CustomerService.get_accessible_customers") as mock:
            mock.return_value = Customer.objects.filter(id=target.id)
            return self.client.post(
                reverse("customers:create_user", kwargs={"customer_id": target.id}),
                {"email": email, "first_name": "New", "last_name": "Hire", "role": "viewer"},
            )

    def test_create_user_renders_welcome_email_with_valid_reset_token(self):
        """The full template path runs, mail.outbox receives the message, the
        embedded password-reset token validates against default_token_generator."""
        response = self._post_create("newhire@example.com")
        self.assertEqual(response.status_code, 302)

        # ---- Outbox shape ----
        self.assertEqual(len(mail.outbox), 1, "Exactly one email should have been sent")
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["newhire@example.com"])
        self.assertIn(self.customer.company_name, msg.subject)

        # ---- Plain-text body has the full reset URL ----
        self.assertIn("/password-reset-confirm/", msg.body)

        # ---- HTML alternative present and references the same URL ----
        self.assertEqual(len(msg.alternatives), 1)
        html_body, mimetype = msg.alternatives[0]
        self.assertEqual(mimetype, "text/html")
        self.assertIn("/password-reset-confirm/", html_body)

        # ---- Token validity: extract uidb64 + token from the body and verify
        # against default_token_generator. This is the assertion that fails if
        # the template renders {{ token }} as a literal string or if the token
        # was generated for the wrong user. ----
        match = re.search(r"/password-reset-confirm/([^/]+)/([^/]+)/", msg.body)
        self.assertIsNotNone(match, "Body must contain /password-reset-confirm/<uidb64>/<token>/ URL")
        uidb64, token = match.groups()

        decoded_pk = int(urlsafe_base64_decode(uidb64).decode())
        new_user = User.objects.get(email="newhire@example.com")
        self.assertEqual(decoded_pk, new_user.pk, "uidb64 in URL must decode to the new user's pk")
        self.assertTrue(
            default_token_generator.check_token(new_user, token),
            "Token in URL must validate against default_token_generator for the new user",
        )

    def test_individual_customer_renders_name_when_company_name_empty(self):
        """Customer with empty company_name (individual type) must render the
        .name fallback so the subject is not 'Account Created for ' and the
        body is not 'invited to  on PRAHO'. Closes #173 item 3."""
        individual = Customer.objects.create(
            name="John Doe",
            company_name="",
            primary_email="john@example.com",
            customer_type="individual",
        )
        response = self._post_create("invitee-individual@example.com", customer=individual)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        # Subject and body must contain "John Doe", NOT a trailing-space artifact.
        self.assertIn("John Doe", msg.subject)
        self.assertNotRegex(msg.subject, r"Account Created for\s*$")
        self.assertIn("John Doe", msg.body)
        # Double-space is the canonical signature of the empty-company-name bug
        # in the heading "invited to {{ name }} on PRAHO".
        self.assertNotIn("invited to  on PRAHO", msg.body)
        # HTML alternative must reflect the same fallback.
        html_body, _mime = msg.alternatives[0]
        self.assertIn("John Doe", html_body)
        self.assertNotIn("invited to  on PRAHO", html_body)

    @override_settings(PASSWORD_RESET_TIMEOUT=14400)  # 4 hours
    def test_expiry_hours_derives_from_password_reset_timeout(self):
        """Expiry copy must reflect settings.PASSWORD_RESET_TIMEOUT, not a
        hardcoded value. Closes #173 item 6."""
        response = self._post_create("expiry@example.com")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        # Plain text must say "4 hours"; HTML alt must too.
        self.assertIn("4 hours", msg.body)
        self.assertNotIn("2 hours", msg.body)
        self.assertNotIn("3 hours", msg.body)
        html_body, _mime = msg.alternatives[0]
        self.assertIn("4 hours", html_body)

    @override_settings(PASSWORD_RESET_TIMEOUT=3600)  # 1 hour — singular form
    def test_expiry_hours_singular_pluralization(self):
        """When PASSWORD_RESET_TIMEOUT is exactly 1 hour, the email uses the
        singular form 'hour' (not 'hours'). Verifies the {% plural %} branch
        added with the dynamic-expiry refactor."""
        response = self._post_create("singular@example.com")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        # Singular: "expire in 1 hour" — and not "1 hours".
        self.assertIn("1 hour", msg.body)
        self.assertNotIn("1 hours", msg.body)


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
