"""Tests for the three distinct invitation-related rate-limit policies."""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.customers.models import Customer
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from apps.users.services import SecureCustomerUserService, SecureUserRegistrationService, UserInvitationRequest

LOCMEM_TEST_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class InvitationRateLimitPolicyTests(TestCase):
    """Each policy is independently configurable at its real enforcement boundary."""

    def setUp(self) -> None:
        cache.clear()
        self.customer = Customer.objects.create(
            name="Invite Customer",
            company_name="Invite Customer",
            primary_email="customer@example.test",
            customer_type="company",
        )
        self.owner = User.objects.create_user(email="owner@example.test", password="owner-password")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)

    @patch("apps.users.services._render_and_send_welcome_email", return_value=True)
    def test_membership_invitation_limit_follows_inviter_across_source_ips(self, _mock_send) -> None:
        result = SettingsService.update_setting(
            "security.membership_invitation_limit_per_inviter_per_hour",
            1,
        )
        self.assertTrue(result.is_ok(), result)
        first = UserInvitationRequest(
            inviter=self.owner,
            invitee_email="first@example.test",
            customer=self.customer,
            role="viewer",
            request_ip="192.0.2.10",
        )
        second = UserInvitationRequest(
            inviter=self.owner,
            invitee_email="second@example.test",
            customer=self.customer,
            role="viewer",
            request_ip="192.0.2.11",
        )

        self.assertTrue(SecureCustomerUserService.invite_user_to_customer(first).is_ok())
        self.assertTrue(SecureCustomerUserService.invite_user_to_customer(second).is_err())
        self.assertFalse(User.objects.filter(email="second@example.test").exists())

    def test_zero_membership_invitation_limit_blocks_the_first_attempt(self) -> None:
        result = SettingsService.update_setting(
            "security.membership_invitation_limit_per_inviter_per_hour",
            0,
        )
        self.assertTrue(result.is_ok(), result)
        request = UserInvitationRequest(
            inviter=self.owner,
            invitee_email="blocked@example.test",
            customer=self.customer,
            role="viewer",
            request_ip="192.0.2.12",
        )

        self.assertTrue(SecureCustomerUserService.invite_user_to_customer(request).is_err())
        self.assertFalse(User.objects.filter(email="blocked@example.test").exists())

    @patch("apps.users.services.SecureCustomerUserService._send_welcome_email_secure", return_value=True)
    def test_welcome_resend_limit_is_scoped_to_target(self, mock_send) -> None:
        invitee = User.objects.create_user(email="target@example.test")
        result = SettingsService.update_setting("security.welcome_invite_limit_per_target_per_hour", 1)
        self.assertTrue(result.is_ok(), result)

        self.assertTrue(SecureCustomerUserService.send_welcome_invite(invitee, self.customer))
        self.assertFalse(SecureCustomerUserService.send_welcome_invite(invitee, self.customer))
        self.assertEqual(mock_send.call_count, 1)

    @patch("apps.users.services.send_mail")
    def test_zero_join_request_notification_limit_blocks_owner_email(self, mock_send_mail) -> None:
        requester = User.objects.create_user(email="requester@example.test")
        result = SettingsService.update_setting(
            "security.join_request_notification_limit_per_customer_per_hour",
            0,
        )
        self.assertTrue(result.is_ok(), result)

        SecureUserRegistrationService._notify_owners_of_join_request_secure(
            self.customer,
            requester,
            request_ip="192.0.2.20",
        )

        mock_send_mail.assert_not_called()
