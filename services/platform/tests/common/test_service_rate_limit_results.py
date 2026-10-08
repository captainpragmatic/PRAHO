"""Rate-limit metadata survives the security wrapper without changing Result contracts."""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.common.security_decorators import SecurityConfig, secure_customer_operation, secure_service_method
from apps.common.types import Err, Ok, Result
from apps.customers.models import Customer
from apps.settings.services import SettingsService
from apps.users.models import CustomerMembership, User
from apps.users.services import SecureCustomerUserService, SecureUserRegistrationService, UserInvitationRequest


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class ServiceRateLimitResultTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_registration_refusal_is_a_typed_string_inside_err(self) -> None:
        stored = SettingsService.update_setting("security.registration_rate_limit_per_ip", 0)
        self.assertTrue(stored.is_ok(), stored)
        result = SecureUserRegistrationService.register_new_customer_owner(
            user_data={}, customer_data={}, request_ip="198.51.100.30"
        )
        self.assertIsInstance(result, Err)
        error = result.unwrap_err()
        self.assertIsInstance(error, str)
        self.assertEqual(getattr(error, "status_code", None), 429)
        self.assertEqual(getattr(error, "retry_after", None), 3600)
        self.assertEqual(error, "Too many registration attempts. Please try again later.")
        self.assertFalse(User.objects.exists())
        self.assertFalse(Customer.objects.exists())

    def test_registration_store_failure_is_a_distinct_typed_err(self) -> None:
        with patch("apps.common.security_decorators.counters.increment", side_effect=RuntimeError("store offline")):
            result = SecureUserRegistrationService.register_new_customer_owner(
                user_data={}, customer_data={}, request_ip="198.51.100.31"
            )
        self.assertIsInstance(result, Err)
        error = result.unwrap_err()
        self.assertIsInstance(error, str)
        self.assertEqual(getattr(error, "status_code", None), 503)
        self.assertIsNone(getattr(error, "retry_after", None))
        self.assertFalse(User.objects.exists())
        self.assertFalse(Customer.objects.exists())

    def test_invitation_and_legacy_caller_keep_result_string_contracts(self) -> None:
        customer = Customer.objects.create(name="FX Invite", company_name="FX Invite")
        owner = User.objects.create_user(email="owner@example.test", password="CorrectHorse12!")
        CustomerMembership.objects.create(customer=customer, user=owner, role="owner", is_primary=True)
        stored = SettingsService.update_setting("security.membership_invitation_limit_per_inviter_per_hour", 0)
        self.assertTrue(stored.is_ok(), stored)
        before = (User.objects.count(), CustomerMembership.objects.count())
        request = UserInvitationRequest(
            inviter=owner,
            invitee_email="blocked@example.test",
            customer=customer,
            role="viewer",
            request_ip="198.51.100.32",
        )
        results = (
            SecureCustomerUserService.invite_user_to_customer(request),
            SecureCustomerUserService.invite_user_to_customer_legacy(
                owner, "legacy@example.test", customer, request_ip="198.51.100.33"
            ),
        )
        for result in results:
            self.assertIsInstance(result, Err)
            error = result.unwrap_err()
            self.assertIsInstance(error, str)
            self.assertEqual(getattr(error, "status_code", None), 429)
            self.assertEqual(getattr(error, "retry_after", None), 3600)
            self.assertEqual(error, "Rate limit exceeded")
        self.assertEqual((User.objects.count(), CustomerMembership.objects.count()), before)

    def test_customer_operation_wrappers_keep_results_when_a_limit_is_configured(self) -> None:
        accepted: list[str] = []

        @secure_customer_operation()
        def operation(*, request_ip: str) -> Result[str, str]:
            accepted.append(request_ip)
            return Ok("accepted")

        first = operation(request_ip="198.51.100.34")
        self.assertIsInstance(first, Ok)
        self.assertEqual(first.unwrap(), "accepted")

        limited_operation = secure_service_method(
            SecurityConfig(
                rate_limit_key="customer_operation",
                rate_limit=0,
                log_attempts=False,
                prevent_timing_attacks=False,
            )
        )(operation)
        refused = limited_operation(request_ip="198.51.100.35")
        self.assertIsInstance(refused, Err)
        error = refused.unwrap_err()
        self.assertIsInstance(error, str)
        self.assertEqual(getattr(error, "status_code", None), 429)
        self.assertEqual(getattr(error, "retry_after", None), 3600)
        self.assertEqual(accepted, ["198.51.100.34"])
