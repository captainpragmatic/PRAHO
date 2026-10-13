"""The enrolment API the Portal calls: one pending secret, the password, and the browser's own address (#689).

- Setup wrote a new secret onto the user row on every call, so the Portal page shown again
  after one mistyped code carried a different secret from the one the customer had scanned.
  It now offers the pending enrolment's secret until it is confirmed or expires.
- Verify took only the code, so a hijacked Portal session could enrol its own authenticator.
  It now needs the current password, with one answer for a wrong password and a wrong code.
- Audit rows for enrolling, disabling and regenerating recorded the Portal server's address;
  they now record the address and user agent of the customer's browser, sent in the signed body.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pyotp
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User
from apps.users.pending_totp import PendingTOTPEnrolment
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

PASSWORD = "Original-secure123!"  # test fixture, not a credential
BROWSER_IP = "198.51.100.23"
BROWSER_AGENT = "Mozilla/5.0 (Customer Browser 1.0)"
INCORRECT = "The password or the code is incorrect."


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class MFAEnrolmentAPITests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="owner@example.com", password=PASSWORD)
        self.customer = Customer.objects.create(name="Enrolment Co", customer_type="company", status="active")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_primary=True)

    def call(self, suffix: str, **data: Any) -> Any:
        body = {"user_id": self.user.pk, "customer_id": self.customer.pk, **data}
        return self.portal_post("/api/users/" + suffix, body)

    def setup_secret(self) -> str:
        response = self.call("mfa/setup/")
        self.assertEqual(response.status_code, 200, response.content)
        return str(response.json()["setup_data"]["manual_entry_key"])

    def test_setup_offers_one_secret_and_keeps_it_off_the_user_row(self) -> None:
        secret = self.setup_secret()
        self.assertEqual(self.setup_secret(), secret)
        self.user.refresh_from_db()
        self.assertEqual(self.user._two_factor_secret, "")
        self.assertEqual(PendingTOTPEnrolment.objects.get(user=self.user).secret(), secret)

    def test_verify_needs_the_current_password(self) -> None:
        secret = self.setup_secret()
        missing = self.call("mfa/verify/", token=pyotp.TOTP(secret).now())
        self.assertEqual(missing.status_code, 400)
        self.assertIn("password", missing.json())
        for data in (
            {"password": "not-the-password", "token": pyotp.TOTP(secret).now()},
            {"password": PASSWORD, "token": "000000"},
        ):
            with self.subTest(data=data):
                response = self.call("mfa/verify/", **data)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()["error"], INCORRECT)
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_enabled)
        # A wrong attempt leaves the scanned secret in place.
        self.assertEqual(self.setup_secret(), secret)

    def test_the_right_password_and_code_enrol_once(self) -> None:
        secret = self.setup_secret()
        response = self.call("mfa/verify/", password=PASSWORD, token=pyotp.TOTP(secret).now())
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(len(response.json()["backup_codes"]), 8)
        self.user.refresh_from_db()
        self.assertTrue(self.user.mfa_enabled)
        self.assertEqual(response.json()["session_auth_hash"], self.user.get_session_auth_hash())
        self.assertFalse(PendingTOTPEnrolment.objects.filter(user=self.user).exists())

        again = self.call("mfa/verify/", password=PASSWORD, token="123456")
        self.assertEqual(again.status_code, 400)
        self.assertEqual(again.json()["code"], "mfa_already_enabled")

    def test_an_eight_digit_code_cannot_finish_setup(self) -> None:
        self.setup_secret()
        response = self.call("mfa/verify/", password=PASSWORD, token="11111111")
        self.assertEqual(response.status_code, 400)
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_enabled)

    def test_an_expired_setup_says_so(self) -> None:
        secret = self.setup_secret()
        later = timezone.now() + timedelta(minutes=16)
        with patch("apps.users.pending_totp.timezone.now", return_value=later):
            response = self.call("mfa/verify/", password=PASSWORD, token=pyotp.TOTP(secret).now())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], "mfa_setup_expired")

    def test_audit_rows_name_the_customers_browser(self) -> None:
        browser = {"client_ip": BROWSER_IP, "client_user_agent": BROWSER_AGENT}
        secret = self.setup_secret()
        enrolled = self.call("mfa/verify/", password=PASSWORD, token=pyotp.TOTP(secret).now(), **browser)
        codes = enrolled.json()["backup_codes"]
        self.call("mfa/regenerate-backup-codes/", password=PASSWORD, token=codes[0], **browser)
        self.user.refresh_from_db()
        fresh_code = self.user.generate_backup_codes()[0]
        self.call("mfa/disable/", password=PASSWORD, token=fresh_code, **browser)

        for action in ("2fa_enabled", "2fa_backup_codes_generated", "2fa_disabled"):
            with self.subTest(action=action):
                event = AuditEvent.objects.filter(user=self.user, action=action).latest("timestamp")
                self.assertEqual(event.ip_address, BROWSER_IP)
                self.assertEqual(event.user_agent, BROWSER_AGENT)
