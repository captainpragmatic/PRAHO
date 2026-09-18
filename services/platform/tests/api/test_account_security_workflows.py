"""Real signed account mutations, including non-coincident user/customer IDs."""

import json
import time

import pyotp
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.customers.models import Customer
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin, hmac_headers


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class AccountSecurityWorkflows(HMACTestMixin, TestCase):
    def setUp(self):
        cache.clear()
        self.other = User.objects.create_user(email="other@example.com", password="Other-secure123!")
        self.user = User.objects.create_user(email="owner@example.com", password="Original-secure123!")
        self.customer = Customer.objects.create(name="Security Company", customer_type="company", status="active")
        CustomerMembership.objects.create(user=self.other, customer=self.customer, role="owner")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_primary=True)

    def request_security(self, suffix, **data):
        return self.portal_post(
            "/api/users/" + suffix, {"user_id": self.user.pk, "customer_id": self.customer.pk, **data}
        )

    def test_customer_switch_requires_current_active_membership(self):
        path = "verify-customer-access/"
        response = self.request_security(path)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["data"],
            {
                "has_access": True,
                "customer_name": self.customer.name,
                "role": "owner",
            },
        )
        foreign = Customer.objects.create(name="Private company", customer_type="company")
        for customer_id in (foreign.pk, foreign.pk + 1000):
            response = self.request_security(path, customer_id=customer_id)
            self.assertEqual(response.json(), {"success": True, "data": {"has_access": False}})
        CustomerMembership.objects.filter(user=self.user).update(is_active=False)
        response = self.request_security(path)
        self.assertEqual(response.json()["data"], {"has_access": False})
        self.assertEqual(self.request_security(path, customer_id="invalid").status_code, 400)
        response = self.client.post("/api/users/" + path, {"user_id": self.user.pk, "customer_id": self.customer.pk})
        self.assertIn(response.status_code, (401, 403))

    def enroll(self):
        response = self.request_security("mfa/setup/")
        self.assertEqual(response.status_code, 200, response.content)
        secret = response.json()["setup_data"]["manual_entry_key"]
        self.other.refresh_from_db()
        self.assertEqual(self.other.two_factor_secret, "")
        response = self.request_security("mfa/verify/", token=pyotp.TOTP(secret).now())
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.assertTrue(self.user.mfa_enabled)
        codes = response.json()["backup_codes"]
        self.assertEqual(len(codes), 8)
        self.assertEqual(len(set(codes)), 8)
        self.assertTrue(all(code not in self.user.backup_tokens for code in codes))
        return secret, codes

    def change_password(self, **overrides):
        path = "/api/users/change-password/"
        data = {
            "user_id": self.user.pk,
            "current_password": "Original-secure123!",
            "new_password": "Replacement-secure123!",
            "timestamp": time.time(),
            **overrides,
        }
        body = json.dumps(data).encode()
        return self.client.put(path, body, content_type="application/json", **hmac_headers("PUT", path, body))

    @override_settings(ACCOUNT_LOCKOUT_THRESHOLD=5)
    def test_password_change_checks_current_password_and_preserves_other_user(self):
        self.assertEqual(self.change_password(current_password="wrong").status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Original-secure123!"))
        response = self.change_password()
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.other.refresh_from_db()
        self.assertTrue(self.user.check_password("Replacement-secure123!"))
        self.assertTrue(self.other.check_password("Other-secure123!"))

    def test_password_policy_and_unsigned_mutations_fail_closed(self):
        self.assertEqual(self.change_password(new_password="123").status_code, 400)
        response = self.client.put("/api/users/change-password/", "{}", content_type="application/json")
        self.assertIn(response.status_code, (401, 403))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Original-secure123!"))

    def test_enrollment_identity_status_and_duplicate_verification(self):
        secret, codes = self.enroll()
        response = self.request_security("mfa/status/")
        self.assertEqual(response.json(), {"success": True, "enabled": True, "backup_codes_remaining": 8})
        self.assertNotIn(secret, response.content.decode())
        self.assertNotIn(codes[0], response.content.decode())
        self.assertEqual(self.request_security("mfa/verify/", token=pyotp.TOTP(secret).now()).status_code, 400)

    def test_wrong_setup_code_is_validation_error_without_enrollment(self):
        self.request_security("mfa/setup/")
        response = self.request_security("mfa/verify/", token="11111111")
        self.assertEqual(response.status_code, 400, response.content)
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_enabled)

    def test_recovery_code_regeneration_rejects_totp_replay(self):
        secret, _ = self.enroll()
        token = pyotp.TOTP(secret).now()
        first = self.request_security("mfa/regenerate-backup-codes/", password="Original-secure123!", token=token)
        self.assertEqual(first.status_code, 200, first.content)
        codes = first.json()["backup_codes"]
        second = self.request_security("mfa/regenerate-backup-codes/", password="Original-secure123!", token=token)
        self.assertEqual(second.status_code, 400)
        response = self.request_security("mfa/disable/", password="Original-secure123!", token=codes[0])
        self.assertEqual(response.status_code, 200, response.content)

    @override_settings(ACCOUNT_LOCKOUT_THRESHOLD=5)
    def test_login_requires_second_factor_and_recovery_code_is_single_use(self):
        _, codes = self.enroll()
        credentials = {"email": self.user.email, "password": "Original-secure123!"}
        self.assertEqual(self.portal_post("/api/users/login/", credentials.copy()).status_code, 401)
        response = self.portal_post("/api/users/login/", {**credentials, "mfa_token": codes[0]})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["user"]["id"], self.user.pk)
        self.assertEqual(self.portal_post("/api/users/login/", {**credentials, "mfa_token": codes[0]}).status_code, 401)
        self.user.refresh_from_db()
        self.assertEqual(len(self.user.backup_tokens), 7)

    def test_disable_requires_password_and_code(self):
        _, codes = self.enroll()
        self.assertEqual(self.request_security("mfa/disable/", password="wrong", token=codes[0]).status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(self.user.mfa_enabled)
        response = self.request_security("mfa/disable/", password="Original-secure123!", token=codes[0])
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.assertFalse(self.user.mfa_enabled)
        self.assertEqual(self.user.two_factor_secret, "")
        self.assertEqual(self.user.backup_tokens, [])

    def test_regeneration_invalidates_previous_codes(self):
        _, codes = self.enroll()
        response = self.request_security("mfa/regenerate-backup-codes/", password="Original-secure123!", token=codes[0])
        self.assertEqual(response.status_code, 200, response.content)
        self.user.refresh_from_db()
        self.assertFalse(self.user.verify_backup_code(codes[1]))
        self.assertTrue(self.user.verify_backup_code(response.json()["backup_codes"][0]))

    def test_password_change_requires_second_factor_if_enabled(self):
        _, codes = self.enroll()
        self.assertEqual(self.change_password().status_code, 400)
        self.assertEqual(self.change_password(token=codes[0]).status_code, 200)

    def test_wrong_current_password_applies_account_lockout(self):
        self.assertEqual(self.change_password(current_password="wrong").status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_account_locked())
        self.assertEqual(self.change_password().status_code, 400)
