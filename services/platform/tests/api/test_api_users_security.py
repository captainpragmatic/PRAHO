"""
Regression tests for platform API user security fixes.

Covers:
- Token revocation requires TokenAuthentication (#60)
- Account lockout in obtain_token (#53)
- Email PII masked in auth failure logs (#54)
- HMAC exempt paths use exact match, not startswith (#61)
"""

import logging
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.common.middleware import _is_auth_exempt
from apps.customers.models import Customer
from apps.users.models import APIToken, CustomerMembership
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

User = get_user_model()


def _make_token(user, name="test"):
    """Create an APIToken and return (token, raw_key) for test setup."""
    raw_key = APIToken.generate_key()
    token = APIToken.objects.create(
        user=user,
        key_hash=APIToken.hash_key(raw_key),
        key_prefix=raw_key[:8],
        name=name,
    )
    return token, raw_key


# ===============================================================================
# TOKEN REVOCATION TESTS (#60)
# ===============================================================================


class TokenRevocationTests(TestCase):
    """Revoke endpoint must require TokenAuthentication; no side-channel leaks."""

    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="revoke@example.com",
            password="StrongPass123!",
            first_name="Revoke",
            last_name="User",
        )
        self.url = "/api/users/token/revoke/"

    def test_revoke_token_requires_authentication(self) -> None:
        """Unauthenticated DELETE to revoke endpoint must return 401."""
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, 401)

    def test_revoke_token_self_revocation_deletes_token(self) -> None:
        """Authenticated DELETE with own token in Authorization header deletes the token."""
        token, raw_key = _make_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {raw_key}")

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, 200)
        # Token must be gone from DB after successful revocation
        self.assertFalse(APIToken.objects.filter(pk=token.pk).exists())

    def test_revoke_token_success_returns_message(self) -> None:
        """Successful revocation response body must contain the expected message key."""
        _token, raw_key = _make_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {raw_key}")

        response = self.client.delete(self.url)
        data = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertIn("message", data)
        self.assertEqual(data["message"], "Token revoked successfully")

    def test_revoke_token_post_rejected_with_405(self) -> None:
        """POST to revoke endpoint must return 405 — regression guard for the old verb.

        Before #60, the endpoint accepted POST with a body token. Ensuring 405 here
        prevents accidental reintroduction of the insecure pattern.
        """
        token, raw_key = _make_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {raw_key}")

        response = self.client.post(self.url, data={"token": raw_key}, format="json")

        self.assertEqual(response.status_code, 405)
        # Token must still exist — the POST must not have deleted anything
        self.assertTrue(APIToken.objects.filter(pk=token.pk).exists())

    def test_revoke_token_uses_header_token_not_body(self) -> None:
        """Revocation must use request.auth (header token), ignoring any body payload.

        A request authenticated as user_a that includes user_b's token key in the
        body must only revoke user_a's token.
        """
        user_b = User.objects.create_user(
            email="other@example.com",
            password="StrongPass123!",
            first_name="Other",
            last_name="User",
        )
        token_a, key_a = _make_token(self.user, name="token-a")
        token_b, key_b = _make_token(user_b, name="token-b")

        # Authenticate as user_a but include user_b's key in the body
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {key_a}")
        response = self.client.delete(self.url, data={"token": key_b}, format="json")

        self.assertEqual(response.status_code, 200)
        # user_a's token is gone — the body was ignored
        self.assertFalse(APIToken.objects.filter(pk=token_a.pk).exists())
        # user_b's token is untouched
        self.assertTrue(APIToken.objects.filter(pk=token_b.pk).exists())


# ===============================================================================
# ACCOUNT LOCKOUT TESTS (#53)
# ===============================================================================


class AccountLockoutTokenTests(TestCase):
    """obtain_token must integrate with account lockout model methods."""

    def setUp(self) -> None:
        self.client = APIClient()
        self.password = "StrongPass123!"
        self.user = User.objects.create_user(
            email="lockout@example.com",
            password=self.password,
            first_name="Lock",
            last_name="Out",
        )
        self.url = "/api/users/token/"

    def test_obtain_token_failed_login_does_not_touch_the_account_lockout_counter(self) -> None:
        """Inverted deliberately. This asserted the opposite until the counter was removed.

        Driving the lockout from a PUBLIC endpoint made it an unauthenticated weapon: five
        wrong passwords for a known address locked that account across every login path,
        with no credentials and nothing to attribute the attempt to. The per-account
        budget in TokenRequestAccountThrottle replaces it, keyed on the submitted address
        so it binds without a populated trusted-proxy list. The full reasoning and the
        replacement's own coverage live in tests/api/test_token_endpoint_lockout.py.
        """
        response = self.client.post(
            self.url,
            {"email": self.user.email, "password": "WRONG_PASSWORD"},
            format="json",
        )

        self.assertEqual(response.status_code, 401, "a wrong password must still be rejected")
        self.user.refresh_from_db()
        self.assertEqual(
            self.user.failed_login_attempts,
            0,
            "the public endpoint is driving the account lockout again",
        )

    def test_obtain_token_locked_account_returns_invalid_credentials(self) -> None:
        """Locked account must return the same 401 'Invalid credentials' as a bad password.

        Attacker must not be able to distinguish locked account from wrong password.
        """
        self.user.account_locked_until = timezone.now() + timedelta(minutes=30)
        self.user.failed_login_attempts = 1
        self.user.save()

        response = self.client.post(
            self.url,
            {"email": self.user.email, "password": self.password},
            format="json",
        )

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data.get("error"), "Invalid credentials")

    def test_obtain_token_success_resets_failed_attempts(self) -> None:
        """Successful authentication must reset failed_login_attempts to 0."""
        # Seed some prior failures
        self.user.failed_login_attempts = 2
        # Ensure account is not locked so the successful login can proceed
        self.user.account_locked_until = timezone.now() - timedelta(minutes=10)
        self.user.save()

        response = self.client.post(
            self.url,
            {"email": self.user.email, "password": self.password},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)
        self.assertIsNone(self.user.account_locked_until)

    def test_obtain_token_response_excludes_is_staff(self) -> None:
        """Token response body must NOT leak the is_staff boolean.

        Exposing is_staff allows attackers to enumerate staff accounts.
        """
        response = self.client.post(
            self.url,
            {"email": self.user.email, "password": self.password},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertNotIn("is_staff", data)


# ===============================================================================
# TOKEN INFO ENDPOINT (ADR-0031 Gap 1 fix)
# ===============================================================================


class TokenInfoTests(TestCase):
    """GET /api/users/token/me/ must use TokenAuthentication, not HMAC."""

    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="tokeninfo@example.com",
            password="StrongPass123!",
            first_name="Token",
            last_name="Info",
        )
        self.url = "/api/users/token/me/"

    def test_token_info_requires_token_auth(self) -> None:
        """Unauthenticated GET must return 401."""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 401)

    def test_token_info_returns_caller_identity(self) -> None:
        """Authenticated GET returns user_id, staff_role, and created_at."""
        _token, raw_key = _make_token(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {raw_key}")

        response = self.client.get(self.url)
        data = response.json()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(data["user_id"], self.user.id)
        self.assertIn("created_at", data)
        self.assertIn("staff_role", data)

    def test_token_info_does_not_require_hmac_headers(self) -> None:
        """No portal HMAC headers needed — pure token auth is sufficient."""
        _token, raw_key = _make_token(self.user)
        # Only set Authorization header, no X-Portal-Id, X-Signature, etc.
        self.client.credentials(HTTP_AUTHORIZATION=f"Token {raw_key}")

        response = self.client.get(self.url)

        self.assertEqual(
            response.status_code,
            200,
            msg="token/me/ must not require HMAC headers — it is for CLI/script consumers",
        )


# ===============================================================================
# EMAIL PII MASKING IN LOGS (#54)
# ===============================================================================


class AuthEmailMaskingTests(TestCase):
    """Failed auth must not write the raw email address to any log record."""

    def setUp(self) -> None:
        self.client = APIClient()
        self.raw_email = "sensitiveuser@example.com"
        self.url = "/api/users/token/"

    def test_auth_failure_does_not_log_raw_email(self) -> None:
        """A failed token request must not emit the raw email in any log output."""
        with self.assertLogs("apps.api.users.views", level=logging.WARNING) as cm:
            self.client.post(
                self.url,
                {"email": self.raw_email, "password": "WRONG"},
                format="json",
            )

        # None of the captured log messages should contain the raw email string
        for record_message in cm.output:
            self.assertNotIn(
                self.raw_email,
                record_message,
                msg=f"Raw email found in log: {record_message!r}",
            )


# ===============================================================================
# HMAC EXEMPT PATHS EXACT MATCH (#61)
# ===============================================================================


class HMACExemptPathsExactMatchTests(TestCase):
    """Exemption must be exact, not prefix-based.

    A path like /api/users/health/extra/ must NOT bypass HMAC validation even though it
    starts with /api/users/health/ (which IS exempt).

    The guarantees are unchanged; only the argument is. Exemption is now derived from
    the resolved view's @public_api_endpoint marker rather than a hand-kept path list,
    so the helper takes the request.
    """

    def _request(self, path: str) -> HttpRequest:
        return RequestFactory().get(path)

    def test_hmac_middleware_exempt_paths_exact_match(self) -> None:
        """Path that starts-with but is not an exact match must NOT be exempt."""
        extended_path = "/api/users/health/extra"
        self.assertFalse(
            _is_auth_exempt(self._request(extended_path)),
            msg=(
                f"{extended_path!r} should NOT be exempt. "
                "Exemption resolves the exact route; a prefix must never grant a bypass."
            ),
        )

    def test_hmac_middleware_exempt_exact_path_is_present(self) -> None:
        """The public health endpoint remains exempt."""
        self.assertTrue(_is_auth_exempt(self._request("/api/users/health/")))
        self.assertFalse(_is_auth_exempt(self._request("/api/users/register/")))

    def test_hmac_middleware_exempt_path_without_trailing_slash(self) -> None:
        """Exempt check normalizes trailing slashes — both forms must match."""
        self.assertTrue(_is_auth_exempt(self._request("/api/users/health")))
        self.assertTrue(_is_auth_exempt(self._request("/api/users/health/")))
        self.assertFalse(_is_auth_exempt(self._request("/api/users/register")))
        self.assertFalse(_is_auth_exempt(self._request("/api/users/register/")))

    def test_hmac_middleware_non_api_path_not_in_exempt(self) -> None:
        """Non-API paths should not be exempt from HMAC validation."""
        self.assertFalse(_is_auth_exempt(self._request("/users/register/")))
        self.assertFalse(_is_auth_exempt(self._request("/register/")))


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class RegistrationRouteTests(HMACTestMixin, TestCase):
    def test_unsigned_registration_is_denied_without_creating_accounts(self) -> None:
        users_before = User.objects.count()
        customers_before = Customer.objects.count()
        response = self.client.post(
            "/api/users/register/",
            {
                "email": "unsigned-registration@example.test",
                "first_name": "Ana",
                "last_name": "Pop",
                "password1": "Copper!Valley92-Forest",
                "password2": "Copper!Valley92-Forest",
                "gdpr_consent": True,
            },
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401, response.content)
        self.assertEqual(User.objects.count(), users_before)
        self.assertEqual(Customer.objects.count(), customers_before)

    def test_signed_registration_uses_only_the_customer_route(self) -> None:
        payload = {
            "user_data": {
                "email": "signed-registration@example.test",
                "password": "Copper!Valley92-Forest",
                "first_name": "Ana",
                "last_name": "Pop",
                "phone": "+40722123456",
            },
            "customer_data": {
                "customer_type": "company",
                "company_name": "Registration SRL",
                "address_line1": "Str. Victoriei 10",
                "city": "București",
                "county": "București",
                "postal_code": "010061",
                "country": "România",
                "data_processing_consent": True,
            },
        }
        users_before = User.objects.count()
        customers_before = Customer.objects.count()
        removed = self.portal_post("/api/users/register/", payload)
        self.assertEqual(removed.status_code, 404, removed.content)
        self.assertEqual(User.objects.count(), users_before)
        self.assertEqual(Customer.objects.count(), customers_before)

        registered = self.portal_post("/api/customers/register/", payload)
        self.assertEqual(registered.status_code, 201, registered.content)
        self.assertTrue(registered.json()["success"])
        self.assertEqual(User.objects.count(), users_before + 1)
        self.assertEqual(Customer.objects.count(), customers_before + 1)
        user = User.objects.get(email="signed-registration@example.test")
        self.assertTrue(user.check_password("Copper!Valley92-Forest"))
        self.assertTrue(CustomerMembership.objects.filter(user=user, role="owner", is_active=True).exists())


# ===============================================================================
# PORTAL LOGIN API LOCKOUT TESTS (related to #53)
# ===============================================================================


# PortalServiceHMACMiddleware is excluded from the test middleware stack, so
# _portal_authenticated is never set. Override middleware to include it and
# send HMAC-signed requests so the lockout logic is tested, not HMAC auth.
@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class PortalLoginAPILockoutTests(HMACTestMixin, TestCase):
    """portal_login_api must integrate with account lockout model methods.

    Mirrors AccountLockoutTokenTests but targets /api/users/login/ — the
    Portal-to-Platform credential validation endpoint.  Without lockout
    integration an attacker who compromises the HMAC secret (or exploits a
    Portal bug) gets unlimited brute-force against every account.
    """

    def setUp(self) -> None:
        self.client = APIClient()
        self.password = "StrongPass123!"
        self.user = User.objects.create_user(
            email="portal-lockout@example.com",
            password=self.password,
            first_name="Portal",
            last_name="Lockout",
        )
        self.url = "/api/users/login/"

    def test_portal_login_increments_failed_attempts_on_wrong_password(self) -> None:
        """Failed portal login with wrong password must increment failed_login_attempts."""
        response = self.portal_post(self.url, {"email": self.user.email, "password": "WRONG_PASSWORD"})

        self.assertEqual(response.status_code, 401)
        self.user.refresh_from_db()
        self.assertGreater(self.user.failed_login_attempts, 0)

    def test_portal_login_locked_account_returns_401(self) -> None:
        """Locked account must return the same 401 as wrong credentials.

        Attacker must not be able to distinguish locked from wrong password.
        """
        self.user.account_locked_until = timezone.now() + timedelta(minutes=30)
        self.user.failed_login_attempts = 1
        self.user.save()

        response = self.portal_post(self.url, {"email": self.user.email, "password": self.password})

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data.get("error"), "Invalid email or password")

    def test_portal_login_resets_counter_on_success(self) -> None:
        """Successful authentication must reset failed_login_attempts to 0."""
        self.user.failed_login_attempts = 2
        self.user.account_locked_until = timezone.now() - timedelta(minutes=10)
        self.user.save()

        response = self.portal_post(self.url, {"email": self.user.email, "password": self.password})

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)
        self.assertIsNone(self.user.account_locked_until)

    def test_portal_login_nonexistent_email_returns_401(self) -> None:
        """Non-existent email must return 401 without raising an exception."""
        response = self.portal_post(self.url, {"email": "nonexistent@example.com", "password": "anything"})

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data.get("error"), "Invalid email or password")

    def test_portal_login_inactive_account_returns_401(self) -> None:
        """Inactive account must return the same 401 as wrong credentials.

        Attacker must not be able to distinguish inactive from locked or wrong password.
        """
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.portal_post(self.url, {"email": self.user.email, "password": self.password})

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertEqual(data.get("error"), "Invalid email or password")

    def test_portal_login_error_responses_identical(self) -> None:
        """All failure modes must return byte-identical JSON bodies.

        Prevents distinguishing account state via response body differences.
        """
        # Wrong password
        resp_wrong = self.portal_post(self.url, {"email": self.user.email, "password": "WRONG"})

        # Locked account
        self.user.refresh_from_db()
        self.user.account_locked_until = timezone.now() + timedelta(minutes=30)
        self.user.failed_login_attempts = 1
        self.user.save()
        resp_locked = self.portal_post(self.url, {"email": self.user.email, "password": self.password})

        # Inactive account
        self.user.account_locked_until = None
        self.user.failed_login_attempts = 0
        self.user.is_active = False
        self.user.save()
        resp_inactive = self.portal_post(self.url, {"email": self.user.email, "password": self.password})

        # Nonexistent email
        resp_nouser = self.portal_post(self.url, {"email": "ghost@example.com", "password": "anything"})

        # All must be identical status + body
        bodies = {resp_wrong.content, resp_locked.content, resp_inactive.content, resp_nouser.content}
        self.assertEqual(len(bodies), 1, f"Response bodies differ: {bodies}")
        self.assertEqual(resp_wrong.status_code, 401)
