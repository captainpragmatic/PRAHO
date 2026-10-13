"""`users.mfa_required_for_staff`: while it is on, a staff account without 2FA can only enrol.

Two-factor authentication was opt-in for staff: the web login asked for a code only from staff
who had enrolled, and an unenrolled staff account got API tokens and Portal sessions with a password
alone. The setting, retired in #377 because nothing read it, is back with a reader, and it is off by
default. While it is on:

- every Platform page sends an unenrolled staff session to TOTP setup (HTMX gets `HX-Redirect`, a
  session `/api/` request a JSON 403), so sessions that already exist are caught too;
- API tokens are not issued to an unenrolled staff account, through the API or the staff page;
- the Portal refuses to log one in, and refuses its existing sessions on their next signed call;
- staff cannot disable 2FA, on Platform or through the Portal.

Only administrators may switch it: it sits in the admin-only platform zone of the settings.
"""

from __future__ import annotations

from typing import Any

import pyotp
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.common.middleware import StaffMFAEnrollmentMiddleware
from apps.settings.catalog import CATALOG_BY_KEY, GROUPS_BY_SLUG, ZONE_BUSINESS
from apps.settings.services import SettingsService
from apps.users.mfa import TOTPService, staff_mfa_required
from apps.users.models import APIToken, CustomerMembership, User
from apps.users.services import APITokenService
from config.settings import base as base_settings
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

KEY = "users.mfa_required_for_staff"
PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
# Platform's production order: test settings strip the custom middleware, which would hide the gate.
PRODUCTION_MIDDLEWARE = list(base_settings.MIDDLEWARE)


def set_policy(on: bool) -> None:
    result = SettingsService.update_setting(KEY, on)
    assert result.is_ok(), result
    cache.clear()


class PolicyTestBase(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.staff = User.objects.create_user(email="unenrolled@example.ro", password=PASSWORD, staff_role="support")
        self.enrolled = User.objects.create_user(email="enrolled@example.ro", password=PASSWORD, staff_role="support")
        self.secret = TOTPService.generate_secret()
        self.enrolled.two_factor_secret = self.secret
        self.enrolled.two_factor_enabled = True
        self.enrolled.save()
        self.backup_codes = self.enrolled.generate_backup_codes()


@override_settings(CACHES=LOCMEM)
class StaffMFASettingTests(PolicyTestBase):
    def test_the_setting_is_off_by_default_and_admin_only(self) -> None:
        definition = CATALOG_BY_KEY[KEY]

        self.assertEqual((definition.data_type, definition.default), ("boolean", False))
        self.assertNotEqual(GROUPS_BY_SLUG[definition.group].zone, ZONE_BUSINESS)
        self.assertFalse(staff_mfa_required())

    def test_only_an_administrator_may_switch_it(self) -> None:
        admin = User.objects.create_user(email="settings-admin@example.ro", password=PASSWORD, staff_role="admin")
        for user, expected in ((self.staff, 403), (admin, 200)):
            with self.subTest(role=user.staff_role):
                self.client.force_login(user)
                response = self.client.post(
                    reverse("settings:save_change_set"),
                    data={"changes": {KEY: True}, "baselines": {KEY: None}},
                    content_type="application/json",
                )
                self.assertEqual(response.status_code, expected, response.content)
        self.assertTrue(staff_mfa_required())


@override_settings(CACHES=LOCMEM)
class StaffMFAEnrollmentMiddlewareEffectTests(PolicyTestBase):
    """Drives the middleware directly, so the settings lint sees the setting's effect."""

    def switch_on(self) -> None:
        # Written here, in the class, where the settings lint looks for the write.
        self.assertTrue(SettingsService.update_setting("users.mfa_required_for_staff", True).is_ok())
        cache.clear()

    def run_middleware(self, user: User, path: str = "/dashboard/", **headers: str) -> HttpResponse:
        request: HttpRequest = RequestFactory().get(path, **headers)
        SessionMiddleware(lambda _r: HttpResponse()).process_request(request)
        request.user = user
        middleware = StaffMFAEnrollmentMiddleware(lambda _r: HttpResponse("page"))
        return middleware.__call__(request)

    def test_off_lets_an_unenrolled_staff_session_through(self) -> None:
        self.assertEqual(self.run_middleware(self.staff).content, b"page")

    def test_on_sends_an_unenrolled_staff_session_to_setup(self) -> None:
        self.switch_on()

        self.assertTrue(staff_mfa_required())
        response = self.run_middleware(self.staff)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("users:mfa_setup_totp"))

    def test_on_lets_an_enrolled_staff_session_through(self) -> None:
        self.switch_on()

        self.assertEqual(self.run_middleware(self.enrolled).content, b"page")


@override_settings(CACHES=LOCMEM, MIDDLEWARE=PRODUCTION_MIDDLEWARE)
class StaffMFAThroughProductionMiddlewareTests(PolicyTestBase):
    """Client requests through Platform's production middleware order."""

    def setUp(self) -> None:
        super().setUp()
        set_policy(True)
        self.client.force_login(self.staff)

    def test_a_page_redirects_to_setup(self) -> None:
        response = self.client.get(reverse("dashboard"))

        self.assertRedirects(response, reverse("users:mfa_setup_totp"), fetch_redirect_response=False)

    def test_an_htmx_request_gets_a_full_page_redirect(self) -> None:
        response = self.client.get(reverse("dashboard"), HTTP_HX_REQUEST="true")

        self.assertEqual(response["HX-Redirect"], reverse("users:mfa_setup_totp"))

    def test_a_session_api_request_is_refused_with_json(self) -> None:
        response = self.client.get("/api/customers/")

        self.assertEqual(response.status_code, 403)
        self.assertIn("two-factor", response.json()["error"].lower())

    def test_an_unenrolled_admin_cannot_switch_the_policy_off(self) -> None:
        """Without the gate an administrator could; with it, the only way off is to enrol first."""
        admin = User.objects.create_user(email="unenrolled-admin@example.ro", password=PASSWORD, staff_role="admin")
        self.client.force_login(admin)

        response = self.client.post(
            reverse("settings:save_change_set"),
            data={"changes": {KEY: False}, "baselines": {KEY: None}},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(staff_mfa_required())

    def test_enrolment_sign_out_and_language_stay_reachable(self) -> None:
        self.assertEqual(self.client.get(reverse("users:mfa_setup_totp")).status_code, 200)
        self.assertEqual(self.client.get(reverse("users:mfa_setup")).status_code, 200)
        self.assertNotEqual(
            self.client.post("/i18n/setlang/", {"language": "ro", "next": "/"})["Location"],
            reverse("users:mfa_setup_totp"),
        )
        self.assertEqual(self.client.post(reverse("users:logout")).status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_an_enrolled_staff_session_is_not_redirected(self) -> None:
        self.client.force_login(self.enrolled)

        self.assertEqual(self.client.get(reverse("dashboard")).status_code, 200)

    def test_off_lets_the_unenrolled_session_through(self) -> None:
        set_policy(False)

        self.assertEqual(self.client.get(reverse("dashboard")).status_code, 200)


class MiddlewarePresenceTests(TestCase):
    """Prod and staging redefine MIDDLEWARE wholesale; the gate must be in each list."""

    _MW = "apps.common.middleware.StaffMFAEnrollmentMiddleware"

    def test_every_settings_module_registers_the_gate_after_the_staff_check(self) -> None:
        from pathlib import Path  # noqa: PLC0415

        for settings_file in ("base.py", "prod.py", "staging.py"):
            with self.subTest(settings_file):
                source = (Path(__file__).parents[2] / "config" / "settings" / settings_file).read_text()
                self.assertIn(self._MW, source)
                staff_only = source.index("apps.common.middleware.StaffOnlyPlatformMiddleware")
                hmac = source.index("apps.common.middleware.PortalServiceHMACMiddleware")
                self.assertLess(staff_only, source.index(self._MW))
                self.assertLess(source.index(self._MW), hmac)  # before the staff-session /api/ bypass


@override_settings(CACHES=LOCMEM, RATE_LIMITING_ENABLED=True)
class StaffMFATokenIssuanceTests(PolicyTestBase):
    url = "/api/users/token/"

    def post(self, email: str, **extra: str) -> Any:
        return self.client.post(
            self.url, {"email": email, "password": PASSWORD, **extra}, content_type="application/json"
        )

    def test_an_unenrolled_staff_account_gets_no_token_and_the_refusal_is_audited(self) -> None:
        set_policy(True)

        response = self.post(self.staff.email)

        self.assertEqual((response.status_code, response.json()), (401, {"error": "Invalid credentials"}))
        self.assertFalse(APIToken.objects.filter(user=self.staff).exists())
        refusal = AuditEvent.objects.filter(action__startswith="login_failed").latest("timestamp")
        self.assertEqual(refusal.metadata["failure_reason"], "mfa_not_enrolled")

    def test_an_enrolled_staff_account_gets_a_token_with_its_code(self) -> None:
        set_policy(True)

        response = self.post(self.enrolled.email, mfa_token=self.backup_codes[0])

        self.assertEqual(response.status_code, 200, response.content)

    def test_off_issues_to_an_unenrolled_staff_account(self) -> None:
        self.assertEqual(self.post(self.staff.email).status_code, 200)

    def test_the_staff_token_page_shares_the_rule(self) -> None:
        set_policy(True)

        result = APITokenService.issue_token(user=self.staff, name="script")

        self.assertTrue(result.is_err())
        self.assertFalse(APIToken.objects.filter(user=self.staff).exists())
        self.assertTrue(APITokenService.issue_token(user=self.enrolled, name="script").is_ok())


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES=LOCMEM,
)
class StaffMFAPortalTests(HMACTestMixin, PolicyTestBase):
    def setUp(self) -> None:
        super().setUp()
        from apps.customers.models import Customer  # noqa: PLC0415

        self.customer = Customer.objects.create(name="Portal Staff SRL", customer_type="company", status="active")
        CustomerMembership.objects.create(user=self.staff, customer=self.customer, role="owner", is_primary=True)
        self.member = User.objects.create_user(email="member@example.ro", password=PASSWORD)
        CustomerMembership.objects.create(user=self.member, customer=self.customer, role="owner")

    def login(self, user: User, **extra: str) -> Any:
        return self.portal_post("/api/users/login/", {"email": user.email, "password": PASSWORD, **extra})

    def test_an_unenrolled_staff_account_cannot_log_in_to_the_portal(self) -> None:
        set_policy(True)

        response = self.login(self.staff)

        self.assertEqual(response.status_code, 401)
        refusal = AuditEvent.objects.filter(action__startswith="login_failed").latest("timestamp")
        self.assertEqual(refusal.metadata["failure_reason"], "mfa_not_enrolled")

    def test_customers_are_unaffected(self) -> None:
        set_policy(True)

        self.assertEqual(self.login(self.member).status_code, 200)

    def test_an_existing_portal_session_is_refused_on_its_next_signed_call(self) -> None:
        signed = {"user_id": self.staff.pk, "customer_id": self.customer.pk}
        session = {"user_id": self.staff.pk, "session_auth_hash": self.staff.get_session_auth_hash()}
        self.assertEqual(self.portal_post("/api/users/session/validate/", session).status_code, 200)
        self.assertEqual(self.portal_post("/api/customers/details/", signed).status_code, 200)
        self.assertEqual(self.portal_post("/api/users/mfa/status/", signed).status_code, 200)

        set_policy(True)

        # Session validation ends the Portal session; business and user calls stop at once.
        self.assertEqual(self.portal_post("/api/users/session/validate/", session).status_code, 401)
        self.assertNotEqual(self.portal_post("/api/customers/details/", signed).status_code, 200)
        self.assertNotEqual(self.portal_post("/api/users/mfa/status/", signed).status_code, 200)
        member = {"user_id": self.member.pk, "customer_id": self.customer.pk}
        self.assertEqual(self.portal_post("/api/customers/details/", member).status_code, 200)

    def test_the_portal_calls_that_name_their_own_user_refuse_one_without_2fa(self) -> None:
        """Company creation and the person's GDPR calls resolve the signed user themselves."""
        from apps.customers.models import Customer  # noqa: PLC0415

        set_policy(True)
        customers_before = Customer.objects.count()

        created = self.portal_post(
            "/api/customers/create/",
            {"user_id": self.staff.pk, "action": "create_company", "company_data": {"company_name": "Refused SRL"}},
        )
        history = self.portal_post("/api/gdpr/consent-history/", {"user_id": self.staff.pk})
        export = self.portal_post("/api/gdpr/data-export/", {"user_id": self.staff.pk, "action": "status"})

        for response in (created, history, export):
            self.assertEqual(response.status_code, 401, response.content[:200])
        self.assertEqual(Customer.objects.count(), customers_before)

    def test_enrolled_staff_keep_the_portal_while_the_policy_is_on(self) -> None:
        """Positive control: the policy refuses staff without 2FA, not staff."""
        CustomerMembership.objects.create(user=self.enrolled, customer=self.customer, role="owner")
        set_policy(True)
        signed = {"user_id": self.enrolled.pk, "customer_id": self.customer.pk}

        self.assertEqual(self.login(self.enrolled, mfa_token=self.backup_codes[0]).status_code, 200)
        session = {
            "user_id": self.enrolled.pk,
            "session_auth_hash": User.objects.get(pk=self.enrolled.pk).get_session_auth_hash(),
        }
        self.assertEqual(self.portal_post("/api/users/session/validate/", session).status_code, 200)
        self.assertEqual(self.portal_post("/api/customers/details/", signed).status_code, 200)
        self.assertEqual(self.portal_post("/api/users/mfa/status/", signed).status_code, 200)
        self.assertEqual(self.portal_post("/api/gdpr/consent-history/", {"user_id": self.enrolled.pk}).status_code, 200)

    def test_staff_cannot_disable_2fa_through_the_portal(self) -> None:
        set_policy(True)
        token = pyotp.TOTP(self.secret).now()

        response = self.portal_post(
            "/api/users/mfa/disable/", {"user_id": self.enrolled.pk, "password": PASSWORD, "token": token}
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["code"], "staff_mfa_required")
        self.enrolled.refresh_from_db()
        self.assertTrue(self.enrolled.two_factor_enabled)


@override_settings(CACHES=LOCMEM)
class StaffMFADisableTests(PolicyTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(self.enrolled)

    def test_staff_cannot_disable_2fa_on_platform_while_the_policy_is_on(self) -> None:
        set_policy(True)

        response = self.client.post(
            reverse("users:mfa_disable"),
            {"password": PASSWORD, "token": self.backup_codes[0], "confirm_disable": "on"},
        )

        self.assertEqual(response.status_code, 302)
        self.enrolled.refresh_from_db()
        self.assertTrue(self.enrolled.two_factor_enabled)
        # The refusal comes before the code is checked, so the backup code is not spent.
        self.assertTrue(self.enrolled.verify_backup_code(self.backup_codes[0]))

    def test_the_profile_offers_no_disable_link_while_the_policy_is_on(self) -> None:
        disable_url = reverse("users:mfa_disable")
        self.assertContains(self.client.get(reverse("users:user_profile")), disable_url)

        set_policy(True)

        self.assertNotContains(self.client.get(reverse("users:user_profile")), disable_url)
