"""The staff two-factor flow works from enrolment to recovery codes.

- TOTP setup made a new secret on every render, including the page shown again after a wrong
  code, so the app the person had just scanned could never be verified; it now keeps one secret
  until enrolment succeeds or the person asks to start over. It also accepts the code from the
  previous 30-second step, as sign-in does.
- Setup asked for nothing but a code, so a hijacked session could enrol its own authenticator; it
  now asks for the current password, as disabling and regenerating already did.
- Disabling and regenerating told a wrong password apart from a wrong code, with no limit on tries;
  they now answer the same for both and allow 15 attempts an hour, as setup does.
- Regenerating backup codes, on Platform or through the Portal, wrote no audit event.
- The method page offered Passkeys as "recommended", which bounced to the authenticator app.
- Pages that show a secret or recovery codes are not cached; a rate-limited code attempt is
  audited; 2FA events record the client address behind the proxy, not the proxy's.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pyotp
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.settings.services import SettingsService
from apps.users.mfa import MFAService, TOTPService
from apps.users.models import User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

PASSWORD = "correct-horse-battery-staple"  # test fixture, not a credential
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
GENERIC_ERROR = "The password or the code is incorrect."


class StaffTestBase(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="flow@example.ro", password=PASSWORD, staff_role="support")
        self.client.force_login(self.user)

    def enrol(self) -> str:
        secret = TOTPService.generate_secret()
        self.user.two_factor_secret = secret
        self.user.two_factor_enabled = True
        self.user.save()
        self.codes = self.user.generate_backup_codes()
        return secret


class TOTPSetupTests(StaffTestBase):
    url = "/auth/mfa/setup/totp/"

    def setup_page(self) -> Any:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        return response

    def test_the_secret_stays_the_same_across_renders_and_a_wrong_code(self) -> None:
        secret = self.setup_page().context["secret"]

        self.assertEqual(self.setup_page().context["secret"], secret)
        wrong = self.client.post(self.url, {"token": "000000", "password": PASSWORD})
        self.assertEqual(wrong.context["secret"], secret)

        self.client.post(self.url, {"token": pyotp.TOTP(secret).now(), "password": PASSWORD})
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
        self.assertEqual(self.user.two_factor_secret, secret)

    def test_starting_over_gives_a_new_secret(self) -> None:
        page = self.setup_page()
        secret = page.context["secret"]
        # The page offers it: someone whose app holds a different secret needs a way out.
        self.assertContains(page, 'href="/auth/mfa/setup/totp/?restart=1"')

        self.assertNotEqual(self.client.get(self.url, {"restart": "1"}, follow=True).context["secret"], secret)

    def test_starting_over_then_submitting_enrols_with_the_new_secret(self) -> None:
        """The setup form has no action, so a browser posts back to the URL it came from.

        Starting over used to rotate the secret on any request with ?restart=1, including that
        POST, so the code from the app never matched and every try spent one of 15 an hour.
        """
        restarted = self.client.get(self.url, {"restart": "1"})
        self.assertRedirects(restarted, self.url, fetch_redirect_response=False)
        secret = self.setup_page().context["secret"]

        response = self.client.post(self.url + "?restart=1", {"token": pyotp.TOTP(secret).now(), "password": PASSWORD})

        self.assertEqual(len(response.context["backup_codes"]), 8)
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
        self.assertEqual(self.user.two_factor_secret, secret)

    def test_a_credential_change_after_enrolment_is_not_adopted_by_the_session(self) -> None:
        """The session is bound to the credentials enrolment committed, not to a later read.

        Re-reading the user after the commit let a password reset landing in between be adopted,
        so the enrolling session survived a credential change meant to end it.
        """
        from unittest.mock import patch  # noqa: PLC0415

        from apps.users.services import SessionSecurityService  # noqa: PLC0415

        secret = self.setup_page().context["secret"]
        rotate = SessionSecurityService.rotate_session_on_2fa_change

        def rotate_then_reset_elsewhere(request: Any) -> None:
            rotate(request)
            concurrent = User.objects.get(pk=self.user.pk)
            concurrent.set_password("reset-elsewhere-Passphrase-2026")
            concurrent.save(update_fields=["password"])

        with patch.object(
            SessionSecurityService, "rotate_session_on_2fa_change", side_effect=rotate_then_reset_elsewhere
        ):
            self.client.post(self.url, {"token": pyotp.TOTP(secret).now(), "password": PASSWORD})

        response = self.client.get(reverse("users:user_profile"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("users:login"), response["Location"])

    def test_the_previous_code_is_accepted_as_at_sign_in(self) -> None:
        secret = self.setup_page().context["secret"]
        previous = pyotp.TOTP(secret).at(time.time() - 30)

        self.client.post(self.url, {"token": previous, "password": PASSWORD})

        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)

    def test_setup_needs_the_current_password(self) -> None:
        secret = self.setup_page().context["secret"]
        for password in ("", "not-the-password"):
            with self.subTest(password=password):
                response = self.client.post(self.url, {"token": pyotp.TOTP(secret).now(), "password": password})
                self.assertContains(response, GENERIC_ERROR)
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_factor_enabled)

    def test_the_setup_and_backup_code_pages_are_not_cached(self) -> None:
        page = self.setup_page()
        self.assertIn("no-store", page["Cache-Control"])
        secret = page.context["secret"]

        response = self.client.post(self.url, {"token": pyotp.TOTP(secret).now(), "password": PASSWORD})

        # The recovery codes are in this response (#689), so it must not be cached either.
        self.assertIn("backup_codes", response.context)
        self.assertIn("no-store", response["Cache-Control"])

    def test_the_backup_code_page_counts_the_codes_it_shows(self) -> None:
        secret = self.setup_page().context["secret"]

        response = self.client.post(self.url, {"token": pyotp.TOTP(secret).now(), "password": PASSWORD})

        self.assertContains(response, "Your 8 backup codes")


class GenericErrorTests(StaffTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.secret = self.enrol()

    def test_a_wrong_password_and_a_wrong_code_get_the_same_answer(self) -> None:
        for url in (reverse("users:mfa_disable"), reverse("users:mfa_regenerate_backup_codes")):
            for data in (
                {"password": "not-the-password", "token": pyotp.TOTP(self.secret).now()},
                {"password": PASSWORD, "token": "00000000"},
            ):
                with self.subTest(url=url, data=data):
                    response = self.client.post(url, data)
                    self.assertContains(response, GENERIC_ERROR)
                    self.assertNotContains(response, "Invalid password.")
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)


@override_settings(CACHES=LOCMEM, RATE_LIMITING_ENABLED=True)
class RateLimitTests(StaffTestBase):
    def test_each_form_allows_15_attempts_an_hour(self) -> None:
        secret = self.enrol()
        for url in (reverse("users:mfa_disable"), reverse("users:mfa_regenerate_backup_codes")):
            with self.subTest(url=url):
                for _attempt in range(15):
                    self.assertNotEqual(
                        self.client.post(url, {"password": "wrong", "token": "00000000"}).status_code, 429
                    )
                # The 16th is refused before anything is checked, even with the right password and code.
                response = self.client.post(url, {"password": PASSWORD, "token": pyotp.TOTP(secret).now()})
                self.assertEqual(response.status_code, 429)
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)

    def test_setup_allows_15_attempts_an_hour(self) -> None:
        url = "/auth/mfa/setup/totp/"
        secret = self.client.get(url).context["secret"]
        for _attempt in range(15):
            self.client.post(url, {"password": "wrong", "token": "000000"})

        response = self.client.post(url, {"password": PASSWORD, "token": pyotp.TOTP(secret).now()})

        self.assertEqual(response.status_code, 429)
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_factor_enabled)


class RegenerateAuditTests(StaffTestBase):
    def test_regenerating_on_platform_is_audited(self) -> None:
        secret = self.enrol()
        profile_events = AuditEvent.objects.filter(action="profile_updated").count()

        self.client.post(
            reverse("users:mfa_regenerate_backup_codes"), {"password": PASSWORD, "token": pyotp.TOTP(secret).now()}
        )

        event = AuditEvent.objects.get(action="2fa_backup_codes_generated")
        self.assertEqual(event.user, self.user)
        self.assertEqual(event.metadata["count"], 8)
        # Only the codes are saved: a full save would also write a generic profile_updated event.
        self.assertEqual(AuditEvent.objects.filter(action="profile_updated").count(), profile_events)


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES=LOCMEM,
)
class PortalRegenerateAuditTests(HMACTestMixin, StaffTestBase):
    def test_regenerating_through_the_portal_is_audited(self) -> None:
        customer = User.objects.create_user(email="customer-codes@example.ro", password=PASSWORD)
        self.user = customer
        secret = self.enrol()

        response = self.portal_post(
            "/api/users/mfa/regenerate-backup-codes/",
            {"user_id": customer.pk, "password": PASSWORD, "token": pyotp.TOTP(secret).now()},
        )

        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(len(response.json()["backup_codes"]), 8)
        self.assertEqual(AuditEvent.objects.filter(action="2fa_backup_codes_generated").count(), 1)


class MethodPageTests(StaffTestBase):
    def test_only_the_authenticator_app_is_offered(self) -> None:
        response = self.client.get(reverse("users:mfa_setup"))

        self.assertNotContains(response, "Passkey")
        self.assertNotContains(response, "RECOMMENDED")
        self.assertContains(response, f'href="{reverse("users:mfa_setup_totp")}"')

    def test_the_page_says_whether_staff_must_enrol(self) -> None:
        self.assertNotContains(self.client.get(reverse("users:mfa_setup")), "Required for staff accounts")

        self.assertTrue(SettingsService.update_setting("users.mfa_required_for_staff", True).is_ok())
        cache.clear()

        self.assertContains(self.client.get(reverse("users:mfa_setup")), "Required for staff accounts")


class VerifyPageTests(TestCase):
    def test_the_code_field_offers_one_time_code_autofill_and_focus(self) -> None:
        user = User.objects.create_user(email="verify-page@example.ro", password=PASSWORD, staff_role="support")
        user.two_factor_secret = TOTPService.generate_secret()
        user.two_factor_enabled = True
        user.save()

        response = self.client.post(reverse("users:login"), {"email": user.email, "password": PASSWORD}, follow=True)

        self.assertContains(response, 'autocomplete="one-time-code"')
        self.assertContains(response, "autofocus")

    def test_an_expired_sign_in_says_so(self) -> None:
        """It used to send the browser back to the password step with no word of why."""
        user = User.objects.create_user(email="expired@example.ro", password=PASSWORD, staff_role="support")
        session = self.client.session
        session["pre_2fa"] = {
            "user_id": user.pk,
            "issued_at": int(time.time()) - 3600,  # long past the five-minute window
            "remember_me": False,
            "next": "",
            "auth_hash": user.get_session_auth_hash(),
            "backend": "django.contrib.auth.backends.ModelBackend",
        }
        session.save()

        response = self.client.get(reverse("users:mfa_verify"), follow=True)

        self.assertContains(response, "Your sign-in timed out. Enter your password again.")

    def test_no_message_without_a_sign_in_in_progress(self) -> None:
        response = self.client.get(reverse("users:mfa_verify"), follow=True)

        self.assertNotContains(response, "Your sign-in timed out.")


@override_settings(CACHES=LOCMEM, IPWARE_TRUSTED_PROXY_LIST=["10.0.0.1"])
class TwoFactorAuditTests(StaffTestBase):
    def request(self) -> Any:
        return RequestFactory().post("/", REMOTE_ADDR="10.0.0.1", HTTP_X_FORWARDED_FOR="203.0.113.7")

    def test_events_record_the_client_behind_the_proxy(self) -> None:
        self.enrol()

        MFAService.verify_mfa_code(self.user, "000000", self.request())

        event = AuditEvent.objects.get(action="2fa_verification_failed")
        self.assertEqual(event.ip_address, "203.0.113.7")

    def test_a_rate_limited_attempt_is_audited(self) -> None:
        self.enrol()
        for _attempt in range(10):
            result = MFAService.verify_mfa_code(self.user, "000000", self.request())
            if result["rate_limited"]:
                break
        self.assertTrue(result["rate_limited"])

        limited = [
            event
            for event in AuditEvent.objects.filter(action="2fa_verification_failed")
            if event.metadata.get("rate_limited")
        ]
        self.assertEqual(len(limited), 1)


class PageStructureTests(StaffTestBase):
    """Each 2FA page closes only the elements it opens.

    The profile closed its container early, so its later cards rendered outside it and its last
    </div> closed a wrapper of the base layout; the regenerate page closed its card before its own
    form and ended with two such </div>.
    """

    def assert_balanced(self, url: str) -> None:
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200, url)
        html = response.content.decode()
        self.assertEqual(html.count("<div"), html.count("</div>"), url)
        self.assertEqual(html.count("<form"), html.count("</form>"), url)

    def test_the_pages_of_an_unenrolled_account(self) -> None:
        for url in (reverse("users:user_profile"), reverse("users:mfa_setup"), "/auth/mfa/setup/totp/"):
            with self.subTest(url=url):
                self.assert_balanced(url)

    def test_the_pages_of_an_enrolled_account(self) -> None:
        self.enrol()
        for url in (
            reverse("users:user_profile"),
            reverse("users:mfa_regenerate_backup_codes"),
            reverse("users:mfa_disable"),
        ):
            with self.subTest(url=url):
                self.assert_balanced(url)


class TwoFactorCopyTests(StaffTestBase):
    def test_the_disable_page_suggests_only_what_exists(self) -> None:
        self.enrol()

        response = self.client.get(reverse("users:mfa_disable"))

        self.assertNotContains(response, "Add a second authenticator device")  # one device per account
        self.assertNotContains(response, "Enable email notifications")  # none are sent for 2FA changes

    def test_confirmation_dialogs_escape_their_translated_text(self) -> None:
        """A Romanian apostrophe in an unescaped '{% trans %}' ends the JS string and breaks the page."""
        from pathlib import Path  # noqa: PLC0415

        templates = Path(__file__).parents[2] / "templates" / "users"
        sources = {path.name: path.read_text(encoding="utf-8") for path in templates.glob("*.html")}
        unescaped = [name for name, source in sources.items() if "confirm('{% trans" in source]
        self.assertEqual(unescaped, [])
        # The scan reaches the two dialogs it was written for, so an empty result means something.
        escaped = sorted(
            name for name, source in sources.items() if "|escapejs }}');" in source and "confirm(" in source
        )
        self.assertEqual(escaped, ["mfa_disable.html", "mfa_regenerate_backup_codes.html"])


@override_settings(
    PLATFORM_API_SECRET=HMAC_TEST_SECRET,
    MIDDLEWARE=HMAC_TEST_MIDDLEWARE,
    HMAC_ALLOW_LEGACY_SECRET=True,
    CACHES=LOCMEM,
)
class PortalCredentialRefusalTests(HMACTestMixin, StaffTestBase):
    """Through the Portal API: one answer for both factors, and the failed attempt stays audited.

    The refusal used to raise inside the transaction that would have applied the change, which
    rolled back the failed-verification audit row with it.
    """

    def setUp(self) -> None:
        super().setUp()
        self.user = User.objects.create_user(email="portal-refusal@example.ro", password=PASSWORD)
        self.secret = self.enrol()

    def test_a_wrong_password_and_a_wrong_code_get_the_same_answer_and_are_audited(self) -> None:
        for path in ("/api/users/mfa/disable/", "/api/users/mfa/regenerate-backup-codes/"):
            wrong_password = self.portal_post(
                path, {"user_id": self.user.pk, "password": "not-the-password", "token": pyotp.TOTP(self.secret).now()}
            )
            wrong_code = self.portal_post(path, {"user_id": self.user.pk, "password": PASSWORD, "token": "00000000"})
            with self.subTest(path=path):
                self.assertEqual((wrong_password.status_code, wrong_code.status_code), (400, 400))
                self.assertEqual(wrong_password.json(), wrong_code.json())
                self.assertIn(GENERIC_ERROR, json.dumps(wrong_code.json()))
        self.assertEqual(AuditEvent.objects.filter(action="2fa_verification_failed", user=self.user).count(), 2)
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
