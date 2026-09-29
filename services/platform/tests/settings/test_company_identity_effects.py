"""The `company.*` identity settings, asserted where a reader actually sees them.

Nine of the ten keys in the `company` group had no effect test. Their consumer is not Python -
it is `{% setting "company.x" %}` inside `templates/legal/privacy_policy.html` and
`templates/legal/terms_of_service.html`, the two pages that carry PRAHO's legal identity for GDPR
purposes. A wrong legal name, registration number or DPO address on those pages is a compliance
defect, and nothing asserted that changing the setting changed the page.

These tests request the real page and assert the rendered text, which is the only place the
`{% setting %}` tag's output can be observed. That shape also drove a fix to the effect detector
in `scripts/lint_settings_coverage.py`: it required a test to import from another app, and a
render test imports nothing from `apps.` at all, so it reported these very tests as untested. A
detector that silently dictates test style under-reports forever.

`company.email_noreply` is the one key here with a Python consumer, and it gets the test its real
behaviour deserves rather than the one that would look tidier - see `NoReplyAddressPrecedenceTests`.
"""

from __future__ import annotations

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.notifications.services import NotificationService
from apps.settings.services import SettingsService

# Every key below is rendered by BOTH legal pages unless noted.
PRIVACY_KEYS = {
    "company.legal_name": "Effect Test Holdings SRL",
    "company.registration_number": "J40/99999/2099",
    "company.address": "Bulevardul Verificat 42, Cluj-Napoca",
    "company.phone": "+40.99.888.7777",
    "company.email_contact": "contact-effect@example.test",
    "company.email_dpo": "dpo-effect@example.test",
}
TERMS_KEYS = {
    "company.legal_name": "Effect Test Holdings SRL",
    "company.registration_number": "J40/99999/2099",
    "company.address": "Bulevardul Verificat 42, Cluj-Napoca",
    "company.phone": "+40.99.888.7777",
    "company.email_contact": "contact-effect@example.test",
    "company.email_support": "support-effect@example.test",
}
COOKIE_KEYS = {"company.email_privacy": "privacy-effect@example.test"}


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class CompanyIdentityRenderTests(TestCase):
    """Write the setting, request the page a visitor would read, assert the text changed."""

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def set_value(self, key: str, value: str) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def assert_page_renders_settings(self, url_name: str, values: dict[str, str]) -> None:
        """Each value must appear on the page, and the catalog default must be gone.

        The second half is what makes the assertion mean anything. A page that renders both the
        configured value and the default would satisfy `assertContains` while proving nothing
        about which one won. `company.legal_name` is exempt from it only because the page genuinely
        still contains the default in hardcoded prose - see
        `LegalProseHardcodesTheCompanyNameTests`, which pins that defect rather than hiding it.
        """
        defaults = {key: str(SettingsService.DEFAULT_SETTINGS[key]) for key in values}
        for key, value in values.items():
            self.set_value(key, value)

        response = self.client.get(reverse(url_name))
        self.assertEqual(response.status_code, 200)
        for key, value in values.items():
            with self.subTest(key=key):
                self.assertContains(response, value)
                if key == "company.legal_name":
                    continue
                if defaults[key] and defaults[key] != value:
                    self.assertNotContains(response, defaults[key])

    def test_privacy_policy_renders_the_configured_identity(self) -> None:
        self.assert_page_renders_settings("privacy_policy", PRIVACY_KEYS)

    def test_terms_of_service_renders_the_configured_identity(self) -> None:
        self.assert_page_renders_settings("terms_of_service", TERMS_KEYS)

    def test_cookie_policy_renders_the_configured_privacy_contact(self) -> None:
        self.assert_page_renders_settings("cookie_policy", COOKIE_KEYS)

    def test_defaults_render_when_nothing_is_configured(self) -> None:
        """The paired default test: no stored row, and the catalog value reaches the page."""
        response = self.client.get(reverse("privacy_policy"))
        self.assertEqual(response.status_code, 200)
        for key in PRIVACY_KEYS:
            default = str(SettingsService.DEFAULT_SETTINGS[key])
            if default:  # `company.address` and `company.phone` ship empty on purpose
                with self.subTest(key=key):
                    self.assertContains(response, default)

    def test_a_changed_value_replaces_the_previous_one_on_the_next_request(self) -> None:
        """Guards the cache: a stale settings cache would serve the first value forever."""
        self.set_value("company.legal_name", "First Name SRL")
        self.assertContains(self.client.get(reverse("privacy_policy")), "First Name SRL")
        self.set_value("company.legal_name", "Second Name SRL")
        response = self.client.get(reverse("privacy_policy"))
        self.assertContains(response, "Second Name SRL")
        self.assertNotContains(response, "First Name SRL")


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class LegalProseHardcodesTheCompanyNameTests(TestCase):
    """A known defect, pinned so it is visible and so fixing it breaks this test loudly.

    `company.legal_name` half-works. The identity block of both legal pages renders
    `{% setting "company.legal_name" %}`; five prose sentences across the same two pages hardcode
    "PragmaticHost SRL" inside `{% blocktrans %}` blocks. Change the setting and the Terms of
    Service names the configured company in its identity block and a different company in the
    sentence that says who the agreement binds you to - a legal document naming two entities.

    Not fixed here on purpose. Interpolating the name means rewriting five translatable msgids,
    which costs the existing Romanian translations of legal prose, and that is a call for whoever
    owns the translations rather than a drive-by. Recorded in
    `QA/cycle-02-v0.30.0/findings.md`.

    When it IS fixed, this test fails. Delete it then - that is the point of it.
    """

    HARDCODED = "PragmaticHost SRL"

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        with self.captureOnCommitCallbacks(execute=True):
            SettingsService.update_setting("company.legal_name", "Renamed Entity SRL")

    def test_terms_of_service_names_two_different_companies(self) -> None:
        response = self.client.get(reverse("terms_of_service"))
        self.assertContains(response, "Renamed Entity SRL")  # the identity block honours the setting
        self.assertContains(response, self.HARDCODED)  # ...and the prose does not

    def test_privacy_policy_names_two_different_companies(self) -> None:
        response = self.client.get(reverse("privacy_policy"))
        self.assertContains(response, "Renamed Entity SRL")
        self.assertContains(response, self.HARDCODED)


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    ADMIN_ALERT_EMAILS=["ops@example.test"],
)
class NoReplyAddressPrecedenceTests(TestCase):
    """`company.email_noreply` and the Django setting that shadows it.

    `EmailService._send_email` resolves its sender as
    `getattr(settings, "DEFAULT_FROM_EMAIL", None) or SettingsService.get_setting("company.email_noreply", ...)`.

    Every shipped settings module gives `DEFAULT_FROM_EMAIL` a non-empty value - base, dev, staging
    and prod all do - so the left operand is never falsy and the setting is unreachable in every
    deployment. That is a third variety of inert setting, and it is invisible to check 6 of
    `scripts/lint_settings_coverage.py`: the read IS inside a live method, so the getter is called;
    it is the VALUE that is never used.

    Both branches are asserted rather than only the tidy one. Testing the setting with
    `DEFAULT_FROM_EMAIL` blanked would show it "working" and hide the fact that no real deployment
    reaches it. Compare `apps/common/context_processors._maintenance_mode_active`, which gets the
    same precedence right by testing `is not None` on a setting that may legitimately be unset.
    """

    NOREPLY_KEY = "company.email_noreply"

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        mail.outbox.clear()
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(self.NOREPLY_KEY, "configured-noreply@example.test")
        self.assertTrue(result.is_ok(), result)

    @override_settings(DEFAULT_FROM_EMAIL="deployment-wins@example.test")
    def test_the_deployment_setting_wins_and_the_runtime_setting_is_ignored(self) -> None:
        self.assertTrue(NotificationService.send_admin_alert("Subject", "Body"))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, "deployment-wins@example.test")
        self.assertNotIn("configured-noreply@example.test", mail.outbox[0].from_email)

    @override_settings(DEFAULT_FROM_EMAIL="")
    def test_the_runtime_setting_is_used_only_when_the_deployment_setting_is_blank(self) -> None:
        self.assertTrue(NotificationService.send_admin_alert("Subject", "Body"))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, "configured-noreply@example.test")
