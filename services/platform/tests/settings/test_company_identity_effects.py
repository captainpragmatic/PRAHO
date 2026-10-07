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

from collections.abc import Callable
from html import unescape
from unittest.mock import patch

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.html import strip_tags
from django.utils.translation import override

from apps.notifications.models import EmailLog
from apps.notifications.services import EmailService, NotificationService
from apps.notifications.tasks import send_email_task
from apps.settings.models import SystemSetting
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
        """The configured identity replaces the catalog defaults throughout the page."""
        defaults = {key: str(SettingsService.DEFAULT_SETTINGS[key]) for key in values}
        for key, value in values.items():
            self.set_value(key, value)

        response = self.client.get(reverse(url_name))
        self.assertEqual(response.status_code, 200)
        for key, value in values.items():
            with self.subTest(key=key):
                self.assertContains(response, value)
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
class LegalProseIdentityEffectTests(TestCase):
    """Every translated prose sentence names the configured legal entity."""

    LEGAL_NAME = "Renamed Entity SRL"

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting("company.legal_name", self.LEGAL_NAME)
        self.assertTrue(result.is_ok(), result)

    def page_text(self, url_name: str, language: str) -> str:
        with override(language):
            response = self.client.get(reverse(url_name), HTTP_ACCEPT_LANGUAGE=language)
        self.assertEqual(response.status_code, 200)
        return " ".join(unescape(strip_tags(response.content.decode())).split())

    def test_every_terms_sentence_uses_the_configured_name_in_en_and_ro(self) -> None:
        sentences = {
            "en": (
                f"services provided by {self.LEGAL_NAME}",
                f"a legally binding agreement between you and {self.LEGAL_NAME}.",
                f"{self.LEGAL_NAME} provides web hosting and related services",
                f"{self.LEGAL_NAME} and protected by intellectual property laws.",
            ),
            "ro": (
                f"serviciilor PRAHO Platform furnizate de {self.LEGAL_NAME}",
                f"un acord legal obligatoriu între dvs. și {self.LEGAL_NAME}.",
                f"{self.LEGAL_NAME} oferă servicii de găzduire web și servicii conexe",
                f"{self.LEGAL_NAME} și protejată de legile de proprietate intelectuală.",
            ),
        }
        for language, expected in sentences.items():
            with self.subTest(language=language):
                text = self.page_text("terms_of_service", language)
                for sentence in expected:
                    with self.subTest(sentence=sentence):
                        self.assertIn(sentence, text)
                self.assertNotIn("PragmaticHost SRL", text)

    def test_privacy_sentence_uses_the_configured_name_in_en_and_ro(self) -> None:
        sentences = {
            "en": f'{self.LEGAL_NAME} ("we", "us", "our") is committed to protecting your privacy',
            "ro": f'{self.LEGAL_NAME} ("noi", "ne", "noastre") este angajată să vă protejeze intimitatea',
        }
        for language, sentence in sentences.items():
            with self.subTest(language=language):
                text = self.page_text("privacy_policy", language)
                self.assertIn(sentence, text)
                self.assertNotIn("PragmaticHost SRL", text)


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    ADMIN_ALERT_EMAILS=["ops@example.test"],
    DEFAULT_FROM_EMAIL="deployment@example.test",
)
class NoReplyAddressPrecedenceTests(TestCase):
    """Stored identity wins over deployment defaults; explicit and logged senders survive."""

    NOREPLY_KEY = "company.email_noreply"
    RUNTIME = "configured-noreply@example.test"
    DEPLOYMENT = "deployment@example.test"
    EXPLICIT = "explicit@example.test"

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        mail.outbox.clear()

    def configure_sender(self, value: str) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(self.NOREPLY_KEY, value)
        self.assertTrue(result.is_ok(), result)

    def assert_precedence(self, send: Callable[[str | None], str], *, explicit: bool = True) -> None:
        self.configure_sender(self.RUNTIME)
        self.assertEqual(send(None), self.RUNTIME)

        with self.captureOnCommitCallbacks(execute=True):
            SystemSetting.objects.filter(key=self.NOREPLY_KEY).delete()
        # A catalog fallback must not masquerade as a stored row.
        self.assertEqual(
            SettingsService.get_setting(self.NOREPLY_KEY),
            SettingsService.DEFAULT_SETTINGS[self.NOREPLY_KEY],
        )
        self.assertEqual(send(None), self.DEPLOYMENT)

        if explicit:
            self.configure_sender(self.RUNTIME)
            self.assertEqual(send(self.EXPLICIT), self.EXPLICIT)

    def admin_sender(self, sender: str | None) -> str:
        self.assertIsNone(sender)
        mail.outbox.clear()
        self.assertTrue(NotificationService.send_admin_alert("Subject", "Body"))
        self.assertEqual(len(mail.outbox), 1)
        return mail.outbox[0].from_email

    def synchronous_sender(self, sender: str | None) -> str:
        mail.outbox.clear()
        result = EmailService._send_now(
            to=["recipient@example.test"], subject="Subject", body_text="Body", from_email=sender
        )
        self.assertTrue(result.success, result.error)
        self.assertEqual(len(mail.outbox), 1)
        log = EmailLog.objects.get(pk=result.email_log_id)
        self.assertEqual(log.from_addr, mail.outbox[0].from_email)
        return mail.outbox[0].from_email

    def queued_sender(self, sender: str | None, *, rate_limited: bool = False) -> str:
        send = EmailService._queue_email_for_retry if rate_limited else EmailService._send_async
        with patch("django_q.tasks.async_task", return_value="wp5-queued"):
            result = send(to=["recipient@example.test"], subject="Subject", body_text="Body", from_email=sender)
        self.assertTrue(result.success, result.error)
        log = EmailLog.objects.get(pk=result.email_log_id)
        resolved = log.from_addr
        self.assertEqual(log.status, "queued")

        # Delivery must retain the queued sender after the live setting changes.
        self.configure_sender("changed-after-queue@example.test")
        mail.outbox.clear()
        delivered = send_email_task(
            email_log_id=str(log.pk),
            to=[log.to_addr],
            subject=log.subject,
            body_text="Body",
            from_email=resolved,
            retry_count=1,
        )
        self.assertTrue(delivered["success"], delivered)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, resolved)
        log.refresh_from_db()
        self.assertEqual(log.status, "sent")
        self.assertEqual(log.from_addr, resolved)
        return resolved

    def task_sender(self, sender: str | None) -> str:
        log = EmailLog.objects.create(
            to_addr="recipient@example.test", from_addr="", subject="Subject", status="queued"
        )
        mail.outbox.clear()
        result = send_email_task(
            email_log_id=str(log.pk),
            to=[log.to_addr],
            subject=log.subject,
            body_text="Body",
            from_email=sender,
        )
        self.assertTrue(result["success"], result)
        self.assertEqual(len(mail.outbox), 1)
        log.refresh_from_db()
        self.assertEqual(log.from_addr, mail.outbox[0].from_email)
        return mail.outbox[0].from_email

    def test_admin_sender_uses_stored_row_then_deployment_default(self) -> None:
        self.assert_precedence(self.admin_sender, explicit=False)

    def test_synchronous_sender_preserves_explicit_override(self) -> None:
        self.assert_precedence(self.synchronous_sender)

    def test_async_sender_preserves_override_and_queued_sender_on_retry(self) -> None:
        self.assert_precedence(self.queued_sender)

    def test_rate_limited_sender_preserves_override_and_queued_sender_on_retry(self) -> None:
        self.assert_precedence(lambda sender: self.queued_sender(sender, rate_limited=True))

    def test_task_sender_uses_row_then_default_and_preserves_override(self) -> None:
        self.assert_precedence(self.task_sender)

    def test_retry_without_sender_argument_preserves_logged_sender(self) -> None:
        self.configure_sender(self.RUNTIME)
        log = EmailLog.objects.create(
            to_addr="recipient@example.test",
            from_addr="original-logged@example.test",
            subject="Retry",
            status="queued",
        )
        result = send_email_task(
            email_log_id=str(log.pk),
            to=[log.to_addr],
            subject=log.subject,
            body_text="Retry body",
            retry_count=1,
        )
        self.assertTrue(result["success"], result)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].from_email, "original-logged@example.test")
        log.refresh_from_db()
        self.assertEqual(log.status, "sent")
        self.assertEqual(log.from_addr, "original-logged@example.test")

        # A caller-provided sender remains authoritative even with an existing log.
        mail.outbox.clear()
        result = send_email_task(
            email_log_id=str(log.pk),
            to=[log.to_addr],
            subject=log.subject,
            body_text="Explicit retry body",
            from_email=self.EXPLICIT,
            retry_count=2,
        )
        self.assertTrue(result["success"], result)
        self.assertEqual(mail.outbox[0].from_email, self.EXPLICIT)
        log.refresh_from_db()
        self.assertEqual(log.from_addr, self.EXPLICIT)
