"""The `company.*` identity settings, asserted where a reader actually sees them.

The portal's legal pages state who the operator is (ADR-0061): the legal name, registration number,
address and contacts, which the portal reads from Platform's signed localisation payload. These
tests write the setting and assert what the portal receives, which is the only place its effect
on those pages can be observed from Platform. The portal's rendering of the payload is tested in
the portal (tests/common/test_legal_pages.py).

`company.email_noreply` is the one key here with a Python consumer, and it gets the test its real
behaviour deserves rather than the one that would look tidier - see `NoReplyAddressPrecedenceTests`.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any
from unittest.mock import patch

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory

from apps.api.localisation.views import localisation_defaults
from apps.notifications.models import EmailLog
from apps.notifications.services import EmailService, NotificationService
from apps.notifications.tasks import send_email_task
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService, get_company_legal_name

IDENTITY_KEYS = {
    "company.legal_name": "Effect Test Holdings SRL",
    "company.registration_number": "J40/99999/2099",
    "company.address": "Bulevardul Verificat 42, Cluj-Napoca",
    "company.phone": "+40.99.888.7777",
    "company.email_contact": "contact-effect@example.test",
    "company.email_dpo": "dpo-effect@example.test",
    "company.email_support": "support-effect@example.test",
    "company.email_finance": "finance-effect@example.test",
    "company.email_privacy": "privacy-effect@example.test",
}


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class CompanyIdentityPayloadTests(TestCase):
    """Write the setting, read what the portal's legal pages receive, assert it changed."""

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def set_value(self, key: str, value: str) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def company(self) -> dict[str, Any]:
        """What the portal's signed localisation request receives (HMAC is verified by middleware)."""
        request = APIRequestFactory().post("/api/localisation/", {"timestamp": int(time.time())}, format="json")
        request._portal_authenticated = True  # type: ignore[attr-defined]  # Set by the HMAC middleware
        response = localisation_defaults(request)
        self.assertEqual(response.status_code, 200, response.data)
        return response.data["company"]

    def test_the_portal_receives_the_configured_identity(self) -> None:
        for key, value in IDENTITY_KEYS.items():
            self.set_value(key, value)
        company = self.company()
        for key, value in IDENTITY_KEYS.items():
            with self.subTest(key=key):
                self.assertEqual(company[key.removeprefix("company.")], value)

    def test_defaults_reach_the_portal_when_nothing_is_configured(self) -> None:
        company = self.company()
        for key in IDENTITY_KEYS:
            if key != "company.legal_name":  # Inherits the seller name: see below
                with self.subTest(key=key):
                    self.assertEqual(company[key.removeprefix("company.")], str(SettingsService.DEFAULT_SETTINGS[key]))

    @override_settings(COMPANY_NAME="Seller From Env SRL")
    def test_legal_name_inherits_the_invoice_seller_until_staff_override_it(self) -> None:
        """One name for the operator: the legal pages use COMPANY_NAME until staff store their own."""
        SystemSetting.objects.filter(key="company.legal_name").delete()
        self.assertEqual(self.company()["legal_name"], "Seller From Env SRL")
        self.set_value("company.legal_name", "Staff Chosen Name SRL")
        self.assertEqual(self.company()["legal_name"], "Staff Chosen Name SRL")

    def test_a_changed_value_replaces_the_previous_one_on_the_next_request(self) -> None:
        """Guards the cache: a stale settings cache would serve the first value forever."""
        self.set_value("company.legal_name", "First Name SRL")
        self.assertEqual(self.company()["legal_name"], "First Name SRL")
        self.set_value("company.legal_name", "Second Name SRL")
        self.assertEqual(self.company()["legal_name"], "Second Name SRL")


class BrandNameEffectTests(TestCase):
    """The brand name customers see: in their authenticator app as well as in emails and the portal."""

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def test_a_brand_is_one_non_blank_line(self) -> None:
        for bad in ("", "   ", "Two\nLines", "x" * 65):
            with self.subTest(value=bad):
                self.assertFalse(SettingsService.update_setting("company.brand_name", bad).is_ok())
        self.assertTrue(SettingsService.update_setting("company.brand_name", "Smith & Co Hosting").is_ok())

    def test_brand_name_names_the_customers_authenticator_entry(self) -> None:
        from urllib.parse import parse_qs, urlsplit  # noqa: PLC0415

        from django.contrib.auth import get_user_model  # noqa: PLC0415

        from apps.api.users.serializers import MFASetupSerializer  # noqa: PLC0415

        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting("company.brand_name", "Acme Hosting")
        self.assertTrue(result.is_ok(), result)
        user = get_user_model().objects.create_user(email="brand-2fa@example.test", password="x-Strong-Pass-123")
        uri = MFASetupSerializer(context={"user": user}).create({})["provisioning_uri"]
        self.assertEqual(parse_qs(urlsplit(uri).query)["issuer"], ["Acme Hosting"])


class CompanyLegalNameResolverTests(TestCase):
    """The public legal name: a stored value wins; unset, it is the seller name invoices carry."""

    KEY = "company.legal_name"

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    @override_settings(COMPANY_NAME="Seller From Env SRL")
    def test_stored_name_wins_and_an_unset_one_inherits_the_seller(self) -> None:
        SystemSetting.objects.filter(key=self.KEY).delete()
        self.assertEqual(get_company_legal_name(), "Seller From Env SRL")
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(self.KEY, "Staff Name SRL")
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(get_company_legal_name(), "Staff Name SRL")


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
