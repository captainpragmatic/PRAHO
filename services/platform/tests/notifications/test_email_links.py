"""Links in customer emails point at the services that actually serve them.

They were built on ``COMPANY_WEBSITE``, the operator's marketing site, which serves neither the
customer invoice pages (the Portal, addressed by invoice number) nor the unsubscribe page (the
Platform, published at /notifications/unsubscribe/ by the reverse proxy).
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO
from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.invoice_models import Invoice
from apps.notifications.services import EmailResult, EmailService
from apps.settings.services import SettingsService
from tests.billing import _fiscal_correction_helpers as h

PORTAL = "https://portal.example.test"


class CustomerEmailLinkTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        call_command("setup_email_templates", stdout=StringIO())
        self.invoice = h.issued_invoice(h.customer())
        Invoice.objects.filter(pk=self.invoice.pk).update(due_at=timezone.now() + timedelta(days=5))
        self.invoice.refresh_from_db()

    def _context(self, send: Any) -> dict[str, Any]:
        with patch.object(EmailService, "send_template_email", return_value=EmailResult(success=True)) as sent:
            send(self.invoice)
        return dict(sent.call_args.kwargs["context"])

    @override_settings(COMPANY_WEBSITE="https://marketing.example.test")
    def test_invoice_links_open_the_portal_invoice_by_number(self) -> None:
        expected = f"{PORTAL}/billing/invoices/{self.invoice.number}/"
        self.assertEqual(self._context(EmailService.send_invoice_created)["invoice_url"], expected)
        self.assertEqual(self._context(EmailService.send_invoice_paid)["invoice_url"], expected)
        self.assertEqual(self._context(EmailService.send_payment_reminder)["payment_url"], expected)

    @override_settings(PLATFORM_DOMAIN="platform.example.test", COMPANY_WEBSITE="https://marketing.example.test")
    def test_unsubscribe_link_opens_the_platform_page(self) -> None:
        url = EmailService._generate_unsubscribe_url("user@example.com", "marketing")
        self.assertTrue(url.startswith("https://platform.example.test/notifications/unsubscribe/"), url)


class SeededEmailBrandTests(TestCase):
    """Seeded emails carry the configured brand and the invoice number, rendered at send time."""

    def setUp(self) -> None:
        cache.clear()
        call_command("setup_email_templates", stdout=StringIO())
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(SettingsService.update_setting("company.brand_name", "Acme Hosting").is_ok())
            self.assertTrue(SettingsService.update_setting("company.email_support", "help@acme.test").is_ok())
        self.invoice = h.issued_invoice(h.customer())

    def _sent(self, send: Any) -> dict[str, Any]:
        with patch.object(EmailService, "send_email", return_value=EmailResult(success=True)) as sent:
            send(self.invoice)
        return dict(sent.call_args.kwargs)

    def test_invoice_email_names_the_brand_and_the_number(self) -> None:
        sent = self._sent(EmailService.send_invoice_created)
        self.assertIn(self.invoice.number, sent["subject"])
        self.assertIn("Acme Hosting", sent["subject"])
        self.assertNotIn("{", sent["subject"])
        self.assertIn("Acme Hosting", sent["body_html"])

    def test_any_template_email_gets_the_brand_and_support_address_in_its_context(self) -> None:
        with patch.object(EmailService, "send_email", return_value=EmailResult(success=True)) as sent:
            EmailService.send_template_email(
                template_key="payment_overdue",
                recipient="customer@example.test",
                context={"customer_name": "C", "invoice_number": "INV-1", "total_amount": "1", "currency": "EUR",
                         "due_date": "2026-10-20", "days_until_due": 3, "payment_url": ""},
                locale="en",
            )
        body = sent.call_args.kwargs["body_html"]
        self.assertIn("Acme Hosting", body)
        self.assertIn("help@acme.test", body)

    def test_plain_text_parts_keep_an_ampersand_in_the_brand(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(SettingsService.update_setting("company.brand_name", "Smith & Co").is_ok())
        sent = self._sent(EmailService.send_invoice_created)
        self.assertIn("Smith & Co", sent["subject"])
        self.assertNotIn("&amp;", sent["subject"])
        self.assertIn("Smith &amp; Co", sent["body_html"])  # HTML stays escaped

    def test_reminder_email_points_customers_at_the_configured_support_address(self) -> None:
        Invoice.objects.filter(pk=self.invoice.pk).update(due_at=timezone.now() - timedelta(days=3))
        self.invoice.refresh_from_db()
        sent = self._sent(EmailService.send_payment_reminder)
        self.assertIn(self.invoice.number, sent["subject"])
        self.assertIn("help@acme.test", sent["body_html"])


class EmailTemplateSeedTests(TestCase):
    """Seeding is safe to repeat: a brand change needs no re-seed, and a re-seed adds no duplicates."""

    def test_reseeding_keeps_one_template_per_key_and_locale(self) -> None:
        from apps.notifications.models import EmailTemplate  # noqa: PLC0415

        call_command("setup_email_templates", stdout=StringIO())
        first = EmailTemplate.objects.count()
        call_command("setup_email_templates", stdout=StringIO())
        call_command("setup_email_templates", overwrite=True, stdout=StringIO())
        self.assertEqual(EmailTemplate.objects.count(), first)
        self.assertFalse(EmailTemplate.objects.filter(body_html__icontains="pragmatic" + "host").exists())


class WelcomeEmailBrandTests(TestCase):
    """The invite email a new customer user receives names the brand and its support address."""

    def setUp(self) -> None:
        cache.clear()
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(SettingsService.update_setting("company.brand_name", "Acme Hosting").is_ok())
            self.assertTrue(SettingsService.update_setting("company.email_support", "help@acme.test").is_ok())

    def test_welcome_invite_names_the_brand_and_support_address(self) -> None:
        from django.contrib.auth import get_user_model  # noqa: PLC0415
        from django.core import mail  # noqa: PLC0415

        from apps.users.services import SecureCustomerUserService  # noqa: PLC0415

        customer = h.customer()
        user = get_user_model().objects.create_user(email="welcome@example.test", password="x-Strong-Pass-123")
        mail.outbox.clear()
        self.assertTrue(SecureCustomerUserService.send_welcome_invite(user, customer))
        message = mail.outbox[0]
        self.assertIn("Acme Hosting", message.subject)
        self.assertIn("Acme Hosting", message.body)
        self.assertIn("help@acme.test", message.body)
