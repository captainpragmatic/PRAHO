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
from apps.settings.models import SystemSetting
from tests.billing import _fiscal_correction_helpers as h

PORTAL = "https://portal.example.test"


class CustomerEmailLinkTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        SystemSetting.objects.update_or_create(
            key="portal.public_base_url",
            defaults={
                "name": "Portal URL",
                "category": "platform",
                "data_type": "string",
                "value": PORTAL,
                "default_value": "",
            },
        )
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
