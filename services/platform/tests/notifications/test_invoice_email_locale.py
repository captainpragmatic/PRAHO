"""Invoice emails go out in the customer's language.

The invoice email methods read `customer.preferred_locale`, which `Customer` has never had, so every
customer got the English template. A customer's language is their primary user's preference,
Romanian by default (`get_customer_locale`), as the customer tasks already read it.
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO
from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import Invoice
from apps.notifications.services import EmailResult, EmailService
from tests.billing import _fiscal_correction_helpers as h


class InvoiceEmailLocaleTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        call_command("setup_email_templates", stdout=StringIO())
        self.invoice = h.issued_invoice(h.customer())
        Invoice.objects.filter(pk=self.invoice.pk).update(due_at=timezone.now() + timedelta(days=5))
        self.invoice.refresh_from_db()

    def _subject(self, send: Any) -> str:
        with patch.object(EmailService, "send_email", return_value=EmailResult(success=True)) as sent:
            send(self.invoice)
        return str(sent.call_args.kwargs["subject"])

    def test_a_customer_without_a_preference_gets_romanian_invoice_emails(self) -> None:
        self.assertTrue(self._subject(EmailService.send_invoice_created).startswith("Factură nouă"))
        self.assertTrue(self._subject(EmailService.send_invoice_paid).startswith("Plată primită"))
        self.assertTrue(self._subject(EmailService.send_payment_reminder).startswith("Memento"))
