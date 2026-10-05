"""The draft invoice editor's line controls carry the classes its script looks them up by.

`{% button ... css_class="add-line-btn" %}` was dropped by the button tag, whose field is
`class_`, so `document.querySelector('.add-line-btn')` found nothing and the page script threw
before wiring "Add Line Item" or the first line's remove button.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from apps.billing.invoice_models import Invoice
from tests.factories.billing_factories import create_currency, create_customer
from tests.factories.core_factories import create_admin_user


class InvoiceEditLineControlsTests(TestCase):
    def test_the_add_and_remove_buttons_carry_their_script_hooks(self) -> None:
        invoice = Invoice.objects.create(customer=create_customer(), currency=create_currency(), status="draft")
        self.client.force_login(create_admin_user())

        response = self.client.get(reverse("billing:invoice_edit", args=[invoice.pk]))

        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        self.assertRegex(html, r'<button[^>]*class="ui-btn[^"]*\badd-line-btn\b')
        self.assertRegex(html, r'<button[^>]*class="ui-btn[^"]*\bremove-line\b')
