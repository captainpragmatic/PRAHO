"""The draft invoice editor's line controls carry the classes its script looks them up by.

`{% button ... css_class="add-line-btn" %}` was dropped by the button tag, whose field is
`class_`, so `document.querySelector('.add-line-btn')` found nothing and the page script threw
before wiring "Add Line Item" or the first line's remove button.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse
from lxml import etree

from apps.billing.invoice_models import Invoice, InvoiceLine
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

    def test_existing_and_cloned_lines_render_component_remove_buttons(self) -> None:
        invoice = Invoice.objects.create(customer=create_customer(), currency=create_currency(), status="draft")
        line = InvoiceLine.objects.create(invoice=invoice, kind="service", description="Existing hosting")
        self.client.force_login(create_admin_user())

        response = self.client.get(reverse("billing:invoice_edit", args=[invoice.pk]))

        self.assertEqual(response.status_code, 200)
        doc = etree.HTML(response.content)
        for container_id in ("invoice-lines", "invoice-new-line"):
            with self.subTest(container_id=container_id):
                buttons = doc.xpath(
                    "//*[@id=$container_id]//button["
                    "contains(concat(' ', normalize-space(@class), ' '), ' remove-line ')]",
                    container_id=container_id,
                )
                self.assertEqual(len(buttons), 1)
                self.assertIn("ui-btn", buttons[0].get("class", "").split())
                self.assertEqual(buttons[0].get("type"), "button")
        self.assertEqual(doc.xpath("//input[@name='line_0_id']/@value"), [str(line.pk)])
        self.assertEqual(
            doc.xpath("//template[@id='invoice-new-line']//input/@name"),
            [
                "line___index___id",
                "line___index___description",
                "line___index___quantity",
                "line___index___unit_price",
            ],
        )
