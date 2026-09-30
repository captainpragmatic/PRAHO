"""Invoice and proforma PDF export, found untouched by any test.

Both proxy raw bytes from the platform straight through as `application/pdf` with a
`Content-Disposition` header - the one thing a status-only check on a redirect-heavy view
would never verify is that the disposition header actually names the right file.
"""

from __future__ import annotations

import time
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse


class InvoicePdfExportTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    @patch("apps.billing.views.InvoiceViewService.get_invoice_pdf")
    def test_the_pdf_bytes_and_filename_are_returned(self, get_pdf) -> None:
        get_pdf.return_value = b"%PDF-1.4 fake invoice bytes"

        response = self.client.get(
            reverse("billing:invoice_pdf_export", kwargs={"invoice_number": "INV-2026-0100"})
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        self.assertEqual(response["Content-Disposition"], 'attachment; filename="factura_INV-2026-0100.pdf"')
        self.assertEqual(response.content, b"%PDF-1.4 fake invoice bytes")
        get_pdf.assert_called_once_with("INV-2026-0100", 42, 7)

    @patch("apps.billing.views.InvoiceViewService.get_invoice_pdf")
    def test_a_platform_failure_redirects_to_the_invoice_rather_than_500ing(self, get_pdf) -> None:
        get_pdf.side_effect = RuntimeError("platform unreachable")

        response = self.client.get(
            reverse("billing:invoice_pdf_export", kwargs={"invoice_number": "INV-2026-0100"})
        )

        # fetch_redirect_response=False: this test's claim is only about the redirect TARGET, not
        # that invoice_detail itself renders correctly. The default True follows the redirect with
        # an unmocked request, which hit real outbound Platform calls under this session's
        # customer_id/user_id - network-dependent and not what this test is meant to verify.
        self.assertRedirects(
            response,
            reverse("billing:invoice_detail", kwargs={"invoice_number": "INV-2026-0100"}),
            fetch_redirect_response=False,
        )

    def test_an_unauthenticated_request_is_redirected_to_login(self) -> None:
        self.client.session.flush()
        response = self.client.get(
            reverse("billing:invoice_pdf_export", kwargs={"invoice_number": "INV-2026-0100"})
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)


class ProformaPdfExportTests(TestCase):
    def setUp(self) -> None:
        session = self.client.session
        session["customer_id"] = 42
        session["user_id"] = 7
        session["user_memberships"] = [{"customer_id": 42, "role": "owner"}]
        session["user_memberships_fetched_at"] = time.time()
        session.save()

    @patch("apps.billing.views.InvoiceViewService.get_proforma_pdf")
    def test_the_pdf_bytes_and_filename_are_returned(self, get_pdf) -> None:
        get_pdf.return_value = b"%PDF-1.4 fake proforma bytes"

        response = self.client.get(
            reverse("billing:proforma_pdf_export", kwargs={"proforma_number": "PRO-2026-0050"})
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/pdf")
        # A bare substring match on the document number would still pass for the wrong prefix,
        # extension, or disposition type (inline vs attachment) - assert the full header value.
        self.assertEqual(response["Content-Disposition"], 'attachment; filename="proforma_PRO-2026-0050.pdf"')
        self.assertEqual(response.content, b"%PDF-1.4 fake proforma bytes")
        get_pdf.assert_called_once_with("PRO-2026-0050", 42, 7)
