"""Customer-typed document numbers must name exactly one Platform path segment."""

from unittest.mock import patch

from django.test import SimpleTestCase

from apps.api_client.services import quote_path_segment
from apps.billing.services import InvoiceViewService


class QuotePathSegmentTests(SimpleTestCase):
    def test_everything_outside_the_unreserved_set_is_escaped(self) -> None:
        cases = {
            "INV-0001": "INV-0001",
            "INV 0001": "INV%200001",
            "FACTă-1": "FACT%C4%83-1",
            "A;B=1": "A%3BB%3D1",
            "x%2Fpdf": "x%252Fpdf",
            "%C8": "%25C8",
            "a\nb": "a%0Ab",
            42: "42",
        }
        for value, quoted in cases.items():
            with self.subTest(value=value):
                self.assertEqual(quote_path_segment(value), quoted)

    def test_values_that_cannot_stay_one_segment_are_refused(self) -> None:
        for value in ("", ".", "..", "x/pdf", "/", "a/../b"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                quote_path_segment(value)

    def test_a_refused_number_never_reaches_platform(self) -> None:
        service = InvoiceViewService()
        with patch("apps.api_client.services.portal_request") as transport:
            self.assertIsNone(service.get_invoice_detail("..", customer_id=1, user_id=1))
            with self.assertRaises(ValueError):
                service.get_invoice_pdf("..", customer_id=1, user_id=1)
        transport.assert_not_called()
