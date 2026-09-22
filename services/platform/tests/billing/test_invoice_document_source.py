"""Which PDF a customer receives.

A locally-issued invoice is rendered by PRAHO. An externally-issued one must show
the provider's own document: that is what the customer gets, what the accountant
sees, and what sits behind whatever reached ANAF. Rendering our own version would
be a second, unofficial copy of a legal document that can differ in layout or
rounding from the real one.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from apps.billing.invoice_models import ISSUER_BUILTIN, ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.documents import get_invoice_pdf_bytes
from apps.billing.issuers.models import IssuanceState, ProviderIssuance
from apps.common.types import Err, Ok
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory

PROVIDER_PDF = b"%PDF-1.4 provider rendering"


def _currency(code: str = "RON") -> Currency:
    obj, _ = Currency.objects.get_or_create(code=code, defaults={"symbol": "L", "decimals": 2})
    return obj


class DocumentSourceTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()
        self._n = 0

    def _invoice(self, issuer: str, number: str | None) -> Invoice:
        self._n += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=number,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=issuer,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return invoice

    def test_a_builtin_invoice_is_rendered_locally(self) -> None:
        invoice = self._invoice(ISSUER_BUILTIN, "INV-DOC-0001")

        with patch(
            "apps.billing.pdf_generators.generate_invoice_pdf", return_value=b"%PDF-local"
        ) as render:
            result = get_invoice_pdf_bytes(invoice)

        self.assertTrue(result.is_ok())
        render.assert_called_once()

    def test_a_provider_invoice_uses_the_providers_own_document(self) -> None:
        """THE point of the chokepoint: never render our own copy of their document."""
        invoice = self._invoice(ISSUER_SMARTBILL, "FCT-000123")
        ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.ISSUED.value,
            provider_series="FCT",
            provider_number="000123",
        )

        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.fetch_pdf",
                return_value=Ok(PROVIDER_PDF),
            ),
            patch("apps.billing.pdf_generators.generate_invoice_pdf") as render,
        ):
            result = get_invoice_pdf_bytes(invoice)

        self.assertEqual(result.unwrap(), PROVIDER_PDF)
        render.assert_not_called()

    def test_the_provider_document_is_fetched_once_and_kept(self) -> None:
        """Re-fetching would spend the rate-limited token on something immutable,
        and would make the customer portal depend on a third party being up."""
        invoice = self._invoice(ISSUER_SMARTBILL, "FCT-000124")
        ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.ISSUED.value,
            provider_series="FCT",
            provider_number="000124",
        )

        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.fetch_pdf",
            return_value=Ok(PROVIDER_PDF),
        ) as fetch:
            get_invoice_pdf_bytes(invoice)
            invoice.refresh_from_db()
            second = get_invoice_pdf_bytes(invoice)

        fetch.assert_called_once()
        self.assertEqual(second.unwrap(), PROVIDER_PDF)

    def test_an_unissued_provider_invoice_has_no_document_yet(self) -> None:
        """There is nothing to show: the provider has not created it."""
        invoice = self._invoice(ISSUER_SMARTBILL, None)
        ProviderIssuance.objects.create(invoice=invoice, provider=ISSUER_SMARTBILL)

        result = get_invoice_pdf_bytes(invoice)

        self.assertTrue(result.is_err())
        self.assertIn("not been issued", result.error)

    def test_a_provider_fetch_failure_is_reported_not_substituted(self) -> None:
        """Falling back to our own rendering would hand the customer a document
        that is not the one their invoice actually is."""
        invoice = self._invoice(ISSUER_SMARTBILL, "FCT-000125")
        ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.ISSUED.value,
            provider_series="FCT",
            provider_number="000125",
        )

        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.fetch_pdf",
                return_value=Err("SmartBill returned 503 for the PDF"),
            ),
            patch("apps.billing.pdf_generators.generate_invoice_pdf") as render,
        ):
            result = get_invoice_pdf_bytes(invoice)

        self.assertTrue(result.is_err())
        render.assert_not_called()


class CustomerVisibilityTests(TestCase):
    """An invoice awaiting its provider is not yet a document the customer has."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()

    def test_an_unnumbered_invoice_is_excluded_from_the_customer_listing(self) -> None:
        """Serving it would put `number: null` on the wire and show the customer a
        document that does not legally exist yet."""
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            issuer_provider=ISSUER_SMARTBILL,
        )
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-VISIBLE-0001",
            status="issued",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
        )

        visible = Invoice.objects.filter(customer=self.customer).exclude(number__isnull=True)

        self.assertEqual(visible.count(), 1)
        self.assertEqual(visible.get().number, "INV-VISIBLE-0001")


class DeferralAndConcurrencyTests(TestCase):
    """Pacing and racing, the two ways this can go wrong quietly."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()

    def _issued_external(self, number: str) -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=number,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            issuer_provider=ISSUER_SMARTBILL,
        )
        ProviderIssuance.objects.create(
            invoice=invoice,
            provider=ISSUER_SMARTBILL,
            state=IssuanceState.ISSUED.value,
            provider_series="FCT",
            provider_number=number.rsplit("-", maxsplit=1)[-1],
        )
        return invoice

    def test_a_paced_fetch_is_a_deferral_not_a_failure(self) -> None:
        """Otherwise a rate-limited download becomes a 500, or worse, tells the
        customer their invoice does not exist."""
        from apps.billing.issuers.documents import DocumentDeferred  # noqa: PLC0415
        from apps.billing.issuers.smartbill.client import RateGateWait  # noqa: PLC0415

        invoice = self._issued_external("FCT-000200")

        with (
            patch(
                "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.fetch_pdf",
                side_effect=RateGateWait("2026-01-01T00:00:00Z"),
            ),
            self.assertRaises(DocumentDeferred),
        ):
            get_invoice_pdf_bytes(invoice)

    def test_a_stored_file_is_not_served_for_an_unconfirmed_document(self) -> None:
        """Bytes existing is not evidence the provider issued anything.

        Without this check, a stored file short-circuits every issuance check and
        gets served as a legal document.
        """
        from django.core.files.base import ContentFile  # noqa: PLC0415

        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            issuer_provider=ISSUER_SMARTBILL,
        )
        ProviderIssuance.objects.create(invoice=invoice, provider=ISSUER_SMARTBILL)
        invoice.pdf_file.save("stray.pdf", ContentFile(b"%PDF-stray"), save=False)
        invoice.save(update_fields=["pdf_file"])

        result = get_invoice_pdf_bytes(invoice)

        self.assertTrue(result.is_err())
        self.assertIn("not been issued", result.error)

    def test_a_racing_writer_does_not_produce_a_second_stored_document(self) -> None:
        """Two downloads can both see an empty cache. One archived rendition wins."""
        from django.core.files.base import ContentFile  # noqa: PLC0415

        invoice = self._issued_external("FCT-000201")

        def _store_behind_us(series: str, number: str) -> object:
            fresh = Invoice.objects.get(pk=invoice.pk)
            fresh.pdf_file.save("winner.pdf", ContentFile(b"%PDF-winner"), save=False)
            fresh.save(update_fields=["pdf_file"])
            return Ok(b"%PDF-loser")

        with patch(
            "apps.billing.issuers.smartbill.issuer.SmartBillIssuer.fetch_pdf",
            side_effect=_store_behind_us,
        ):
            result = get_invoice_pdf_bytes(invoice)

        self.assertEqual(result.unwrap(), b"%PDF-winner", msg="the first published document must win")
