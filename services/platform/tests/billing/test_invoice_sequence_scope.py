"""Every local numbering path records the family the legal number came from (ADR-0053).

A credit note is numbered from its original's family, so an invoice numbered without recording one
would send its correction to whatever the fallback picks. A provider-numbered invoice records none.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, TransactionTestCase

from apps.billing.invoice_models import ISSUER_BUILTIN, ISSUER_SMARTBILL, Invoice, InvoiceSequence
from apps.billing.models import ProformaInvoice, ProformaLine
from apps.billing.services import InvoiceService, ProformaConversionService
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from tests.billing import _fiscal_correction_helpers as h


class SequenceScopeIsRecordedTests(TestCase):
    def setUp(self) -> None:
        self.owner = h.customer()
        InvoiceSequence.objects.get_or_create(scope="default")

    def _order(self) -> Order:
        product = Product.objects.create(
            name="Shared Hosting", slug="hosting-scope", product_type="shared_hosting", is_active=True
        )
        order = Order.objects.create(
            customer=self.owner,
            currency=h.ron(),
            customer_email="scope@example.test",
            customer_name="Scope SRL",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address={"company_name": "Scope SRL", "country": "RO"},
        )
        OrderItem.objects.create(
            order=order,
            product=product,
            product_name=product.name,
            product_type=product.product_type,
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return order

    def test_an_invoice_from_an_order_records_the_default_family(self) -> None:
        invoice = InvoiceService().create_from_order(self._order()).unwrap()

        self.assertTrue(invoice.number)
        self.assertEqual(invoice.sequence_scope, "default")

    def test_a_provider_numbered_invoice_records_no_family(self) -> None:
        with patch("apps.billing.services.issuer_for_new_document", return_value=(ISSUER_SMARTBILL, True)):
            invoice = InvoiceService().create_from_order(self._order()).unwrap()

        self.assertIsNone(invoice.number)
        self.assertEqual(invoice.sequence_scope, "")

    def test_a_converted_proforma_records_the_default_family(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.owner,
            number="PRO-SCOPE",
            currency=h.ron(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Scope SRL",
        )
        ProformaLine.objects.create(
            proforma=proforma,
            kind="service",
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )

        invoice = ProformaConversionService.convert_to_invoice(str(proforma.id)).unwrap()

        self.assertEqual(invoice.sequence_scope, "default")

    def test_a_draft_numbered_at_issue_records_the_default_family(self) -> None:
        draft = Invoice.objects.create(
            customer=self.owner,
            currency=h.ron(),
            issuer_provider=ISSUER_BUILTIN,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )

        draft.issue()
        draft.save()

        stored = Invoice.objects.get(pk=draft.pk)
        self.assertTrue(stored.number)
        self.assertEqual(stored.sequence_scope, "default")


class UsageInvoiceSequenceScopeTests(TestCase):
    def setUp(self) -> None:
        from tests.billing import test_metering_services as metering_fixtures  # noqa: PLC0415

        metering_fixtures.UsageInvoiceServiceTestCase.setUp(self)

    def test_a_usage_invoice_records_the_default_family(self) -> None:
        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.pk))

        invoice = Invoice.objects.get(pk=result.unwrap()["invoice_id"])
        self.assertTrue(invoice.number)
        self.assertEqual(invoice.sequence_scope, "default")


class BuiltinIssuanceGatewaySequenceScopeTests(TransactionTestCase):
    """The provider issuance path numbers a built-in document through the same gateway."""

    def test_a_builtin_document_finalised_through_the_gateway_records_the_default_family(self) -> None:
        from apps.billing.issuers.service import issue_invoice_externally  # noqa: PLC0415

        draft = Invoice.objects.create(
            customer=h.customer(),
            currency=h.ron(),
            issuer_provider=ISSUER_BUILTIN,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )

        result = issue_invoice_externally(draft.pk)

        stored = Invoice.objects.get(pk=draft.pk)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual((stored.number, stored.sequence_scope), (result.unwrap(), "default"))
