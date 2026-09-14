"""Recorded VAT decisions survive customer/cache changes and issuance."""

from __future__ import annotations

from copy import deepcopy
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import TestCase
from django.utils import timezone

from apps.billing.ec_sales_service import ReportingPeriod, aggregate_ec_services
from apps.billing.efactura.xml_builder import UBLInvoiceBuilder
from apps.billing.invoice_models import Invoice, InvoiceLine, InvoiceSequence
from apps.billing.models import Currency
from apps.billing.proforma_service import ProformaService
from apps.billing.services import InvoiceService, ProformaConversionService
from apps.billing.tax_evidence import capture_vat_evidence, read_vat_evidence
from apps.billing.tax_models import VATValidation
from apps.common.tax_service import TaxService
from apps.customers.models import Customer, CustomerTaxProfile
from apps.orders.models import Order, OrderItem
from apps.products.models import Product


class TaxEvidenceLifecycleTests(TestCase):
    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei"})
        self.customer = Customer.objects.create(
            name="Example GmbH",
            company_name="Example GmbH",
            customer_type="company",
            primary_email="evidence@example.com",
            status="active",
        )
        self.profile = CustomerTaxProfile.objects.create(
            customer=self.customer, vat_number="DE136695976", is_vat_payer=True, reverse_charge_eligible=True
        )
        self.validation = VATValidation.objects.create(
            country_code="DE",
            vat_number="136695976",
            full_vat_number="DE136695976",
            is_valid=True,
            is_active=True,
            consultation_reference="consultation-original",
            validation_source="vies",
            validation_date=timezone.now() - timedelta(hours=1),
            expires_at=timezone.now() + timedelta(days=1),
        )
        product = Product.objects.create(name="Hosting", slug="vat-evidence-hosting", product_type="shared_hosting")
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_name=self.customer.company_name,
            customer_email=self.customer.primary_email,
            billing_address={"country": "DE", "vat_number": "DE136695976", "company_name": "Example GmbH"},
            subtotal_cents=11000,
            tax_cents=0,
            total_cents=11000,
        )
        OrderItem.objects.create(
            order=self.order,
            product=product,
            product_name="Hosting",
            product_type="shared_hosting",
            quantity=1,
            unit_price_cents=10000,
            setup_cents=1000,
            tax_rate=0,
            tax_cents=0,
            line_total_cents=11000,
        )

    def test_order_proforma_conversion_preserves_original_decision_and_vies_proof(self):
        proforma = ProformaService.create_from_order(self.order).unwrap()
        original = deepcopy(proforma.vat_evidence)
        self.assertEqual(original["category"], "AE")
        self.assertEqual(original["vies"]["consultation_reference"], "consultation-original")
        self.assertEqual(list(proforma.lines.values_list("tax_category_code", flat=True)), ["AE", "AE"])
        VATValidation.objects.filter(pk=self.validation.pk).update(is_valid=False, consultation_reference="changed")
        self.profile.vat_number = "FR40303265045"
        self.profile.reverse_charge_eligible = False
        self.profile.save()
        self.customer.company_name = "Changed Name"
        self.customer.save(update_fields=["company_name"])
        with patch(
            "apps.common.tax_service.TaxService.calculate_vat_for_document", side_effect=AssertionError("recalculated")
        ):
            invoice = ProformaConversionService.convert_to_invoice(str(proforma.pk)).unwrap()
        self.assertEqual(invoice.vat_evidence, original)
        self.assertEqual(invoice.bill_to_tax_id, "DE136695976")
        self.assertEqual(invoice.total_cents, proforma.total_cents)
        self.assertEqual(invoice.converted_from_proforma_id, proforma.pk)
        self.assertEqual(UBLInvoiceBuilder(invoice)._get_tax_category(), "AE")
        self.assertEqual(invoice.lines.count(), 2)

    def test_direct_order_records_decision_on_service_and_setup_lines(self):
        invoice = InvoiceService().create_from_order(self.order).unwrap()
        self.assertEqual(invoice.vat_evidence["scenario"], "eu_b2b_reverse")
        self.assertEqual(invoice.vat_evidence["country_code"], "DE")
        self.assertEqual(invoice.vat_evidence["vat_number"], "DE136695976")
        self.assertEqual(set(invoice.lines.values_list("tax_category_code", flat=True)), {"AE"})
        invoice.issue()
        invoice.save()
        report = aggregate_ec_services(ReportingPeriod(invoice.tax_point_date.year, invoice.tax_point_date.month))
        self.assertTrue(report.can_export, report.exceptions)
        self.assertEqual(report.contributions[0].vies_status, "vies:valid")
        self.assertEqual(report.contributions[0].consultation_reference, "consultation-original")

    def test_snapshot_copies_invalid_validation_without_turning_it_into_valid_evidence(self):
        self.validation.is_valid = False
        self.validation.save(update_fields=["is_valid"])
        invoice = InvoiceService().create_from_order(self.order).unwrap()
        self.assertFalse(invoice.vat_evidence["vies"]["is_valid"])
        self.assertEqual(invoice.vat_evidence["vies"]["consultation_reference"], "consultation-original")

    def test_later_validation_cannot_be_captured_as_contemporaneous_proof(self):
        VATValidation.objects.filter(pk=self.validation.pk).update(validation_date=timezone.now() + timedelta(days=1))
        invoice = InvoiceService().create_from_order(self.order).unwrap()
        self.assertIsNone(invoice.vat_evidence["vies"])

    def test_issued_evidence_identity_and_lines_reject_model_and_bulk_changes(self):
        invoice = InvoiceService().create_from_order(self.order).unwrap()
        invoice.issue()
        invoice.save()
        for field, value in (("vat_evidence", {}), ("locked_at", None), ("bill_to_tax_id", "FR40303265045")):
            invoice.refresh_from_db()
            setattr(invoice, field, value)
            with self.subTest(field=field), self.assertRaises(ValidationError):
                invoice.save(update_fields=[field])
            with self.assertRaises(ValidationError):
                Invoice.objects.filter(pk=invoice.pk).update(**{field: value})
            with self.assertRaises(ValidationError), transaction.atomic():
                Invoice.objects.bulk_update([invoice], [field])
        invoice.refresh_from_db()
        line = invoice.lines.first()
        for field, value in (
            ("unit_price_cents", 99),
            ("quantity", Decimal(2)),
            ("tax_category_code", "Z"),
            ("kind", "refund"),
            ("tax_rate", Decimal("0.21")),
            ("description", "Changed"),
        ):
            line.refresh_from_db()
            setattr(line, field, value)
            with self.subTest(field=field), self.assertRaises(ValidationError):
                line.save()
            with self.assertRaises(ValidationError):
                InvoiceLine.objects.filter(pk=line.pk).update(**{field: value})
        with self.assertRaises(ValidationError), transaction.atomic():
            InvoiceLine.objects.bulk_update([line], ["description"])
        with self.assertRaises(ValidationError):
            invoice.lines.all().delete()
        with self.assertRaises(ValidationError):
            line.delete()
        with self.assertRaises(ValidationError):
            InvoiceLine.objects.create(invoice=invoice, kind="service", description="Extra", unit_price_cents=100)
        with self.assertRaises(ValidationError):
            InvoiceLine.objects.bulk_create([InvoiceLine(invoice=invoice, kind="service", description="Extra")])
        with self.assertRaises(ValidationError):
            invoice.delete()
        with self.assertRaises(ValidationError):
            Invoice.objects.filter(pk=invoice.pk).delete()
        with self.assertRaises(ValidationError):
            InvoiceLine.objects.bulk_create(
                [line], update_conflicts=True, update_fields=["description"], unique_fields=["pk"]
            )

    def test_moving_a_line_into_or_out_of_locked_invoice_is_rejected(self):
        invoice = InvoiceService().create_from_order(self.order).unwrap()
        draft = InvoiceService().create_from_order(self.order).unwrap()
        invoice.issue()
        invoice.save()
        line = invoice.lines.first()
        line.invoice = draft
        with self.assertRaises(ValidationError):
            line.save()
        with self.assertRaises(ValidationError):
            line.delete()
        self.assertTrue(InvoiceLine.objects.filter(pk=line.pk, invoice=invoice).exists())
        with self.assertRaises(ValidationError):
            draft.lines.update(invoice=invoice)

    def test_temporary_number_is_allocated_before_issuance_locks_the_invoice(self):
        invoice = InvoiceService().create_from_order(self.order).unwrap()
        invoice.number = "TMP-D390-ISSUE"
        invoice.save(update_fields=["number"])
        sequence = InvoiceSequence.objects.get(scope="default")
        expected_number = sequence.next_number_preview
        expected_value = sequence.last_value + 1
        invoice.issue()
        issued_at = invoice.issued_at
        evidence = deepcopy(invoice.vat_evidence)
        invoice.save(update_fields=["status"])
        self.assertEqual(invoice.number, expected_number)
        invoice.refresh_from_db()
        self.assertEqual(invoice.number, expected_number)
        self.assertEqual(invoice.issued_at, issued_at)
        self.assertEqual(invoice.vat_evidence, evidence)
        self.assertIsNotNone(invoice.locked_at)
        invoice.save(update_fields=["status"])
        sequence.refresh_from_db()
        self.assertEqual(sequence.last_value, expected_value)
        with self.assertRaises(ValidationError):
            Invoice.objects.filter(pk=invoice.pk).update(number="INV-CHANGED")

    def test_numbering_failure_rolls_back_invoice_issuance(self):
        invoice = InvoiceService().create_from_order(self.order).unwrap()
        invoice.number = "TMP-D390-FAILURE"
        invoice.save(update_fields=["number"])
        invoice.issue()
        with (
            patch(
                "apps.billing.numbering_service.InvoiceNumberingService.get_next_number",
                side_effect=RuntimeError("sequence unavailable"),
            ),
            self.assertRaises(RuntimeError),
        ):
            invoice.save(update_fields=["status"])
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "draft")
        self.assertIsNone(invoice.locked_at)
        self.assertEqual(invoice.number, "TMP-D390-FAILURE")

    def test_explicit_zero_override_is_not_rendered_as_reverse_charge(self):
        invoice = InvoiceService().create_from_order(self.order).unwrap()
        invoice.vat_evidence = capture_vat_evidence(
            TaxService.calculate_vat_for_document(
                11000,
                {
                    "country": "DE",
                    "is_business": True,
                    "vat_number": "DE136695976",
                    "is_vat_payer": True,
                    "custom_vat_rate": Decimal(0),
                },
            )
        )
        self.assertEqual(UBLInvoiceBuilder(invoice)._get_tax_category(), "Z")
        invoice.vat_evidence = {}
        self.assertIsNone(read_vat_evidence(invoice))
        self.assertEqual(UBLInvoiceBuilder(invoice)._get_tax_category(), "AE")
