"""
Lifecycle hardening tests for Order-Proforma-Invoice findings.

TDD RED phase tests for:
- C1: ProformaConversionService recalculates VAT — amount drift risk
- H1: Proforma expiry hardcoded 7 days — too short for bank transfers
- H2: Invoice.save() calls clean() unconditionally — extra DB query
- H4: Bare except Exception on audit logging hides code bugs
"""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.core.exceptions import ValidationError
from django.db import DatabaseError, connection
from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import Invoice, InvoiceSequence
from apps.billing.models import Currency
from apps.billing.proforma_models import ProformaSequence
from apps.billing.proforma_service import ProformaPaymentService, ProformaService
from apps.billing.services import ProformaConversionService
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status


class ProformaLifecycleTestBaseLocal(TestCase):
    """Local base — mirrors ProformaLifecycleTestBase for isolation."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Hardening Test SRL",
            customer_type="company",
            status="active",
            primary_email="hardening@test.ro",
            company_name="Hardening Test SRL",
        )
        self.product = Product.objects.create(
            name="Shared Hosting Basic",
            slug="hardening-test-hosting",
            product_type="shared_hosting",
            is_active=True,
        )
        self.user = User.objects.create_user(
            email="admin-hardening@pragmatichost.com",
            password="testpass123",
            is_staff=True,
        )
        ProformaSequence.objects.get_or_create(scope="default")
        InvoiceSequence.objects.get_or_create(scope="default")

    def _create_order_with_items(self, total_cents=12100, **kwargs):
        defaults = {
            "customer": self.customer,
            "currency": self.currency,
            "customer_email": self.customer.primary_email,
            "customer_name": self.customer.name,
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": total_cents,
            "billing_address": {"company_name": "Hardening SRL", "country": "RO"},
        }
        defaults.update(kwargs)
        order = Order.objects.create(**defaults)
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return order


# =============================================================================
# C1: ProformaConversionService recalculates VAT — amount drift risk
# =============================================================================


class TestC1ProformaConversionVATDrift(ProformaLifecycleTestBaseLocal):
    """C1: Invoice must copy proforma totals, not recalculate VAT."""

    def test_invoice_totals_match_proforma_when_vat_rate_changes(self):
        """If VAT rate changes between proforma creation and conversion,
        invoice header totals must still match proforma (the agreed quote)."""
        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma_result = ProformaService.create_from_order(order)
        self.assertTrue(proforma_result.is_ok())
        proforma = proforma_result.unwrap()
        force_status(proforma, "sent")

        # Record original proforma totals
        original_tax = proforma.tax_cents
        original_total = proforma.total_cents
        original_subtotal = proforma.subtotal_cents

        # Simulate VAT rate change: TaxService now returns 25% instead of ~21%
        fake_vat = MagicMock(
            subtotal_cents=original_subtotal,
            vat_cents=2500,  # wrong — proforma has original_tax
            total_cents=12500,  # wrong — proforma has original_total
            vat_rate=Decimal("25"),
        )
        with patch(
            "apps.billing.services.TaxService.calculate_vat_for_document",
            return_value=fake_vat,
        ):
            result = ProformaConversionService.convert_to_invoice(str(proforma.id))

        self.assertTrue(result.is_ok(), f"Conversion failed: {result}")
        invoice = result.unwrap()
        # CRITICAL: invoice must match proforma, not the recalculated values
        self.assertEqual(invoice.subtotal_cents, original_subtotal)
        self.assertEqual(invoice.tax_cents, original_tax)
        self.assertEqual(invoice.total_cents, original_total)

    def test_invoice_line_totals_equal_header_totals(self):
        """Sum of invoice line items must match invoice header totals after conversion."""
        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma_result = ProformaService.create_from_order(order)
        self.assertTrue(proforma_result.is_ok())
        proforma = proforma_result.unwrap()
        force_status(proforma, "sent")

        result = ProformaConversionService.convert_to_invoice(str(proforma.id))
        self.assertTrue(result.is_ok())
        invoice = result.unwrap()

        line_total = sum(line.line_total_cents for line in invoice.lines.all())
        self.assertEqual(
            invoice.total_cents,
            line_total,
            f"Header total ({invoice.total_cents}) != sum of lines ({line_total})",
        )


# =============================================================================
# H1: Proforma expiry hardcoded 7 days — too short for bank transfers
# =============================================================================


class TestH1ProformaExpiryConfiguration(ProformaLifecycleTestBaseLocal):
    """H1: Proforma expiry should use billing.proforma_validity_days setting."""

    def test_proforma_uses_settings_validity_days(self):
        """Proforma valid_until should use billing.proforma_validity_days (default 30)."""
        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")

        before = timezone.now()
        result = ProformaService.create_from_order(order)
        self.assertTrue(result.is_ok())
        proforma = result.unwrap()

        # Default from SettingsService is 30 days, not 7
        expected_min = before + timedelta(days=29)  # 1-day clock tolerance
        expected_max = before + timedelta(days=31)
        self.assertGreaterEqual(
            proforma.valid_until,
            expected_min,
            f"valid_until ({proforma.valid_until}) is less than 29 days from now — "
            f"still using hardcoded 7-day expiry?",
        )
        self.assertLessEqual(proforma.valid_until, expected_max)

    def test_proforma_respects_custom_validity_override(self):
        """When setting is overridden to 14 days, proforma reflects that."""
        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")

        before = timezone.now()
        with patch(
            "apps.settings.services.SettingsService.get_integer_setting",
            return_value=14,
        ):
            result = ProformaService.create_from_order(order)

        self.assertTrue(result.is_ok())
        proforma = result.unwrap()

        expected_min = before + timedelta(days=13)
        expected_max = before + timedelta(days=15)
        self.assertGreaterEqual(proforma.valid_until, expected_min)
        self.assertLessEqual(proforma.valid_until, expected_max)


# =============================================================================
# H2: Invoice.save() calls clean() unconditionally — extra DB query
# =============================================================================


class TestH2InvoiceSaveOptimization(TestCase):
    """H2: Invoice.save(update_fields=[non-financial]) should skip DB immutability check."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="H2 Test SRL",
            customer_type="company",
            status="active",
            primary_email="h2@test.ro",
        )
        InvoiceSequence.objects.get_or_create(scope="default")
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-H2-001",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            due_at=timezone.now() + timedelta(days=30),
        )
        # Issue to set locked_at
        self.invoice.issue()
        self.invoice.save()

    def test_non_financial_update_skips_immutability_query(self):
        """Saving only meta on a locked invoice should not trigger the
        immutability SELECT (locked_at, total_cents, ...) from clean()."""
        from django.test.utils import CaptureQueriesContext  # noqa: PLC0415

        self.assertIsNotNone(self.invoice.locked_at)

        with CaptureQueriesContext(connection) as ctx:
            self.invoice.meta = {"test": True}
            self.invoice.save(update_fields=["meta"])

        # The immutability check uses values_list with exactly 4 columns:
        # SELECT locked_at, total_cents, subtotal_cents, tax_cents
        # A full SELECT * (from signals/refresh_from_db) also contains these columns
        # but additionally contains "customer_id", "number", "status", etc.
        # We detect the immutability query by checking it does NOT include "number".
        immutability_queries = [
            q for q in ctx.captured_queries
            if "locked_at" in q["sql"]
            and "total_cents" in q["sql"]
            and "SELECT" in q["sql"]
            and "UPDATE" not in q["sql"]
            and '"number"' not in q["sql"]  # values_list(4 cols) won't have "number"
        ]
        self.assertEqual(
            len(immutability_queries),
            0,
            f"Immutability SELECT should be skipped for non-financial update, "
            f"but found {len(immutability_queries)} query(ies): {immutability_queries}",
        )

    def test_financial_update_still_blocked_on_locked_invoice(self):
        """Saving a financial field on a locked invoice must still raise ValidationError."""
        self.assertIsNotNone(self.invoice.locked_at)
        self.invoice.total_cents = 99999
        with self.assertRaises(ValidationError):
            self.invoice.save(update_fields=["total_cents"])


# =============================================================================
# H4: Bare except Exception on audit logging hides code bugs
# =============================================================================


class TestH4AuditExceptionNarrowing(ProformaLifecycleTestBaseLocal):
    """H4: Audit logging should catch infra errors but propagate code bugs."""

    def test_type_error_in_audit_propagates(self):
        """TypeError in audit logging must NOT be silenced — it indicates a code bug."""
        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma_result = ProformaService.create_from_order(order)
        self.assertTrue(proforma_result.is_ok())
        proforma = proforma_result.unwrap()
        force_status(proforma, "sent")

        with (
            patch(
                "apps.audit.services.AuditService.log_simple_event",
                side_effect=TypeError("bad argument type"),
            ),
            self.assertRaises(TypeError),
        ):
                ProformaPaymentService.record_payment_and_convert(
                    proforma_id=str(proforma.id),
                    amount_cents=proforma.total_cents,
                    payment_method="bank",
                )

    def test_database_error_in_audit_is_caught_safely(self):
        """DatabaseError in audit logging should be caught — financial txn must succeed."""
        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")
        proforma_result = ProformaService.create_from_order(order)
        self.assertTrue(proforma_result.is_ok())
        proforma = proforma_result.unwrap()
        force_status(proforma, "sent")

        with patch(
            "apps.audit.services.AuditService.log_simple_event",
            side_effect=DatabaseError("connection lost"),
        ):
            result = ProformaPaymentService.record_payment_and_convert(
                proforma_id=str(proforma.id),
                amount_cents=proforma.total_cents,
                payment_method="bank",
            )
            self.assertTrue(result.is_ok(), f"Financial txn should succeed despite audit failure: {result}")
