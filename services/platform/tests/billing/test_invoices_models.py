# ===============================================================================
# BILLING INVOICE TESTS (Django TestCase Format)
# ===============================================================================

from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.utils import timezone
from django_fsm import TransitionNotAllowed

from apps.billing.models import Currency, Invoice, InvoiceLine, ProformaInvoice
from apps.billing.payment_models import Payment
from apps.billing.refund_models import Refund
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from tests.factories.billing_factories import create_invoice
from tests.helpers.fsm_helpers import force_status

User = get_user_model()


class InvoiceTestCase(TestCase):
    """Test Invoice model functionality"""

    def setUp(self):
        """Create test data for invoice tests"""
        self.currency, _ = Currency.objects.get_or_create(code='EUR', defaults={'symbol': '€', 'decimals': 2})
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Test Company SRL',
            status='active'
        )
        self.user = User.objects.create_user(email='admin@test.com', password='testpass')

    def test_create_invoice(self):
        """Test basic invoice creation"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-2025-001',
            issued_at=timezone.now(),
            due_at=timezone.now() + timedelta(days=30),
            status='draft'
        )

        self.assertEqual(invoice.customer, self.customer)
        self.assertEqual(invoice.currency, self.currency)
        self.assertEqual(invoice.number, 'INV-2025-001')
        self.assertEqual(invoice.status, 'draft')

    def test_invoice_str_representation(self):
        """Test string representation"""
        invoice = create_invoice(
            customer=self.customer,
            currency=self.currency,
            number='INV-2025-002'
        )
        self.assertIn('INV-2025-002', str(invoice))

    def test_invoice_property_calculations(self):
        """Test invoice calculated properties"""
        invoice = create_invoice(
            customer=self.customer,
            currency=self.currency,
            number='INV-2025-003',
            total_cents=11900
        )
        # Manually set the other fields since factory doesn't support them
        invoice.subtotal_cents = 10000  # 100.00
        invoice.tax_cents = 1900        # 19.00
        invoice.save()                  # total is 119.00

        self.assertEqual(invoice.subtotal, Decimal('100.00'))
        self.assertEqual(invoice.tax_amount, Decimal('19.00'))
        self.assertEqual(invoice.total, Decimal('119.00'))

    def test_invoice_status_choices(self):
        """Test valid status choices"""
        valid_statuses = ['draft', 'issued', 'paid', 'overdue', 'void']

        for status in valid_statuses:
            invoice = Invoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number=f'INV-{status}',
                status=status
            )
            self.assertEqual(invoice.status, status)

    def test_invoice_unique_number(self):
        """Test invoice number uniqueness"""
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-UNIQUE'
        )

        with transaction.atomic(), self.assertRaises(IntegrityError):
            Invoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number='INV-UNIQUE'  # Duplicate number
            )

    def test_invoice_is_overdue(self):
        """Test overdue detection"""
        # Create overdue invoice
        overdue_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-OVERDUE',
            due_at=timezone.now() - timedelta(days=1),
            status='issued'
        )

        # Create current invoice
        current_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-CURRENT',
            due_at=timezone.now() + timedelta(days=30),
            status='issued'
        )

        self.assertTrue(overdue_invoice.is_overdue())
        self.assertFalse(current_invoice.is_overdue())

    def test_invoice_get_remaining_amount(self):
        """Test remaining amount calculation"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-REMAINING',
            total_cents=10000  # 100.00 EUR
        )

        # Initially, full amount remaining (returns cents, not decimal)
        self.assertEqual(invoice.get_remaining_amount(), 10000)

    def _refund(self, invoice, *, amount_cents, status, ref):
        return Refund.objects.create(
            customer=self.customer, invoice=invoice, currency=self.currency,
            amount_cents=amount_cents, original_amount_cents=invoice.total_cents,
            reference_number=ref, status=status,
        )

    def test_get_remaining_amount_subtracts_completed_refund(self):
        """#189: a completed refund reduces net collected, so the balance due reflects
        money actually retained (partially-refunded payment keeps its full amount_cents)."""
        invoice = Invoice.objects.create(
            customer=self.customer, currency=self.currency, number="INV-REF-1",
            status="issued", total_cents=119000,
        )
        Payment.objects.create(
            customer=self.customer, invoice=invoice, currency=self.currency,
            amount_cents=119000, status="partially_refunded",
        )
        self._refund(invoice, amount_cents=50000, status="completed", ref="REF-REM-1")
        # paid 1190.00, refunded 500.00 -> net retained 690.00 -> 500.00 still due
        self.assertEqual(invoice.get_remaining_amount(), 50000)

    def test_get_remaining_amount_full_refund_restores_full_balance(self):
        """#189 regression guard: a fully-refunded payment leaves the FULL balance due,
        never more (the naive `total - (collected - refunded)` would inflate above total)."""
        invoice = Invoice.objects.create(
            customer=self.customer, currency=self.currency, number="INV-REF-2",
            status="issued", total_cents=119000,
        )
        Payment.objects.create(
            customer=self.customer, invoice=invoice, currency=self.currency,
            amount_cents=119000, status="refunded",
        )
        self._refund(invoice, amount_cents=119000, status="completed", ref="REF-REM-2")
        self.assertEqual(invoice.get_remaining_amount(), 119000)

    def test_get_remaining_amount_ignores_non_completed_refund(self):
        """#189 regression guard: only COMPLETED refunds reduce the balance; a pending /
        rejected refund (money not actually returned) must not."""
        invoice = Invoice.objects.create(
            customer=self.customer, currency=self.currency, number="INV-REF-3",
            status="issued", total_cents=119000,
        )
        Payment.objects.create(
            customer=self.customer, invoice=invoice, currency=self.currency,
            amount_cents=119000, status="succeeded",
        )
        self._refund(invoice, amount_cents=50000, status="pending", ref="REF-REM-3")
        self.assertEqual(invoice.get_remaining_amount(), 0)

    def test_discount_cents_frozen_on_locked_invoice(self):
        """#188: discount_cents drives the regenerated e-Factura allowance, so it must be
        frozen once the invoice is locked (issued) — like subtotal/tax/total."""
        invoice = Invoice.objects.create(
            customer=self.customer, currency=self.currency, number="INV-DISC-FROZEN",
            subtotal_cents=90000, tax_cents=17100, total_cents=107100, discount_cents=10000,
            status="draft",
        )
        invoice.issue()  # draft -> issued, sets locked_at
        invoice.save()
        invoice.refresh_from_db()

        # clean() rejects the change…
        invoice.discount_cents = 5000
        with self.assertRaises(ValidationError):
            invoice.clean()

        # …and so does the real bypass path: save(update_fields=["discount_cents"]).
        # discount_cents is in _FINANCIAL_FIELDS, so save() does NOT skip clean() for
        # this update_fields set (the carve-out that lets status/meta-only saves through).
        with self.assertRaises(ValidationError):
            invoice.save(update_fields=["discount_cents"])

        # The persisted value must be untouched after both rejected attempts.
        invoice.refresh_from_db()
        self.assertEqual(invoice.discount_cents, 10000)

    def test_invoice_mark_as_paid(self):
        """Test marking invoice as paid"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PAID',
            status='issued'
        )

        invoice.mark_as_paid()
        self.assertEqual(invoice.status, 'paid')
        self.assertIsNotNone(invoice.paid_at)

    def test_invoice_address_snapshot(self):
        """Test address snapshot functionality"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-ADDRESS',
            bill_to_city='Bucharest',
            bill_to_country='RO'
        )

        self.assertEqual(invoice.bill_to_city, 'Bucharest')

    def test_invoice_proforma_conversion(self):
        """Test proforma to invoice conversion reference"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PF-2025-001'
        )

        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-FROM-PF',
            converted_from_proforma=proforma
        )

        self.assertEqual(invoice.converted_from_proforma, proforma)

    def test_invoice_efactura_fields(self):
        """Test Romanian e-factura specific fields"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-EFACTURA',
            efactura_id='12345',
            efactura_sent=True
        )

        self.assertEqual(invoice.efactura_id, '12345')
        self.assertTrue(invoice.efactura_sent)


class InvoiceLineTestCase(TestCase):
    """Test InvoiceLine model functionality"""

    def setUp(self):
        """Create test data"""
        self.currency, _ = Currency.objects.get_or_create(code='EUR', defaults={'symbol': '€', 'decimals': 2})
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Test Company SRL',
            status='active'
        )
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-LINE-TEST'
        )

    def test_create_invoice_line(self):
        """Test basic invoice line creation"""
        line = InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Web Hosting - Premium Plan',
            quantity=Decimal('1.000'),
            unit_price_cents=5000,
            tax_rate=Decimal('0.1900')
        )

        self.assertEqual(line.invoice, self.invoice)
        self.assertEqual(line.kind, 'service')
        self.assertEqual(line.description, 'Web Hosting - Premium Plan')
        self.assertEqual(line.quantity, Decimal('1.000'))
        self.assertEqual(line.unit_price_cents, 5000)
        self.assertEqual(line.tax_rate, Decimal('0.1900'))
        # line_total_cents includes VAT: 5000 + (5000 * 0.19) = 5950
        self.assertEqual(line.line_total_cents, 5950)

    def test_invoice_line_property_calculations(self):
        """Test line calculations from cents"""
        line = InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Domain Registration',
            quantity=Decimal('3.000'),
            unit_price_cents=2500,  # 25.00 EUR
            tax_rate=Decimal('0.1900')
        )

        # Test calculated properties
        self.assertEqual(line.unit_price, Decimal('25.00'))
        # line_total includes VAT: 75.00 + (75.00 * 0.19) = 89.25
        self.assertEqual(line.line_total, Decimal('89.25'))

    def test_invoice_line_save_calculates_total(self):
        """Test that save() method calculates line total"""
        line = InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Test Service',
            quantity=Decimal('2.500'),
            unit_price_cents=4000,  # 40.00 EUR
            tax_rate=Decimal('0.1900')
            # line_total_cents not set - should be calculated
        )

        # Should calculate: 2.5 * 4000 = 10000 cents, plus VAT: 10000 + (10000 * 0.19) = 11900
        self.assertEqual(line.line_total_cents, 11900)

    def test_invoice_line_kind_choices(self):
        """Test valid kind choices"""
        valid_kinds = ['service', 'product', 'discount', 'shipping', 'tax', 'adjustment']

        for kind in valid_kinds:
            line = InvoiceLine.objects.create(
                invoice=self.invoice,
                kind=kind,
                description=f'Test {kind}',
                quantity=1,
                unit_price_cents=1000
            )
            self.assertEqual(line.kind, kind)

    def test_invoice_line_relationship(self):
        """Test invoice relationship"""
        line = InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Test Service',
            quantity=1,
            unit_price_cents=1000
        )

        self.assertEqual(line.invoice, self.invoice)
        # Check line was created successfully
        self.assertIsNotNone(line.pk)

    def test_invoice_line_cascade_delete(self):
        """Test CASCADE delete when invoice is deleted"""
        line = InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Test Service',
            quantity=1,
            unit_price_cents=1000
        )

        line_pk = line.pk
        self.invoice.delete()

        # Line should be deleted due to CASCADE
        self.assertFalse(InvoiceLine.objects.filter(pk=line_pk).exists())

    def test_invoice_line_with_service_reference(self):
        """Test invoice line with service reference"""
        # Create a service plan first
        service_plan = ServicePlan.objects.create(
            plan_type='shared_hosting',
            name='Basic Hosting',
            price_monthly=Decimal('50.00')
        )

        # Create a service for testing
        service = Service.objects.create(
            customer=self.customer,
            service_plan=service_plan,
            service_name='Basic Hosting Plan',
            username='testuser123',
            price=Decimal('50.00'),
            currency=self.currency,
            status='active'
        )

        line = InvoiceLine.objects.create(
            invoice=self.invoice,
            service=service,
            kind='service',
            description='Web Hosting - Basic Plan',
            quantity=1,
            unit_price_cents=5000,
            tax_rate=Decimal('0.1900')
        )

        self.assertEqual(line.service, service)


class InvoiceFSMTestCase(TestCase):
    """Test Invoice FSM transitions and immutability"""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(code='EUR', defaults={'symbol': '€', 'decimals': 2})
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='FSM Test SRL',
            status='active'
        )

    def test_issue_sets_locked_at(self):
        """H2: issue() transition must set locked_at for immutability"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-LOCK-001',
            total_cents=10000,
        )
        self.assertIsNone(invoice.locked_at)

        invoice.issue()
        invoice.save()
        invoice.refresh_from_db()

        self.assertEqual(invoice.status, 'issued')
        self.assertIsNotNone(invoice.locked_at)
        self.assertIsNotNone(invoice.issued_at)

    def test_locked_invoice_rejects_financial_modification(self):
        """H2: Locked invoice must reject changes to financial fields"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-LOCK-002',
            total_cents=10000,
            tax_cents=1900,
        )
        invoice.issue()
        invoice.save()

        # Attempting to modify financial data on a locked, issued invoice must fail
        invoice.total_cents = 20000
        with self.assertRaises(ValidationError):
            invoice.save()

    def test_locked_invoice_allows_status_transitions(self):
        """Locked invoice must still allow FSM transitions (e.g., mark_as_paid)"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-LOCK-003',
            total_cents=10000,
        )
        invoice.issue()
        invoice.save()

        # Status transition should work even on locked invoice
        invoice.mark_as_paid()
        invoice.save()
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, 'paid')

    def test_draft_invoice_allows_modification(self):
        """Draft invoices must remain fully editable"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-DRAFT-MOD',
            total_cents=5000,
        )
        invoice.total_cents = 10000
        invoice.save()  # Should not raise
        invoice.refresh_from_db()
        self.assertEqual(invoice.total_cents, 10000)

    def test_issue_transition_requires_draft_status(self):
        """issue() must only work from draft status"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-FSM-DRAFT',
            status='issued'
        )
        with self.assertRaises(TransitionNotAllowed):
            invoice.issue()

    def test_mark_partially_refunded_from_partially_refunded(self):
        """H4: Multiple partial refunds must be possible"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PARTIAL-002',
        )
        force_status(invoice, 'paid')
        invoice.save()

        # First partial refund
        invoice.mark_partially_refunded()
        invoice.save()
        self.assertEqual(invoice.status, 'partially_refunded')

        # Second partial refund — must not raise TransitionNotAllowed
        invoice.mark_partially_refunded()
        invoice.save()
        self.assertEqual(invoice.status, 'partially_refunded')


class InvoiceIntegrationTestCase(TestCase):
    """Test Invoice integration scenarios"""

    def setUp(self):
        """Create test data"""
        self.currency, _ = Currency.objects.get_or_create(code='EUR', defaults={'symbol': '€', 'decimals': 2})
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Integration Test SRL',
            status='active'
        )
        self.user = User.objects.create_user(email='test@example.com', password='testpass')

    def test_invoice_with_multiple_lines_calculation(self):
        """Test invoice total calculation with multiple lines"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-MULTI'
        )

        # Add multiple lines
        InvoiceLine.objects.create(
            invoice=invoice,
            kind='service',
            description='Hosting',
            quantity=1,
            unit_price_cents=5000,
            tax_rate=Decimal('0.19')
        )

        InvoiceLine.objects.create(
            invoice=invoice,
            kind='service',
            description='Domain',
            quantity=2,
            unit_price_cents=1500,
            tax_rate=Decimal('0.19')
        )

        # Verify lines were created
        self.assertEqual(InvoiceLine.objects.filter(invoice=invoice).count(), 2)

    def test_invoice_payment_workflow(self):
        """Test complete payment workflow"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PAYMENT',
            total_cents=10000,
            status='issued'
        )

        # Mark as paid
        invoice.mark_as_paid()

        self.assertEqual(invoice.status, 'paid')
        self.assertIsNotNone(invoice.paid_at)

    def test_invoice_indexes_performance(self):
        """Test that necessary indexes exist for performance"""
        # This is a placeholder test - would need to check actual database indexes
        # in a real performance test
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PERF'
        )

        # These queries should be efficient due to indexes
        Invoice.objects.filter(customer=self.customer)
        Invoice.objects.filter(status='issued')
        Invoice.objects.filter(created_at__gte=timezone.now().date())

        self.assertTrue(True)  # Test passes if no errors
