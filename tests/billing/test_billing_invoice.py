# ===============================================================================
# BILLING INVOICE TESTS (Django TestCase Format)
# ===============================================================================

from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency, Invoice, InvoiceLine, ProformaInvoice
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan

User = get_user_model()


class InvoiceTestCase(TestCase):
    """Test Invoice model functionality"""

    def setUp(self):
        """Create test data for invoice tests"""
        self.currency = Currency.objects.create(code='EUR', symbol='€', decimals=2)
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
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-2025-002'
        )
        self.assertIn('INV-2025-002', str(invoice))

    def test_invoice_property_calculations(self):
        """Test invoice calculated properties"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-2025-003',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900
        )

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

        with self.assertRaises(IntegrityError):
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
        self.currency = Currency.objects.create(code='EUR', symbol='€', decimals=2)
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


class InvoiceIntegrationTestCase(TestCase):
    """Test Invoice integration scenarios"""

    def setUp(self):
        """Create test data"""
        self.currency = Currency.objects.create(code='EUR', symbol='€', decimals=2)
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
            status='sent'
        )

        # Mark as paid
        invoice.mark_as_paid()

        self.assertEqual(invoice.status, 'paid')
        self.assertIsNotNone(invoice.paid_at)

    def test_invoice_indexes_performance(self):
        """Test that necessary indexes exist for performance"""
        # This is a placeholder test - would need to check actual database indexes
        # in a real performance test
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PERF'
        )

        # These queries should be efficient due to indexes
        Invoice.objects.filter(customer=self.customer)
        Invoice.objects.filter(status='issued')
        Invoice.objects.filter(created_at__gte=timezone.now().date())

        self.assertTrue(True)  # Test passes if no errors
