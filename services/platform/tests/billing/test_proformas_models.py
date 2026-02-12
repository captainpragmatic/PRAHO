# ===============================================================================
# BILLING PROFORMA TESTS (Django TestCase Format)
# ===============================================================================

from datetime import timedelta
from decimal import Decimal

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency, ProformaInvoice, ProformaLine
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan

User = get_user_model()


class ProformaInvoiceTestCase(TestCase):
    """Test ProformaInvoice model functionality"""

    def setUp(self):
        """Create test data"""
        self.currency = Currency.objects.create(code='EUR', symbol='€', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Test Company SRL',
            status='active'
        )

    def test_create_proforma_invoice(self):
        """Test basic proforma invoice creation"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-001',
            subtotal_cents=5000,
            tax_cents=950,
            total_cents=5950
        )

        self.assertEqual(proforma.customer, self.customer)
        self.assertEqual(proforma.currency, self.currency)
        self.assertEqual(proforma.number, 'PRO-001')
        self.assertEqual(proforma.subtotal_cents, 5000)
        self.assertEqual(proforma.tax_cents, 950)
        self.assertEqual(proforma.total_cents, 5950)

    def test_proforma_invoice_str_representation(self):
        """Test string representation"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-STR-001',
            total_cents=10000
        )

        str_repr = str(proforma)
        self.assertIn('PRO-STR-001', str_repr)
        self.assertIn('Test Company SRL', str_repr)

    def test_proforma_invoice_valid_until(self):
        """Test valid_until field and is_expired property"""
        future_date = timezone.now() + timedelta(days=30)
        past_date = timezone.now() - timedelta(days=1)

        # Future valid_until
        proforma_valid = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-VALID',
            total_cents=1000,
            valid_until=future_date
        )
        self.assertFalse(proforma_valid.is_expired)

        # Past valid_until
        proforma_expired = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-EXPIRED',
            total_cents=1000,
            valid_until=past_date
        )
        self.assertTrue(proforma_expired.is_expired)

    def test_proforma_invoice_customer_relationship(self):
        """Test customer relationship"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-CUSTOMER',
            total_cents=1000
        )

        self.assertEqual(proforma.customer, self.customer)

    def test_proforma_invoice_currency_relationship(self):
        """Test currency relationship"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-CURRENCY',
            total_cents=1000
        )

        self.assertEqual(proforma.currency, self.currency)

    def test_proforma_invoice_calculation_consistency(self):
        """Test that subtotal + tax = total"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-CALC',
            subtotal_cents=5000,
            tax_cents=950,
            total_cents=5950
        )

        calculated_total = proforma.subtotal_cents + proforma.tax_cents
        self.assertEqual(calculated_total, proforma.total_cents)

    def test_proforma_invoice_properties(self):
        """Test decimal properties"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-PROPS',
            subtotal_cents=10000,  # 100.00
            tax_cents=2100,        # 21.00
            total_cents=12100      # 121.00
        )

        self.assertEqual(proforma.subtotal, Decimal('100.00'))
        self.assertEqual(proforma.tax_amount, Decimal('21.00'))
        self.assertEqual(proforma.total, Decimal('121.00'))

    def test_proforma_invoice_meta_json_field(self):
        """Test meta JSON field"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-META',
            total_cents=1000,
            meta={'source': 'web', 'campaign': 'spring2024'}
        )

        self.assertEqual(proforma.meta['source'], 'web')
        self.assertEqual(proforma.meta['campaign'], 'spring2024')

    def test_proforma_invoice_billing_address(self):
        """Test billing address snapshot fields"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-ADDRESS',
            total_cents=1000,
            bill_to_name='Test Company SRL',
            bill_to_tax_id='RO12345678',
            bill_to_email='billing@testcompany.ro',
            bill_to_address1='Strada Principala 123',
            bill_to_city='Bucuresti',
            bill_to_postal='010101',
            bill_to_country='RO'
        )

        self.assertEqual(proforma.bill_to_name, 'Test Company SRL')
        self.assertEqual(proforma.bill_to_tax_id, 'RO12345678')
        self.assertEqual(proforma.bill_to_city, 'Bucuresti')


class ProformaLineTestCase(TestCase):
    """Test ProformaLine model functionality"""

    def setUp(self):
        """Create test data"""
        self.currency = Currency.objects.create(code='EUR', symbol='€', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Test Company SRL',
            status='active'
        )
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-LINE-001',
            total_cents=10000
        )
        # Note: ServicePlan is in provisioning app, need to create minimal one
        self.service_plan = ServicePlan.objects.create(
            plan_type='hosting',
            name='Basic Hosting',
            price_monthly=2999  # 29.99 EUR
        )
        # Create a Service instance from the ServicePlan
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            service_name='Test Service',
            username='testuser',
            price=Decimal('99.99'),
            status='active'
        )

    def test_create_proforma_line(self):
        """Test basic proforma line creation"""
        line = ProformaLine.objects.create(
            proforma=self.proforma,
            service=self.service,
            kind='service',
            description='Basic Hosting Plan',
            quantity=Decimal('1.000'),
            unit_price_cents=2999,
            line_total_cents=2999
        )

        self.assertEqual(line.proforma, self.proforma)
        self.assertEqual(line.service, self.service)
        self.assertEqual(line.kind, 'service')
        self.assertEqual(line.description, 'Basic Hosting Plan')
        self.assertEqual(line.quantity, Decimal('1.000'))
        self.assertEqual(line.unit_price_cents, 2999)
        self.assertEqual(line.line_total_cents, 2999)

    def test_proforma_line_kind_choices(self):
        """Test valid kind choices"""
        valid_kinds = ['service', 'setup', 'discount', 'misc']

        for _i, kind in enumerate(valid_kinds):
            line = ProformaLine.objects.create(
                proforma=self.proforma,
                kind=kind,
                description=f'Test {kind} item',
                quantity=Decimal('1.000'),
                unit_price_cents=1000,
                line_total_cents=1000
            )
            self.assertEqual(line.kind, kind)

    def test_proforma_line_quantity_calculation(self):
        """Test quantity and unit price relationship"""
        line = ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Multiple Units',
            quantity=Decimal('3.000'),
            unit_price_cents=1500,
            line_total_cents=4500
        )

        # Check quantity precision
        self.assertEqual(line.quantity, Decimal('3.000'))
        # Check total makes sense (though not automatically calculated)
        expected_total = int(line.quantity * line.unit_price_cents)
        self.assertEqual(line.line_total_cents, expected_total)

    def test_proforma_line_without_service(self):
        """Test proforma line without service (custom item)"""
        line = ProformaLine.objects.create(
            proforma=self.proforma,
            kind='setup',
            description='Custom Setup Fee',
            quantity=Decimal('1.000'),
            unit_price_cents=5000,
            line_total_cents=5000
        )

        self.assertIsNone(line.service)
        self.assertEqual(line.description, 'Custom Setup Fee')
        self.assertEqual(line.kind, 'setup')

    def test_proforma_line_tax_rate(self):
        """Test tax rate field"""
        line = ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Taxable Service',
            quantity=Decimal('1.000'),
            unit_price_cents=10000,
            tax_rate=Decimal('0.2100'),  # 21% VAT
            line_total_cents=12100
        )

        self.assertEqual(line.tax_rate, Decimal('0.2100'))

    def test_proforma_line_properties(self):
        """Test decimal properties"""
        line = ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Property Test',
            quantity=Decimal('1.000'),
            unit_price_cents=2550,    # 25.50
            line_total_cents=2550
        )

        self.assertEqual(line.unit_price, Decimal('25.50'))
        self.assertEqual(line.line_total, Decimal('25.50'))

    def test_proforma_line_discount(self):
        """Test discount line with negative amount"""
        line = ProformaLine.objects.create(
            proforma=self.proforma,
            kind='discount',
            description='Early Bird Discount',
            quantity=Decimal('1.000'),
            unit_price_cents=-1000,  # Negative for discount
            line_total_cents=-1000
        )

        self.assertEqual(line.kind, 'discount')
        self.assertEqual(line.unit_price_cents, -1000)
        self.assertEqual(line.line_total_cents, -1000)


class ProformaIntegrationTestCase(TestCase):
    """Test ProformaInvoice integration scenarios"""

    def setUp(self):
        """Create test data"""
        self.currency = Currency.objects.create(code='EUR', symbol='€', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Integration Test SRL',
            status='active'
        )
        self.hosting_plan = ServicePlan.objects.create(
            plan_type='hosting',
            name='Premium Hosting',
            price_monthly=4999  # 49.99 EUR
        )
        self.domain_plan = ServicePlan.objects.create(
            plan_type='domain',
            name='Domain Registration',
            price_monthly=1299  # 12.99 EUR
        )
        self.hosting_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.hosting_plan,
            service_name='Integration Test Hosting',
            username='inttest_hosting',
            price=Decimal('49.99'),
            status='active'
        )
        self.domain_service = Service.objects.create(
            customer=self.customer,
            service_plan=self.domain_plan,
            service_name='Integration Test Domain',
            username='inttest_domain',
            price=Decimal('12.99'),
            status='active'
        )

    def test_multi_line_proforma(self):
        """Test proforma with multiple lines"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-MULTI',
            subtotal_cents=6298,  # 49.99 + 12.99
            tax_cents=1323,       # 21% VAT
            total_cents=7621      # Total with VAT
        )

        # Hosting line
        ProformaLine.objects.create(
            proforma=proforma,
            service=self.hosting_service,
            kind='service',
            description='Premium Hosting - Monthly',
            quantity=Decimal('1.000'),
            unit_price_cents=4999,
            line_total_cents=4999
        )

        # Domain line
        ProformaLine.objects.create(
            proforma=proforma,
            service=self.domain_service,
            kind='service',
            description='Domain Registration - Annual',
            quantity=Decimal('1.000'),
            unit_price_cents=1299,
            line_total_cents=1299
        )

        self.assertEqual(proforma.lines.count(), 2)

        # Calculate line totals
        line_total = sum(line.line_total_cents for line in proforma.lines.all())
        self.assertEqual(line_total, proforma.subtotal_cents)

    def test_proforma_expiration_workflow(self):
        """Test proforma expiration logic"""
        tomorrow = timezone.now() + timedelta(days=1)
        yesterday = timezone.now() - timedelta(days=1)

        # Valid proforma
        valid_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-VALID',
            total_cents=1000,
            valid_until=tomorrow
        )

        # Expired proforma
        expired_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-EXPIRED',
            total_cents=1000,
            valid_until=yesterday
        )

        self.assertFalse(valid_proforma.is_expired)
        self.assertTrue(expired_proforma.is_expired)

    def test_proforma_with_discount(self):
        """Test proforma with discount line"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-DISCOUNT',
            subtotal_cents=3999,  # After discount
            tax_cents=840,        # VAT on discounted amount
            total_cents=4839
        )

        # Regular line
        ProformaLine.objects.create(
            proforma=proforma,
            service=self.hosting_service,
            kind='service',
            description='Premium Hosting',
            quantity=Decimal('1.000'),
            unit_price_cents=4999,
            line_total_cents=4999
        )

        # Discount line (negative amount)
        ProformaLine.objects.create(
            proforma=proforma,
            kind='discount',
            description='Early Bird Discount',
            quantity=Decimal('1.000'),
            unit_price_cents=-1000,  # Negative for discount
            line_total_cents=-1000
        )

        lines = proforma.lines.all()
        self.assertEqual(len(lines), 2)

        # One positive, one negative
        amounts = [line.line_total_cents for line in lines]
        self.assertIn(4999, amounts)
        self.assertIn(-1000, amounts)

    def test_proforma_conversion_tracking(self):
        """Test tracking conversion to invoice"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-CONVERT',
            total_cents=10000,
            meta={'converted_to_invoice': 'INV-123', 'conversion_date': '2024-01-15'}
        )

        self.assertEqual(proforma.meta['converted_to_invoice'], 'INV-123')

        # Test conversion method exists (even if not implemented)
        self.assertTrue(hasattr(proforma, 'convert_to_invoice'))

    def test_complex_proforma_scenario(self):
        """Test complex proforma with multiple services and fees"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-COMPLEX',
            subtotal_cents=13297,  # Total before VAT
            tax_cents=2792,        # 21% VAT
            total_cents=16089,     # Total with VAT
            bill_to_name='Integration Test SRL',
            bill_to_tax_id='RO98765432',
            meta={'project': 'new_customer_onboarding'}
        )

        # Hosting service
        ProformaLine.objects.create(
            proforma=proforma,
            service=self.hosting_service,
            kind='service',
            description='Premium Hosting - 6 months',
            quantity=Decimal('6.000'),
            unit_price_cents=4999,
            line_total_cents=29994
        )

        # Domain
        ProformaLine.objects.create(
            proforma=proforma,
            service=self.domain_service,
            kind='service',
            description='Domain Registration .com',
            quantity=Decimal('1.000'),
            unit_price_cents=1299,
            line_total_cents=1299
        )

        # Setup fee
        ProformaLine.objects.create(
            proforma=proforma,
            kind='setup',
            description='Initial Setup and Configuration',
            quantity=Decimal('1.000'),
            unit_price_cents=5000,
            line_total_cents=5000
        )

        # Volume discount
        ProformaLine.objects.create(
            proforma=proforma,
            kind='discount',
            description='6-month prepayment discount',
            quantity=Decimal('1.000'),
            unit_price_cents=-22996,  # Significant discount
            line_total_cents=-22996
        )

        self.assertEqual(proforma.lines.count(), 4)
        self.assertEqual(proforma.meta['project'], 'new_customer_onboarding')
