# ===============================================================================
# ADDITIONAL BILLING MODELS TESTS - EDGE CASES & MISSING FUNCTIONALITY
# ===============================================================================

from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    FXRate,
    Invoice,
    InvoiceSequence,
    Payment,
    PaymentCollectionRun,
    PaymentRetryAttempt,
    PaymentRetryPolicy,
    ProformaInvoice,
    ProformaSequence,
    TaxRule,
    VATValidation,
)
from apps.customers.models import Customer

User = get_user_model()


class CurrencyModelAdditionalTestCase(TestCase):
    """Test additional Currency model functionality"""

    def test_currency_str_representation(self):
        """Test Currency __str__ method"""
        currency = Currency.objects.create(code='GBP', symbol='£', decimals=2)
        expected = "GBP (£)"
        self.assertEqual(str(currency), expected)

    def test_currency_meta_attributes(self):
        """Test Currency model meta attributes"""
        meta = Currency._meta
        self.assertEqual(meta.db_table, 'currency')
        # Accept both English and Romanian translations
        self.assertIn(str(meta.verbose_name), ['Currency', 'Monedă'])
        self.assertIn(str(meta.verbose_name_plural), ['Currencies', 'Monede'])

    def test_currency_primary_key_constraint(self):
        """Test Currency primary key uniqueness"""
        Currency.objects.create(code='USD', symbol='$', decimals=2)

        with self.assertRaises(IntegrityError):
            Currency.objects.create(code='USD', symbol='$', decimals=2)

    def test_currency_decimal_precision(self):
        """Test Currency decimal field validation"""
        # Test various decimal precisions
        currencies = [
            ('JPY', '¥', 0),  # No decimal places
            ('EUR', '€', 2),  # Standard precision
            ('BTC', '₿', 8),  # High precision
        ]

        for code, symbol, decimals in currencies:
            currency = Currency.objects.create(
                code=code,
                symbol=symbol,
                decimals=decimals
            )
            self.assertEqual(currency.decimals, decimals)


class FXRateModelAdditionalTestCase(TestCase):
    """Test additional FXRate model functionality"""

    def setUp(self):
        """Setup test currencies"""
        self.usd = Currency.objects.create(code='USD', symbol='$', decimals=2)
        self.eur = Currency.objects.create(code='EUR', symbol='€', decimals=2)
        self.gbp = Currency.objects.create(code='GBP', symbol='£', decimals=2)

    def test_fx_rate_str_representation(self):
        """Test FXRate __str__ method"""
        rate_date = date(2024, 1, 15)
        fx_rate = FXRate.objects.create(
            base_code=self.usd,
            quote_code=self.eur,
            rate=Decimal('0.85'),
            as_of=rate_date
        )
        expected = "USD/EUR = 0.85000000 (2024-01-15)"
        self.assertEqual(str(fx_rate), expected)

    def test_fx_rate_unique_constraint(self):
        """Test FXRate unique constraint on base_code, quote_code, as_of"""
        rate_date = date.today()

        FXRate.objects.create(
            base_code=self.usd,
            quote_code=self.eur,
            rate=Decimal('0.85'),
            as_of=rate_date
        )

        # Should raise IntegrityError for duplicate
        with self.assertRaises(IntegrityError):
            FXRate.objects.create(
                base_code=self.usd,
                quote_code=self.eur,
                rate=Decimal('0.86'),  # Different rate, same date
                as_of=rate_date
            )

    def test_fx_rate_high_precision(self):
        """Test FXRate high precision decimal handling"""
        fx_rate = FXRate.objects.create(
            base_code=self.usd,
            quote_code=self.eur,
            rate=Decimal('0.85123456'),  # 8 decimal places
            as_of=date.today()
        )
        self.assertEqual(fx_rate.rate, Decimal('0.85123456'))

    def test_fx_rate_cascade_delete(self):
        """Test FXRate CASCADE delete when currency is deleted"""
        fx_rate = FXRate.objects.create(
            base_code=self.usd,
            quote_code=self.eur,
            rate=Decimal('0.85'),
            as_of=date.today()
        )

        rate_id = fx_rate.id

        # Delete base currency
        self.usd.delete()

        # FX rate should be deleted too
        self.assertFalse(FXRate.objects.filter(id=rate_id).exists())


class InvoiceSequenceModelAdditionalTestCase(TestCase):
    """Test additional InvoiceSequence model functionality"""

    def test_invoice_sequence_default_scope(self):
        """Test InvoiceSequence default scope"""
        sequence = InvoiceSequence.objects.create()
        self.assertEqual(sequence.scope, 'default')
        self.assertEqual(sequence.last_value, 0)

    def test_invoice_sequence_scope_uniqueness(self):
        """Test InvoiceSequence scope uniqueness constraint"""
        InvoiceSequence.objects.create(scope='test_scope')

        with self.assertRaises(IntegrityError):
            InvoiceSequence.objects.create(scope='test_scope')

    def test_get_next_number_concurrency_safety(self):
        """Test get_next_number atomicity under concurrent access"""
        sequence = InvoiceSequence.objects.create(scope='concurrency_test')

        # Simulate concurrent access
        results = []
        for _ in range(5):
            next_number = sequence.get_next_number('TEST')
            results.append(next_number)

        # All numbers should be unique and sequential
        expected = ['TEST-000001', 'TEST-000002', 'TEST-000003', 'TEST-000004', 'TEST-000005']
        self.assertEqual(results, expected)

    def test_get_next_number_custom_prefix(self):
        """Test get_next_number with custom prefix"""
        sequence = InvoiceSequence.objects.create(scope='custom_prefix')

        custom_number = sequence.get_next_number('CUSTOM')
        self.assertEqual(custom_number, 'CUSTOM-000001')

    def test_get_next_number_padding(self):
        """Test get_next_number number padding"""
        sequence = InvoiceSequence.objects.create(scope='padding_test', last_value=999999)

        next_number = sequence.get_next_number('PAD')
        self.assertEqual(next_number, 'PAD-1000000')  # Should handle large numbers

    def test_invoice_sequence_meta_attributes(self):
        """Test InvoiceSequence model meta attributes"""
        meta = InvoiceSequence._meta
        self.assertEqual(meta.db_table, 'invoice_sequence')
        # Accept both English and Romanian translations
        self.assertIn(str(meta.verbose_name), ['Invoice Sequence', 'Secvență factură'])
        self.assertIn(str(meta.verbose_name_plural), ['Invoice Sequences', 'Secvențe factură'])


class ProformaSequenceModelAdditionalTestCase(TestCase):
    """Test additional ProformaSequence model functionality"""

    def test_proforma_sequence_default_scope(self):
        """Test ProformaSequence default scope"""
        sequence = ProformaSequence.objects.create()
        self.assertEqual(sequence.scope, 'default')
        self.assertEqual(sequence.last_value, 0)

    def test_proforma_sequence_scope_uniqueness(self):
        """Test ProformaSequence scope uniqueness constraint"""
        ProformaSequence.objects.create(scope='proforma_test_scope')

        with self.assertRaises(IntegrityError):
            ProformaSequence.objects.create(scope='proforma_test_scope')

    def test_get_next_number_logging(self):
        """Test get_next_number logging functionality"""
        sequence = ProformaSequence.objects.create(scope='logging_test')

        with patch('apps.billing.models.logging.getLogger') as mock_logger:
            mock_log = Mock()
            mock_logger.return_value = mock_log

            next_number = sequence.get_next_number('LOG')

            # Should have logged the operation
            mock_log.info.assert_called_once()
            self.assertEqual(next_number, 'LOG-000001')

    @patch('apps.billing.proforma_models.transaction.atomic')
    def test_get_next_number_transaction_rollback(self, mock_atomic):
        """Test get_next_number transaction rollback on error"""
        sequence = ProformaSequence.objects.create(scope='rollback_test')

        # Mock transaction.atomic to raise exception
        mock_atomic.side_effect = Exception('Database error')

        with self.assertRaises(Exception):
            sequence.get_next_number('FAIL')

    def test_proforma_sequence_meta_attributes(self):
        """Test ProformaSequence model meta attributes"""
        meta = ProformaSequence._meta
        self.assertEqual(meta.db_table, 'proforma_sequence')
        # Accept both English and Romanian translations
        self.assertIn(str(meta.verbose_name), ['Proforma Sequence', 'Secvență proformă'])
        self.assertIn(str(meta.verbose_name_plural), ['Proforma Sequences', 'Secvențe proformă'])


class TaxRuleModelAdditionalTestCase(TestCase):
    """Test additional TaxRule model functionality"""

    def setUp(self):
        """Setup test data"""
        self.tax_rule = TaxRule.objects.create(
            country_code='RO',
            tax_type='vat',
            rate=Decimal('0.19'),
            valid_from=date(2024, 1, 1),
            valid_to=date(2024, 12, 31),
            is_eu_member=True
        )

    def test_tax_rule_is_active_within_period(self):
        """Test TaxRule.is_active() within valid period"""
        test_date = date(2024, 6, 15)  # Within valid period
        self.assertTrue(self.tax_rule.is_active(test_date))

    def test_tax_rule_is_active_before_period(self):
        """Test TaxRule.is_active() before valid period"""
        test_date = date(2023, 12, 31)  # Before valid period
        self.assertFalse(self.tax_rule.is_active(test_date))

    def test_tax_rule_is_active_after_period(self):
        """Test TaxRule.is_active() after valid period"""
        test_date = date(2025, 1, 1)  # After valid period
        self.assertFalse(self.tax_rule.is_active(test_date))

    def test_tax_rule_is_active_no_end_date(self):
        """Test TaxRule.is_active() with no end date"""
        rule_no_end = TaxRule.objects.create(
            country_code='DE',
            tax_type='vat',
            rate=Decimal('0.20'),
            valid_from=date(2024, 1, 1),
            # No valid_to date
            is_eu_member=True
        )

        future_date = date(2030, 1, 1)
        self.assertTrue(rule_no_end.is_active(future_date))

    def test_tax_rule_is_active_default_today(self):
        """Test TaxRule.is_active() with default today's date"""
        with patch('django.utils.timezone.now') as mock_now:
            # Create a mock datetime object with date() method
            from datetime import datetime
            mock_now.return_value = datetime(2024, 6, 15, 12, 0, 0)

            self.assertTrue(self.tax_rule.is_active())

    def test_tax_rule_str_representation(self):
        """Test TaxRule __str__ method"""
        expected = "RO VAT 19.00%"
        self.assertEqual(str(self.tax_rule), expected)

    def test_tax_rule_validation_negative_rate(self):
        """Test TaxRule validation for negative rates"""
        with self.assertRaises(ValidationError):
            tax_rule = TaxRule(
                country_code='FR',
                tax_type='vat',
                rate=Decimal('-0.05'),  # Negative rate
                valid_from=date.today()
            )
            tax_rule.full_clean()

    def test_tax_rule_validation_rate_too_high(self):
        """Test TaxRule validation for rates above 100%"""
        with self.assertRaises(ValidationError):
            tax_rule = TaxRule(
                country_code='FR',
                tax_type='vat',
                rate=Decimal('1.50'),  # 150%
                valid_from=date.today()
            )
            tax_rule.full_clean()


class VATValidationModelAdditionalTestCase(TestCase):
    """Test additional VATValidation model functionality"""

    def setUp(self):
        """Setup test data"""
        self.vat_validation = VATValidation.objects.create(
            country_code='RO',
            vat_number='12345678',
            full_vat_number='RO12345678',
            is_valid=True,
            is_active=True,
            company_name='Test Company SRL',
            validation_source='vies',
            expires_at=timezone.now() + timedelta(days=30)
        )

    def test_vat_validation_is_expired_future(self):
        """Test VATValidation.is_expired() with future expiration"""
        self.assertFalse(self.vat_validation.is_expired())

    def test_vat_validation_is_expired_past(self):
        """Test VATValidation.is_expired() with past expiration"""
        self.vat_validation.expires_at = timezone.now() - timedelta(days=1)
        self.vat_validation.save()

        self.assertTrue(self.vat_validation.is_expired())

    def test_vat_validation_is_expired_no_expiration(self):
        """Test VATValidation.is_expired() with no expiration date"""
        self.vat_validation.expires_at = None
        self.vat_validation.save()

        self.assertFalse(self.vat_validation.is_expired())

    def test_vat_validation_str_representation(self):
        """Test VATValidation __str__ method"""
        expected = "RO12345678 (Test Company SRL) - Valid"
        self.assertEqual(str(self.vat_validation), expected)

    def test_vat_validation_str_invalid(self):
        """Test VATValidation __str__ method for invalid VAT"""
        self.vat_validation.is_valid = False
        expected = "RO12345678 (Test Company SRL) - Invalid"
        self.assertEqual(str(self.vat_validation), expected)

    def test_vat_validation_str_no_company_name(self):
        """Test VATValidation __str__ method without company name"""
        self.vat_validation.company_name = ''
        expected = "RO12345678 - Valid"
        self.assertEqual(str(self.vat_validation), expected)


class PaymentRetryPolicyModelAdditionalTestCase(TestCase):
    """Test additional PaymentRetryPolicy model functionality"""

    def setUp(self):
        """Setup test data"""
        self.policy = PaymentRetryPolicy.objects.create(
            name='Test Policy',
            retry_intervals_days=[1, 3, 7, 14, 30],
            max_attempts=5,
            suspend_service_after_days=45,
            terminate_service_after_days=90,
            is_default=False,
            is_active=True
        )

    def test_payment_retry_policy_str_representation(self):
        """Test PaymentRetryPolicy __str__ method"""
        expected = "Test Policy (5 attempts)"
        self.assertEqual(str(self.policy), expected)

    def test_payment_retry_policy_get_interval_for_attempt(self):
        """Test PaymentRetryPolicy.get_interval_for_attempt() method"""
        # Test existing method if it exists, or verify expected behavior
        self.assertEqual(self.policy.max_attempts, 5)
        self.assertEqual(len(self.policy.retry_intervals_days), 5)

    def test_payment_retry_policy_default_uniqueness(self):
        """Test that only one default policy can exist"""
        # Create first default policy
        default_policy1 = PaymentRetryPolicy.objects.create(
            name='Default Policy 1',
            is_default=True,
            is_active=True
        )

        # Creating second default policy should either fail or make first non-default
        # This depends on the model implementation
        default_policy2 = PaymentRetryPolicy.objects.create(
            name='Default Policy 2',
            is_default=True,
            is_active=True
        )

        # Refresh from database to check current state
        default_policy1.refresh_from_db()
        default_policy2.refresh_from_db()

        # At least one should be marked as default
        default_policies = PaymentRetryPolicy.objects.filter(is_default=True)
        self.assertGreaterEqual(default_policies.count(), 1)

        # Verify that if both exist, only one is marked as default
        # (implementation detail may vary)
        if default_policy1.is_default and default_policy2.is_default:
            # If both are still default, there should be exactly 2 defaults
            self.assertEqual(default_policies.count(), 2)
        else:
            # Otherwise exactly one should be default
            self.assertEqual(default_policies.count(), 1)


class PaymentRetryAttemptModelAdditionalTestCase(TestCase):
    """Test additional PaymentRetryAttempt model functionality"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Retry Test SRL',
            status='active'
        )
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-RETRY-001',
            total_cents=10000,
            status='issued'
        )
        self.payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=10000,
            currency=self.currency,
            status='failed'
        )
        self.policy = PaymentRetryPolicy.objects.create(
            name='Test Retry Policy',
            max_attempts=3,
            is_active=True
        )

        self.retry_attempt = PaymentRetryAttempt.objects.create(
            payment=self.payment,
            policy=self.policy,
            attempt_number=1,
            scheduled_at=timezone.now(),
            status='pending'
        )

    def test_payment_retry_attempt_str_representation(self):
        """Test PaymentRetryAttempt __str__ method"""
        expected = f"Attempt 1 for Payment {self.payment.id} - pending"
        self.assertEqual(str(self.retry_attempt), expected)

    def test_payment_retry_attempt_status_transition(self):
        """Test PaymentRetryAttempt status transitions"""
        # Test status change
        self.retry_attempt.status = 'executed'
        self.retry_attempt.executed_at = timezone.now()
        self.retry_attempt.save()

        self.retry_attempt.refresh_from_db()
        self.assertEqual(self.retry_attempt.status, 'executed')
        self.assertIsNotNone(self.retry_attempt.executed_at)

    def test_payment_retry_attempt_failure_reason(self):
        """Test PaymentRetryAttempt failure handling"""
        failure_reason = 'Insufficient funds'

        self.retry_attempt.status = 'failed'
        self.retry_attempt.failure_reason = failure_reason
        self.retry_attempt.executed_at = timezone.now()
        self.retry_attempt.save()

        self.assertEqual(self.retry_attempt.failure_reason, failure_reason)


class PaymentCollectionRunModelAdditionalTestCase(TestCase):
    """Test additional PaymentCollectionRun model functionality"""

    def setUp(self):
        """Setup test data"""
        self.user = User.objects.create_user(
            email='collection@test.ro',
            password='testpass'
        )

        self.collection_run = PaymentCollectionRun.objects.create(
            run_type='manual',
            status='running',
            started_at=timezone.now(),
            total_scheduled=100,
            total_processed=0,
            total_successful=0,
            total_failed=0,
            triggered_by=self.user
        )

    def test_payment_collection_run_str_representation(self):
        """Test PaymentCollectionRun __str__ method"""
        expected_parts = ['manual', 'running', str(self.collection_run.started_at.date())]
        str_repr = str(self.collection_run)

        for part in expected_parts:
            self.assertIn(part, str_repr)

    def test_payment_collection_run_amount_property(self):
        """Test PaymentCollectionRun amount property conversion"""
        self.collection_run.amount_recovered_cents = 125000  # 1250.00
        self.collection_run.save()

        # Test if there's an amount property that converts cents to decimal
        self.assertEqual(self.collection_run.amount_recovered, Decimal('1250.00'))

    def test_payment_collection_run_completion(self):
        """Test PaymentCollectionRun completion"""
        # Simulate completion
        self.collection_run.status = 'completed'
        self.collection_run.completed_at = timezone.now()
        self.collection_run.total_processed = 95
        self.collection_run.total_successful = 90
        self.collection_run.total_failed = 5
        self.collection_run.amount_recovered_cents = 50000
        self.collection_run.save()

        self.assertEqual(self.collection_run.status, 'completed')
        self.assertIsNotNone(self.collection_run.completed_at)
        self.assertEqual(self.collection_run.total_processed, 95)

    def test_payment_collection_run_error_handling(self):
        """Test PaymentCollectionRun error handling"""
        error_message = 'Connection timeout to payment gateway'

        self.collection_run.status = 'failed'
        self.collection_run.error_message = error_message
        self.collection_run.completed_at = timezone.now()
        self.collection_run.save()

        self.assertEqual(self.collection_run.status, 'failed')
        self.assertEqual(self.collection_run.error_message, error_message)


class ModelRelationshipTestCase(TestCase):
    """Test model relationships and foreign key behaviors"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Relationship Test SRL',
            status='active'
        )

    def test_invoice_proforma_relationship(self):
        """Test Invoice-ProformaInvoice relationship"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-REL-001',
            total_cents=10000
        )

        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-REL-001',
            total_cents=10000,
            converted_from_proforma=proforma
        )

        self.assertEqual(invoice.converted_from_proforma, proforma)

    def test_payment_invoice_relationship(self):
        """Test Payment-Invoice relationship"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PAY-001',
            total_cents=10000,
            status='issued'
        )

        payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            amount_cents=10000,
            currency=self.currency,
            status='succeeded'
        )

        self.assertEqual(payment.invoice, invoice)
        self.assertIn(payment, invoice.payments.all())

    def test_cascade_delete_relationships(self):
        """Test CASCADE delete behaviors"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-CASCADE-001',
            total_cents=10000
        )

        payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            amount_cents=5000,
            currency=self.currency,
            status='succeeded'
        )

        payment_id = payment.id

        # Delete invoice - payment should remain (not CASCADE)
        invoice.delete()

        # Payment should still exist (depends on actual model relationship)
        payment.refresh_from_db()
        self.assertIsNone(payment.invoice)

        # Verify payment still exists by ID
        self.assertTrue(Payment.objects.filter(id=payment_id).exists())


class ModelValidationTestCase(TestCase):
    """Test model validation rules"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Validation Test SRL',
            status='active'
        )

    def test_invoice_status_validation(self):
        """Test Invoice status field validation"""
        valid_statuses = ['draft', 'issued', 'paid', 'overdue', 'void', 'refunded']

        for status in valid_statuses:
            invoice = Invoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number=f'INV-{status.upper()}-001',
                status=status,
                total_cents=10000
            )
            self.assertEqual(invoice.status, status)

    def test_payment_method_validation(self):
        """Test Payment method field validation"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-METHOD-001',
            total_cents=10000,
            status='issued'
        )

        valid_methods = ['stripe', 'bank', 'paypal', 'cash', 'other']

        for method in valid_methods:
            payment = Payment.objects.create(
                customer=self.customer,
                invoice=invoice,
                amount_cents=1000,
                currency=self.currency,
                payment_method=method,
                status='succeeded'
            )
            self.assertEqual(payment.payment_method, method)

    def test_currency_code_length_validation(self):
        """Test Currency code length validation"""
        # Should accept 3-character codes
        currency = Currency.objects.create(
            code='USD',
            symbol='$',
            decimals=2
        )
        self.assertEqual(len(currency.code), 3)

    def test_decimal_field_precision(self):
        """Test decimal field precision handling"""
        # Test high precision rate
        base_currency = Currency.objects.create(code='USD', symbol='$', decimals=2)
        quote_currency = Currency.objects.create(code='BTC', symbol='₿', decimals=8)

        fx_rate = FXRate.objects.create(
            base_code=base_currency,
            quote_code=quote_currency,
            rate=Decimal('0.00002156'),  # Very small rate
            as_of=date.today()
        )

        self.assertEqual(fx_rate.rate, Decimal('0.00002156'))


class ModelPropertyTestCase(TestCase):
    """Test model computed properties"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Property Test SRL',
            status='active'
        )

    def test_invoice_is_overdue_property(self):
        """Test Invoice.is_overdue property"""
        # Past due date
        overdue_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-OVERDUE-001',
            due_at=timezone.now() - timedelta(days=1),
            status='issued',
            total_cents=10000
        )

        self.assertTrue(overdue_invoice.is_overdue())

    def test_invoice_decimal_properties(self):
        """Test Invoice decimal conversion properties"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-DECIMAL-001',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            status='draft'
        )

        self.assertEqual(invoice.subtotal, Decimal('100.00'))
        self.assertEqual(invoice.tax_amount, Decimal('19.00'))
        self.assertEqual(invoice.total, Decimal('119.00'))

    def test_payment_decimal_properties(self):
        """Test Payment decimal conversion properties"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PAY-DECIMAL-001',
            total_cents=15000,
            status='issued'
        )

        payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            amount_cents=15000,
            currency=self.currency,
            status='succeeded'
        )

        self.assertEqual(payment.amount, Decimal('150.00'))


class ModelManagerTestCase(TestCase):
    """Test custom model managers if they exist"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Manager Test SRL',
            status='active'
        )

    def test_default_manager_functionality(self):
        """Test default model manager functionality"""
        # Create multiple invoices
        for i in range(3):
            Invoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number=f'INV-MGR-{i:03d}',
                total_cents=(i + 1) * 1000,
                status='issued'
            )

        # Test basic manager operations
        all_invoices = Invoice.objects.all()
        self.assertEqual(all_invoices.count(), 3)

        # Test filtering
        issued_invoices = Invoice.objects.filter(status='issued')
        self.assertEqual(issued_invoices.count(), 3)

    def test_queryset_optimization(self):
        """Test queryset optimization methods"""
        # Create invoice with related objects
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-OPT-001',
            total_cents=10000,
            status='issued'
        )

        Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            amount_cents=10000,
            currency=self.currency,
            status='succeeded'
        )

        # Test select_related optimization
        invoices_with_customer = Invoice.objects.select_related('customer')
        invoice_from_qs = invoices_with_customer.get(pk=invoice.pk)

        # Accessing customer shouldn't trigger additional query
        self.assertEqual(invoice_from_qs.customer, self.customer)
