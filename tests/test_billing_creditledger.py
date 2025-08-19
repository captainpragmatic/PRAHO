# ===============================================================================
# BILLING CREDIT LEDGER TESTS (Django TestCase Format) 
# ===============================================================================

from decimal import Decimal
from datetime import date, timedelta
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, models
from django.utils import timezone

from apps.billing.models import CreditLedger, Currency, Invoice, Payment
from apps.customers.models import Customer

User = get_user_model()


class CreditLedgerTestCase(TestCase):
    """Test CreditLedger model functionality"""
    
    def setUp(self):
        """Create test data"""
        self.currency = Currency.objects.create(code='EUR', symbol='€', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Test Company SRL',
            status='active'
        )
        self.user = User.objects.create(
            email='admin@testcompany.ro',
            first_name='Admin',
            last_name='User'
        )
    
    def test_create_credit_ledger_entry(self):
        """Test basic credit ledger entry creation"""
        entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=5000,  # 50.00 EUR
            reason='Manual credit adjustment',
            created_by=self.user
        )
        
        self.assertEqual(entry.customer, self.customer)
        self.assertEqual(entry.delta_cents, 5000)
        self.assertEqual(entry.reason, 'Manual credit adjustment')
        self.assertEqual(entry.created_by, self.user)
    
    def test_credit_ledger_str_representation(self):
        """Test string representation"""
        entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=2500,
            reason='Service charge'
        )
        
        str_repr = str(entry)
        self.assertIn('Test Company SRL', str_repr)
        self.assertIn('25', str_repr)  # Should show amount in some form
    
    def test_credit_ledger_positive_and_negative_amounts(self):
        """Test positive and negative amounts"""
        # Positive amount (credit added)
        credit_entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=5000,
            reason='Credit added'
        )
        
        # Negative amount (credit used)
        debit_entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=-3000,
            reason='Credit used'
        )
        
        self.assertEqual(credit_entry.delta_cents, 5000)
        self.assertEqual(debit_entry.delta_cents, -3000)
    
    def test_credit_ledger_customer_relationship(self):
        """Test customer relationship"""
        entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=1000,
            reason='Test entry'
        )
        
        self.assertEqual(entry.customer, self.customer)
        # Test reverse relationship
        self.assertIn(entry, self.customer.credit_entries.all())
    
    def test_credit_ledger_invoice_reference(self):
        """Test optional invoice reference"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-CREDIT-001',
            total_cents=10000
        )
        
        entry = CreditLedger.objects.create(
            customer=self.customer,
            invoice=invoice,
            delta_cents=-10000,
            reason='Credit applied to invoice'
        )
        
        self.assertEqual(entry.invoice, invoice)
    
    def test_credit_ledger_payment_reference(self):
        """Test optional payment reference"""
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=5000,
            method='bank_transfer',
            status='succeeded'
        )
        
        entry = CreditLedger.objects.create(
            customer=self.customer,
            payment=payment,
            delta_cents=5000,
            reason='Payment converted to credit'
        )
        
        self.assertEqual(entry.payment, payment)
    
    def test_credit_ledger_delta_property(self):
        """Test delta property converts cents to decimal"""
        entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=2550,  # 25.50
            reason='Property test'
        )
        
        self.assertEqual(entry.delta, Decimal('25.50'))
    
    def test_credit_ledger_timestamps(self):
        """Test created_at timestamp"""
        before_creation = timezone.now()
        
        entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=1000,
            reason='Timestamp test'
        )
        
        after_creation = timezone.now()
        
        self.assertGreaterEqual(entry.created_at, before_creation)
        self.assertLessEqual(entry.created_at, after_creation)
    
    def test_credit_ledger_created_by_optional(self):
        """Test that created_by is optional"""
        entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=1000,
            reason='No user specified'
        )
        
        self.assertIsNone(entry.created_by)


class CreditLedgerIntegrationTestCase(TestCase):
    """Test CreditLedger integration scenarios"""
    
    def setUp(self):
        """Create test data"""
        self.currency = Currency.objects.create(code='EUR', symbol='€', decimals=2)
        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Integration Test SRL',
            status='active'
        )
        self.admin_user = User.objects.create(
            email='admin@integration.ro',
            first_name='Admin',
            last_name='User'
        )
    
    def test_credit_balance_calculation(self):
        """Test credit balance calculation across multiple entries"""
        # Initial credit
        CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=10000,  # +100.00
            reason='Initial credit'
        )
        
        # Partial use
        CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=-3000,  # -30.00
            reason='Credit used'
        )
        
        # Additional credit
        CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=5000,  # +50.00
            reason='Additional credit'
        )
        
        # Another use
        CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=-2000,  # -20.00
            reason='More credit used'
        )
        
        # Calculate balance manually
        entries = CreditLedger.objects.filter(customer=self.customer)
        balance = sum(entry.delta_cents for entry in entries)
        
        # Should be: 10000 - 3000 + 5000 - 2000 = 10000
        self.assertEqual(balance, 10000)
        self.assertEqual(len(entries), 4)
    
    def test_credit_application_to_invoice(self):
        """Test applying credit to an invoice"""
        # Customer has existing credit
        CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=15000,  # 150.00 EUR credit
            reason='Prepayment credit'
        )
        
        # Create invoice
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-CREDIT-APP',
            total_cents=8000  # 80.00 EUR
        )
        
        # Apply credit to invoice
        CreditLedger.objects.create(
            customer=self.customer,
            invoice=invoice,
            delta_cents=-8000,  # -80.00 (debit)
            reason=f'Credit applied to {invoice.number}'
        )
        
        # Calculate remaining credit
        total_credit = CreditLedger.objects.filter(
            customer=self.customer
        ).aggregate(
            total=models.Sum('delta_cents')
        )['total']
        
        # Should have 150.00 - 80.00 = 70.00 remaining
        self.assertEqual(total_credit, 7000)
    
    def test_overpayment_to_credit_conversion(self):
        """Test converting overpayment to credit"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-OVERPAY',
            total_cents=5000  # 50.00 EUR
        )
        
        # Customer pays more than invoice amount
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=invoice,
            currency=self.currency,
            amount_cents=8000,  # 80.00 EUR (overpaid by 30.00)
            method='card',
            status='succeeded'
        )
        
        # Convert overpayment to credit
        overpayment_amount = payment.amount_cents - invoice.total_cents
        CreditLedger.objects.create(
            customer=self.customer,
            payment=payment,
            invoice=invoice,
            delta_cents=overpayment_amount,  # 30.00 EUR credit
            reason=f'Overpayment from payment converted to credit',
            created_by=self.admin_user
        )
        
        credit_entry = CreditLedger.objects.get(payment=payment)
        self.assertEqual(credit_entry.delta_cents, 3000)
        self.assertEqual(credit_entry.created_by, self.admin_user)
    
    def test_refund_to_credit_workflow(self):
        """Test refund converted to customer credit"""
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=10000,
            method='card',
            status='succeeded'
        )
        
        # Refund converted to credit instead of bank refund
        CreditLedger.objects.create(
            customer=self.customer,
            payment=payment,
            delta_cents=10000,
            reason='Refund converted to account credit',
            created_by=self.admin_user
        )
        
        refund_entry = CreditLedger.objects.get(payment=payment)
        self.assertEqual(refund_entry.delta_cents, 10000)
        self.assertEqual(refund_entry.created_by, self.admin_user)
    
    def test_chargeback_credit_adjustment(self):
        """Test chargeback resulting in credit adjustment"""
        # Original credit from payment
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=5000,
            method='card',
            status='succeeded'
        )
        
        CreditLedger.objects.create(
            customer=self.customer,
            payment=payment,
            delta_cents=5000,
            reason='Payment credit'
        )
        
        # Chargeback removes the credit
        CreditLedger.objects.create(
            customer=self.customer,
            payment=payment,
            delta_cents=-5000,
            reason='Chargeback reversal',
            created_by=self.admin_user
        )
        
        # Net credit should be zero
        total_credit = CreditLedger.objects.filter(
            customer=self.customer
        ).aggregate(
            total=models.Sum('delta_cents')
        )['total']
        
        self.assertEqual(total_credit, 0)
    
    def test_credit_audit_trail(self):
        """Test comprehensive audit trail for credit movements"""
        # Series of credit operations
        operations = [
            (10000, 'Initial account credit'),
            (-3000, 'Service payment'),
            (5000, 'Bonus credit'),
            (-2000, 'Domain renewal'),
            (1000, 'Billing correction'),
            (-500, 'Transaction fee'),
        ]
        
        for delta_cents, reason in operations:
            CreditLedger.objects.create(
                customer=self.customer,
                delta_cents=delta_cents,
                reason=reason,
                created_by=self.admin_user if delta_cents > 0 else None
            )
        
        # Verify all entries were recorded
        entries = CreditLedger.objects.filter(customer=self.customer).order_by('created_at')
        self.assertEqual(len(entries), 6)
        
        # Verify audit trail preserves order and details
        for i, (delta_cents, reason) in enumerate(operations):
            entry = entries[i]
            self.assertEqual(entry.delta_cents, delta_cents)
            self.assertEqual(entry.reason, reason)
        
        # Verify final balance
        final_balance = sum(entry.delta_cents for entry in entries)
        expected_balance = 10000 - 3000 + 5000 - 2000 + 1000 - 500
        self.assertEqual(final_balance, expected_balance)
    
    def test_credit_ledger_with_user_tracking(self):
        """Test credit ledger entries with user tracking"""
        # Admin adds credit
        admin_entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=10000,
            reason='Admin credit adjustment',
            created_by=self.admin_user
        )
        
        # System deducts credit (no user)
        system_entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=-2000,
            reason='Automatic billing cycle charge'
        )
        
        self.assertEqual(admin_entry.created_by, self.admin_user)
        self.assertIsNone(system_entry.created_by)
    
    def test_credit_balance_aggregation(self):
        """Test aggregating customer credit balance"""
        # Create multiple entries
        entries_data = [
            (5000, 'Credit 1'),
            (-2000, 'Usage 1'),
            (3000, 'Credit 2'),
            (-1000, 'Usage 2'),
            (2000, 'Credit 3'),
        ]
        
        for delta_cents, reason in entries_data:
            CreditLedger.objects.create(
                customer=self.customer,
                delta_cents=delta_cents,
                reason=reason
            )
        
        # Test aggregation
        balance = CreditLedger.objects.filter(
            customer=self.customer
        ).aggregate(
            balance=models.Sum('delta_cents'),
            credit_count=models.Count('id', filter=models.Q(delta_cents__gt=0)),
            debit_count=models.Count('id', filter=models.Q(delta_cents__lt=0))
        )
        
        expected_balance = 5000 - 2000 + 3000 - 1000 + 2000  # 7000
        self.assertEqual(balance['balance'], expected_balance)
        self.assertEqual(balance['credit_count'], 3)  # 3 positive entries
        self.assertEqual(balance['debit_count'], 2)   # 2 negative entries
    
    def test_credit_ledger_cascade_behavior(self):
        """Test cascade behavior when customer is deleted"""
        entry = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=1000,
            reason='Test cascade'
        )
        
        customer_id = self.customer.id
        
        # Delete customer should cascade to credit entries
        self.customer.delete()
        
        # Entry should be deleted
        self.assertFalse(CreditLedger.objects.filter(customer_id=customer_id).exists())
    
    def test_credit_ledger_null_references(self):
        """Test SET_NULL behavior for invoice/payment references"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-NULL-TEST',
            total_cents=5000
        )
        
        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=5000,
            method='card',
            status='succeeded'
        )
        
        entry = CreditLedger.objects.create(
            customer=self.customer,
            invoice=invoice,
            payment=payment,
            delta_cents=5000,
            reason='Test null references'
        )
        
        # Delete invoice and payment
        invoice.delete()
        payment.delete()
        
        # Entry should still exist but with null references
        entry.refresh_from_db()
        self.assertIsNone(entry.invoice)
        self.assertIsNone(entry.payment)
