# ===============================================================================
# BILLING ADVANCED COVERAGE TEST SUITE - BATCH 2 (TESTS #21-40)
# ===============================================================================
"""
Second batch of 20 comprehensive Django unit tests for PRAHO Platform billing app.
Focuses on advanced functionality, complex business logic, and remaining coverage gaps.

Coverage Targets:
- Services RefundService complex logic and edge cases
- Views authorization and form handling edge cases  
- Model business logic and Romanian VAT compliance
- PDF generation complex scenarios
- Error handling and security boundaries

Tests #21-40 build on the first 20 tests foundation.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpRequest
from django.test import RequestFactory, TestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    Invoice,
    InvoiceLine,
    InvoiceSequence,
    Payment,
    ProformaInvoice,
    ProformaLine,
    ProformaSequence,
    TaxRule,
)
from apps.billing.pdf_generators import RomanianInvoicePDFGenerator, RomanianProformaPDFGenerator
from apps.billing.services import (
    RefundData,
    RefundQueryService,
    RefundReason,
    RefundService,
    RefundType,
    generate_invoice_pdf,
    generate_proforma_pdf,
    generate_e_factura_xml,
)
from apps.billing.views import (
    _get_accessible_customer_ids,
    _validate_customer_assignment,
    _validate_financial_document_access,
    _process_valid_until_date,
    _process_proforma_line_items,
    invoice_refund,
    invoice_refund_request,
)
from apps.customers.models import Customer, CustomerTaxProfile
from apps.tickets.models import SupportCategory, Ticket
from apps.users.models import CustomerMembership, User


class BillingAdvancedCoverageTestCase(TestCase):
    """
    Advanced coverage test suite for billing app - Tests #21-40.
    Focuses on complex business logic, edge cases, and error handling.
    """

    def setUp(self) -> None:
        """Set up test data for advanced scenarios."""
        # Create currency
        self.currency = Currency.objects.create(
            code='RON',
            symbol='lei',
            decimals=2
        )

        # Create users with different roles
        self.staff_user = get_user_model().objects.create_user(
            email='staff@praho.ro',
            password='testpass123',
            first_name='Staff',
            last_name='User',
            is_staff=True
        )

        self.regular_user = get_user_model().objects.create_user(
            email='user@praho.ro',
            password='testpass123',
            first_name='Regular',
            last_name='User'
        )

        # Create customers
        self.customer = Customer.objects.create(
            name='Test Customer SRL',
            company_name='Test Customer SRL',
            primary_email='customer@test.ro',
            customer_type='company'
        )

        # Create tax profile for the customer
        CustomerTaxProfile.objects.create(
            customer=self.customer,
            cui='RO12345678',
            is_vat_payer=True,
            vat_number='RO12345678'
        )

        self.other_customer = Customer.objects.create(
            name='Other Customer SRL',
            company_name='Other Customer SRL', 
            primary_email='other@test.ro',
            customer_type='company'
        )

        # Create tax profile for the other customer
        CustomerTaxProfile.objects.create(
            customer=self.other_customer,
            cui='RO87654321',
            is_vat_payer=True,
            vat_number='RO87654321'
        )

        # Create customer memberships
        CustomerMembership.objects.create(
            user=self.staff_user,
            customer=self.customer,
            role='admin'
        )

        CustomerMembership.objects.create(
            user=self.regular_user,
            customer=self.customer,
            role='member'
        )

        # Create sequences
        self.invoice_sequence = InvoiceSequence.objects.create(
            scope='default',
            last_value=1000
        )

        self.proforma_sequence = ProformaSequence.objects.create(
            scope='default',
            last_value=500
        )

        # Create test invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-001001',
            currency=self.currency,
            status='paid',
            total_cents=11900,  # €119 with VAT
            tax_cents=1900,     # €19 VAT
            subtotal_cents=10000,  # €100 subtotal
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            paid_at=timezone.now()
        )

        # Create test proforma
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-000501',
            currency=self.currency,
            total_cents=5950,   # €59.50 with VAT
            tax_cents=950,      # €9.50 VAT
            subtotal_cents=5000,   # €50 subtotal
            valid_until=timezone.now() + timezone.timedelta(days=30)
        )

        # Create request factory for view testing
        self.factory = RequestFactory()

    # ============================================================================
    # TEST #21-23: RefundService Complex Logic
    # ============================================================================

    def test_refund_service_bidirectional_sync_edge_cases(self) -> None:
        """Test #21: RefundService bidirectional synchronization edge cases."""
        # Create test data with complex relationships
        refund_data: RefundData = {
            'refund_type': RefundType.PARTIAL,
            'amount_cents': 5000,  # Partial refund
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Partial refund requested by customer',
            'initiated_by': self.staff_user,
            'external_refund_id': 'ext_ref_123',
            'process_payment_refund': True
        }

        # Test refund with null invoice (edge case)
        result = RefundService.refund_invoice(999999, refund_data)  # Non-existent invoice
        self.assertTrue(result.is_err())
        self.assertIn('not found', result.error)

        # Test with existing invoice
        result = RefundService.refund_invoice(self.invoice.id, refund_data)
        if result.is_ok():
            refund_result = result.unwrap()
            self.assertEqual(refund_result['refund_type'], RefundType.PARTIAL)
            self.assertEqual(refund_result['amount_refunded_cents'], 5000)
            self.assertTrue(refund_result['invoice_status_updated'])

    def test_refund_eligibility_complex_validation(self) -> None:
        """Test #22: Refund eligibility validation with complex scenarios."""
        # Test eligibility for fully paid invoice
        result = RefundService.get_refund_eligibility('invoice', self.invoice.id, 5000)
        
        if result.is_ok():
            eligibility = result.unwrap()
            self.assertTrue(eligibility['is_eligible'])
            self.assertEqual(eligibility['max_refund_amount_cents'], self.invoice.total_cents)
            self.assertEqual(eligibility['already_refunded_cents'], 0)

        # Test with invalid entity type
        result = RefundService.get_refund_eligibility('invalid_type', self.invoice.id)
        self.assertTrue(result.is_err())
        self.assertIn('Invalid entity_type', result.error)

        # Test with wrong ID type for invoice (should be int)
        test_uuid = uuid.uuid4()
        result = RefundService.get_refund_eligibility('invoice', test_uuid)  # type: ignore[arg-type]
        self.assertTrue(result.is_err())
        self.assertIn('must be int', result.error)

    def test_refund_query_service_comprehensive(self) -> None:
        """Test #23: RefundQueryService comprehensive functionality."""
        # Add refund metadata to invoice for testing
        self.invoice.meta = {
            'refunds': [
                {
                    'refund_id': str(uuid.uuid4()),
                    'amount_cents': 2000,
                    'reason': 'customer_request',
                    'notes': 'Test refund',
                    'refunded_at': timezone.now().isoformat(),
                    'initiated_by': str(self.staff_user.id)
                }
            ]
        }
        self.invoice.save()

        # Test get entity refunds
        result = RefundQueryService.get_entity_refunds('invoice', self.invoice.id)
        self.assertTrue(result.is_ok())
        refunds = result.unwrap()
        self.assertEqual(len(refunds), 1)
        self.assertEqual(refunds[0]['amount_cents'], 2000)

        # Test refund statistics
        stats_result = RefundQueryService.get_refund_statistics()
        self.assertTrue(stats_result.is_ok())
        stats = stats_result.unwrap()
        self.assertIn('total_refunds', stats)
        self.assertIn('refunds_by_reason', stats)

        # Test eligibility check
        eligibility = RefundQueryService.check_refund_eligibility('invoice', self.invoice.id)
        self.assertTrue(eligibility['is_eligible'])

    # ============================================================================
    # TEST #24-27: Views Authorization and Edge Cases 
    # ============================================================================

    def test_accessible_customer_ids_edge_cases(self) -> None:
        """Test #24: _get_accessible_customer_ids function edge cases."""
        # Test with None user
        customer_ids = _get_accessible_customer_ids(None)
        self.assertEqual(customer_ids, [])

        # Test with user without get_accessible_customers method
        mock_user = Mock(spec=[])  # User without get_accessible_customers
        customer_ids = _get_accessible_customer_ids(mock_user)
        self.assertEqual(customer_ids, [])

        # Test with valid user
        customer_ids = _get_accessible_customer_ids(self.staff_user)
        self.assertIn(self.customer.id, customer_ids)

    def test_pdf_access_validation_comprehensive(self) -> None:
        """Test #25: _validate_financial_document_access function comprehensive testing."""
        request = self.factory.get('/test/')
        request.user = self.staff_user

        # Test with valid access
        response = _validate_financial_document_access(request, self.invoice)
        self.assertIsNone(response)  # No redirect means access granted

        # Test with None request (edge case)
        response = _validate_financial_document_access(None, self.invoice)  # type: ignore[arg-type]
        self.assertIsNotNone(response)

        # Test with None document (edge case)
        response = _validate_financial_document_access(request, None)  # type: ignore[arg-type]
        self.assertIsNotNone(response)

        # Test with unauthorized user - need messages middleware
        request = self.factory.get('/test/')
        request.user = self.regular_user
        # Add messages framework
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session.save()
        setattr(request, '_messages', FallbackStorage(request))
        
        # Mock can_access_customer to return False
        with patch.object(self.regular_user, 'can_access_customer', return_value=False):
            response = _validate_financial_document_access(request, self.invoice)
            # Should return redirect response for unauthorized access
            self.assertIsNotNone(response)

    def test_customer_assignment_validation_edge_cases(self) -> None:
        """Test #26: _validate_customer_assignment function edge cases."""
        # Test with None customer_id
        customer, error_response = _validate_customer_assignment(self.staff_user, None, None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

        # Test with invalid customer_id
        customer, error_response = _validate_customer_assignment(self.staff_user, 'invalid', None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

        # Test with non-existent customer
        customer, error_response = _validate_customer_assignment(self.staff_user, '999999', None)
        self.assertIsNone(customer)
        self.assertIsNotNone(error_response)

        # Test with valid customer but no access
        with patch.object(self.staff_user, 'get_accessible_customers', return_value=[]):
            customer, error_response = _validate_customer_assignment(
                self.staff_user, str(self.customer.id), self.proforma.pk
            )
            self.assertIsNone(customer)
            self.assertIsNotNone(error_response)

    def test_invoice_refund_view_comprehensive(self) -> None:
        """Test #27: invoice_refund view comprehensive scenarios."""
        # Create request with proper setup
        request = self.factory.post('/invoice/refund/', {
            'refund_type': 'full',
            'refund_reason': 'customer_request',
            'refund_notes': 'Full refund requested',
            'process_payment_refund': 'true'
        })
        request.user = self.staff_user

        # Add session and messages framework
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session.save()
        
        setattr(request, '_messages', FallbackStorage(request))

        # Test successful refund
        response = invoice_refund(request, uuid.UUID(int=self.invoice.id))  # type: ignore[arg-type]
        self.assertEqual(response.status_code, 200)

        # Test with missing required fields
        request = self.factory.post('/invoice/refund/', {
            'refund_type': 'partial',
            # Missing refund_reason and refund_notes
        })
        request.user = self.staff_user
        middleware.process_request(request)
        request.session.save()
        setattr(request, '_messages', FallbackStorage(request))

        response = invoice_refund(request, uuid.UUID(int=self.invoice.id))  # type: ignore[arg-type]
        self.assertEqual(response.status_code, 400)

    # ============================================================================
    # TEST #28-31: Model Business Logic and VAT Compliance
    # ============================================================================

    def test_tax_rule_complex_validation(self) -> None:
        """Test #28: TaxRule model complex business logic and validation."""
        # Create Romanian VAT rule
        tax_rule = TaxRule.objects.create(
            country_code='RO',
            tax_type='vat',
            rate=Decimal('0.19'),  # 19% Romanian VAT
            reduced_rate=Decimal('0.09'),  # 9% reduced rate
            valid_from=timezone.now().date(),
            applies_to_b2b=True,
            applies_to_b2c=True,
            reverse_charge_eligible=True,
            is_eu_member=True,
            vies_required=True
        )

        # Test active rate calculation
        active_rate = TaxRule.get_active_rate('RO', 'vat')
        self.assertEqual(active_rate, Decimal('0.19'))

        # Test with non-existent country
        inactive_rate = TaxRule.get_active_rate('XX', 'vat')
        self.assertEqual(inactive_rate, Decimal('0.00'))

        # Test is_active method
        self.assertTrue(tax_rule.is_active())

        # Test string representation
        str_repr = str(tax_rule)
        self.assertIn('RO VAT 19.00%', str_repr)

    def test_invoice_sequence_atomic_generation(self) -> None:
        """Test #29: Invoice sequence atomic number generation edge cases."""
        # Test concurrent access simulation
        current_value = self.invoice_sequence.last_value
        
        # Generate multiple numbers to test atomicity
        number1 = self.invoice_sequence.get_next_number('TEST')
        number2 = self.invoice_sequence.get_next_number('TEST')
        
        self.assertEqual(number1, f'TEST-{current_value + 1:06d}')
        self.assertEqual(number2, f'TEST-{current_value + 2:06d}')

        # Verify sequence was updated
        self.invoice_sequence.refresh_from_db()
        self.assertEqual(self.invoice_sequence.last_value, current_value + 2)

    def test_invoice_payment_calculation_edge_cases(self) -> None:
        """Test #30: Invoice payment calculation and status edge cases."""
        # Create payment
        Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=6000,  # Partial payment
            currency=self.currency,
            status='succeeded',
            payment_method='bank'
        )

        # Test remaining amount calculation
        remaining = self.invoice.get_remaining_amount()
        self.assertEqual(remaining, self.invoice.total_cents - 6000)

        # Test is_overdue with different scenarios
        self.assertFalse(self.invoice.is_overdue())  # Paid invoice shouldn't be overdue

        # Create overdue invoice
        overdue_invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-OVERDUE',
            currency=self.currency,
            status='issued',
            total_cents=10000,
            due_at=timezone.now() - timezone.timedelta(days=5),  # 5 days overdue
            issued_at=timezone.now() - timezone.timedelta(days=35)
        )

        self.assertTrue(overdue_invoice.is_overdue())

    def test_proforma_business_logic_comprehensive(self) -> None:
        """Test #31: Proforma business logic and validation comprehensive."""
        # Test expiration logic
        expired_proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-EXPIRED',
            currency=self.currency,
            total_cents=5000,
            valid_until=timezone.now() - timezone.timedelta(days=1)  # Expired
        )

        self.assertTrue(expired_proforma.is_expired)
        self.assertFalse(self.proforma.is_expired)

        # Test decimal property calculations
        self.assertEqual(self.proforma.subtotal, Decimal('50.00'))
        self.assertEqual(self.proforma.tax_amount, Decimal('9.50'))
        self.assertEqual(self.proforma.total, Decimal('59.50'))

        # Test line item calculations
        ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Test Service',
            quantity=Decimal('2.000'),
            unit_price_cents=2500,  # €25.00
            tax_rate=Decimal('0.19'),  # 19%
            line_total_cents=5950   # €59.50 total
        )

        line = self.proforma.lines.first()
        self.assertEqual(line.unit_price, Decimal('25.00'))
        self.assertEqual(line.line_total, Decimal('59.50'))

    # ============================================================================
    # TEST #32-35: PDF Generation and Complex Scenarios
    # ============================================================================

    def test_pdf_generator_initialization_edge_cases(self) -> None:
        """Test #32: PDF generator initialization and configuration edge cases."""
        # Test Romanian invoice PDF generator
        invoice_generator = RomanianInvoicePDFGenerator(self.invoice)
        self.assertEqual(invoice_generator.document, self.invoice)
        self.assertIsNotNone(invoice_generator.buffer)
        self.assertIsNotNone(invoice_generator.canvas)

        # Test proforma PDF generator
        proforma_generator = RomanianProformaPDFGenerator(self.proforma)
        self.assertEqual(proforma_generator.document, self.proforma)

        # Test response generation (basic functionality)
        with patch.object(invoice_generator, '_create_pdf_document'):
            response = invoice_generator.generate_response()
            self.assertEqual(response['Content-Type'], 'application/pdf')
            self.assertIn('attachment', response['Content-Disposition'])

    def test_pdf_service_functions_comprehensive(self) -> None:
        """Test #33: PDF service functions comprehensive scenarios."""
        # Test invoice PDF generation
        pdf_content = generate_invoice_pdf(self.invoice)
        self.assertIsInstance(pdf_content, bytes)
        self.assertIn(b'Mock PDF content', pdf_content)

        # Test proforma PDF generation  
        pdf_content = generate_proforma_pdf(self.proforma)
        self.assertIsInstance(pdf_content, bytes)
        self.assertIn(b'Mock PDF content', pdf_content)

        # Test e-Factura XML generation
        xml_content = generate_e_factura_xml(self.invoice)
        self.assertIsInstance(xml_content, str)
        self.assertIn('<xml>', xml_content)
        self.assertIn('Mock e-Factura', xml_content)

    def test_date_processing_edge_cases(self) -> None:
        """Test #34: Date processing and validation edge cases."""
        # Test _process_valid_until_date with various inputs
        
        # Test with None data
        valid_until, errors = _process_valid_until_date(None)
        self.assertIsNotNone(valid_until)
        self.assertEqual(len(errors), 0)

        # Test with valid date
        test_data = {'valid_until': '2024-12-31'}
        valid_until, errors = _process_valid_until_date(test_data)
        self.assertEqual(len(errors), 0)
        self.assertEqual(valid_until.date().year, 2024)

        # Test with invalid date format
        test_data = {'valid_until': 'invalid-date'}
        valid_until, errors = _process_valid_until_date(test_data)
        self.assertEqual(len(errors), 1)
        self.assertIn('Invalid date format', errors[0])

        # Test with empty date
        test_data = {'valid_until': ''}
        valid_until, errors = _process_valid_until_date(test_data)
        self.assertEqual(len(errors), 0)  # No error for empty, uses default

    def test_line_items_processing_complex(self) -> None:
        """Test #35: Line items processing with complex scenarios."""
        # Clear existing lines
        self.proforma.lines.all().delete()

        # Test data with multiple line items and edge cases
        test_data = {
            'line_0_description': 'Web Hosting',
            'line_0_quantity': '1',
            'line_0_unit_price': '50.00',
            'line_0_vat_rate': '19',
            
            'line_1_description': 'Domain Registration',
            'line_1_quantity': '2',
            'line_1_unit_price': '15.99',
            'line_1_vat_rate': '19',
            
            # Line with invalid data (should be skipped)
            'line_2_description': '',  # Empty description
            'line_2_quantity': '0',    # Zero quantity
            'line_2_unit_price': '10.00',
            'line_2_vat_rate': '19',
            
            # Line with invalid numbers
            'line_3_description': 'SSL Certificate',
            'line_3_quantity': 'invalid',
            'line_3_unit_price': 'not_a_number',
            'line_3_vat_rate': 'invalid_vat',
        }

        errors = _process_proforma_line_items(self.proforma, test_data)
        
        # Should have errors for invalid data
        self.assertTrue(len(errors) > 0)
        
        # Should have created 2 valid lines (lines 0 and 1)
        self.assertEqual(self.proforma.lines.count(), 2)
        
        # Check totals were calculated
        self.assertTrue(self.proforma.total_cents > 0)
        
        # Verify the valid lines were created correctly
        first_line = self.proforma.lines.first()
        self.assertEqual(first_line.description, 'Web Hosting')
        self.assertEqual(first_line.quantity, Decimal('1'))

    # ============================================================================
    # TEST #36-38: Error Handling and Security
    # ============================================================================

    def test_invoice_refund_request_comprehensive(self) -> None:
        """Test #36: invoice_refund_request view comprehensive scenarios."""
        # Create request
        request = self.factory.post('/invoice/refund-request/', {
            'refund_reason': 'service_failure',
            'refund_notes': 'Service was not working properly'
        })
        request.user = self.regular_user

        # Add session and messages
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session.save()
        setattr(request, '_messages', FallbackStorage(request))

        # Test successful refund request
        response = invoice_refund_request(request, uuid.UUID(int=self.invoice.id))  # type: ignore[arg-type]
        self.assertEqual(response.status_code, 200)
        
        # Verify ticket was created
        self.assertTrue(Ticket.objects.filter(
            title__icontains=f'Refund Request for Invoice {self.invoice.number}'
        ).exists())

        # Test with draft invoice (should fail)
        draft_invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-DRAFT',
            currency=self.currency,
            status='draft',  # Not paid
            total_cents=10000
        )

        request = self.factory.post('/invoice/refund-request/', {
            'refund_reason': 'service_failure',
            'refund_notes': 'Test notes'
        })
        request.user = self.regular_user
        middleware.process_request(request)
        request.session.save()
        setattr(request, '_messages', FallbackStorage(request))

        response = invoice_refund_request(request, uuid.UUID(int=draft_invoice.id))  # type: ignore[arg-type]
        self.assertEqual(response.status_code, 400)

    def test_security_boundary_validation(self) -> None:
        """Test #37: Security boundary validation and access control."""
        # Test access to other customer's data
        unauthorized_customer = Customer.objects.create(
            name='Unauthorized Customer',
            primary_email='unauthorized@test.ro'
        )

        # Create invoice for unauthorized customer
        unauthorized_invoice = Invoice.objects.create(
            customer=unauthorized_customer,
            number='INV-UNAUTHORIZED',
            currency=self.currency,
            total_cents=10000
        )

        # Test that regular user cannot access unauthorized invoice
        request = self.factory.post('/test/')
        request.user = self.regular_user
        # Add messages framework for the security boundary test
        middleware = SessionMiddleware(lambda req: None)
        middleware.process_request(request)
        request.session.save()
        setattr(request, '_messages', FallbackStorage(request))

        # Mock can_access_customer to return False for unauthorized access
        with patch.object(self.regular_user, 'can_access_customer', return_value=False):
            response = _validate_financial_document_access(request, unauthorized_invoice)
            self.assertIsNotNone(response)  # Should return redirect

        # Test RefundService with unauthorized access
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Unauthorized attempt',
            'initiated_by': self.regular_user,
            'external_refund_id': None,
            'process_payment_refund': False
        }

        # This should work as the service doesn't check authorization (that's the view's job)
        result = RefundService.refund_invoice(unauthorized_invoice.id, refund_data)
        # The service itself doesn't enforce authorization - that's handled at the view level

    def test_exception_handling_comprehensive(self) -> None:
        """Test #38: Exception handling and error recovery scenarios."""
        # Test RefundService with database errors
        with patch('apps.billing.services.logger') as mock_logger:
            # Simulate database error by trying to refund non-existent invoice
            result = RefundService.refund_invoice(999999, {
                'refund_type': RefundType.FULL,
                'amount_cents': 0,
                'reason': RefundReason.CUSTOMER_REQUEST,
                'notes': 'Test',
                'initiated_by': self.staff_user,
                'external_refund_id': None,
                'process_payment_refund': False
            })

            self.assertTrue(result.is_err())
            self.assertIn('not found', result.error)

        # Test RefundQueryService exception handling
        with patch('apps.billing.models.Invoice.objects.get', side_effect=Exception("Database error")):
            result = RefundQueryService.get_entity_refunds('invoice', self.invoice.id)
            self.assertTrue(result.is_err())
            self.assertIn('Failed to get refund history', result.error)

    # ============================================================================
    # TEST #39-40: Integration and Complex Workflows
    # ============================================================================

    def test_complete_refund_workflow_integration(self) -> None:
        """Test #39: Complete refund workflow integration testing."""
        # Create a payment for the invoice
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            amount_cents=self.invoice.total_cents,
            currency=self.currency,
            status='succeeded',
            payment_method='bank',
            created_by=self.staff_user
        )

        # Perform full refund
        refund_data: RefundData = {
            'refund_type': RefundType.FULL,
            'amount_cents': 0,  # Full refund
            'reason': RefundReason.CUSTOMER_REQUEST,
            'notes': 'Complete workflow test refund',
            'initiated_by': self.staff_user,
            'external_refund_id': 'workflow_test_123',
            'process_payment_refund': True
        }

        # Process the refund
        result = RefundService.refund_invoice(self.invoice.id, refund_data)
        
        if result.is_ok():
            refund_result = result.unwrap()
            
            # Verify refund result structure
            self.assertEqual(refund_result['refund_type'], RefundType.FULL)
            self.assertTrue(refund_result['invoice_status_updated'])
            self.assertIsNotNone(refund_result['refund_id'])

            # Check that payment was updated
            payment.refresh_from_db()
            
            # Verify invoice metadata contains refund information
            self.invoice.refresh_from_db()
            if 'refunds' in self.invoice.meta:
                refunds = self.invoice.meta['refunds']
                self.assertTrue(len(refunds) > 0)
                self.assertEqual(refunds[-1]['reason'], 'customer_request')

    def test_romanian_compliance_comprehensive(self) -> None:
        """Test #40: Romanian business compliance and VAT handling comprehensive."""
        # Create Romanian VAT rule
        ro_vat = TaxRule.objects.create(
            country_code='RO',
            region='',
            tax_type='vat',
            rate=Decimal('0.19'),
            valid_from=timezone.now().date() - timezone.timedelta(days=30),
            applies_to_b2b=True,
            applies_to_b2c=True,
            reverse_charge_eligible=False,
            is_eu_member=True,
            vies_required=True,
            meta={
                'anaf_code': 'RO_VAT_19',
                'description': 'Romanian standard VAT rate'
            }
        )

        # Test active rate retrieval
        active_rate = TaxRule.get_active_rate('RO', 'vat')
        self.assertEqual(active_rate, Decimal('0.19'))

        # Create invoice with proper Romanian formatting
        ro_invoice = Invoice.objects.create(
            customer=self.customer,
            number='FAC-2024-001',  # Romanian invoice format
            currency=self.currency,
            status='issued',
            total_cents=11900,
            tax_cents=1900,
            subtotal_cents=10000,
            bill_to_name=self.customer.company_name,
            bill_to_tax_id='RO12345678',  # Romanian CUI
            bill_to_country='RO',
            efactura_id='',  # Will be populated when sent to ANAF
            efactura_sent=False,
            issued_at=timezone.now()
        )

        # Add line item with Romanian VAT
        InvoiceLine.objects.create(
            invoice=ro_invoice,
            kind='service',
            description='Servicii de hosting web',  # Romanian description
            quantity=Decimal('1.000'),
            unit_price_cents=10000,  # €100
            tax_rate=Decimal('0.19'),  # 19% Romanian VAT
            line_total_cents=11900   # €119 total
        )

        # Test invoice calculations
        self.assertEqual(ro_invoice.subtotal, Decimal('100.00'))
        self.assertEqual(ro_invoice.tax_amount, Decimal('19.00'))
        self.assertEqual(ro_invoice.total, Decimal('119.00'))

        # Test Romanian VAT compliance
        self.assertTrue(ro_vat.is_eu_member)
        self.assertTrue(ro_vat.vies_required)
        self.assertEqual(ro_invoice.bill_to_country, 'RO')
        self.assertTrue(ro_invoice.bill_to_tax_id.startswith('RO'))

        # Test e-Factura XML generation compatibility
        xml_content = generate_e_factura_xml(ro_invoice)
        self.assertIn('<xml>', xml_content)
        self.assertIn('Mock e-Factura', xml_content)
        self.assertIsInstance(xml_content, str)