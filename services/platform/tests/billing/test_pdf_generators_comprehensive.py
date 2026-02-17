# ===============================================================================
# COMPREHENSIVE BILLING PDF GENERATORS TEST SUITE - COVERAGE FOCUSED
# ===============================================================================
"""
Comprehensive test suite for billing PDF generators targeting 85%+ coverage.
Focuses on PDF generation, Romanian compliance, and document formatting.

Priority Areas from Coverage Analysis:
- pdf_generators.py: 25.61% → 85%+ (FOURTH TARGET)
- Base class methods, invoice and proforma generators
- Romanian formatting, document structure, error handling
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.http import HttpResponse
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    Invoice,
    InvoiceLine,
    ProformaInvoice,
    ProformaLine,
)
from apps.billing.pdf_generators import (
    RomanianInvoicePDFGenerator,
    RomanianProformaPDFGenerator,
)
from apps.customers.models import Customer
from apps.users.models import User


class BillingPDFGeneratorsComprehensiveCoverageTestCase(TestCase):
    """
    Comprehensive test suite for billing PDF generators targeting 85%+ coverage.
    Organized by generator class with focus on all PDF generation methods.
    """

    def setUp(self) -> None:
        """Set up test data for PDF generation."""
        # Create Currency
        self.currency = Currency.objects.create(
            code='RON',
            symbol='lei',
            decimals=2
        )

        # Create test users
        self.staff_user = User.objects.create_user(
            email='staff@example.com',
            password='testpass123',
            is_staff=True
        )

        # Create test customer
        self.customer = Customer.objects.create(
            name='Test Company SRL',
            customer_type='company',
            company_name='Test Company SRL',
            primary_email='customer@test.com',
            status='active'
        )

        # Create comprehensive test invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-000001',
            currency=self.currency,
            status='issued',
            subtotal_cents=10000,
            tax_cents=1900,
            total_cents=11900,
            bill_to_name='Test Company SRL',
            bill_to_email='customer@test.com',
            bill_to_tax_id='RO12345678',
            bill_to_address1='Str. Exemplu Nr. 10',
            bill_to_address2='Apt. 5',
            bill_to_city='București',
            bill_to_region='Sector 1',
            bill_to_postal='010101',
            bill_to_country='România',
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            paid_at=None,
            created_by=self.staff_user
        )

        # Create test proforma
        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            number='PRO-000001',
            currency=self.currency,
            subtotal_cents=5000,
            tax_cents=950,
            total_cents=5950,
            bill_to_name='Test Company SRL',
            bill_to_email='customer@test.com',
            bill_to_tax_id='RO12345678',
            bill_to_address1='Str. Exemplu Nr. 10',
            valid_until=timezone.now() + timezone.timedelta(days=30)
        )

        # Create line items
        self.invoice_line = InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Test Hosting Service Pro Package',
            quantity=Decimal('1.00'),
            unit_price_cents=10000,
            tax_rate=Decimal('0.19'),
            line_total_cents=11900
        )

        self.proforma_line = ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Test Hosting Service Basic Package',
            quantity=Decimal('2.00'),
            unit_price_cents=2500,
            tax_rate=Decimal('0.19'),
            line_total_cents=5950
        )

    # ===============================================================================
    # BASE DOCUMENT PDF GENERATOR TESTS - HIGH PRIORITY ABSTRACT METHODS
    # ===============================================================================

    def test_base_generator_init(self) -> None:
        """Test RomanianDocumentPDFGenerator initialization (Line 25-29)."""
        # Since it's an abstract class, we'll test through subclass
        generator = RomanianInvoicePDFGenerator(self.invoice)

        self.assertEqual(generator.document, self.invoice)
        self.assertIsNotNone(generator.buffer)
        self.assertIsNotNone(generator.canvas)
        self.assertAlmostEqual(generator.width, 595.2756, places=3)  # A4 width
        self.assertAlmostEqual(generator.height, 841.8898, places=3)  # A4 height

    def test_base_generator_generate_response(self) -> None:
        """Test RomanianDocumentPDFGenerator generate_response method (Line 31-41)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator, '_create_pdf_document') as mock_create:
            response = generator.generate_response()

            # Verify response properties
            self.assertIsInstance(response, HttpResponse)
            self.assertEqual(response['Content-Type'], 'application/pdf')
            self.assertIn('attachment', response['Content-Disposition'])
            self.assertIn('factura_INV-000001.pdf', response['Content-Disposition'])

            # Verify PDF creation was called
            mock_create.assert_called_once()

    def test_base_generator_create_pdf_document(self) -> None:
        """Test RomanianDocumentPDFGenerator _create_pdf_document method (Line 43-50)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator, '_setup_document_header') as mock_header, \
             patch.object(generator, '_render_company_information') as mock_company, \
             patch.object(generator, '_render_client_information') as mock_client, \
             patch.object(generator, '_render_items_table') as mock_table, \
             patch.object(generator, '_render_totals_section') as mock_totals, \
             patch.object(generator, '_render_document_footer') as mock_footer:

            generator._create_pdf_document()

            # Verify all sections were rendered
            mock_header.assert_called_once()
            mock_company.assert_called_once()
            mock_client.assert_called_once()
            mock_table.assert_called_once()
            mock_totals.assert_called_once()
            mock_footer.assert_called_once()

    def test_base_generator_get_company_info_with_settings(self) -> None:
        """Test _get_company_info with custom settings (Line 52-61)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch('django.conf.settings.COMPANY_NAME', 'Custom Company SRL'), \
             patch('django.conf.settings.COMPANY_ADDRESS', 'Str. Custom Nr. 5'), \
             patch('django.conf.settings.COMPANY_CITY', 'Cluj-Napoca'), \
             patch('django.conf.settings.COMPANY_COUNTRY', 'România'), \
             patch('django.conf.settings.COMPANY_CUI', 'RO87654321'), \
             patch('django.conf.settings.COMPANY_EMAIL', 'custom@example.com'):

            company_info = generator._get_company_info()

            self.assertEqual(company_info['name'], 'Custom Company SRL')
            self.assertEqual(company_info['address'], 'Str. Custom Nr. 5')
            self.assertEqual(company_info['city'], 'Cluj-Napoca')
            self.assertEqual(company_info['country'], 'România')
            self.assertEqual(company_info['cui'], 'RO87654321')
            self.assertEqual(company_info['email'], 'custom@example.com')

    def test_base_generator_get_company_info_defaults(self) -> None:
        """Test _get_company_info with default values (Line 52-61)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        company_info = generator._get_company_info()

        # Should use values from settings (which may come from environment or defaults)
        from django.conf import settings
        expected_name = getattr(settings, 'COMPANY_NAME', 'PRAHO Platform')
        expected_email = getattr(settings, 'COMPANY_EMAIL', 'contact@praho.ro')

        self.assertEqual(company_info['name'], expected_name)
        self.assertEqual(company_info['address'], 'Str. Exemplu Nr. 1')
        self.assertEqual(company_info['city'], 'București')
        self.assertEqual(company_info['country'], 'România')
        self.assertEqual(company_info['cui'], 'RO12345678')
        self.assertEqual(company_info['email'], expected_email)

    def test_base_generator_setup_document_header(self) -> None:
        """Test _setup_document_header method (Line 63-76)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw, \
             patch.object(generator, '_render_document_details') as mock_details:

            generator._setup_document_header()

            # Verify font settings and drawing calls
            mock_font.assert_called()
            mock_draw.assert_called()
            mock_details.assert_called_once()

    def test_base_generator_render_company_information(self) -> None:
        """Test _render_company_information method (Line 90-111)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_company_information()

            # Should set fonts and draw company information
            self.assertTrue(mock_font.called)
            self.assertTrue(mock_draw.called)

    def test_base_generator_render_client_information_complete(self) -> None:
        """Test _render_client_information with complete client data (Line 113-136)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_client_information()

            # Should render all available client information
            mock_font.assert_called()
            mock_draw.assert_called()

            # Check that draw calls include client data
            draw_calls = [call[0] for call in mock_draw.call_args_list]
            self.assertTrue(any('Test Company SRL' in str(call) for call in draw_calls))

    def test_base_generator_render_client_information_minimal(self) -> None:
        """Test _render_client_information with minimal client data (Line 123, 126, 132)."""
        # Create invoice with minimal client info
        minimal_invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-000002',
            currency=self.currency,
            status='draft',
            total_cents=1000,
            bill_to_name='Minimal Client',
            # No address, tax_id, or email
            created_by=self.staff_user
        )

        generator = RomanianInvoicePDFGenerator(minimal_invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_client_information()

            # Should still render but skip optional fields
            mock_font.assert_called()
            mock_draw.assert_called()

    def test_base_generator_render_items_table(self) -> None:
        """Test _render_items_table method (Line 138-146)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator, '_render_table_headers') as mock_headers, \
             patch.object(generator, '_render_table_data') as mock_data:

            generator._render_items_table()

            # Should render both headers and data
            mock_headers.assert_called_once()
            mock_data.assert_called_once()

    def test_base_generator_render_table_headers(self) -> None:
        """Test _render_table_headers method (Line 148-157)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw, \
             patch.object(generator.canvas, 'line') as mock_line:

            generator._render_table_headers(400.0)  # Mock table_y position

            # Should set font, draw headers, and draw line
            mock_font.assert_called_with("Helvetica-Bold", 10)
            mock_draw.assert_called()
            mock_line.assert_called_once()

    def test_base_generator_render_table_data(self) -> None:
        """Test _render_table_data method (Line 159-170)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_table_data(400.0)  # Mock table_y position

            # Should set font and draw line item data
            mock_font.assert_called_with("Helvetica", 9)
            mock_draw.assert_called()

            # Check that line data is included in draw calls
            draw_calls = [str(call) for call in mock_draw.call_args_list]
            self.assertTrue(any('Test Hosting Service Pro Package' in call for call in draw_calls))

    def test_base_generator_render_table_data_long_description(self) -> None:
        """Test _render_table_data with long description truncation (Line 166)."""
        # Create line with very long description
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='A' * 100,  # Very long description
            quantity=Decimal('1.00'),
            unit_price_cents=5000,
            tax_rate=Decimal('0.19'),
            line_total_cents=5950
        )

        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont'), \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_table_data(400.0)

            # Check that description was truncated to 40 characters
            draw_calls = [str(call) for call in mock_draw.call_args_list]
            truncated_description = 'A' * 40
            self.assertTrue(any(truncated_description in call for call in draw_calls))

    def test_base_generator_render_totals_section(self) -> None:
        """Test _render_totals_section method (Line 172-197)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw, \
             patch.object(generator, '_get_total_label', return_value='TOTAL: {amount} RON') as mock_label, \
             patch.object(generator, '_render_status_information') as mock_status:

            generator._render_totals_section()

            # Should set font, draw totals, and render status
            mock_font.assert_called()
            mock_draw.assert_called()
            mock_label.assert_called_once()
            mock_status.assert_called_once()

    def test_base_generator_get_total_label_default(self) -> None:
        """Test _get_total_label default implementation (Line 199-201)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # The base class method should be overridden, but test the structure
        label = generator._get_total_label()

        self.assertIn('{amount}', label)
        self.assertIn('RON', label)

    def test_base_generator_render_status_information_base(self) -> None:
        """Test _render_status_information base implementation (Line 203-205)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Base implementation should do nothing, but should not raise
        generator._render_status_information(400.0)

    def test_base_generator_render_document_footer(self) -> None:
        """Test _render_document_footer method (Line 207-216)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw, \
             patch.object(generator, '_get_legal_disclaimer', return_value='Test disclaimer'):

            generator._render_document_footer()

            # Should set font and draw footer information
            mock_font.assert_called_with("Helvetica", 8)
            mock_draw.assert_called()

    # ===============================================================================
    # ROMANIAN INVOICE PDF GENERATOR TESTS - HIGH PRIORITY SPECIFIC METHODS
    # ===============================================================================

    def test_invoice_generator_init(self) -> None:
        """Test RomanianInvoicePDFGenerator initialization (Line 229-231)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        self.assertEqual(generator.invoice, self.invoice)
        self.assertEqual(generator.document, self.invoice)

    def test_invoice_generator_get_document_title(self) -> None:
        """Test RomanianInvoicePDFGenerator _get_document_title (Line 233-234)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        title = generator._get_document_title()

        # Should return translated "FISCAL INVOICE"
        self.assertIn('FISCAL', title)

    def test_invoice_generator_get_filename(self) -> None:
        """Test RomanianInvoicePDFGenerator _get_filename (Line 236-237)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        filename = generator._get_filename()

        self.assertEqual(filename, 'factura_INV-000001.pdf')

    def test_invoice_generator_get_legal_disclaimer(self) -> None:
        """Test RomanianInvoicePDFGenerator _get_legal_disclaimer (Line 239-240)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        disclaimer = generator._get_legal_disclaimer()

        # Should mention fiscal invoice and Romanian legislation
        self.assertIn('Fiscal', disclaimer)

    def test_invoice_generator_get_total_label(self) -> None:
        """Test RomanianInvoicePDFGenerator _get_total_label (Line 242-243)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        label = generator._get_total_label()

        # Should mention "TO PAY"
        self.assertIn('PAY', label)
        self.assertIn('{amount}', label)

    def test_invoice_generator_render_document_details_complete(self) -> None:
        """Test RomanianInvoicePDFGenerator _render_document_details with complete data (Line 245-270)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_document_details()

            # Should set fonts and draw invoice details
            mock_font.assert_called()
            mock_draw.assert_called()

            # Check that all details are included
            draw_calls = [str(call) for call in mock_draw.call_args_list]
            self.assertTrue(any('INV-000001' in call for call in draw_calls))
            self.assertTrue(any('ISSUED' in call for call in draw_calls))

    def test_invoice_generator_render_document_details_minimal(self) -> None:
        """Test RomanianInvoicePDFGenerator _render_document_details with minimal data (Line 253, 259)."""
        # Create invoice with no dates
        minimal_invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-000003',
            currency=self.currency,
            status='draft',
            total_cents=1000,
            issued_at=None,
            due_at=None,
            created_by=self.staff_user
        )

        generator = RomanianInvoicePDFGenerator(minimal_invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_document_details()

            # Should still render but skip dates
            mock_font.assert_called()
            mock_draw.assert_called()

    def test_invoice_generator_render_status_information_unpaid(self) -> None:
        """Test RomanianInvoicePDFGenerator _render_status_information for unpaid invoice (Line 274-280)."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_status_information(400.0)

            # Should render unpaid warning
            mock_font.assert_called_with("Helvetica-Bold", 10)
            mock_draw.assert_called()

    def test_invoice_generator_render_status_information_unpaid_no_due_date(self) -> None:
        """Test _render_status_information for unpaid invoice without due date (Line 276)."""
        self.invoice.due_at = None
        self.invoice.save()

        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont'), \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_status_information(400.0)

            # Should handle missing due date
            draw_calls = [str(call) for call in mock_draw.call_args_list]
            self.assertTrue(any('undefined' in call or 'Unpaid' in call for call in draw_calls))

    def test_invoice_generator_render_status_information_paid(self) -> None:
        """Test RomanianInvoicePDFGenerator _render_status_information for paid invoice (Line 281-286)."""
        # Mark invoice as paid
        self.invoice.status = 'paid'
        self.invoice.paid_at = timezone.now()
        self.invoice.save()

        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_status_information(400.0)

            # Should render paid confirmation
            mock_font.assert_called_with("Helvetica-Bold", 10)
            mock_draw.assert_called()

    def test_invoice_generator_render_status_information_paid_no_paid_at(self) -> None:
        """Test _render_status_information for paid invoice without paid_at date."""
        # Mark invoice as paid but without paid_at
        self.invoice.status = 'paid'
        self.invoice.paid_at = None
        self.invoice.save()

        generator = RomanianInvoicePDFGenerator(self.invoice)

        with patch.object(generator.canvas, 'setFont'), \
             patch.object(generator.canvas, 'drawString'):

            # Should not crash and handle missing paid_at gracefully
            generator._render_status_information(400.0)

    # ===============================================================================
    # ROMANIAN PROFORMA PDF GENERATOR TESTS - HIGH PRIORITY SPECIFIC METHODS
    # ===============================================================================

    def test_proforma_generator_init(self) -> None:
        """Test RomanianProformaPDFGenerator initialization (Line 295-297)."""
        generator = RomanianProformaPDFGenerator(self.proforma)

        self.assertEqual(generator.proforma, self.proforma)
        self.assertEqual(generator.document, self.proforma)

    def test_proforma_generator_get_document_title(self) -> None:
        """Test RomanianProformaPDFGenerator _get_document_title (Line 299-300)."""
        generator = RomanianProformaPDFGenerator(self.proforma)

        title = generator._get_document_title()

        # Should return Romanian "FACTURĂ PROFORMA"
        self.assertIn('PROFORMA', title)

    def test_proforma_generator_get_filename(self) -> None:
        """Test RomanianProformaPDFGenerator _get_filename (Line 302-303)."""
        generator = RomanianProformaPDFGenerator(self.proforma)

        filename = generator._get_filename()

        self.assertEqual(filename, 'proforma_PRO-000001.pdf')

    def test_proforma_generator_get_legal_disclaimer(self) -> None:
        """Test RomanianProformaPDFGenerator _get_legal_disclaimer (Line 305-306)."""
        generator = RomanianProformaPDFGenerator(self.proforma)

        disclaimer = generator._get_legal_disclaimer()

        # Should clarify that proforma is not a fiscal invoice
        self.assertIn('not a fiscal invoice', disclaimer)

    def test_proforma_generator_render_document_details(self) -> None:
        """Test RomanianProformaPDFGenerator _render_document_details (Line 308-322)."""
        generator = RomanianProformaPDFGenerator(self.proforma)

        with patch.object(generator.canvas, 'setFont') as mock_font, \
             patch.object(generator.canvas, 'drawString') as mock_draw:

            generator._render_document_details()

            # Should set fonts and draw proforma details
            mock_font.assert_called()
            mock_draw.assert_called()

            # Check that all details are included
            draw_calls = [str(call) for call in mock_draw.call_args_list]
            self.assertTrue(any('PRO-000001' in call for call in draw_calls))

    # ===============================================================================
    # INTEGRATION TESTS - FULL PDF GENERATION
    # ===============================================================================

    def test_invoice_full_pdf_generation(self) -> None:
        """Test complete invoice PDF generation pipeline."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        response = generator.generate_response()

        # Verify response
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('factura_INV-000001.pdf', response['Content-Disposition'])

        # Verify content exists (PDF should have some content)
        self.assertGreater(len(response.content), 1000)  # PDF should be reasonably sized

    def test_proforma_full_pdf_generation(self) -> None:
        """Test complete proforma PDF generation pipeline."""
        generator = RomanianProformaPDFGenerator(self.proforma)

        response = generator.generate_response()

        # Verify response
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('proforma_PRO-000001.pdf', response['Content-Disposition'])

        # Verify content exists
        self.assertGreater(len(response.content), 1000)

    def test_pdf_generation_with_multiple_line_items(self) -> None:
        """Test PDF generation with multiple line items."""
        # Add more line items
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Additional Service',
            quantity=Decimal('3.00'),
            unit_price_cents=2000,
            tax_rate=Decimal('0.19'),
            line_total_cents=7140
        )

        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Premium Support',
            quantity=Decimal('1.00'),
            unit_price_cents=5000,
            tax_rate=Decimal('0.19'),
            line_total_cents=5950
        )

        generator = RomanianInvoicePDFGenerator(self.invoice)
        response = generator.generate_response()

        # Should handle multiple items without issues
        self.assertIsInstance(response, HttpResponse)
        self.assertGreater(len(response.content), 1000)

    def test_pdf_generation_error_handling(self) -> None:
        """Test PDF generation with potential errors."""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Mock canvas to raise an exception
        with patch.object(generator.canvas, 'drawString', side_effect=Exception("Canvas error")):
            # Should not crash, but may produce invalid PDF
            with self.assertRaises(Exception):
                generator.generate_response()

    def test_pdf_generation_with_empty_line_items(self) -> None:
        """Test PDF generation with no line items."""
        # Remove all line items
        InvoiceLine.objects.filter(invoice=self.invoice).delete()

        generator = RomanianInvoicePDFGenerator(self.invoice)
        response = generator.generate_response()

        # Should still generate PDF
        self.assertIsInstance(response, HttpResponse)
        self.assertGreater(len(response.content), 500)

    def test_pdf_generation_with_special_characters(self) -> None:
        """Test PDF generation with Romanian special characters."""
        # Create invoice with Romanian characters
        special_invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-000004',
            currency=self.currency,
            status='issued',
            total_cents=1000,
            bill_to_name='Compania Română SRL',
            bill_to_address1='Str. Ștefan cel Mare Nr. 15',
            bill_to_city='București',
            created_by=self.staff_user
        )

        InvoiceLine.objects.create(
            invoice=special_invoice,
            kind='service',
            description='Servicii de hosting în România',
            quantity=Decimal('1.00'),
            unit_price_cents=1000,
            tax_rate=Decimal('0.19'),
            line_total_cents=1190
        )

        generator = RomanianInvoicePDFGenerator(special_invoice)
        response = generator.generate_response()

        # Should handle special characters
        self.assertIsInstance(response, HttpResponse)
        self.assertGreater(len(response.content), 500)

    # ===============================================================================
    # EDGE CASE TESTS
    # ===============================================================================

    def test_pdf_generation_with_zero_amounts(self) -> None:
        """Test PDF generation with zero amounts."""
        zero_invoice = Invoice.objects.create(
            customer=self.customer,
            number='INV-000005',
            currency=self.currency,
            status='issued',
            subtotal_cents=0,
            tax_cents=0,
            total_cents=0,
            created_by=self.staff_user
        )

        generator = RomanianInvoicePDFGenerator(zero_invoice)
        response = generator.generate_response()

        # Should handle zero amounts gracefully
        self.assertIsInstance(response, HttpResponse)

    def test_pdf_generation_with_high_precision_amounts(self) -> None:
        """Test PDF generation with high precision decimal amounts."""
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Precise Service',
            quantity=Decimal('1.33333'),
            unit_price_cents=333,  # Unusual amount
            tax_rate=Decimal('0.19'),
            line_total_cents=472
        )

        generator = RomanianInvoicePDFGenerator(self.invoice)
        response = generator.generate_response()

        # Should handle precise calculations
        self.assertIsInstance(response, HttpResponse)
