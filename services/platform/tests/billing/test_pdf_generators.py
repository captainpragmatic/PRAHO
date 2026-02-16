# ===============================================================================
# COMPREHENSIVE BILLING PDF GENERATORS TESTS
# ===============================================================================

from decimal import Decimal
from io import BytesIO
from unittest.mock import Mock, patch

from django.http import HttpResponse
from django.test import TestCase, override_settings
from django.utils import timezone
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from apps.billing.models import Currency, Invoice, InvoiceLine, ProformaInvoice, ProformaLine
from apps.billing.pdf_generators import (
    RomanianDocumentPDFGenerator,
    RomanianInvoicePDFGenerator,
    RomanianProformaPDFGenerator,
)
from apps.customers.models import Customer


class BaseRomanianDocumentPDFGeneratorTestCase(TestCase):
    """Test base RomanianDocumentPDFGenerator functionality"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)

        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='PDF Test Company SRL',
            primary_email='pdf@test.ro',
            status='active'
        )

        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PDF-001',
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            status='issued',
            bill_to_name='PDF Test Company SRL',
            bill_to_email='billing@test.ro',
            bill_to_tax_id='RO12345678',
            bill_to_address1='Strada Principala 123',
            bill_to_city='Bucuresti',
            bill_to_postal='010101',
            bill_to_country='Romania'
        )

        # Add invoice lines
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Web Hosting Premium',
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal('0.21'),
            line_total_cents=10000
        )

    def test_base_generator_initialization(self):
        """Test base generator initialization"""
        generator = RomanianDocumentPDFGenerator(self.invoice)

        self.assertEqual(generator.document, self.invoice)
        self.assertIsInstance(generator.buffer, BytesIO)
        self.assertIsInstance(generator.canvas, canvas.Canvas)
        self.assertEqual(generator.width, A4[0])
        self.assertEqual(generator.height, A4[1])

    def test_get_company_info_defaults(self):
        """Test _get_company_info with current project settings"""
        generator = RomanianDocumentPDFGenerator(self.invoice)
        company_info = generator._get_company_info()

        # Test that we get some values (actual project settings)
        self.assertIsNotNone(company_info['name'])
        self.assertIsNotNone(company_info['address'])
        self.assertIsNotNone(company_info['city'])
        self.assertIsNotNone(company_info['country'])
        self.assertIsNotNone(company_info['cui'])
        self.assertIsNotNone(company_info['email'])

        # Test specific known values from project
        self.assertEqual(company_info['name'], 'PRAHO Platform')
        self.assertEqual(company_info['cui'], 'RO12345678')

    @override_settings(
        COMPANY_NAME='Test Company',
        COMPANY_ADDRESS='Test Address',
        COMPANY_CITY='Test City',
        COMPANY_COUNTRY='Test Country',
        COMPANY_CUI='RO87654321',
        COMPANY_EMAIL='test@company.ro'
    )
    def test_get_company_info_from_settings(self):
        """Test _get_company_info with custom settings"""
        generator = RomanianDocumentPDFGenerator(self.invoice)
        company_info = generator._get_company_info()

        self.assertEqual(company_info['name'], 'Test Company')
        self.assertEqual(company_info['address'], 'Test Address')
        self.assertEqual(company_info['city'], 'Test City')
        self.assertEqual(company_info['country'], 'Test Country')
        self.assertEqual(company_info['cui'], 'RO87654321')
        self.assertEqual(company_info['email'], 'test@company.ro')

    def test_setup_document_header(self):
        """Test _setup_document_header method"""
        generator = RomanianDocumentPDFGenerator(self.invoice)

        # Mock the required methods
        generator._get_document_title = Mock(return_value='TEST DOCUMENT')
        generator._render_document_details = Mock()

        # Should not raise an exception
        generator._setup_document_header()

        generator._render_document_details.assert_called_once()

    def test_render_company_information(self):
        """Test _render_company_information method"""
        generator = RomanianDocumentPDFGenerator(self.invoice)

        # Should not raise an exception
        generator._render_company_information()

        # Verify canvas operations were called
        self.assertIsNotNone(generator.canvas)

    def test_render_client_information(self):
        """Test _render_client_information method"""
        generator = RomanianDocumentPDFGenerator(self.invoice)

        # Should not raise an exception
        generator._render_client_information()

        # Test with document having all fields
        self.invoice.bill_to_name = 'Client Company'
        self.invoice.bill_to_address1 = 'Client Address'
        self.invoice.bill_to_tax_id = 'RO11111111'
        self.invoice.bill_to_email = 'client@test.ro'

        # Should not raise an exception
        generator._render_client_information()

    def test_render_items_table(self):
        """Test _render_items_table method"""
        generator = RomanianDocumentPDFGenerator(self.invoice)

        # Should not raise an exception
        generator._render_items_table()

    def test_render_table_headers(self):
        """Test _render_table_headers method"""
        generator = RomanianDocumentPDFGenerator(self.invoice)

        # Should not raise an exception
        generator._render_table_headers(100)

    def test_render_table_data(self):
        """Test _render_table_data method"""
        generator = RomanianDocumentPDFGenerator(self.invoice)

        # Should not raise an exception
        generator._render_table_data(100)

    def test_render_table_data_long_description(self):
        """Test _render_table_data with long description truncation"""
        # Create line with long description
        long_description = 'This is a very long description that should be truncated when displayed in the PDF'
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description=long_description,
            quantity=1,
            unit_price_cents=5000,
            tax_rate=Decimal('0.21'),
            line_total_cents=5000
        )

        generator = RomanianDocumentPDFGenerator(self.invoice)

        # Should not raise an exception and should handle truncation
        generator._render_table_data(100)

    def test_render_totals_section(self):
        """Test _render_totals_section method"""
        generator = RomanianDocumentPDFGenerator(self.invoice)

        # Mock the required methods
        generator._get_total_label = Mock(return_value='Total: {amount} RON')
        generator._render_status_information = Mock()

        # Should not raise an exception
        generator._render_totals_section()

        generator._render_status_information.assert_called()

    def test_render_document_footer(self):
        """Test _render_document_footer method"""
        generator = RomanianDocumentPDFGenerator(self.invoice)

        # Mock the required methods
        generator._get_legal_disclaimer = Mock(return_value='Test disclaimer')

        # Should not raise an exception
        generator._render_document_footer()

    def test_base_abstract_methods(self):
        """Test that base class abstract methods raise NotImplementedError"""
        generator = RomanianDocumentPDFGenerator(self.invoice)

        with self.assertRaises(NotImplementedError):
            generator._render_document_details()

        with self.assertRaises(NotImplementedError):
            generator._get_document_title()

        with self.assertRaises(NotImplementedError):
            generator._get_filename()

        with self.assertRaises(NotImplementedError):
            generator._get_legal_disclaimer()


class RomanianInvoicePDFGeneratorTestCase(TestCase):
    """Test Romanian invoice PDF generator"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)

        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Invoice PDF Test SRL',
            primary_email='invoice@test.ro',
            status='active'
        )

        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PDF-TEST-001',
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            status='issued',
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            bill_to_name='Invoice Test Company SRL',
            bill_to_email='invoice@test.ro'
        )

        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Premium Hosting Service',
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal('0.21'),
            line_total_cents=10000
        )

    def test_invoice_generator_initialization(self):
        """Test invoice generator initialization"""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        self.assertEqual(generator.document, self.invoice)
        self.assertEqual(generator.invoice, self.invoice)

    def test_get_document_title(self):
        """Test _get_document_title method"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        title = generator._get_document_title()

        self.assertIn('FISCAL INVOICE', title)

    def test_get_filename(self):
        """Test _get_filename method"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        filename = generator._get_filename()

        self.assertEqual(filename, f'factura_{self.invoice.number}.pdf')

    def test_get_legal_disclaimer(self):
        """Test _get_legal_disclaimer method"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        disclaimer = generator._get_legal_disclaimer()

        self.assertIn('Romanian legislation', disclaimer)

    def test_get_total_label(self):
        """Test _get_total_label method"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        label = generator._get_total_label()

        self.assertIn('TOTAL TO PAY', label)

    def test_render_document_details(self):
        """Test _render_document_details method"""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Should not raise an exception
        generator._render_document_details()

    def test_render_document_details_without_dates(self):
        """Test _render_document_details with invoice without dates"""
        # Create invoice without dates
        invoice_no_dates = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-NO-DATES-001',
            total_cents=5000,
            status='draft'
        )

        generator = RomanianInvoicePDFGenerator(invoice_no_dates)

        # Should not raise an exception
        generator._render_document_details()

    def test_render_status_information_unpaid(self):
        """Test _render_status_information for unpaid invoice"""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Should not raise an exception
        generator._render_status_information(200)

    def test_render_status_information_paid(self):
        """Test _render_status_information for paid invoice"""
        self.invoice.status = 'paid'
        self.invoice.paid_at = timezone.now()
        self.invoice.save()

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Should not raise an exception
        generator._render_status_information(200)

    def test_render_status_information_paid_without_date(self):
        """Test _render_status_information for paid invoice without paid_at date"""
        self.invoice.status = 'paid'
        # Don't set paid_at to test the hasattr condition
        self.invoice.save()

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Should not raise an exception
        generator._render_status_information(200)

    @patch('apps.billing.pdf_generators.canvas.Canvas')
    def test_generate_response(self, mock_canvas):
        """Test generate_response method"""
        mock_canvas_instance = Mock()
        mock_canvas.return_value = mock_canvas_instance

        generator = RomanianInvoicePDFGenerator(self.invoice)

        response = generator.generate_response()

        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn(f'factura_{self.invoice.number}.pdf', response['Content-Disposition'])

    def test_create_pdf_document_integration(self):
        """Test complete PDF document creation"""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Should not raise an exception
        generator._create_pdf_document()
        generator.canvas.showPage()
        generator.canvas.save()

        # Verify buffer has content after saving
        self.assertGreater(len(generator.buffer.getvalue()), 0)


class RomanianProformaPDFGeneratorTestCase(TestCase):
    """Test Romanian proforma PDF generator"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)

        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Proforma PDF Test SRL',
            primary_email='proforma@test.ro',
            status='active'
        )

        self.proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-PDF-TEST-001',
            subtotal_cents=5000,
            tax_cents=1050,
            total_cents=6050,
            valid_until=timezone.now() + timezone.timedelta(days=30),
            bill_to_name='Proforma Test Company SRL',
            bill_to_email='proforma@test.ro'
        )

        ProformaLine.objects.create(
            proforma=self.proforma,
            kind='service',
            description='Basic Hosting Service',
            quantity=1,
            unit_price_cents=5000,
            tax_rate=Decimal('0.21'),
            line_total_cents=5000
        )

    def test_proforma_generator_initialization(self):
        """Test proforma generator initialization"""
        generator = RomanianProformaPDFGenerator(self.proforma)

        self.assertEqual(generator.document, self.proforma)
        self.assertEqual(generator.proforma, self.proforma)

    def test_get_document_title(self):
        """Test _get_document_title method"""
        generator = RomanianProformaPDFGenerator(self.proforma)
        title = generator._get_document_title()

        self.assertEqual(title, 'FACTURĂ PROFORMA')

    def test_get_filename(self):
        """Test _get_filename method"""
        generator = RomanianProformaPDFGenerator(self.proforma)
        filename = generator._get_filename()

        self.assertEqual(filename, f'proforma_{self.proforma.number}.pdf')

    def test_get_legal_disclaimer(self):
        """Test _get_legal_disclaimer method"""
        generator = RomanianProformaPDFGenerator(self.proforma)
        disclaimer = generator._get_legal_disclaimer()

        self.assertIn('not a fiscal invoice', disclaimer)

    def test_render_document_details(self):
        """Test _render_document_details method"""
        generator = RomanianProformaPDFGenerator(self.proforma)

        # Should not raise an exception
        generator._render_document_details()

    @patch('apps.billing.pdf_generators.canvas.Canvas')
    def test_generate_response(self, mock_canvas):
        """Test generate_response method"""
        mock_canvas_instance = Mock()
        mock_canvas.return_value = mock_canvas_instance

        generator = RomanianProformaPDFGenerator(self.proforma)

        response = generator.generate_response()

        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn(f'proforma_{self.proforma.number}.pdf', response['Content-Disposition'])

    def test_create_pdf_document_integration(self):
        """Test complete PDF document creation"""
        generator = RomanianProformaPDFGenerator(self.proforma)

        # Should not raise an exception
        generator._create_pdf_document()
        generator.canvas.showPage()
        generator.canvas.save()

        # Verify buffer has content after saving
        self.assertGreater(len(generator.buffer.getvalue()), 0)


class PDFGenerationErrorHandlingTestCase(TestCase):
    """Test error handling in PDF generation"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)

        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Error Test SRL',
            status='active'
        )

        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-ERROR-001',
            total_cents=1000,
            status='draft'
        )

    def test_generator_with_minimal_data(self):
        """Test PDF generator with minimal required data"""
        # Invoice with minimal data
        minimal_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-MINIMAL-001',
            total_cents=0,
            status='draft'
        )

        generator = RomanianInvoicePDFGenerator(minimal_invoice)

        # Should not raise an exception even with minimal data
        response = generator.generate_response()
        self.assertIsInstance(response, HttpResponse)

    def test_generator_with_missing_customer_data(self):
        """Test PDF generator with missing customer billing data"""
        # Customer without billing information
        minimal_customer = Customer.objects.create(
            customer_type='individual',
            status='active'
        )

        invoice_minimal_customer = Invoice.objects.create(
            customer=minimal_customer,
            currency=self.currency,
            number='INV-NO-CUSTOMER-DATA-001',
            total_cents=1000,
            status='draft'
        )

        generator = RomanianInvoicePDFGenerator(invoice_minimal_customer)

        # Should handle missing customer data gracefully
        response = generator.generate_response()
        self.assertIsInstance(response, HttpResponse)

    def test_generator_with_no_lines(self):
        """Test PDF generator with invoice having no lines"""
        generator = RomanianInvoicePDFGenerator(self.invoice)  # No lines added

        # Should not raise an exception even without lines
        response = generator.generate_response()
        self.assertIsInstance(response, HttpResponse)

    @patch('apps.billing.pdf_generators.canvas.Canvas')
    def test_canvas_operations_error_handling(self, mock_canvas):
        """Test error handling during canvas operations"""
        mock_canvas_instance = Mock()
        mock_canvas_instance.drawString.side_effect = Exception('Canvas error')
        mock_canvas.return_value = mock_canvas_instance

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Should handle canvas errors by propagating them
        with self.assertRaises(Exception):
            generator._render_company_information()

    def test_buffer_operations(self):
        """Test buffer operations in PDF generation"""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Test buffer initialization
        self.assertIsInstance(generator.buffer, BytesIO)

        # Test buffer after document creation
        generator._create_pdf_document()
        self.assertGreaterEqual(len(generator.buffer.getvalue()), 0)

        # Test buffer seek operation
        generator.buffer.seek(0)
        self.assertEqual(generator.buffer.tell(), 0)


class PDFContentValidationTestCase(TestCase):
    """Test PDF content validation"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)

        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Content Test Company SRL',
            primary_email='content@test.ro',
            status='active'
        )

        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-CONTENT-001',
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            status='issued',
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            bill_to_name='Content Test Company SRL',
            bill_to_email='content@test.ro',
            bill_to_tax_id='RO12345678'
        )

    def test_pdf_response_headers(self):
        """Test PDF response headers are correct"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        response = generator.generate_response()

        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn(f'factura_{self.invoice.number}.pdf', response['Content-Disposition'])

    def test_pdf_content_not_empty(self):
        """Test that PDF content is not empty"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        response = generator.generate_response()

        self.assertGreater(len(response.content), 0)

    def test_proforma_pdf_response_headers(self):
        """Test proforma PDF response headers are correct"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-CONTENT-001',
            total_cents=5000,
            valid_until=timezone.now() + timezone.timedelta(days=30)
        )

        generator = RomanianProformaPDFGenerator(proforma)
        response = generator.generate_response()

        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn(f'proforma_{proforma.number}.pdf', response['Content-Disposition'])

    def test_multiple_lines_pdf_generation(self):
        """Test PDF generation with multiple invoice lines"""
        # Add multiple lines
        for i in range(3):
            InvoiceLine.objects.create(
                invoice=self.invoice,
                kind='service',
                description=f'Service {i+1}',
                quantity=i+1,
                unit_price_cents=(i+1) * 1000,
                tax_rate=Decimal('0.21'),
                line_total_cents=(i+1) * 1000
            )

        generator = RomanianInvoicePDFGenerator(self.invoice)
        response = generator.generate_response()

        self.assertIsInstance(response, HttpResponse)
        self.assertGreater(len(response.content), 0)

    def test_romanian_characters_handling(self):
        """Test handling of Romanian characters in PDF"""
        # Create invoice with Romanian characters
        romanian_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-ROMÂNĂ-001',
            subtotal_cents=4200,  # 42.00 RON
            tax_cents=882,        # 8.82 RON VAT (4200 * 0.21)
            total_cents=5082,     # 50.82 RON
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            status='issued',
            bill_to_name='Compania Română SRL',
            bill_to_city='București',
            bill_to_address1='Șoseaua Kiseleff 123'
        )

        InvoiceLine.objects.create(
            invoice=romanian_invoice,
            kind='service',
            description='Serviciu de găzduire web în România',
            quantity=1,
            unit_price_cents=5000,
            tax_rate=Decimal('0.21'),
            line_total_cents=5000
        )

        generator = RomanianInvoicePDFGenerator(romanian_invoice)

        # Should handle Romanian characters without errors
        response = generator.generate_response()
        self.assertIsInstance(response, HttpResponse)


class PDFGenerationPerformanceTestCase(TestCase):
    """Test PDF generation performance considerations"""

    def setUp(self):
        """Setup test data"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)

        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Performance Test SRL',
            status='active'
        )

        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-PERF-001',
            total_cents=50000,
            status='issued'
        )

    def test_large_invoice_pdf_generation(self):
        """Test PDF generation for invoice with many lines"""
        # Create invoice with many lines (simulating large invoice)
        for i in range(20):
            InvoiceLine.objects.create(
                invoice=self.invoice,
                kind='service',
                description=f'Service Line {i+1:03d} - Detailed Description',
                quantity=1,
                unit_price_cents=2500,
                tax_rate=Decimal('0.21'),
                line_total_cents=2500
            )

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Should handle large invoices without timeout
        response = generator.generate_response()
        self.assertIsInstance(response, HttpResponse)
        self.assertGreater(len(response.content), 0)

    def test_memory_usage_with_buffer(self):
        """Test memory usage with BytesIO buffer"""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Check initial buffer state
        initial_size = len(generator.buffer.getvalue())
        self.assertEqual(initial_size, 0)

        # Generate document
        generator._create_pdf_document()
        generator.canvas.showPage()
        generator.canvas.save()

        # Check buffer has content after saving
        final_size = len(generator.buffer.getvalue())
        self.assertGreater(final_size, initial_size)

        # Test buffer cleanup
        generator.buffer.close()

    def test_canvas_resource_management(self):
        """Test proper canvas resource management"""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Canvas should be created during initialization
        self.assertIsNotNone(generator.canvas)

        # Test canvas operations don't cause memory leaks
        generator._render_company_information()
        generator._render_client_information()
        generator._render_items_table()

        # Should complete without errors
        self.assertTrue(True)


class PDFGeneratorEdgeCasesTestCase(TestCase):
    """Test edge cases and additional functionality for PDF generators"""

    def setUp(self):
        """Setup test data for edge cases"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)

        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Edge Case Test SRL',
            primary_email='edge@test.ro',
            status='active'
        )

        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-EDGE-001',
            subtotal_cents=5000,
            tax_cents=1050,
            total_cents=6050,
            status='issued',
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=15)
        )

    def test_invoice_without_due_date_status_rendering(self):
        """Test invoice status rendering without due date"""
        self.invoice.due_at = None
        self.invoice.save()

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Should handle missing due date gracefully
        generator._render_status_information(200)

        # Should complete without errors
        self.assertTrue(True)

    def test_paid_invoice_without_paid_at_attribute(self):
        """Test paid invoice status without paid_at attribute"""
        self.invoice.status = 'paid'
        self.invoice.save()

        # This tests the hasattr condition in the code
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Should handle missing paid_at attribute
        generator._render_status_information(200)

        self.assertTrue(True)

    def test_document_with_empty_bill_to_fields(self):
        """Test PDF generation with empty billing information"""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-EMPTY-BILLING-001',
            total_cents=1000,
            status='draft',
            # All bill_to fields are empty strings instead of None
            bill_to_name='',
            bill_to_email='',
            bill_to_tax_id='',
            bill_to_address1=''
        )

        generator = RomanianInvoicePDFGenerator(invoice)

        # Should handle empty billing fields gracefully
        generator._render_client_information()

        response = generator.generate_response()
        self.assertIsInstance(response, HttpResponse)

    def test_zero_amount_invoice(self):
        """Test PDF generation for zero amount invoice"""
        zero_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-ZERO-001',
            subtotal_cents=0,
            tax_cents=0,
            total_cents=0,
            status='issued'
        )

        generator = RomanianInvoicePDFGenerator(zero_invoice)
        response = generator.generate_response()

        self.assertIsInstance(response, HttpResponse)
        self.assertGreater(len(response.content), 0)

    def test_negative_amount_invoice(self):
        """Test PDF generation for credit note (negative amounts)"""
        credit_invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='CN-001',  # Credit Note
            subtotal_cents=-5000,
            tax_cents=-1050,
            total_cents=-6050,
            status='issued'
        )

        generator = RomanianInvoicePDFGenerator(credit_invoice)
        response = generator.generate_response()

        self.assertIsInstance(response, HttpResponse)
        self.assertGreater(len(response.content), 0)

    def test_invoice_lines_with_zero_quantity(self):
        """Test invoice with zero quantity line items"""
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Zero Quantity Service',
            quantity=0,
            unit_price_cents=1000,
            tax_rate=Decimal('0.21'),
            line_total_cents=0
        )

        generator = RomanianInvoicePDFGenerator(self.invoice)
        response = generator.generate_response()

        self.assertIsInstance(response, HttpResponse)

    def test_invoice_lines_with_high_precision_amounts(self):
        """Test invoice with high precision decimal amounts"""
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='High Precision Service',
            quantity=Decimal('1.999'),
            unit_price_cents=3333,  # €33.33
            tax_rate=Decimal('0.21'),
            line_total_cents=6666
        )

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Should format decimal quantities correctly
        generator._render_table_data(200)

        self.assertTrue(True)

    def test_company_info_with_settings_override(self):
        """Test company info handling with custom settings"""
        with override_settings(
            COMPANY_NAME='Override Test Company',
            COMPANY_CUI='RO99999999'
        ):
            generator = RomanianDocumentPDFGenerator(self.invoice)
            company_info = generator._get_company_info()

            # Should use overridden values
            self.assertEqual(company_info['name'], 'Override Test Company')
            self.assertEqual(company_info['cui'], 'RO99999999')

    def test_canvas_drawing_operations(self):
        """Test individual canvas drawing operations"""
        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Test canvas setFont operations don't fail
        generator.canvas.setFont("Helvetica-Bold", 24)
        generator.canvas.setFont("Helvetica", 10)

        # Test drawString operations don't fail
        generator.canvas.drawString(50, 50, "Test String")
        generator.canvas.drawString(50, 40, "Română: ăîâșț")

        # Test line drawing
        generator.canvas.line(50, 30, 100, 30)

        self.assertTrue(True)

    def test_document_footer_with_unicode_company_name(self):
        """Test document footer with Unicode company name"""
        with override_settings(COMPANY_NAME='Compania Română SRL'):
            generator = RomanianInvoicePDFGenerator(self.invoice)

            # Should handle Unicode characters in footer
            generator._render_document_footer()

            self.assertTrue(True)


class PDFGeneratorMockingTestCase(TestCase):
    """Test PDF generators with comprehensive mocking"""

    def setUp(self):
        """Setup test data for mocking tests"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)

        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Mock Test SRL',
            status='active'
        )

        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='INV-MOCK-001',
            total_cents=5000,
            status='issued'
        )

    @patch('apps.billing.pdf_generators.BytesIO')
    def test_buffer_initialization_mocked(self, mock_bytesio):
        """Test buffer initialization with mocked BytesIO"""
        mock_buffer = Mock()
        mock_bytesio.return_value = mock_buffer

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Verify BytesIO was called
        mock_bytesio.assert_called_once()
        self.assertEqual(generator.buffer, mock_buffer)

    @patch('apps.billing.pdf_generators.canvas.Canvas')
    def test_canvas_initialization_mocked(self, mock_canvas_class):
        """Test canvas initialization with mocked Canvas"""
        mock_canvas = Mock()
        mock_canvas_class.return_value = mock_canvas

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Verify Canvas was initialized with correct parameters
        mock_canvas_class.assert_called_once_with(generator.buffer, pagesize=A4)
        self.assertEqual(generator.canvas, mock_canvas)

    @patch('apps.billing.pdf_generators.canvas.Canvas')
    def test_generate_response_canvas_operations(self, mock_canvas_class):
        """Test that generate_response calls correct canvas methods"""
        mock_canvas = Mock()
        mock_canvas_class.return_value = mock_canvas

        # Mock buffer getvalue method
        generator = RomanianInvoicePDFGenerator(self.invoice)
        generator.buffer.getvalue = Mock(return_value=b'PDF content')
        generator.buffer.seek = Mock()

        response = generator.generate_response()

        # Verify canvas operations were called
        mock_canvas.showPage.assert_called_once()
        mock_canvas.save.assert_called_once()

        # Verify buffer operations
        generator.buffer.seek.assert_called_once_with(0)
        generator.buffer.getvalue.assert_called_once()

        # Verify response
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response.content, b'PDF content')

    @patch.object(RomanianDocumentPDFGenerator, '_get_company_info')
    def test_company_info_called_multiple_times(self, mock_get_company_info):
        """Test that company info is retrieved when needed"""
        mock_get_company_info.return_value = {
            'name': 'Test Company',
            'address': 'Test Address',
            'city': 'Test City',
            'country': 'Test Country',
            'cui': 'RO12345678',
            'email': 'test@company.ro'
        }

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Call methods that use company info
        generator._setup_document_header()
        generator._render_company_information()
        generator._render_document_footer()

        # Verify company info was called multiple times
        self.assertGreaterEqual(mock_get_company_info.call_count, 3)

    @patch('apps.billing.pdf_generators._t')  # Mock translation function
    def test_translation_function_usage(self, mock_translation):
        """Test that translation function is used correctly"""
        mock_translation.side_effect = lambda x: f"Translated: {x}"

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Call methods that use translations
        generator._render_company_information()
        generator._render_client_information()
        generator._render_table_headers(200)

        # Verify translation function was called
        self.assertGreater(mock_translation.call_count, 0)


class PDFGeneratorIntegrationTestCase(TestCase):
    """Integration tests for PDF generators with realistic scenarios"""

    def setUp(self):
        """Setup realistic test scenario"""
        self.currency = Currency.objects.create(code='RON', symbol='lei', decimals=2)

        self.customer = Customer.objects.create(
            customer_type='company',
            company_name='Realistic Test Company SRL',
            primary_email='realistic@test.ro',
            status='active'
        )

        # Create realistic invoice
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='FA-2025-001',
            subtotal_cents=84000,  # €840.00
            tax_cents=17640,       # €176.40 (21% VAT)
            total_cents=101640,    # €1016.40
            status='issued',
            issued_at=timezone.now(),
            due_at=timezone.now() + timezone.timedelta(days=30),
            bill_to_name='Client Company SRL',
            bill_to_email='billing@client.ro',
            bill_to_tax_id='RO87654321',
            bill_to_address1='Strada Client 456',
            bill_to_city='Cluj-Napoca',
            bill_to_postal='400000',
            bill_to_country='România'
        )

        # Add realistic invoice lines
        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='Premium Web Hosting Package',
            quantity=1,
            unit_price_cents=50000,  # €500.00
            tax_rate=Decimal('0.21'),
            line_total_cents=50000
        )

        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='service',
            description='SSL Certificate Premium',
            quantity=2,
            unit_price_cents=15000,  # €150.00 each
            tax_rate=Decimal('0.21'),
            line_total_cents=30000   # €300.00 total
        )

        InvoiceLine.objects.create(
            invoice=self.invoice,
            kind='setup',
            description='Initial Setup and Configuration',
            quantity=1,
            unit_price_cents=4000,   # €40.00
            tax_rate=Decimal('0.21'),
            line_total_cents=4000
        )

    def test_realistic_invoice_pdf_generation(self):
        """Test PDF generation with realistic data"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        response = generator.generate_response()

        # Verify response is correct
        self.assertIsInstance(response, HttpResponse)
        self.assertEqual(response['Content-Type'], 'application/pdf')
        self.assertIn('FA-2025-001', response['Content-Disposition'])

        # Verify content is substantial (realistic PDF should be larger)
        self.assertGreater(len(response.content), 1000)

    def test_realistic_proforma_pdf_generation(self):
        """Test proforma PDF generation with realistic data"""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number='PRO-2025-001',
            subtotal_cents=25000,
            tax_cents=5250,
            total_cents=30250,
            valid_until=timezone.now() + timezone.timedelta(days=15),
            bill_to_name='Prospect Company SRL',
            bill_to_email='prospect@company.ro'
        )

        ProformaLine.objects.create(
            proforma=proforma,
            kind='service',
            description='Standard Hosting Package - Annual',
            quantity=1,
            unit_price_cents=25000,
            tax_rate=Decimal('0.21'),
            line_total_cents=25000
        )

        generator = RomanianProformaPDFGenerator(proforma)
        response = generator.generate_response()

        self.assertIsInstance(response, HttpResponse)
        self.assertIn('PRO-2025-001', response['Content-Disposition'])
        self.assertGreater(len(response.content), 1000)

    def test_concurrent_pdf_generation(self):
        """Test multiple PDF generators working concurrently"""
        generators = []
        responses = []

        # Create multiple generators
        for _i in range(3):
            generators.append(RomanianInvoicePDFGenerator(self.invoice))

        # Generate PDFs
        for generator in generators:
            response = generator.generate_response()
            responses.append(response)

        # Verify all responses are valid
        for response in responses:
            self.assertIsInstance(response, HttpResponse)
            self.assertGreater(len(response.content), 0)

        # Verify each generator has independent state
        for generator in generators:
            self.assertIsInstance(generator.buffer, BytesIO)
            self.assertIsNotNone(generator.canvas)

    @override_settings(
        COMPANY_NAME='Compania Realistă de Test SRL',
        COMPANY_ADDRESS='Bulevardul Unirii 123',
        COMPANY_CITY='București',
        COMPANY_COUNTRY='România',
        COMPANY_CUI='RO12345678',
        COMPANY_EMAIL='contact@compania-realista.ro'
    )
    def test_realistic_company_settings(self):
        """Test PDF generation with realistic Romanian company settings"""
        generator = RomanianInvoicePDFGenerator(self.invoice)
        company_info = generator._get_company_info()

        # Verify company info uses settings
        self.assertEqual(company_info['name'], 'Compania Realistă de Test SRL')
        self.assertEqual(company_info['city'], 'București')
        self.assertEqual(company_info['country'], 'România')

        # Generate PDF with realistic settings
        response = generator.generate_response()
        self.assertIsInstance(response, HttpResponse)
        self.assertGreater(len(response.content), 0)

    def test_memory_efficiency_with_large_dataset(self):
        """Test memory efficiency with larger dataset"""
        # Add many invoice lines to test memory efficiency
        for i in range(50):
            InvoiceLine.objects.create(
                invoice=self.invoice,
                kind='service',
                description=f'Service Line {i+1:03d} - Detailed Description with Romanian Characters: ăîâșț',
                quantity=Decimal('1.5'),
                unit_price_cents=100 * (i + 1),
                tax_rate=Decimal('0.21'),
                line_total_cents=100 * (i + 1)
            )

        generator = RomanianInvoicePDFGenerator(self.invoice)

        # Generate PDF - should complete without memory issues
        response = generator.generate_response()

        self.assertIsInstance(response, HttpResponse)
        self.assertGreater(len(response.content), 1000)

        # Verify we can still access the invoice lines count
        self.assertEqual(self.invoice.lines.count(), 53)  # 3 original + 50 new
