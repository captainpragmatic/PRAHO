"""
🔒 Security Fix Tests for Billing App
Tests all OWASP Top 10 security enhancements implemented for the billing system.
"""

from decimal import Decimal
from unittest.mock import patch
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError, PermissionDenied
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from apps.billing.models import (
    Currency, Invoice, InvoiceSequence, ProformaInvoice, ProformaSequence,
    validate_financial_json, validate_financial_amount, validate_financial_text_field,
    log_security_event
)
from apps.billing.security import validate_efactura_url, validate_external_api_url, sanitize_financial_input
from apps.billing.views import _validate_financial_document_access
from apps.customers.models import Customer

User = get_user_model()


class BillingSecurityValidationTests(TestCase):
    """🔒 Tests for financial data validation security"""
    
    def test_financial_json_size_validation(self):
        """🔒 Test that financial JSON fields reject oversized data"""
        large_data = {"data": "x" * 6000}  # Over 5KB limit for financial data
        
        with self.assertRaises(ValidationError) as cm:
            validate_financial_json(large_data, "test field")
        
        self.assertIn("too large", str(cm.exception))
    
    def test_financial_json_depth_validation(self):
        """🔒 Test that financial JSON fields reject deeply nested data"""
        # Create 7 levels deep (over 5 limit for financial data)
        deep_data = {}
        current = deep_data
        for i in range(7):
            current[f"level{i}"] = {}
            current = current[f"level{i}"]
        
        with self.assertRaises(ValidationError) as cm:
            validate_financial_json(deep_data, "test field")
        
        self.assertIn("too deep", str(cm.exception))
    
    def test_financial_json_sensitive_keys_blocked(self):
        """🔒 Test that sensitive financial keys are blocked"""
        sensitive_data = [
            {"card_number": "1234567890123456"},
            {"cvv": "123"},
            {"bank_account": "12345678"},
            {"ssn": "123456789"},
            {"api_key": "secret123"}
        ]
        
        for data in sensitive_data:
            with self.assertRaises(ValidationError, msg=f"Failed to block: {data}"):
                validate_financial_json(data, "financial field")
    
    def test_financial_json_dangerous_patterns_blocked(self):
        """🔒 Test that dangerous patterns are blocked in financial JSON"""
        dangerous_data = [
            {"script": "<script>alert('xss')</script>"},
            {"template": "${malicious.code}"},
            {"eval": "eval('dangerous')"},
            {"command": "<%=system('rm -rf /')%>"}
        ]
        
        for data in dangerous_data:
            with self.assertRaises(ValidationError, msg=f"Failed to block: {data}"):
                validate_financial_json(data, "financial field")
    
    def test_financial_amount_validation(self):
        """🔒 Test that financial amounts are validated for limits"""
        # Test extremely large amount
        with self.assertRaises(ValidationError):
            validate_financial_amount(20000000000, "Large amount")  # Over 100M limit
        
        # Test extremely negative amount
        with self.assertRaises(ValidationError):
            validate_financial_amount(-20000000000, "Negative amount")  # Under -100M limit
    
    def test_financial_text_field_validation(self):
        """🔒 Test that financial text fields are validated"""
        # Test oversized text
        large_text = "x" * 1500  # Over 1000 char limit
        with self.assertRaises(ValidationError):
            validate_financial_text_field(large_text, "description")
        
        # Test dangerous patterns in text
        dangerous_texts = [
            "<script>alert('xss')</script>",
            "javascript:void(0)",
            "${template.injection}",
            "eval('malicious')"
        ]
        
        for text in dangerous_texts:
            with self.assertRaises(ValidationError, msg=f"Failed to block: {text}"):
                validate_financial_text_field(text, "description")
    
    def test_safe_financial_data_passes_validation(self):
        """✅ Test that safe financial data passes all validations"""
        safe_json = {
            "invoice_number": "INV-001234",
            "customer_info": {
                "name": "Safe Customer Ltd",
                "address": "123 Main St, Bucharest"
            },
            "line_items": [
                {"description": "VPS Hosting", "amount": 29.99},
                {"description": "Domain Registration", "amount": 15.00}
            ]
        }
        
        try:
            validate_financial_json(safe_json, "safe financial data")
            validate_financial_amount(2999, "safe amount")
            validate_financial_text_field("Safe invoice description", "description")
        except ValidationError as e:
            self.fail(f"Safe financial data failed validation: {e}")


class BillingModelSecurityTests(TestCase):
    """🔒 Tests for billing model security enhancements"""
    
    def setUp(self):
        self.currency = Currency.objects.create(
            code="RON",
            symbol="RON",
            decimals=2
        )
        
        self.customer = Customer.objects.create(
            name="Test Customer",
            company_name="Test Customer Ltd",
            primary_email="test@customer.com",
            customer_type="company"
        )
    
    def test_proforma_invoice_validation(self):
        """🔒 Test that ProformaInvoice clean() validates data"""
        # Test financial calculation integrity
        proforma = ProformaInvoice(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=1000,
            tax_cents=190,
            total_cents=2000,  # Wrong calculation: should be 1190
            valid_until=timezone.now() + timedelta(days=30)
        )
        
        with self.assertRaises(ValidationError) as cm:
            proforma.clean()
        
        self.assertIn("Financial calculation error", str(cm.exception))
    
    def test_proforma_expiration_date_validation(self):
        """🔒 Test that ProformaInvoice validates expiration dates"""
        proforma = ProformaInvoice(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=1000,
            tax_cents=190,
            total_cents=1190,
            valid_until=timezone.now() - timedelta(days=1)  # Past date
        )
        
        with self.assertRaises(ValidationError) as cm:
            proforma.clean()
        
        self.assertIn("must be in the future", str(cm.exception))
    
    def test_invoice_validation(self):
        """🔒 Test that Invoice clean() validates data"""
        invoice = Invoice(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=1000,
            tax_cents=190,
            total_cents=2000,  # Wrong calculation
            status="draft"
        )
        
        with self.assertRaises(ValidationError) as cm:
            invoice.clean()
        
        self.assertIn("Financial calculation error", str(cm.exception))
    
    def test_invoice_immutability_validation(self):
        """🔒 Test that locked invoices cannot be modified"""
        invoice = Invoice(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=1000,
            tax_cents=190,
            total_cents=1190,
            status="issued",
            locked_at=timezone.now()
        )
        
        with self.assertRaises(ValidationError) as cm:
            invoice.clean()
        
        self.assertIn("Cannot modify locked invoice", str(cm.exception))
    
    def test_invoice_date_consistency_validation(self):
        """🔒 Test that invoice dates are consistent"""
        now = timezone.now()
        invoice = Invoice(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=1000,
            tax_cents=190,
            total_cents=1190,
            status="draft",
            issued_at=now,
            due_at=now - timedelta(days=1)  # Due date before issue date
        )
        
        with self.assertRaises(ValidationError) as cm:
            invoice.clean()
        
        self.assertIn("Due date must be after issue date", str(cm.exception))
    
    @patch('apps.billing.models.log_security_event')
    def test_sequence_security_logging(self, mock_log):
        """🔒 Test that sequence operations are logged"""
        sequence = InvoiceSequence.objects.create(scope="test", last_value=0)
        
        number = sequence.get_next_number(user_email="admin@test.com")
        
        # Should log the sequence increment
        mock_log.assert_called()
        call_args = mock_log.call_args[1]
        self.assertEqual(call_args['event_type'], 'invoice_number_generated')
        self.assertIn('critical_financial_operation', call_args['details'])
        self.assertTrue(call_args['details']['critical_financial_operation'])
    
    def test_safe_invoice_creation(self):
        """✅ Test that safe invoice creation succeeds"""
        invoice = Invoice(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=1000,
            tax_cents=190,
            total_cents=1190,
            status="draft",
            meta={"safe_data": "invoice metadata"}
        )
        
        try:
            invoice.clean()  # Should not raise ValidationError
        except ValidationError as e:
            self.fail(f"Safe invoice failed validation: {e}")


class BillingAccessControlTests(TestCase):
    """🔒 Tests for billing access control enhancements"""
    
    def setUp(self):
        self.currency = Currency.objects.create(
            code="RON",
            symbol="RON",
            decimals=2
        )
        
        self.customer = Customer.objects.create(
            name="Test Customer",
            company_name="Test Customer Ltd",
            primary_email="test@customer.com",
            customer_type="company"
        )
        
        self.authorized_user = User.objects.create_user(
            email="authorized@test.com",
            password="testpass123",
            is_staff=True
        )
        
        self.unauthorized_user = User.objects.create_user(
            email="unauthorized@test.com",
            password="testpass123",
            is_staff=False
        )
        
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=1000,
            tax_cents=190,
            total_cents=1190,
            status="draft"
        )
        
        # Mock request objects
        class MockRequest:
            def __init__(self, user):
                self.user = user
                self.META = {'REMOTE_ADDR': '127.0.0.1'}
        
        self.authorized_request = MockRequest(self.authorized_user)
        self.unauthorized_request = MockRequest(self.unauthorized_user)
    
    @patch('apps.billing.views.log_security_event')
    def test_financial_document_access_validation_success(self, mock_log):
        """🔒 Test successful financial document access validation"""
        # Mock the can_access_customer method
        self.authorized_user.can_access_customer = lambda customer: True
        
        try:
            _validate_financial_document_access(self.authorized_request, self.invoice, 'view')
        except PermissionDenied:
            self.fail("Valid access was denied")
        
        # Should log successful access
        mock_log.assert_called()
        call_args = mock_log.call_args[1]
        self.assertEqual(call_args['event_type'], 'financial_document_accessed')
        self.assertTrue(call_args['details']['access_granted'])
    
    @patch('apps.billing.views.log_security_event')
    def test_financial_document_access_validation_denied(self, mock_log):
        """🔒 Test financial document access validation denial"""
        # Mock the can_access_customer method to deny access
        self.unauthorized_user.can_access_customer = lambda customer: False
        
        result = _validate_financial_document_access(self.unauthorized_request, self.invoice, 'download')
        from django.http import HttpResponseForbidden
        self.assertIsInstance(result, HttpResponseForbidden)
        
        # Should log access denial
        mock_log.assert_called()
        call_args = mock_log.call_args[1]
        self.assertEqual(call_args['event_type'], 'financial_document_access_denied')
        self.assertTrue(call_args['details']['attempted_unauthorized_access'])
    
    @patch('apps.billing.views.log_security_event')
    def test_unauthenticated_access_denied(self, mock_log):
        """🔒 Test that unauthenticated access is denied"""
        class MockUnauthenticatedRequest:
            def __init__(self):
                self.user = None
                self.META = {'REMOTE_ADDR': '127.0.0.1'}
        
        unauthenticated_request = MockUnauthenticatedRequest()
        
        result = _validate_financial_document_access(unauthenticated_request, self.invoice, 'view')
        from django.http import HttpResponseForbidden
        self.assertIsInstance(result, HttpResponseForbidden)
        
        # Should log unauthenticated access attempt
        mock_log.assert_called()
        call_args = mock_log.call_args[1]
        self.assertEqual(call_args['event_type'], 'financial_document_access_denied')
        self.assertEqual(call_args['details']['reason'], 'unauthenticated_access_attempt')


class BillingSSRFProtectionTests(TestCase):
    """🔒 Tests for SSRF protection in e-Factura integration"""
    
    def test_valid_efactura_urls_accepted(self):
        """✅ Test that valid e-Factura URLs are accepted"""
        valid_urls = [
            "https://efactura.mfinante.ro/api/v1/upload",
            "https://webservicesp.anaf.ro/efactura",
            "https://anaf.ro/efactura-api"
        ]
        
        for url in valid_urls:
            try:
                result = validate_efactura_url(url)
                self.assertEqual(result, url)
            except ValidationError as e:
                self.fail(f"Valid e-Factura URL was rejected: {url}, error: {e}")
    
    def test_dangerous_urls_blocked(self):
        """🔒 Test that dangerous URLs are blocked"""
        dangerous_urls = [
            "http://localhost:8080/admin",
            "https://127.0.0.1/metadata",
            "ftp://internal.server.com/file",
            "https://evil.com/steal-data",
            "https://192.168.1.1/router-admin",
            "file:///etc/passwd"
        ]
        
        for url in dangerous_urls:
            with self.assertRaises(ValidationError, msg=f"Failed to block dangerous URL: {url}"):
                validate_efactura_url(url)
    
    def test_internal_ip_ranges_blocked(self):
        """🔒 Test that internal IP ranges are blocked"""
        internal_ips = [
            "https://10.0.0.1/api",
            "https://172.16.0.1/admin", 
            "https://192.168.0.1/config",
            "https://169.254.169.254/metadata"  # AWS metadata endpoint
        ]
        
        for url in internal_ips:
            with self.assertRaises(ValidationError, msg=f"Failed to block internal IP: {url}"):
                validate_external_api_url(url, ["allowed.domain.com"])
    
    def test_blocked_protocols_rejected(self):
        """🔒 Test that non-HTTP protocols are rejected"""
        blocked_urls = [
            "ftp://anaf.ro/file",
            "ldap://anaf.ro/directory",
            "file:///var/www/html",
            "gopher://anaf.ro/data"
        ]
        
        for url in blocked_urls:
            with self.assertRaises(ValidationError, msg=f"Failed to block protocol: {url}"):
                validate_efactura_url(url)


class BillingInputSanitizationTests(TestCase):
    """🔒 Tests for input sanitization in financial operations"""
    
    def test_dangerous_input_sanitized(self):
        """🔒 Test that dangerous input is sanitized"""
        dangerous_inputs = [
            ("<script>alert('xss')</script>Invoice description", "Invoice description"),
            ("javascript:void(0) Payment note", "void(0) Payment note"),
            ("eval('malicious') Customer note", "'malicious') Customer note"),
            ("onload=steal() Description", "steal() Description")
        ]
        
        for dangerous_input, expected_clean in dangerous_inputs:
            result = sanitize_financial_input(dangerous_input)
            self.assertEqual(result, expected_clean)
    
    def test_oversized_input_truncated(self):
        """🔒 Test that oversized input is truncated"""
        large_input = "x" * 1500
        result = sanitize_financial_input(large_input, max_length=1000)
        
        self.assertEqual(len(result), 1000)
    
    def test_safe_input_preserved(self):
        """✅ Test that safe input is preserved"""
        safe_inputs = [
            "VPS Hosting Service - Monthly",
            "Domain registration for example.com", 
            "SSL Certificate - 1 year validity",
            "Professional support package"
        ]
        
        for safe_input in safe_inputs:
            result = sanitize_financial_input(safe_input)
            self.assertEqual(result, safe_input)


class BillingSecurityLoggingTests(TestCase):
    """🔒 Tests for security logging in billing operations"""
    
    @patch('apps.billing.models.logger')
    def test_security_event_logging_format(self, mock_logger):
        """🔒 Test that security events are logged in correct format"""
        log_security_event(
            event_type='test_financial_operation',
            details={
                'amount': 1000,
                'customer_id': 123,
                'critical': True
            },
            request_ip='192.168.1.100',
            user_email='admin@test.com'
        )
        
        # Should log with correct format
        mock_logger.info.assert_called()
        call_args = str(mock_logger.info.call_args)
        self.assertIn('Billing Security', call_args)
        self.assertIn('test_financial_operation', call_args)
        self.assertIn('financial_operation', call_args)
    
    @patch('apps.billing.models.log_security_event')
    def test_model_validation_triggers_logging(self, mock_log):
        """🔒 Test that model validation triggers security logging"""
        currency = Currency.objects.create(code="RON", symbol="RON", decimals=2)
        customer = Customer.objects.create(
            name="Test Customer",
            company_name="Test Customer Ltd", 
            primary_email="test@customer.com",
            customer_type="company"
        )
        
        proforma = ProformaInvoice(
            customer=customer,
            currency=currency,
            subtotal_cents=1000,
            tax_cents=190,
            total_cents=1190,
            valid_until=timezone.now() + timedelta(days=30)
        )
        
        proforma.clean()
        
        # Should trigger security logging
        mock_log.assert_called()
        call_args = mock_log.call_args[1]
        self.assertEqual(call_args['event_type'], 'proforma_validation')
        self.assertTrue(call_args['details']['validation_passed'])