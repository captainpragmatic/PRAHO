"""
🔒 Security Fix Tests for Customers App
Tests all OWASP Top 10 security enhancements implemented for the customers system.
"""

import socket
from unittest.mock import patch, Mock
from django.test import TestCase, Client, RequestFactory
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError, PermissionDenied
from django.urls import reverse
from django.contrib.messages import get_messages
from django.utils import timezone
from datetime import timedelta

from apps.customers.models import Customer, CustomerPaymentMethod, validate_bank_details
from apps.customers.forms import CustomerTaxProfileForm
from apps.customers.views import _handle_secure_error
from apps.common.validators import SecureInputValidator
from apps.billing.models import Currency

User = get_user_model()


class AccessControlSecurityTests(TestCase):
    """🔒 Tests for A01 - Broken Access Control fixes"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.staff_user = User.objects.create_user(
            email='staff@example.com',
            password='staffpass123',
            is_staff=True
        )
        self.customer = Customer.objects.create(
            name='Test Customer',
            company_name='Test Company',
            primary_email='customer@example.com',
            customer_type='business'
        )
        self.client = Client()

    def test_customer_detail_access_control_before_retrieval(self):
        """Test that access control happens before object retrieval"""
        self.client.force_login(self.user)
        
        # Mock get_accessible_customers to return empty queryset
        with patch.object(self.user, 'get_accessible_customers') as mock_accessible:
            mock_accessible.return_value = Customer.objects.none()
            
            response = self.client.get(
                reverse('customers:detail', kwargs={'customer_id': 999})
            )
            
            # Should get 404 without revealing customer existence
            self.assertEqual(response.status_code, 404)
            mock_accessible.assert_called_once()

    def test_customer_edit_access_control_before_retrieval(self):
        """Test that edit view checks access before retrieval"""
        self.client.force_login(self.staff_user)
        
        with patch.object(self.staff_user, 'get_accessible_customers') as mock_accessible:
            mock_accessible.return_value = Customer.objects.none()
            
            response = self.client.get(
                reverse('customers:edit', kwargs={'customer_id': self.customer.id})
            )
            
            self.assertEqual(response.status_code, 404)
            mock_accessible.assert_called_once()

    def test_customer_delete_access_control_before_retrieval(self):
        """Test that delete view checks access before retrieval"""
        self.client.force_login(self.staff_user)
        
        with patch.object(self.staff_user, 'get_accessible_customers') as mock_accessible:
            mock_accessible.return_value = Customer.objects.none()
            
            response = self.client.post(
                reverse('customers:delete', kwargs={'customer_id': self.customer.id})
            )
            
            self.assertEqual(response.status_code, 404)
            mock_accessible.assert_called_once()

    def test_accessible_customers_used_consistently(self):
        """Test that all views use get_accessible_customers consistently"""
        self.client.force_login(self.staff_user)
        
        # Mock to return the customer
        with patch.object(self.staff_user, 'get_accessible_customers') as mock_accessible:
            mock_accessible.return_value = Customer.objects.filter(id=self.customer.id)
            
            response = self.client.get(
                reverse('customers:detail', kwargs={'customer_id': self.customer.id})
            )
            
            self.assertEqual(response.status_code, 200)
            mock_accessible.assert_called_once()


class RegexSecurityTests(TestCase):
    """🔒 Tests for A03 - Injection (ReDoS) fixes"""

    def test_cui_regex_length_validation(self):
        """Test CUI regex has length limits to prevent ReDoS"""
        form_data = {
            'cui': 'RO' + '1' * 50,  # Very long CUI
        }
        form = CustomerTaxProfileForm(data=form_data)
        
        is_valid = form.is_valid()
        
        self.assertFalse(is_valid)
        self.assertIn('cui', form.errors)
        # Check for either our custom validation message or Django's field validation
        error_msg = str(form.errors['cui']).lower()
        self.assertTrue(
            'too long' in error_msg or 'cel mult' in error_msg,  # 'cel mult' is Romanian for 'at most'
            f"Expected length validation error, got: {form.errors['cui']}"
        )

    def test_vat_number_regex_length_validation(self):
        """Test VAT number regex has length limits to prevent ReDoS"""
        form_data = {
            'vat_number': 'RO' + '1' * 50,  # Very long VAT
            'is_vat_payer': True
        }
        form = CustomerTaxProfileForm(data=form_data)
        
        is_valid = form.is_valid()
        
        self.assertFalse(is_valid)
        self.assertIn('vat_number', form.errors)
        # Check for either our custom validation message or Django's field validation
        error_msg = str(form.errors['vat_number']).lower()
        self.assertTrue(
            'too long' in error_msg or 'cel mult' in error_msg,  # 'cel mult' is Romanian for 'at most'
            f"Expected length validation error, got: {form.errors['vat_number']}"
        )

    def test_cui_pattern_specificity(self):
        """Test CUI pattern is more specific (6-10 digits)"""
        # Valid CUI with required fields
        form_data = {
            'cui': 'RO123456',
            'registration_number': 'J12/123/2020',
            'is_vat_payer': False,
            'vat_rate': 19,
            'reverse_charge_eligible': False
        }
        form = CustomerTaxProfileForm(data=form_data)
        if not form.is_valid():
            print(f"CUI Form errors: {form.errors}")  # Debug output
        self.assertTrue(form.is_valid())
        
        # Invalid CUI (too short)
        form_data = {
            'cui': 'RO12',
            'registration_number': 'J12/123/2020',
            'is_vat_payer': False,
            'vat_rate': 19,
            'reverse_charge_eligible': False
        }
        form = CustomerTaxProfileForm(data=form_data)
        self.assertFalse(form.is_valid())
        
        # Invalid CUI (too long)
        form_data = {
            'cui': 'RO12345678901',
            'registration_number': 'J12/123/2020',
            'is_vat_payer': False,
            'vat_rate': 19,
            'reverse_charge_eligible': False
        }
        form = CustomerTaxProfileForm(data=form_data)
        self.assertFalse(form.is_valid())

    def test_vat_pattern_specificity(self):
        """Test VAT pattern is more specific (6-10 digits)"""
        # Valid VAT with all required fields
        form_data = {
            'vat_number': 'RO123456', 
            'is_vat_payer': True,
            'cui': 'RO123456',
            'registration_number': 'J12/123/2020',
            'vat_rate': 19,
            'reverse_charge_eligible': False
        }
        form = CustomerTaxProfileForm(data=form_data)
        if not form.is_valid():
            print(f"Form errors: {form.errors}")  # Debug output
        self.assertTrue(form.is_valid())
        
        # Invalid VAT (too short)
        form_data = {
            'vat_number': 'RO12', 
            'is_vat_payer': True,
            'cui': 'RO123456',
            'registration_number': 'J12/123/2020',
            'vat_rate': 19,
            'reverse_charge_eligible': False
        }
        form = CustomerTaxProfileForm(data=form_data)
        self.assertFalse(form.is_valid())


class BankDetailsSecurityTests(TestCase):
    """🔒 Tests for A02 - Cryptographic Failures (Bank Details) fixes"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.customer = Customer.objects.create(
            name='Test Customer',
            company_name='Test Company',
            primary_email='customer@example.com',
            customer_type='business'
        )
        self.currency = Currency.objects.create(
            code='RON',
            name='Romanian Leu',
            symbol='lei'
        )

    def test_bank_details_validation_function(self):
        """Test the validate_bank_details function works correctly"""
        # Valid bank details
        valid_details = {
            'bank_name': 'Test Bank',
            'account_number': '1234567890',
            'iban': 'RO49AAAA1B31007593840000',
            'swift_code': 'TESTRO22'
        }
        
        # Should not raise any exception
        try:
            validate_bank_details(valid_details)
        except ValidationError:
            self.fail("validate_bank_details raised ValidationError for valid data")

    def test_bank_details_invalid_field_rejected(self):
        """Test that invalid fields in bank details are rejected"""
        invalid_details = {
            'malicious_field': 'some_value',
            'bank_name': 'Test Bank'
        }
        
        with self.assertRaises(ValidationError) as cm:
            validate_bank_details(invalid_details)
        
        self.assertIn('Invalid bank details field', str(cm.exception))

    def test_bank_details_field_length_limits(self):
        """Test that field length limits are enforced"""
        # Test bank_name length limit (100 chars)
        long_name_details = {
            'bank_name': 'x' * 101,  # Exceeds 100 char limit
            'account_number': '1234567890'
        }
        
        with self.assertRaises(ValidationError) as cm:
            validate_bank_details(long_name_details)
        
        self.assertIn('exceeds maximum length', str(cm.exception))

    def test_bank_details_swift_code_limit(self):
        """Test SWIFT code length limit (11 chars)"""
        invalid_swift_details = {
            'swift_code': 'TOOLONGSWIFTCODE',  # Exceeds 11 char limit
            'bank_name': 'Test Bank'
        }
        
        with self.assertRaises(ValidationError) as cm:
            validate_bank_details(invalid_swift_details)
        
        self.assertIn('exceeds maximum length', str(cm.exception))

    def test_payment_method_clean_calls_validation(self):
        """Test that CustomerPaymentMethod.clean() calls our validation"""
        payment_method = CustomerPaymentMethod(
            customer=self.customer,
            method_type='bank_transfer',
            display_name='Test Payment',
            bank_details={'invalid_field': 'value'}
        )
        
        with self.assertRaises(ValidationError):
            payment_method.clean()

    @patch('apps.customers.models.security_logger')
    def test_bank_details_security_logging(self, mock_logger):
        """Test that bank details validation logs security events"""
        valid_details = {
            'bank_name': 'Test Bank',
            'account_number': '1234567890'
        }
        
        validate_bank_details(valid_details)
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        self.assertIn('Bank details validation completed', call_args[0][0])
        self.assertTrue(call_args[1]['extra']['sensitive_operation'])


class EmailEnumerationSecurityTests(TestCase):
    """🔒 Tests for A07 - Identification and Authentication Failures fixes"""

    @patch('time.time')
    @patch('time.sleep')
    def test_email_validation_consistent_timing(self, mock_sleep, mock_time):
        """Test that email validation has consistent timing"""
        mock_time.side_effect = [0.0, 0.05, 0.0, 0.05]  # start_time, current_time for each call
        
        # Valid email
        try:
            SecureInputValidator.validate_email_secure('test@example.com')
        except Exception:
            pass
        
        # Invalid email
        try:
            SecureInputValidator.validate_email_secure('invalid-email')
        except Exception:
            pass
        
        # Should call sleep for timing normalization
        self.assertTrue(mock_sleep.called)
        # Verify consistent sleep duration
        sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
        self.assertTrue(all(sleep_time >= 0 for sleep_time in sleep_calls))

    def test_email_validation_timing_safe_decorator(self):
        """Test that email validation uses timing_safe_validator decorator"""
        # Check if the decorator is applied by looking at function attributes
        validate_func = SecureInputValidator.validate_email_secure
        
        # The timing_safe_validator decorator should be applied
        # We can test this by ensuring the function behavior is consistent
        import time
        
        start_time = time.time()
        try:
            validate_func('invalid')
        except ValidationError:
            pass
        duration1 = time.time() - start_time
        
        start_time = time.time()
        try:
            validate_func('test@example.com')
        except ValidationError:
            pass
        duration2 = time.time() - start_time
        
        # Both should take similar time due to timing normalization
        # Allow for some variance but should be in same ballpark
        self.assertLess(abs(duration1 - duration2), 0.05)


class SoftDeleteSecurityTests(TestCase):
    """🔒 Tests for A04 - Insecure Design (Soft Delete) fixes"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            is_staff=True
        )
        self.customer = Customer.objects.create(
            name='Test Customer',
            company_name='Test Company',
            primary_email='customer@example.com',
            customer_type='business'
        )

    @patch('apps.customers.models.security_logger')
    def test_soft_delete_security_logging(self, mock_logger):
        """Test that soft delete logs security events"""
        self.customer.soft_delete(self.user)
        
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args
        self.assertIn('Soft delete initiated', call_args[0][0])
        self.assertEqual(call_args[1]['extra']['user_id'], self.user.id)

    @patch('apps.customers.models.security_logger')
    def test_restore_security_logging(self, mock_logger):
        """Test that restore logs security events"""
        # First soft delete
        self.customer.soft_delete(self.user)
        mock_logger.reset_mock()
        
        # Then restore
        self.customer.restore()
        
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args
        self.assertIn('Soft restore initiated', call_args[0][0])

    def test_soft_delete_atomic_transaction(self):
        """Test that soft delete uses atomic transactions"""
        # This test ensures the soft_delete method uses transaction.atomic
        with patch('django.db.transaction.atomic') as mock_atomic:
            mock_atomic.return_value.__enter__ = Mock()
            mock_atomic.return_value.__exit__ = Mock()
            
            self.customer.soft_delete(self.user)
            
            mock_atomic.assert_called_once()

    def test_validation_methods_exist(self):
        """Test that validation methods are available for override"""
        # These methods should exist and be callable
        self.assertTrue(hasattr(self.customer, '_validate_deletion_allowed'))
        self.assertTrue(hasattr(self.customer, '_validate_restoration_allowed'))
        self.assertTrue(hasattr(self.customer, '_cascade_soft_delete'))
        
        # Should not raise exceptions when called
        try:
            self.customer._validate_deletion_allowed()
            self.customer._validate_restoration_allowed()
            self.customer._cascade_soft_delete(self.user)
        except Exception as e:
            self.fail(f"Validation methods raised unexpected exception: {e}")


class ErrorHandlingSecurityTests(TestCase):
    """🔒 Tests for A05 - Security Misconfiguration (Error Handling) fixes"""

    def setUp(self):
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )

    def test_secure_error_handler_validation_error(self):
        """Test that validation errors are handled securely"""
        request = self.factory.get('/')
        
        with patch('django.contrib.messages.error') as mock_message:
            _handle_secure_error(request, ValidationError('Test error'), 'test_operation', self.user.id)
            
            mock_message.assert_called_once()
            call_args = mock_message.call_args[0]
            # Should use generic message, not leak specific error details
            self.assertIn('Invalid data provided', call_args[1])
            self.assertNotIn('Test error', call_args[1])

    def test_secure_error_handler_integrity_error(self):
        """Test that integrity errors are handled securely"""
        request = self.factory.get('/')
        
        with patch('django.contrib.messages.error') as mock_message:
            from django.db import IntegrityError
            _handle_secure_error(request, IntegrityError('DB constraint violation'), 'test_operation', self.user.id)
            
            mock_message.assert_called_once()
            call_args = mock_message.call_args[0]
            # Should use generic message
            self.assertIn('conflicts with existing data', call_args[1])
            self.assertNotIn('constraint violation', call_args[1])

    def test_secure_error_handler_permission_error(self):
        """Test that permission errors are handled securely"""
        request = self.factory.get('/')
        
        with patch('django.contrib.messages.error') as mock_message:
            _handle_secure_error(request, PermissionDenied('Access denied details'), 'test_operation', self.user.id)
            
            mock_message.assert_called_once()
            call_args = mock_message.call_args[0]
            # Should use generic message
            self.assertIn("don't have permission", call_args[1])
            self.assertNotIn('Access denied details', call_args[1])

    @patch('apps.customers.views.security_logger')
    def test_secure_error_handler_unexpected_error_logging(self, mock_logger):
        """Test that unexpected errors are logged for security monitoring"""
        request = self.factory.get('/')
        
        _handle_secure_error(request, Exception('Unexpected error'), 'test_operation', self.user.id)
        
        mock_logger.exception.assert_called_once()
        call_args = mock_logger.exception.call_args
        self.assertIn('Unexpected error during test_operation', call_args[0][0])
        self.assertEqual(call_args[1]['extra']['user_id'], self.user.id)


class SSRFProtectionEnhancementTests(TestCase):
    """🔒 Tests for A10 - Server-Side Request Forgery (SSRF) enhanced protection"""

    @patch('socket.getaddrinfo')
    def test_dns_resolution_validation(self, mock_getaddrinfo):
        """Test that DNS resolution is validated to prevent rebinding"""
        # Mock DNS resolution to return private IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.1.1', 80))
        ]
        
        with self.assertRaises(ValidationError) as cm:
            SecureInputValidator.validate_safe_url('http://malicious.example.com/path')
        
        self.assertIn('blocked IP range', str(cm.exception))
        mock_getaddrinfo.assert_called_once()

    @patch('socket.getaddrinfo')
    def test_dns_resolution_failure_handled(self, mock_getaddrinfo):
        """Test that DNS resolution failures are handled securely"""
        # Mock DNS resolution failure
        import socket
        mock_getaddrinfo.side_effect = socket.gaierror('Name resolution failed')
        
        with self.assertRaises(ValidationError) as cm:
            SecureInputValidator.validate_safe_url('http://nonexistent.example.com/')
        
        self.assertIn('Unable to verify URL destination', str(cm.exception))

    @patch('socket.getaddrinfo')
    def test_private_ip_prefix_patterns_blocked(self, mock_getaddrinfo):
        """Test that private IP prefixes in hostnames are blocked"""
        # Mock DNS resolution to succeed (so we test hostname pattern blocking, not DNS)
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 80))
        ]
        
        dangerous_hostnames = [
            'http://10.0.0.1.example.com/',
            'http://192.168.1.1.example.com/',
            'http://172.16.0.1.example.com/'
        ]
        
        for url in dangerous_hostnames:
            with self.assertRaises(ValidationError) as cm:
                SecureInputValidator.validate_safe_url(url)
            
            error_msg = str(cm.exception)
            # Check for either hostname blocking or IP resolution blocking
            self.assertTrue(
                'not allowed' in error_msg or 'blocked IP range' in error_msg,
                f"Expected blocking message for {url}, got: {error_msg}"
            )

    @patch('socket.getaddrinfo')
    def test_legitimate_urls_still_work(self, mock_getaddrinfo):
        """Test that legitimate URLs still pass validation"""
        # Mock DNS resolution to return public IP
        mock_getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 80))
        ]
        
        # Should not raise an exception
        try:
            result = SecureInputValidator.validate_safe_url('http://google.com/')
            self.assertEqual(result, 'http://google.com/')
        except ValidationError:
            self.fail("validate_safe_url rejected legitimate URL")