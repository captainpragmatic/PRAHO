"""
Security Test Suite - Enhanced Validation Framework
Tests for critical security vulnerabilities and Romanian compliance.
"""

import time
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.common.security_decorators import (
    _check_rate_limit,
    _normalize_response_time,
    monitor_performance,
)
from apps.common.validators import (
    MAX_EMAIL_LENGTH,
    BusinessLogicValidator,
    SecureErrorHandler,
    SecureInputValidator,
    log_security_event,
)
from apps.customers.models import Customer, CustomerTaxProfile
from apps.users.models import CustomerMembership
from apps.users.services import SecureCustomerUserService, SecureUserRegistrationService

User = get_user_model()


class TestSecureInputValidator(TestCase):
    """Test comprehensive input validation"""

    def setUp(self):
        cache.clear()

    def test_email_validation_prevents_xss(self):
        """Test XSS prevention in email validation"""
        malicious_emails = [
            '<script>alert("xss")</script>@example.com',
            'user@<script>alert("xss")</script>.com',
            'user@example.com<script>alert("xss")</script>',
            'javascript:alert("xss")@example.com'
        ]

        for email in malicious_emails:
            with self.assertRaises(ValidationError):
                SecureInputValidator.validate_email_secure(email)

    def test_email_validation_prevents_dos(self):
        """Test DoS prevention via long emails"""
        long_email = 'a' * (MAX_EMAIL_LENGTH + 100) + '@example.com'

        with self.assertRaises(ValidationError):
            SecureInputValidator.validate_email_secure(long_email)

    def test_email_validation_normalizes_input(self):
        """Test email normalization"""
        result = SecureInputValidator.validate_email_secure('  USER@EXAMPLE.COM  ')
        self.assertEqual(result, 'user@example.com')

    def test_name_validation_prevents_xss(self):
        """Test XSS prevention in name validation"""
        malicious_names = [
            '<script>alert("xss")</script>',
            'John<img src=x onerror=alert("xss")>',
            'javascript:alert("xss")',
            'onload=alert("xss")',
        ]

        for name in malicious_names:
            with self.assertRaises(ValidationError):
                SecureInputValidator.validate_name_secure(name)

    def test_name_validation_allows_romanian_characters(self):
        """Test Romanian character support"""
        romanian_names = [
            'Ștefan',
            'Mănescu',
            'Cătălina',
            'Ioană-Maria',
            "O'Brien",
            'Jean-Claude'
        ]

        for name in romanian_names:
            result = SecureInputValidator.validate_name_secure(name)
            self.assertEqual(result, name.strip())

    def test_vat_validation_romanian_format(self):
        """Test Romanian VAT number validation"""
        valid_vat_numbers = [
            'RO12345678',
            'RO123456789',
            'RO1234567890'
        ]

        invalid_vat_numbers = [
            '12345678',       # Missing RO prefix
            'RO1',           # Too short
            'RO12345678901', # Too long
            'DE12345678',    # Wrong country
            '<script>alert("xss")</script>',
            'RO; DROP TABLE customers;--'
        ]

        for vat in valid_vat_numbers:
            result = SecureInputValidator.validate_vat_number_romanian(vat)
            self.assertEqual(result, vat.upper())

        for vat in invalid_vat_numbers:
            with self.assertRaises(ValidationError):
                SecureInputValidator.validate_vat_number_romanian(vat)

    def test_cui_validation_romanian_format(self):
        """Test Romanian CUI validation"""
        valid_cuis = [
            '12345678',
            '123456789',
            '1234567890'
        ]

        invalid_cuis = [
            '1',              # Too short
            '12345678901',    # Too long
            'RO12345678',     # Has prefix (should be removed first)
            '<script>alert("xss")</script>',
            '12345678; DROP TABLE customers;--'
        ]

        for cui in valid_cuis:
            result = SecureInputValidator.validate_cui_romanian(cui)
            self.assertEqual(result, cui)

        for cui in invalid_cuis:
            with self.assertRaises(ValidationError):
                SecureInputValidator.validate_cui_romanian(cui)

    def test_company_name_validation(self):
        """Test company name validation"""
        valid_names = [
            'SC Test SRL',
            'ACME Corp & Co.',
            'Măceșul Roșu SA',
            'IT Solutions "Alpha"'
        ]

        invalid_names = [
            '',               # Empty
            'A',             # Too short
            '<script>alert("xss")</script>',
            'Company; DROP TABLE customers;--',
            'Test\nCompany'  # Newlines
        ]

        for name in valid_names:
            result = SecureInputValidator.validate_company_name(name)
            self.assertEqual(result, name.strip())

        for name in invalid_names:
            with self.assertRaises(ValidationError):
                SecureInputValidator.validate_company_name(name)

    def test_role_validation_prevents_injection(self):
        """Test role validation prevents privilege injection"""
        valid_roles = ['owner', 'admin', 'manager', 'viewer']
        invalid_roles = [
            'superuser',
            'staff',
            '<script>alert("xss")</script>',
            'owner; DROP TABLE users;--',
            '',
            None
        ]

        for role in valid_roles:
            result = SecureInputValidator.validate_customer_role(role)
            self.assertEqual(result, role.lower())

        for role in invalid_roles:
            with self.assertRaises(ValidationError):
                SecureInputValidator.validate_customer_role(role)

    def test_user_data_validation_prevents_privilege_escalation(self):
        """Test user data validation prevents privilege escalation"""
        # Valid user data
        valid_data = {
            'email': 'test@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'phone': '+40721234567',
            'accepts_marketing': True,
            'gdpr_consent_date': '2023-01-01'
        }

        result = SecureInputValidator.validate_user_data_dict(valid_data)
        self.assertEqual(result['email'], 'test@example.com')
        self.assertEqual(result['first_name'], 'John')

        # Invalid user data with privilege escalation attempt
        malicious_data = {
            'email': 'admin@example.com',
            'first_name': 'Admin',
            'last_name': 'User',
            'is_staff': True,          # Restricted field
            'is_superuser': True,      # Restricted field
            'user_permissions': ['all'] # Restricted field
        }

        with self.assertRaises(ValidationError):
            SecureInputValidator.validate_user_data_dict(malicious_data)

    def test_malicious_pattern_detection(self):
        """Test detection of malicious patterns"""
        malicious_inputs = [
            '<script>alert("xss")</script>',
            'javascript:alert("xss")',
            'onload=alert("xss")',
            'SELECT * FROM users',
            'DROP TABLE customers;--',
            '/* SQL comment */',
            'UNION SELECT password FROM users',
            'eval(malicious_code)',
            'exec(dangerous_command)'
        ]

        for malicious_input in malicious_inputs:
            with self.assertRaises(ValidationError):
                SecureInputValidator._check_malicious_patterns(malicious_input)


class TestBusinessLogicValidator(TestCase):
    """Test business logic validation and race condition prevention"""

    def setUp(self):
        cache.clear()
        # Create test customer for uniqueness checks
        self.existing_customer = Customer.objects.create(
            company_name='Existing Company SRL',
            customer_type='srl',
            status='active'
        )

        CustomerTaxProfile.objects.create(
            customer=self.existing_customer,
            vat_number='RO12345678',
            registration_number='12345678'
        )

    def test_company_uniqueness_check_prevents_duplicates(self):
        """Test company uniqueness validation"""
        duplicate_data = {
            'company_name': 'Existing Company SRL',  # Exact match
            'vat_number': 'RO12345678',              # Exact match
            'registration_number': '12345678'        # Exact match
        }

        # Should raise ValidationError for all fields
        with self.assertRaises(ValidationError):
            BusinessLogicValidator.check_company_uniqueness(duplicate_data)

        # Test case-insensitive matching
        case_variant_data = {
            'company_name': 'EXISTING COMPANY SRL',  # Case different
        }

        with self.assertRaises(ValidationError):
            BusinessLogicValidator.check_company_uniqueness(case_variant_data)

    def test_company_uniqueness_allows_unique_data(self):
        """Test that unique companies are allowed"""
        unique_data = {
            'company_name': 'New Unique Company SRL',
            'vat_number': 'RO87654321',
            'registration_number': '87654321'
        }

        # Should not raise ValidationError
        try:
            BusinessLogicValidator.check_company_uniqueness(unique_data)
        except ValidationError:
            self.fail("Unique company data should be allowed")

    @patch('apps.common.validators.cache')
    def test_company_check_rate_limiting(self, mock_cache):
        """Test rate limiting for company existence checks"""
        mock_cache.get.return_value = 35  # Over the limit (30)

        with self.assertRaises(ValidationError):
            BusinessLogicValidator.check_company_uniqueness({
                'company_name': 'Test Company'
            }, '192.168.1.1')

    def test_user_permissions_validation(self):
        """Test user permission validation"""
        # Create test user and customer
        user = User.objects.create_user(
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )

        customer = Customer.objects.create(
            company_name='Test Company',
            customer_type='srl',
            status='active'
        )

        # No membership - should fail
        with self.assertRaises(ValidationError):
            BusinessLogicValidator.validate_user_permissions(user, customer, 'owner')

        # Create membership with owner role
        CustomerMembership.objects.create(
            user=user,
            customer=customer,
            role='owner',
            is_primary=True
        )

        # Should pass
        try:
            BusinessLogicValidator.validate_user_permissions(user, customer, 'owner')
        except ValidationError:
            self.fail("Valid permissions should not raise ValidationError")

        # Test inactive user
        user.is_active = False
        user.save()

        with self.assertRaises(ValidationError):
            BusinessLogicValidator.validate_user_permissions(user, customer, 'owner')


class TestSecurityDecorators(TestCase):
    """Test security decorators functionality"""

    def setUp(self):
        cache.clear()

    def test_rate_limiting_functionality(self):
        """Test rate limiting decorator"""
        with patch('apps.common.security_decorators.cache') as mock_cache:
            # Setup mock cache behavior - track calls
            cache_data = {}

            def mock_get(key, default=0):
                return cache_data.get(key, default)

            def mock_set(key, value, timeout=None):
                cache_data[key] = value
                return True

            mock_cache.get.side_effect = mock_get
            mock_cache.set.side_effect = mock_set

            # Test normal operation (first 5 requests should pass)
            for i in range(5):
                try:
                    _check_rate_limit('test_key', 5, '192.168.1.1', None)
                except ValidationError:
                    self.fail(f"Request {i+1} should not be rate limited")

            # 6th request should fail
            with self.assertRaises(ValidationError):
                _check_rate_limit('test_key', 5, '192.168.1.1', None)

    def test_timing_attack_prevention(self):
        """Test timing normalization"""
        start_time = time.time()

        # Fast operation
        time.sleep(0.01)  # 10ms

        _normalize_response_time(start_time, min_time=0.1)  # 100ms minimum

        total_time = time.time() - start_time
        self.assertGreaterEqual(total_time, 0.1)  # Should be at least 100ms

    def test_secure_error_handling(self):
        """Test secure error message generation"""
        test_error = Exception("Sensitive database error with details")

        safe_message = SecureErrorHandler.safe_error_response(test_error, "registration")

        # Should not contain sensitive information
        self.assertNotIn("database", safe_message.lower())
        self.assertNotIn("sensitive", safe_message.lower())

        # Should contain error ID for support
        self.assertIn("ID:", safe_message)


class TestSecureUserRegistrationService(TestCase):
    """Test secure user registration service"""

    def setUp(self):
        cache.clear()

    @patch('apps.common.security_decorators.log_security_event')
    def test_secure_registration_with_valid_data(self, mock_log):
        """Test secure registration with valid Romanian business data"""
        user_data = {
            'email': 'owner@newcompany.ro',
            'first_name': 'Ion',
            'last_name': 'Popescu',
            'phone': '+40721234567',
            'accepts_marketing': True,
            'gdpr_consent_date': '2023-01-01'
        }

        customer_data = {
            'company_name': 'New Company SRL',
            'customer_type': 'srl',
            'vat_number': 'RO87654321',
            'registration_number': '87654321',
            'billing_address': 'Strada Test 123',
            'billing_city': 'București',
            'billing_postal_code': '010101'
        }

        result = SecureUserRegistrationService.register_new_customer_owner(
            user_data=user_data,
            customer_data=customer_data,
            request_ip='192.168.1.1'
        )

        self.assertTrue(result.is_ok())
        user, customer = result.value

        # Verify user creation
        self.assertEqual(user.email, 'owner@newcompany.ro')
        self.assertEqual(user.first_name, 'Ion')
        self.assertEqual(user.phone, '+40721234567')

        # Verify customer creation
        self.assertEqual(customer.company_name, 'New Company SRL')
        self.assertEqual(customer.customer_type, 'srl')

        # Verify tax profile
        tax_profile = CustomerTaxProfile.objects.get(customer=customer)
        self.assertEqual(tax_profile.vat_number, 'RO87654321')
        self.assertEqual(tax_profile.registration_number, '87654321')

        # Verify membership
        membership = CustomerMembership.objects.get(user=user, customer=customer)
        self.assertEqual(membership.role, 'owner')
        self.assertTrue(membership.is_primary)

        # Verify security logging
        self.assertTrue(mock_log.called)

    def test_registration_prevents_xss_attacks(self):
        """Test XSS prevention in registration"""
        malicious_user_data = {
            'email': 'test@example.com',
            'first_name': '<script>alert("xss")</script>',
            'last_name': 'User',
            'phone': '+40721234567'
        }

        customer_data = {
            'company_name': 'Test Company',
            'customer_type': 'srl'
        }

        result = SecureUserRegistrationService.register_new_customer_owner(
            user_data=malicious_user_data,
            customer_data=customer_data,
            request_ip='192.168.1.1'
        )

        self.assertTrue(result.is_err())
        self.assertIn("registration could not be completed", result.error.lower())

    def test_registration_prevents_privilege_escalation(self):
        """Test privilege escalation prevention"""
        malicious_user_data = {
            'email': 'admin@example.com',
            'first_name': 'Admin',
            'last_name': 'User',
            'is_staff': True,        # Should be blocked
            'is_superuser': True,    # Should be blocked
            'staff_role': 'admin'    # Should be blocked
        }

        customer_data = {
            'company_name': 'Malicious Company',
            'customer_type': 'srl'
        }

        result = SecureUserRegistrationService.register_new_customer_owner(
            user_data=malicious_user_data,
            customer_data=customer_data,
            request_ip='192.168.1.1'
        )

        self.assertTrue(result.is_err())
        self.assertIn("registration could not be completed", result.error.lower())

    @patch('apps.common.security_decorators.cache')
    def test_registration_rate_limiting(self, mock_cache):
        """Test registration rate limiting"""
        mock_cache.get.return_value = 10  # Over the limit (5)

        user_data = {
            'email': 'test@example.com',
            'first_name': 'Test',
            'last_name': 'User'
        }

        customer_data = {
            'company_name': 'Test Company',
            'customer_type': 'srl'
        }

        result = SecureUserRegistrationService.register_new_customer_owner(
            user_data=user_data,
            customer_data=customer_data,
            request_ip='192.168.1.1'
        )

        self.assertTrue(result.is_err())


class TestSecureCustomerUserService(TestCase):
    """Test secure customer user service"""

    def setUp(self):
        cache.clear()

        # Create test customer and owner
        self.owner = User.objects.create_user(
            email='owner@company.ro',
            first_name='Owner',
            last_name='User'
        )

        self.customer = Customer.objects.create(
            company_name='Test Company SRL',
            customer_type='srl',
            status='active'
        )

        CustomerMembership.objects.create(
            user=self.owner,
            customer=self.customer,
            role='owner',
            is_primary=True
        )

    def test_secure_user_invitation_with_rate_limiting(self):
        """Test secure user invitation with rate limiting"""
        # First invitation should succeed
        result = SecureCustomerUserService.invite_user_to_customer(
            inviter=self.owner,
            invitee_email='newuser@example.com',
            customer=self.customer,
            role='viewer',
            request_ip='192.168.1.1',
            user_id=self.owner.id
        )

        self.assertTrue(result.is_ok())

        # Verify membership created
        membership = CustomerMembership.objects.get(
            customer=self.customer,
            user__email='newuser@example.com'
        )
        self.assertEqual(membership.role, 'viewer')

    def test_invitation_prevents_role_injection(self):
        """Test role injection prevention in invitations"""
        result = SecureCustomerUserService.invite_user_to_customer(
            inviter=self.owner,
            invitee_email='hacker@example.com',
            customer=self.customer,
            role='superuser',  # Invalid role
            request_ip='192.168.1.1',
            user_id=self.owner.id
        )

        self.assertTrue(result.is_err())

    def test_invitation_requires_owner_permissions(self):
        """Test that invitations require owner permissions"""
        # Create non-owner user
        viewer = User.objects.create_user(
            email='viewer@company.ro',
            first_name='Viewer',
            last_name='User'
        )

        CustomerMembership.objects.create(
            user=viewer,
            customer=self.customer,
            role='viewer',
            is_primary=False
        )

        # Viewer should not be able to invite
        result = SecureCustomerUserService.invite_user_to_customer(
            inviter=viewer,
            invitee_email='newuser@example.com',
            customer=self.customer,
            role='viewer',
            request_ip='192.168.1.1',
            user_id=viewer.id
        )

        self.assertTrue(result.is_err())


@pytest.mark.django_db
class TestPerformanceAndMonitoring:
    """Test performance monitoring and security metrics"""

    def test_method_performance_monitoring(self):
        """Test that slow methods are detected and logged"""
        with patch('apps.common.security_decorators.logger') as mock_logger:

            @monitor_performance(max_duration_seconds=0.1, alert_threshold=0.05)
            def slow_method():
                time.sleep(0.07)  # Slower than alert threshold
                return "completed"

            result = slow_method()

            assert result == "completed"
            # Should have logged slow operation warning
            mock_logger.warning.assert_called()

    def test_security_event_logging(self):
        """Test security event logging functionality"""
        with patch('apps.common.validators.logger') as mock_logger:
            log_security_event('test_event', {
                'user_id': 123,
                'action': 'registration_attempt'
            }, '192.168.1.1')

            # Verify logger was called
            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args

            # Check that the log message contains expected information
            log_message = call_args[0][0]
            assert 'test_event' in log_message
            assert '192.168.1.1' in log_message
