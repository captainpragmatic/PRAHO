"""
Comprehensive tests for apps/users/services.py targeting 85%+ coverage
Tests specifically designed to cover missing lines based on coverage report.

Target Coverage Increase: 33.90% → 85%+
Key Areas: SecureUserRegistrationService, SecureCustomerUserService, SessionSecurityService

Author: Claude Code Assistant  
Date: 2025-08-27
"""

import time
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.test import RequestFactory, TestCase
from django.utils import timezone

from apps.common.request_ip import get_safe_client_ip
from apps.common.constants import (
    MAX_CUSTOMER_LOOKUPS_PER_HOUR,
    MAX_JOIN_NOTIFICATIONS_PER_HOUR,
    MIN_RESPONSE_TIME_SECONDS,
)
from apps.common.types import Err, Ok
from apps.common.request_ip import get_safe_client_ip
from apps.customers.models import Customer, CustomerTaxProfile
from apps.users.models import CustomerMembership
from apps.users.services import (
    SecureCustomerUserService,
    SecureUserRegistrationService,
    SessionSecurityService,
    UserCreationRequest,
    UserInvitationRequest,
    UserLinkingRequest,
)

User = get_user_model()


class SecureUserRegistrationServiceTests(TestCase):
    """Comprehensive tests for SecureUserRegistrationService"""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        
        # Clear cache before each test
        cache.clear()

        # Sample valid data for testing
        self.valid_user_data = {
            'email': 'newuser@example.com',
            'first_name': 'New',
            'last_name': 'User',
            'phone': '+40721123456',
            'accepts_marketing': False,
            'gdpr_consent_date': timezone.now()
        }
        
        self.valid_customer_data = {
            'company_name': 'Test Company SRL',
            'customer_type': 'company',
            'vat_number': 'RO12345678',
            'registration_number': 'J40/123/2023',
            'billing_address': 'Strada Test 123',
            'billing_city': 'București',
            'billing_postal_code': '010001'
        }

    def test_customer_types_constant(self) -> None:
        """Test CUSTOMER_TYPES constant exists and has expected values"""
        types = SecureUserRegistrationService.CUSTOMER_TYPES
        self.assertIsInstance(types, list)
        self.assertTrue(len(types) > 0)
        
        # Check expected types exist
        type_codes = [t[0] for t in types]
        self.assertIn('individual', type_codes)
        self.assertIn('company', type_codes)
        self.assertIn('pfa', type_codes)
        self.assertIn('ngo', type_codes)

    @patch('apps.users.services.log_security_event')
    @patch('apps.users.services.CustomerTaxProfile.objects.create')
    @patch('apps.users.services.CustomerBillingProfile.objects.create')
    @patch('apps.users.services.CustomerAddress.objects.create')
    @patch('apps.users.services.CustomerMembership.objects.create')
    def test_register_new_customer_owner_success(
        self, 
        mock_membership_create: Mock,
        mock_address_create: Mock,
        mock_billing_create: Mock,
        mock_tax_create: Mock,
        mock_log_event: Mock
    ) -> None:
        """Test successful new customer owner registration"""
        
        result = SecureUserRegistrationService.register_new_customer_owner(
            self.valid_user_data,
            self.valid_customer_data,
            request_ip='127.0.0.1',
            user_agent='Test Agent'
        )
        
        # Should return success result
        self.assertIsInstance(result, Ok)
        user, customer = result.unwrap()
        
        # Check user creation
        self.assertIsInstance(user, User)
        self.assertEqual(user.email, 'newuser@example.com')
        self.assertEqual(user.first_name, 'New')
        self.assertEqual(user.last_name, 'User')
        
        # Check customer creation
        self.assertIsInstance(customer, Customer)
        self.assertEqual(customer.company_name, 'Test Company SRL')
        self.assertEqual(customer.customer_type, 'company')
        
        # Check all related objects were created
        mock_tax_create.assert_called_once()
        mock_billing_create.assert_called_once()  
        mock_address_create.assert_called_once()
        mock_membership_create.assert_called_once()
        
        # Check security logging
        self.assertTrue(mock_log_event.called)
        
        # Verify tax profile creation was logged
        tax_log_calls = [call for call in mock_log_event.call_args_list 
                        if call[0][0] == 'tax_profile_created']
        self.assertTrue(len(tax_log_calls) > 0)

    @patch('apps.users.services.log_security_event')
    def test_register_new_customer_owner_without_vat(self, mock_log_event: Mock) -> None:
        """Test registration without VAT number"""
        customer_data = self.valid_customer_data.copy()
        customer_data['vat_number'] = ''
        customer_data['registration_number'] = ''
        
        result = SecureUserRegistrationService.register_new_customer_owner(
            self.valid_user_data,
            customer_data,
            request_ip='127.0.0.1'
        )
        
        # Should still succeed
        self.assertIsInstance(result, Ok)
        user, customer = result.unwrap()
        
        # Tax profile should not be created (no VAT/CUI)
        tax_profiles = CustomerTaxProfile.objects.filter(customer=customer)
        self.assertEqual(tax_profiles.count(), 0)

    @patch('apps.users.services.User.objects.create_user')
    @patch('apps.users.services.log_security_event')
    def test_register_new_customer_owner_user_creation_exception(
        self, mock_log_event: Mock, mock_create_user: Mock
    ) -> None:
        """Test registration when user creation fails"""
        mock_create_user.side_effect = IntegrityError("Email already exists")
        
        result = SecureUserRegistrationService.register_new_customer_owner(
            self.valid_user_data,
            self.valid_customer_data,
            request_ip='127.0.0.1'
        )
        
        # Should return error result
        self.assertIsInstance(result, Err)
        error_msg = result.unwrap_err()
        self.assertIn("Registration could not be completed", error_msg)
        self.assertIn("ID:", error_msg)  # Should include error ID
        
        # Should log system error
        error_log_calls = [call for call in mock_log_event.call_args_list 
                          if call[0][0] == 'registration_system_error']
        self.assertTrue(len(error_log_calls) > 0)

    @patch('apps.users.services.SecureUserRegistrationService._find_customer_by_identifier_secure')
    @patch('apps.users.services.SecureUserRegistrationService._notify_owners_of_join_request_secure')
    @patch('apps.users.services.log_security_event')
    def test_request_join_existing_customer_success(
        self, mock_log_event: Mock, mock_notify: Mock, mock_find_customer: Mock
    ) -> None:
        """Test successful join request to existing customer"""
        
        # Create existing customer
        existing_customer = Customer.objects.create(
            company_name='Existing Company',
            customer_type='company'
        )
        mock_find_customer.return_value = existing_customer
        
        result = SecureUserRegistrationService.request_join_existing_customer(
            self.valid_user_data,
            'Existing Company',
            'name',
            request_ip='127.0.0.1'
        )
        
        # Should return success result
        self.assertIsInstance(result, Ok)
        response_data = result.unwrap()
        
        self.assertEqual(response_data['status'], 'pending_approval')
        self.assertEqual(response_data['customer'], existing_customer)
        self.assertIsInstance(response_data['user'], User)
        self.assertIsInstance(response_data['membership'], CustomerMembership)
        
        # User should be inactive (pending approval)
        user = response_data['user']
        self.assertFalse(user.is_active)
        
        # Should notify owners
        mock_notify.assert_called_once_with(existing_customer, user, '127.0.0.1')
        
        # Should log join request
        join_log_calls = [call for call in mock_log_event.call_args_list 
                         if call[0][0] == 'join_request_created']
        self.assertTrue(len(join_log_calls) > 0)

    @patch('apps.users.services.SecureUserRegistrationService._find_customer_by_identifier_secure')
    @patch('apps.users.services.log_security_event')  
    def test_request_join_existing_customer_not_found(
        self, mock_log_event: Mock, mock_find_customer: Mock
    ) -> None:
        """Test join request when customer not found"""
        mock_find_customer.return_value = None
        
        result = SecureUserRegistrationService.request_join_existing_customer(
            self.valid_user_data,
            'Nonexistent Company',
            'name',
            request_ip='127.0.0.1'
        )
        
        # Should return error result
        self.assertIsInstance(result, Err)
        error_msg = result.unwrap_err()
        self.assertIn("The provided information is invalid", error_msg)
        
        # Should log invalid company attempt
        invalid_log_calls = [call for call in mock_log_event.call_args_list 
                           if call[0][0] == 'join_request_invalid_company']
        self.assertTrue(len(invalid_log_calls) > 0)

    @patch('apps.users.services.User.objects.create_user')
    def test_request_join_existing_customer_exception(self, mock_create_user: Mock) -> None:
        """Test join request when user creation fails"""
        # Create existing customer first
        existing_customer = Customer.objects.create(
            company_name='Existing Company',
            customer_type='company'
        )
        
        with patch('apps.users.services.SecureUserRegistrationService._find_customer_by_identifier_secure') as mock_find:
            mock_find.return_value = existing_customer
            mock_create_user.side_effect = ValidationError("Invalid email")
            
            result = SecureUserRegistrationService.request_join_existing_customer(
                self.valid_user_data,
                'Existing Company',
                'name',
                request_ip='127.0.0.1'
            )
            
            # Should return error result
            self.assertIsInstance(result, Err)

    def test_find_customer_by_identifier_secure_by_name(self) -> None:
        """Test secure customer lookup by name"""
        customer = Customer.objects.create(
            company_name='Test Company Ltd',
            customer_type='company'
        )
        
        result = SecureUserRegistrationService._find_customer_by_identifier_secure(
            'Test Company Ltd',
            'name',
            '127.0.0.1'
        )
        
        self.assertEqual(result, customer)

    def test_find_customer_by_identifier_secure_by_vat(self) -> None:
        """Test secure customer lookup by VAT number"""
        customer = Customer.objects.create(
            company_name='VAT Company',
            customer_type='company'
        )
        CustomerTaxProfile.objects.create(
            customer=customer,
            vat_number='RO12345678',
            is_vat_payer=True
        )
        
        with patch('apps.users.services.SecureInputValidator.validate_vat_number_romanian') as mock_validate:
            mock_validate.return_value = 'RO12345678'
            
            result = SecureUserRegistrationService._find_customer_by_identifier_secure(
                'RO12345678',
                'vat_number',
                '127.0.0.1'
            )
            
            self.assertEqual(result, customer)

    def test_find_customer_by_identifier_secure_by_cui(self) -> None:
        """Test secure customer lookup by CUI number"""
        customer = Customer.objects.create(
            company_name='CUI Company', 
            customer_type='company'
        )
        CustomerTaxProfile.objects.create(
            customer=customer,
            registration_number='J40/123/2023'
        )
        
        with patch('apps.users.services.SecureInputValidator.validate_cui_romanian') as mock_validate:
            mock_validate.return_value = 'J40/123/2023'
            
            result = SecureUserRegistrationService._find_customer_by_identifier_secure(
                'J40/123/2023',
                'registration_number',
                '127.0.0.1'
            )
            
            self.assertEqual(result, customer)

    def test_find_customer_by_identifier_secure_invalid_identifier(self) -> None:
        """Test secure customer lookup with invalid identifier"""
        result = SecureUserRegistrationService._find_customer_by_identifier_secure(
            '',
            'name',
            '127.0.0.1'
        )
        
        self.assertIsNone(result)

    def test_find_customer_by_identifier_secure_too_long(self) -> None:
        """Test secure customer lookup with too long identifier"""
        from apps.common.constants import IDENTIFIER_MAX_LENGTH
        
        long_identifier = 'x' * (IDENTIFIER_MAX_LENGTH + 1)
        result = SecureUserRegistrationService._find_customer_by_identifier_secure(
            long_identifier,
            'name',
            '127.0.0.1'
        )
        
        self.assertIsNone(result)

    def test_find_customer_by_identifier_secure_rate_limit(self) -> None:
        """Test secure customer lookup rate limiting"""
        ip = '192.168.1.1'
        
        # Set cache to max lookups
        cache.set(f'customer_lookup:{ip}', MAX_CUSTOMER_LOOKUPS_PER_HOUR, timeout=3600)
        
        result = SecureUserRegistrationService._find_customer_by_identifier_secure(
            'Test Company',
            'name',
            ip
        )
        
        # Should return None due to rate limit
        self.assertIsNone(result)

    def test_find_customer_by_identifier_secure_vat_validation_error(self) -> None:
        """Test secure customer lookup with VAT validation error"""
        with patch('apps.users.services.SecureInputValidator.validate_vat_number_romanian') as mock_validate:
            mock_validate.side_effect = ValidationError("Invalid VAT")
            
            result = SecureUserRegistrationService._find_customer_by_identifier_secure(
                'INVALID_VAT',
                'vat_number',
                '127.0.0.1'
            )
            
            self.assertIsNone(result)

    def test_find_customer_by_identifier_secure_cui_validation_error(self) -> None:
        """Test secure customer lookup with CUI validation error"""
        with patch('apps.users.services.SecureInputValidator.validate_cui_romanian') as mock_validate:
            mock_validate.side_effect = ValidationError("Invalid CUI")
            
            result = SecureUserRegistrationService._find_customer_by_identifier_secure(
                'INVALID_CUI',
                'registration_number',
                '127.0.0.1'
            )
            
            self.assertIsNone(result)

    @patch('time.sleep')
    def test_find_customer_by_identifier_secure_timing_attack_prevention(self, mock_sleep: Mock) -> None:
        """Test timing attack prevention in customer lookup"""
        start_time = time.time()
        
        # Patch time.time to control elapsed time - return multiple values for all time.time() calls
        with patch('time.time') as mock_time:
            # Use a lambda to return proper values for all time.time() calls
            call_count = 0
            def mock_time_func():
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return start_time  # start_time
                else:
                    return start_time + MIN_RESPONSE_TIME_SECONDS - 0.1  # make it sleep
            
            mock_time.side_effect = mock_time_func
            
            SecureUserRegistrationService._find_customer_by_identifier_secure(
                'Test Company',
                'name',
                '127.0.0.1'
            )
            
            # Should sleep to ensure minimum response time
            mock_sleep.assert_called_once()

    @patch('apps.users.services.send_mail')
    @patch('apps.users.services.render_to_string', side_effect=['text content', 'html content'])
    @patch('apps.users.services.log_security_event')
    def test_send_welcome_email_secure_success(self, mock_log_event: Mock, mock_render: Mock, mock_send_mail: Mock) -> None:
        """Test successful welcome email sending"""
        user = User.objects.create_user('test@example.com', 'pass123')
        customer = Customer.objects.create(company_name='Test Co', customer_type='company')
        
        result = SecureUserRegistrationService._send_welcome_email_secure(
            user, customer, '127.0.0.1'
        )
        
        self.assertTrue(result)
        mock_send_mail.assert_called_once()
        
        # Should log email sent
        email_log_calls = [call for call in mock_log_event.call_args_list 
                          if call[0][0] == 'welcome_email_sent']
        self.assertTrue(len(email_log_calls) > 0)

    @patch('apps.users.services.send_mail')
    @patch('apps.users.services.render_to_string', side_effect=['text content', 'html content'])
    @patch('apps.users.services.log_security_event')
    def test_send_welcome_email_secure_exception(self, mock_log_event: Mock, mock_render: Mock, mock_send_mail: Mock) -> None:
        """Test welcome email sending with exception"""
        mock_send_mail.side_effect = Exception("SMTP error")
        
        user = User.objects.create_user('test@example.com', 'pass123')
        customer = Customer.objects.create(company_name='Test Co', customer_type='company')
        
        result = SecureUserRegistrationService._send_welcome_email_secure(
            user, customer, '127.0.0.1'
        )
        
        self.assertFalse(result)
        
        # Should log email failure
        failure_log_calls = [call for call in mock_log_event.call_args_list 
                            if call[0][0] == 'welcome_email_failed']
        self.assertTrue(len(failure_log_calls) > 0)

    @patch('apps.users.services.send_mail')
    @patch('apps.users.services.log_security_event')
    def test_notify_owners_of_join_request_secure_success(self, mock_log_event: Mock, mock_send_mail: Mock) -> None:
        """Test successful owner notification"""
        customer = Customer.objects.create(company_name='Test Co', customer_type='company')
        owner = User.objects.create_user('owner@example.com', 'pass123')
        requesting_user = User.objects.create_user('requester@example.com', 'pass123')
        
        # Create owner membership
        CustomerMembership.objects.create(user=owner, customer=customer, role='owner')
        
        SecureUserRegistrationService._notify_owners_of_join_request_secure(
            customer, requesting_user, '127.0.0.1'
        )
        
        # Should send email to owner
        mock_send_mail.assert_called_once()
        
        # Should log notification
        notification_log_calls = [call for call in mock_log_event.call_args_list 
                                 if call[0][0] == 'join_request_notifications_sent']
        self.assertTrue(len(notification_log_calls) > 0)

    def test_notify_owners_of_join_request_secure_rate_limit(self) -> None:
        """Test owner notification rate limiting"""
        customer = Customer.objects.create(company_name='Test Co', customer_type='company')
        requesting_user = User.objects.create_user('requester@example.com', 'pass123')
        
        # Set cache to max notifications
        cache.set(f'join_notifications:{customer.id}', MAX_JOIN_NOTIFICATIONS_PER_HOUR, timeout=3600)
        
        with patch('apps.users.services.send_mail') as mock_send_mail:
            SecureUserRegistrationService._notify_owners_of_join_request_secure(
                customer, requesting_user, '127.0.0.1'
            )
            
            # Should not send email due to rate limit
            mock_send_mail.assert_not_called()

    @patch('apps.users.services.send_mail')
    def test_notify_owners_of_join_request_secure_exception(self, mock_send_mail: Mock) -> None:
        """Test owner notification with exception"""
        mock_send_mail.side_effect = Exception("SMTP error")
        
        customer = Customer.objects.create(company_name='Test Co', customer_type='company')
        owner = User.objects.create_user('owner@example.com', 'pass123')
        requesting_user = User.objects.create_user('requester@example.com', 'pass123')
        
        # Create owner membership
        CustomerMembership.objects.create(user=owner, customer=customer, role='owner')
        
        # Should not raise exception
        SecureUserRegistrationService._notify_owners_of_join_request_secure(
            customer, requesting_user, '127.0.0.1'
        )


class SecureCustomerUserServiceTests(TestCase):
    """Comprehensive tests for SecureCustomerUserService"""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            company_name='Test Company',
            customer_type='company'
        )
        self.creator_user = User.objects.create_user('creator@example.com', 'pass123')
        
        # Create membership for creator user so they have permissions
        CustomerMembership.objects.create(
            user=self.creator_user,
            customer=self.customer,
            role='owner',
            is_primary=True
        )

    def test_create_user_for_customer_success(self) -> None:
        """Test successful user creation for customer"""
        # Set customer primary email for test
        self.customer.primary_email = 'customer@example.com'
        self.customer.save()
        
        request = UserCreationRequest(
            customer=self.customer,
            first_name='New',
            last_name='User',
            send_welcome=False,
            created_by=self.creator_user,
            request_ip='127.0.0.1'
        )
        
        result = SecureCustomerUserService.create_user_for_customer(request)
        
        # Should return success result
        self.assertIsInstance(result, Ok)
        user, email_sent = result.unwrap()
        
        self.assertIsInstance(user, User)
        self.assertEqual(user.email, 'customer@example.com')
        self.assertEqual(user.first_name, 'New')
        self.assertEqual(user.last_name, 'User')
        self.assertFalse(email_sent)  # send_welcome=False
        
        # Should create membership
        membership = CustomerMembership.objects.get(user=user, customer=self.customer)
        self.assertEqual(membership.role, 'owner')
        self.assertTrue(membership.is_primary)

    def test_create_user_for_customer_no_email(self) -> None:
        """Test user creation when customer has no email"""
        # Create customer without primary email
        customer_no_email = Customer.objects.create(
            company_name='No Email Company',
            customer_type='company'
        )
        # Ensure primary_email is not set
        customer_no_email.primary_email = ''
        customer_no_email.save()
        
        request = UserCreationRequest(
            customer=customer_no_email,
            created_by=self.creator_user
        )
        
        result = SecureCustomerUserService.create_user_for_customer(request)
        
        # Should return error result
        self.assertIsInstance(result, Err)
        error_msg = result.unwrap_err()
        self.assertIn("Customer does not have a valid email address", error_msg)

    def test_create_user_for_customer_existing_user(self) -> None:
        """Test user creation when user already exists"""
        # Create existing user
        User.objects.create_user('existing@example.com', 'pass123')
        
        self.customer.primary_email = 'existing@example.com'
        self.customer.save()
        
        request = UserCreationRequest(
            customer=self.customer,
            created_by=self.creator_user
        )
        
        result = SecureCustomerUserService.create_user_for_customer(request)
        
        # Should return error result
        self.assertIsInstance(result, Err)
        error_msg = result.unwrap_err()
        self.assertIn("User account already exists for this email", error_msg)

    def test_create_user_for_customer_name_extraction(self) -> None:
        """Test name extraction from customer name when not provided"""
        self.customer.company_name = 'John Doe Company'  # Use company_name instead of name
        self.customer.primary_email = 'john@example.com' 
        self.customer.save()
        
        request = UserCreationRequest(
            customer=self.customer,
            # No first_name/last_name provided
            created_by=self.creator_user
        )
        
        result = SecureCustomerUserService.create_user_for_customer(request)
        
        # Should extract names from customer name
        self.assertIsInstance(result, Ok)
        user, _ = result.unwrap()
        self.assertEqual(user.first_name, 'John')
        self.assertEqual(user.last_name, 'Doe Company')

    @patch('apps.users.services.SecureCustomerUserService._send_welcome_email_secure')
    def test_create_user_for_customer_with_welcome_email(self, mock_send_email: Mock) -> None:
        """Test user creation with welcome email"""
        mock_send_email.return_value = True
        
        self.customer.primary_email = 'welcome@example.com'
        self.customer.save()
        
        request = UserCreationRequest(
            customer=self.customer,
            send_welcome=True,
            created_by=self.creator_user
        )
        
        result = SecureCustomerUserService.create_user_for_customer(request)
        
        # Should send welcome email
        self.assertIsInstance(result, Ok)
        user, email_sent = result.unwrap()
        self.assertTrue(email_sent)
        
        mock_send_email.assert_called_once_with(user, self.customer, None)

    def test_link_existing_user_success(self) -> None:
        """Test successful linking of existing user to customer"""
        existing_user = User.objects.create_user('existing@example.com', 'pass123')
        
        request = UserLinkingRequest(
            user=existing_user,
            customer=self.customer,
            role='manager',  # Use valid role from ALLOWED_CUSTOMER_ROLES
            is_primary=False,
            created_by=self.creator_user
        )
        
        result = SecureCustomerUserService.link_existing_user(request)
        
        # Should return success result
        self.assertIsInstance(result, Ok)
        membership = result.unwrap()
        
        self.assertIsInstance(membership, CustomerMembership)
        self.assertEqual(membership.user, existing_user)
        self.assertEqual(membership.customer, self.customer)
        self.assertEqual(membership.role, 'manager')  # Updated expected role
        self.assertFalse(membership.is_primary)

    def test_link_existing_user_already_linked(self) -> None:
        """Test linking user that is already associated"""
        existing_user = User.objects.create_user('existing@example.com', 'pass123')
        
        # Create existing membership
        CustomerMembership.objects.create(
            user=existing_user,
            customer=self.customer,
            role='viewer'
        )
        
        request = UserLinkingRequest(
            user=existing_user,
            customer=self.customer,
            role='manager'  # Use valid role from ALLOWED_CUSTOMER_ROLES
        )
        
        result = SecureCustomerUserService.link_existing_user(request)
        
        # Should return error result
        self.assertIsInstance(result, Err)
        error_msg = result.unwrap_err()
        self.assertIn("User is already associated with this organization", error_msg)

    def test_invite_user_to_customer_existing_user(self) -> None:
        """Test inviting existing user to customer"""
        existing_user = User.objects.create_user('existing@example.com', 'pass123')
        inviter = User.objects.create_user('inviter@example.com', 'pass123')
        
        request = UserInvitationRequest(
            inviter=inviter,
            invitee_email='existing@example.com',
            customer=self.customer,
            role='admin',  # Use valid role from ALLOWED_CUSTOMER_ROLES
            request_ip='127.0.0.1'
        )
        
        with patch('apps.users.services.SecureCustomerUserService._send_invitation_email_secure') as mock_send:
            result = SecureCustomerUserService.invite_user_to_customer(request)
            
            # Should return success result
            self.assertIsInstance(result, Ok)
            membership = result.unwrap()
            
            self.assertEqual(membership.user, existing_user)
            self.assertEqual(membership.role, 'admin')  # Updated to match valid role
            self.assertFalse(membership.is_primary)
            
            mock_send.assert_called_once()

    def test_invite_user_to_customer_new_user(self) -> None:
        """Test inviting new user (creates inactive user)"""
        inviter = User.objects.create_user('inviter@example.com', 'pass123')
        
        request = UserInvitationRequest(
            inviter=inviter,
            invitee_email='newuser@example.com',
            customer=self.customer,
            role='viewer',
            request_ip='127.0.0.1'
        )
        
        with patch('apps.users.services.SecureCustomerUserService._send_invitation_email_secure') as mock_send:
            result = SecureCustomerUserService.invite_user_to_customer(request)
            
            # Should return success result
            self.assertIsInstance(result, Ok)
            membership = result.unwrap()
            
            # Should create new inactive user
            new_user = User.objects.get(email='newuser@example.com')
            self.assertFalse(new_user.is_active)  # Inactive until accept
            self.assertEqual(membership.user, new_user)
            
            mock_send.assert_called_once()

    def test_invite_user_to_customer_existing_membership(self) -> None:
        """Test inviting user that already has membership"""
        existing_user = User.objects.create_user('existing@example.com', 'pass123')
        inviter = User.objects.create_user('inviter@example.com', 'pass123')
        
        # Create existing membership
        CustomerMembership.objects.create(
            user=existing_user,
            customer=self.customer,
            role='viewer'
        )
        
        request = UserInvitationRequest(
            inviter=inviter,
            invitee_email='existing@example.com',
            customer=self.customer,
            role='admin'  # Use valid role from ALLOWED_CUSTOMER_ROLES
        )
        
        result = SecureCustomerUserService.invite_user_to_customer(request)
        
        # Should return error result
        self.assertIsInstance(result, Err)
        error_msg = result.unwrap_err()
        self.assertIn("User already has access to this organization", error_msg)

    # Test legacy wrapper methods
    def test_create_user_for_customer_legacy(self) -> None:
        """Test legacy wrapper method"""
        self.customer.primary_email = 'legacy@example.com'
        self.customer.save()
        
        result = SecureCustomerUserService.create_user_for_customer_legacy(
            customer=self.customer,
            first_name='Legacy',
            last_name='User',
            send_welcome=False,
            created_by=self.creator_user,
            request_ip='127.0.0.1'
        )
        
        # Should work like main method
        self.assertIsInstance(result, Ok)
        user, email_sent = result.unwrap()
        self.assertEqual(user.first_name, 'Legacy')

    def test_link_existing_user_legacy(self) -> None:
        """Test legacy wrapper method for linking"""
        existing_user = User.objects.create_user('legacy@example.com', 'pass123')
        
        result = SecureCustomerUserService.link_existing_user_legacy(
            user=existing_user,
            customer=self.customer,
            role='manager',  # Use valid role from ALLOWED_CUSTOMER_ROLES
            is_primary=False,
            created_by=self.creator_user
        )
        
        # Should work like main method
        self.assertIsInstance(result, Ok)

    def test_invite_user_to_customer_legacy(self) -> None:
        """Test legacy wrapper method for invitation"""
        inviter = User.objects.create_user('inviter@example.com', 'pass123')
        
        with patch('apps.users.services.SecureCustomerUserService._send_invitation_email_secure'):
            result = SecureCustomerUserService.invite_user_to_customer_legacy(
                inviter=inviter,
                invitee_email='legacy@example.com',
                customer=self.customer,
                role='viewer'
            )
            
            # Should work like main method
            self.assertIsInstance(result, Ok)

    @patch('apps.users.services.send_mail')
    @patch('apps.users.services.log_security_event')
    def test_send_invitation_email_secure_success(self, mock_log_event: Mock, mock_send_mail: Mock) -> None:
        """Test successful invitation email sending"""
        user = User.objects.create_user('invitee@example.com', 'pass123')
        inviter = User.objects.create_user('inviter@example.com', 'pass123')
        
        membership = CustomerMembership.objects.create(
            user=user,
            customer=self.customer,
            role='viewer'
        )
        
        SecureCustomerUserService._send_invitation_email_secure(
            membership, inviter, '127.0.0.1'
        )
        
        # Should send email
        mock_send_mail.assert_called_once()
        
        # Should log invitation
        invitation_log_calls = [call for call in mock_log_event.call_args_list 
                               if call[0][0] == 'invitation_email_sent']
        self.assertTrue(len(invitation_log_calls) > 0)
        
        # Should store token in cache - test by trying to retrieve with pattern
        # We can't use cache.keys() with LocMemCache, so just verify the cache operation

    @patch('apps.users.services.send_mail')
    def test_send_invitation_email_secure_exception(self, mock_send_mail: Mock) -> None:
        """Test invitation email with exception"""
        mock_send_mail.side_effect = Exception("SMTP error")
        
        user = User.objects.create_user('invitee@example.com', 'pass123')
        inviter = User.objects.create_user('inviter@example.com', 'pass123')
        
        membership = CustomerMembership.objects.create(
            user=user,
            customer=self.customer,
            role='viewer'
        )
        
        # Should not raise exception
        SecureCustomerUserService._send_invitation_email_secure(
            membership, inviter, '127.0.0.1'
        )


class SessionSecurityServiceTests(TestCase):
    """Comprehensive tests for SessionSecurityService"""

    def setUp(self) -> None:
        self.factory = RequestFactory()
        self.user = User.objects.create_user('test@example.com', 'pass123')
        
        # Clear cache before each test
        cache.clear()

    def test_timeout_policies_constant(self) -> None:
        """Test TIMEOUT_POLICIES constant has expected values"""
        policies = SessionSecurityService.TIMEOUT_POLICIES
        self.assertIn('standard', policies)
        self.assertIn('sensitive', policies)
        self.assertIn('shared_device', policies)
        self.assertIn('remember_me', policies)
        
        # Check reasonable timeout values
        self.assertGreater(policies['standard'], 0)
        self.assertLess(policies['shared_device'], policies['standard'])

    @patch('apps.users.services.log_security_event')
    def test_rotate_session_on_password_change_authenticated(self, mock_log_event: Mock) -> None:
        """Test session rotation on password change for authenticated user"""
        request = self.factory.post('/')
        request.user = self.user
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()
        
        old_session_key = request.session.session_key
        
        with patch('apps.users.services.SessionSecurityService._invalidate_other_user_sessions') as mock_invalidate:
            SessionSecurityService.rotate_session_on_password_change(request)
            
            # Should cycle session key
            self.assertNotEqual(request.session.session_key, old_session_key)
            
            # Should invalidate other sessions
            mock_invalidate.assert_called_once()
            
            # Should log rotation
            rotation_log_calls = [call for call in mock_log_event.call_args_list 
                                 if call[0][0] == 'session_rotated_password_change']
            self.assertTrue(len(rotation_log_calls) > 0)

    def test_rotate_session_on_password_change_unauthenticated(self) -> None:
        """Test session rotation does nothing for unauthenticated user"""
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.post('/')
        request.user = AnonymousUser()
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()
        
        # Should not raise exception
        SessionSecurityService.rotate_session_on_password_change(request)

    @patch('apps.users.services.log_security_event')
    def test_rotate_session_on_2fa_change(self, mock_log_event: Mock) -> None:
        """Test session rotation on 2FA change"""
        request = self.factory.post('/')
        request.user = self.user
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()
        
        old_session_key = request.session.session_key
        
        with patch('apps.users.services.SessionSecurityService._invalidate_other_user_sessions') as mock_invalidate:
            SessionSecurityService.rotate_session_on_2fa_change(request)
            
            # Should cycle session key
            self.assertNotEqual(request.session.session_key, old_session_key)
            
            # Should invalidate other sessions
            mock_invalidate.assert_called_once()
            
            # Should log rotation
            rotation_log_calls = [call for call in mock_log_event.call_args_list 
                                 if call[0][0] == 'session_rotated_2fa_change']
            self.assertTrue(len(rotation_log_calls) > 0)

    @patch('apps.users.services.log_security_event')
    def test_cleanup_2fa_secrets_on_recovery(self, mock_log_event: Mock) -> None:
        """Test 2FA secrets cleanup during account recovery"""
        # Set user with 2FA enabled
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = 'SECRET123'
        self.user.backup_tokens = ['token1', 'token2']
        self.user.save()
        
        with patch('apps.users.services.SessionSecurityService._invalidate_all_user_sessions') as mock_invalidate:
            SessionSecurityService.cleanup_2fa_secrets_on_recovery(self.user, '127.0.0.1')
            
            # Should clear 2FA configuration
            self.user.refresh_from_db()
            self.assertFalse(self.user.two_factor_enabled)
            self.assertEqual(self.user.two_factor_secret, '')
            self.assertEqual(self.user.backup_tokens, [])
            
            # Should invalidate all sessions
            mock_invalidate.assert_called_once_with(self.user.id)
            
            # Should log cleanup
            cleanup_log_calls = [call for call in mock_log_event.call_args_list 
                                if call[0][0] == '2fa_secrets_cleared_recovery']
            self.assertTrue(len(cleanup_log_calls) > 0)

    def test_cleanup_2fa_secrets_on_recovery_no_user(self) -> None:
        """Test 2FA cleanup with None user"""
        # Should not raise exception
        SessionSecurityService.cleanup_2fa_secrets_on_recovery(None, '127.0.0.1')

    @patch('apps.users.services.log_security_event')
    def test_update_session_timeout(self, mock_log_event: Mock) -> None:
        """Test session timeout update"""
        request = self.factory.get('/')
        request.user = self.user
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()
        
        SessionSecurityService.update_session_timeout(request)
        
        # Should log timeout update
        timeout_log_calls = [call for call in mock_log_event.call_args_list 
                            if call[0][0] == 'session_timeout_updated']
        self.assertTrue(len(timeout_log_calls) > 0)

    def test_update_session_timeout_unauthenticated(self) -> None:
        """Test session timeout update for unauthenticated user"""
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.get('/')
        request.user = AnonymousUser()
        
        # Should not raise exception
        SessionSecurityService.update_session_timeout(request)

    def test_get_appropriate_timeout_standard(self) -> None:
        """Test appropriate timeout for standard user"""
        request = self.factory.get('/')
        request.user = self.user
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        
        timeout = SessionSecurityService.get_appropriate_timeout(request)
        self.assertEqual(timeout, SessionSecurityService.TIMEOUT_POLICIES['standard'])

    def test_get_appropriate_timeout_shared_device(self) -> None:
        """Test appropriate timeout for shared device mode"""
        request = self.factory.get('/')
        request.user = self.user
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session['shared_device_mode'] = True
        
        timeout = SessionSecurityService.get_appropriate_timeout(request)
        self.assertEqual(timeout, SessionSecurityService.TIMEOUT_POLICIES['shared_device'])

    def test_get_appropriate_timeout_sensitive_staff(self) -> None:
        """Test appropriate timeout for sensitive staff role"""
        self.user.staff_role = 'admin'
        self.user.save()
        
        request = self.factory.get('/')
        request.user = self.user
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        
        timeout = SessionSecurityService.get_appropriate_timeout(request)
        self.assertEqual(timeout, SessionSecurityService.TIMEOUT_POLICIES['sensitive'])

    def test_get_appropriate_timeout_remember_me(self) -> None:
        """Test appropriate timeout for remember me"""
        request = self.factory.get('/')
        request.user = self.user
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session['remember_me'] = True
        
        timeout = SessionSecurityService.get_appropriate_timeout(request)
        self.assertEqual(timeout, SessionSecurityService.TIMEOUT_POLICIES['remember_me'])

    def test_get_appropriate_timeout_unauthenticated(self) -> None:
        """Test appropriate timeout for unauthenticated user"""
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.get('/')
        request.user = AnonymousUser()
        
        timeout = SessionSecurityService.get_appropriate_timeout(request)
        self.assertEqual(timeout, SessionSecurityService.TIMEOUT_POLICIES['standard'])

    @patch('apps.users.services.log_security_event')
    def test_enable_shared_device_mode(self, mock_log_event: Mock) -> None:
        """Test enabling shared device mode"""
        request = self.factory.get('/')
        request.user = self.user
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()
        
        SessionSecurityService.enable_shared_device_mode(request)
        
        # Should set shared device mode
        self.assertTrue(request.session['shared_device_mode'])
        self.assertIn('shared_device_enabled_at', request.session)
        
        # Should clear remember me
        self.assertNotIn('remember_me', request.session)
        
        # Should log mode enabling
        mode_log_calls = [call for call in mock_log_event.call_args_list 
                         if call[0][0] == 'shared_device_mode_enabled']
        self.assertTrue(len(mode_log_calls) > 0)

    def test_enable_shared_device_mode_unauthenticated(self) -> None:
        """Test shared device mode for unauthenticated user"""
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.get('/')
        request.user = AnonymousUser()
        
        # Should not raise exception
        SessionSecurityService.enable_shared_device_mode(request)

    @patch('apps.users.services.log_security_event')
    def test_detect_suspicious_activity_multiple_ips(self, mock_log_event: Mock) -> None:
        """Test suspicious activity detection with multiple IPs"""
        request = self.factory.get('/')
        request.user = self.user
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # Simulate multiple IPs in cache
        cache_key = f'recent_ips:{self.user.id}'
        current_time = time.time()
        recent_ips = [
            {'ip': '192.168.1.1', 'timestamp': current_time - 1800},
            {'ip': '10.0.0.1', 'timestamp': current_time - 1200},
            {'ip': '172.16.0.1', 'timestamp': current_time - 600},
        ]
        cache.set(cache_key, recent_ips, timeout=3600)
        
        is_suspicious = SessionSecurityService.detect_suspicious_activity(request)
        
        # Should detect suspicious activity (3+ different IPs)
        self.assertTrue(is_suspicious)
        
        # Should log suspicious activity
        suspicious_log_calls = [call for call in mock_log_event.call_args_list 
                               if call[0][0] == 'suspicious_activity_detected']
        self.assertTrue(len(suspicious_log_calls) > 0)

    def test_detect_suspicious_activity_normal_activity(self) -> None:
        """Test suspicious activity detection with normal activity"""
        request = self.factory.get('/')
        request.user = self.user
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        is_suspicious = SessionSecurityService.detect_suspicious_activity(request)
        
        # Should not detect suspicious activity (only 1 IP)
        self.assertFalse(is_suspicious)

    def test_detect_suspicious_activity_unauthenticated(self) -> None:
        """Test suspicious activity detection for unauthenticated user"""
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.get('/')
        request.user = AnonymousUser()
        
        is_suspicious = SessionSecurityService.detect_suspicious_activity(request)
        
        # Should return False for unauthenticated users
        self.assertFalse(is_suspicious)

    @patch('apps.users.services.log_security_event')
    def test_log_session_activity(self, mock_log_event: Mock) -> None:
        """Test session activity logging"""
        request = self.factory.get('/test/path/')
        request.user = self.user
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()
        
        SessionSecurityService.log_session_activity(request, 'test_activity', extra_data='test')
        
        # Should log activity
        activity_log_calls = [call for call in mock_log_event.call_args_list 
                             if call[0][0] == 'session_activity_test_activity']
        self.assertTrue(len(activity_log_calls) > 0)
        
        # Check log data includes expected fields
        log_data = activity_log_calls[0][0][1]
        self.assertEqual(log_data['user_id'], self.user.id)
        self.assertEqual(log_data['activity_type'], 'test_activity')
        self.assertEqual(log_data['request_path'], '/test/path/')
        self.assertEqual(log_data['extra_data'], 'test')

    def test_log_session_activity_unauthenticated(self) -> None:
        """Test session activity logging for unauthenticated user"""
        from django.contrib.auth.models import AnonymousUser
        
        request = self.factory.get('/')
        request.user = AnonymousUser()
        
        # Should not raise exception
        SessionSecurityService.log_session_activity(request, 'test_activity')

    def test_invalidate_other_user_sessions(self) -> None:
        """Test invalidating other user sessions"""
        # Create mock sessions
        future_expire = timezone.now() + timezone.timedelta(days=1)
        session1 = Session.objects.create(
            session_key='session1',
            session_data=Session.objects.encode({'_auth_user_id': str(self.user.id)}),
            expire_date=future_expire
        )
        session2 = Session.objects.create(
            session_key='session2', 
            session_data=Session.objects.encode({'_auth_user_id': str(self.user.id)}),
            expire_date=future_expire
        )
        session3 = Session.objects.create(
            session_key='session3',
            session_data=Session.objects.encode({'_auth_user_id': '999'}),  # Different user
            expire_date=future_expire
        )
        
        # Keep session2, delete session1
        SessionSecurityService._invalidate_other_user_sessions(self.user.id, 'session2')
        
        # Should delete session1 but keep session2 and session3
        self.assertFalse(Session.objects.filter(session_key=session1.session_key).exists())
        self.assertTrue(Session.objects.filter(session_key=session2.session_key).exists())
        self.assertTrue(Session.objects.filter(session_key=session3.session_key).exists())

    def test_invalidate_all_user_sessions(self) -> None:
        """Test invalidating all user sessions"""
        # Create mock sessions
        future_expire = timezone.now() + timezone.timedelta(days=1)
        session1 = Session.objects.create(
            session_key='session1',
            session_data=Session.objects.encode({'_auth_user_id': str(self.user.id)}),
            expire_date=future_expire
        )
        session2 = Session.objects.create(
            session_key='session2',
            session_data=Session.objects.encode({'_auth_user_id': str(self.user.id)}),
            expire_date=future_expire
        )
        session3 = Session.objects.create(
            session_key='session3',
            session_data=Session.objects.encode({'_auth_user_id': '999'}),  # Different user
            expire_date=future_expire
        )
        
        SessionSecurityService._invalidate_all_user_sessions(self.user.id)
        
        # Should delete all sessions for this user but keep others
        self.assertFalse(Session.objects.filter(session_key=session1.session_key).exists())
        self.assertFalse(Session.objects.filter(session_key=session2.session_key).exists())
        self.assertTrue(Session.objects.filter(session_key=session3.session_key).exists())

    def test_clear_sensitive_session_data(self) -> None:
        """Test clearing sensitive session data"""
        request = self.factory.get('/')
        
        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()
        
        # Add sensitive data
        sensitive_keys = ['2fa_secret', 'new_backup_codes', 'password_reset_token', 
                         'email_verification_token', 'temp_user_data']
        for key in sensitive_keys:
            request.session[key] = 'sensitive_value'
        
        # Add non-sensitive data
        request.session['user_preference'] = 'safe_value'
        
        SessionSecurityService._clear_sensitive_session_data(request)
        
        # Should clear sensitive data but keep safe data
        for key in sensitive_keys:
            self.assertNotIn(key, request.session)
        self.assertIn('user_preference', request.session)

    def testget_safe_client_ip_forwarded(self) -> None:
        """Test getting client IP with forwarded header"""
        request = self.factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '192.168.1.1, 10.0.0.1'
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # SessionSecurityService uses get_safe_client_ip from apps.common.request_ip
        from apps.common.request_ip import get_safe_client_ip
        ip = get_safe_client_ip(request)
        
        # In development mode, X-Forwarded-For is ignored for security
        self.assertEqual(ip, '127.0.0.1')

    def testget_safe_client_ip_remote_addr(self) -> None:
        """Test getting client IP from remote addr"""
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '127.0.0.1'
        
        # SessionSecurityService uses get_safe_client_ip from apps.common.request_ip
        from apps.common.request_ip import get_safe_client_ip
        ip = get_safe_client_ip(request)
        
        self.assertEqual(ip, '127.0.0.1')

    def testget_safe_client_ip_no_headers(self) -> None:
        """Test getting client IP with no headers"""
        request = self.factory.get('/')
        # RequestFactory automatically sets REMOTE_ADDR to 127.0.0.1
        
        # SessionSecurityService uses get_safe_client_ip from apps.common.request_ip
        from apps.common.request_ip import get_safe_client_ip
        ip = get_safe_client_ip(request)
        
        self.assertEqual(ip, '127.0.0.1')

    def test_get_timeout_policy_name(self) -> None:
        """Test getting timeout policy name"""
        standard_timeout = SessionSecurityService.TIMEOUT_POLICIES['standard']
        policy_name = SessionSecurityService._get_timeout_policy_name(standard_timeout)
        self.assertEqual(policy_name, 'standard')
        
        # Test custom timeout
        custom_timeout = 9999
        policy_name = SessionSecurityService._get_timeout_policy_name(custom_timeout)
        self.assertEqual(policy_name, 'custom')


class ServiceParameterObjectTests(TestCase):
    """Tests for service parameter objects (dataclasses)"""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            company_name='Test Company',
            customer_type='company'
        )
        self.user = User.objects.create_user('test@example.com', 'pass123')

    def test_user_creation_request_defaults(self) -> None:
        """Test UserCreationRequest with defaults"""
        request = UserCreationRequest(customer=self.customer)
        
        self.assertEqual(request.customer, self.customer)
        self.assertEqual(request.first_name, "")
        self.assertEqual(request.last_name, "")
        self.assertTrue(request.send_welcome)
        self.assertIsNone(request.created_by)
        self.assertIsNone(request.request_ip)

    def test_user_creation_request_custom_values(self) -> None:
        """Test UserCreationRequest with custom values"""
        request = UserCreationRequest(
            customer=self.customer,
            first_name='John',
            last_name='Doe',
            send_welcome=False,
            created_by=self.user,
            request_ip='192.168.1.1'
        )
        
        self.assertEqual(request.first_name, 'John')
        self.assertEqual(request.last_name, 'Doe')
        self.assertFalse(request.send_welcome)
        self.assertEqual(request.created_by, self.user)
        self.assertEqual(request.request_ip, '192.168.1.1')

    def test_user_linking_request_defaults(self) -> None:
        """Test UserLinkingRequest with defaults"""
        request = UserLinkingRequest(user=self.user, customer=self.customer)
        
        self.assertEqual(request.user, self.user)
        self.assertEqual(request.customer, self.customer)
        self.assertEqual(request.role, "viewer")  # Secure default
        self.assertFalse(request.is_primary)
        self.assertIsNone(request.created_by)
        self.assertIsNone(request.request_ip)

    def test_user_invitation_request_defaults(self) -> None:
        """Test UserInvitationRequest with defaults"""
        request = UserInvitationRequest(
            inviter=self.user,
            invitee_email='invitee@example.com',
            customer=self.customer
        )
        
        self.assertEqual(request.inviter, self.user)
        self.assertEqual(request.invitee_email, 'invitee@example.com')
        self.assertEqual(request.customer, self.customer)
        self.assertEqual(request.role, "viewer")  # Secure default
        self.assertIsNone(request.request_ip)
        self.assertIsNone(request.user_id)


# Additional edge case tests
class ServiceEdgeCaseTests(TestCase):
    """Tests for edge cases and error conditions in services"""

    def setUp(self) -> None:
        cache.clear()

    def test_service_exception_handling(self) -> None:
        """Test service methods handle unexpected exceptions gracefully"""
        with patch('apps.users.services.User.objects.create_user') as mock_create:
            mock_create.side_effect = Exception("Database connection error")
            
            result = SecureUserRegistrationService.register_new_customer_owner(
                {'email': 'test@example.com', 'first_name': 'Test', 'last_name': 'User'},
                {'company_name': 'Test Co', 'customer_type': 'company'},
                request_ip='127.0.0.1'
            )
            
            # Should return error result, not raise exception
            self.assertIsInstance(result, Err)
            error_msg = result.unwrap_err()
            self.assertIn("Registration could not be completed", error_msg)

    def test_malicious_input_patterns(self) -> None:
        """Test services handle malicious input patterns"""
        with patch('apps.users.services.SecureInputValidator._check_malicious_patterns') as mock_check:
            mock_check.side_effect = ValidationError("Malicious pattern detected")
            
            result = SecureUserRegistrationService._find_customer_by_identifier_secure(
                '<script>alert("xss")</script>',
                'name',
                '127.0.0.1'
            )
            
            # Should return None for malicious input
            self.assertIsNone(result)

    def test_cache_cleanup_on_teardown(self) -> None:
        """Ensure cache is properly managed between tests"""
        # Set some test data
        cache.set('test_key', 'test_value', timeout=60)
        self.assertEqual(cache.get('test_key'), 'test_value')
        
        # Clear cache
        cache.clear()
        self.assertIsNone(cache.get('test_key'))
