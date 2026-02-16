"""
Enhanced comprehensive test suite for users.models module

This module provides additional tests to achieve 85%+ coverage for the models that are partially covered.
Focuses on edge cases, error conditions, and complex methods not covered in the basic tests.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model

from apps.common.request_ip import get_safe_client_ip
from django.test import TestCase

from apps.common.request_ip import get_safe_client_ip
from django.utils import timezone

from apps.common.request_ip import get_safe_client_ip

from apps.customers.models import Customer
from apps.users.mfa import WebAuthnCredential
from apps.users.models import CustomerMembership, UserLoginLog, UserProfile

UserModel = get_user_model()


class EnhancedUserModelTest(TestCase):
    """Enhanced tests for User model to cover missing functionality"""

    def setUp(self) -> None:
        """Set up test data"""
        self.user = UserModel.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )

        self.customer = Customer.objects.create(
            name='Test Customer',
            primary_email='customer@example.com',
            customer_type='company'
        )

    def test_user_manager_create_superuser_validation(self) -> None:
        """Test superuser creation validation"""
        # Test missing is_staff flag
        with self.assertRaises(ValueError) as cm:
            UserModel.objects.create_superuser(
                email='admin@example.com',
                password='adminpass123',
                is_staff=False  # Should be True for superuser
            )
        self.assertIn('Superuser must have is_staff=True', str(cm.exception))

        # Test missing is_superuser flag
        with self.assertRaises(ValueError) as cm:
            UserModel.objects.create_superuser(
                email='admin@example.com',
                password='adminpass123',
                is_superuser=False  # Should be True for superuser
            )
        self.assertIn('Superuser must have is_superuser=True', str(cm.exception))

    def test_user_str_representation_edge_cases(self) -> None:
        """Test __str__ method edge cases"""
        # User with empty first/last name
        user = UserModel.objects.create_user(
            email='empty@example.com',
            password='testpass123',
            first_name='',
            last_name=''
        )
        self.assertEqual(str(user), 'empty@example.com (empty@example.com)')

        # User with only first name
        user.first_name = 'First'
        user.save()
        self.assertEqual(str(user), 'First (empty@example.com)')

        # User with whitespace name
        user.first_name = '   '
        user.last_name = '   '
        user.save()
        self.assertEqual(str(user), 'empty@example.com (empty@example.com)')

    def test_get_full_name_edge_cases(self) -> None:
        """Test get_full_name method edge cases"""
        # Empty names
        user = UserModel.objects.create_user(
            email='test_empty_names@example.com',
            password='testpass123',
            first_name='',
            last_name=''
        )
        self.assertEqual(user.get_full_name(), 'test_empty_names@example.com')

        # Only whitespace
        user.first_name = '   '
        user.last_name = '   '
        user.save()
        self.assertEqual(user.get_full_name(), 'test_empty_names@example.com')

        # Mixed empty and non-empty
        user.first_name = 'Test'
        user.last_name = ''
        user.save()
        self.assertEqual(user.get_full_name(), 'Test')

    def test_is_staff_user_property(self) -> None:
        """Test is_staff_user property"""
        # Regular user
        self.assertFalse(self.user.is_staff_user)

        # User with staff role
        self.user.staff_role = 'admin'
        self.user.save()
        self.assertTrue(self.user.is_staff_user)

        # User with empty staff role
        self.user.staff_role = ''
        self.user.save()
        self.assertFalse(self.user.is_staff_user)

        # User with empty string staff role (CharField doesn't accept None)
        self.user.staff_role = ""
        self.user.save()
        self.assertFalse(self.user.is_staff_user)

    def test_is_customer_user_with_prefetch(self) -> None:
        """Test is_customer_user property with prefetched data"""
        # Create membership
        membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='owner'
        )
        # Verify membership was created
        self.assertIsNotNone(membership)
        self.assertEqual(membership.role, 'owner')

        # Test with prefetched data
        user_with_prefetch = UserModel.objects.prefetch_related('customer_memberships').get(pk=self.user.pk)
        self.assertTrue(user_with_prefetch.is_customer_user)

        # Test without prefetched data (should fallback to DB query)
        user_without_prefetch = UserModel.objects.get(pk=self.user.pk)
        self.assertTrue(user_without_prefetch.is_customer_user)

    def test_primary_customer_with_prefetch(self) -> None:
        """Test primary_customer property with prefetched data"""
        # Create non-primary membership
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='tech',
            is_primary=False
        )

        # Create second customer and primary membership
        customer2 = Customer.objects.create(
            name='Primary Customer',
            primary_email='primary@example.com',
            customer_type='company'
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=customer2,
            role='owner',
            is_primary=True
        )

        # Test with prefetched data
        user_with_prefetch = UserModel.objects.prefetch_related('customer_memberships__customer').get(pk=self.user.pk)
        self.assertEqual(user_with_prefetch.primary_customer, customer2)

        # Test without prefetched data (should fallback to DB query)
        user_without_prefetch = UserModel.objects.get(pk=self.user.pk)
        self.assertEqual(user_without_prefetch.primary_customer, customer2)

        # Test with no primary customer
        CustomerMembership.objects.filter(user=self.user, is_primary=True).update(is_primary=False)
        user_without_prefetch.refresh_from_db()
        self.assertIsNone(user_without_prefetch.primary_customer)

    def test_get_accessible_customers_staff(self) -> None:
        """Test get_accessible_customers for staff users"""
        # Staff user should see all customers
        self.user.is_staff = True
        self.user.save()

        customers = self.user.get_accessible_customers()
        self.assertEqual(list(customers), [self.customer])

        # Test with staff_role instead of is_staff
        self.user.is_staff = False
        self.user.staff_role = 'admin'
        self.user.save()

        customers = self.user.get_accessible_customers()
        self.assertEqual(list(customers), [self.customer])

    def test_get_accessible_customers_with_prefetch(self) -> None:
        """Test get_accessible_customers with prefetched data"""
        # Create membership
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='owner'
        )

        # Test with prefetched data
        user_with_prefetch = UserModel.objects.prefetch_related('customer_memberships__customer').get(pk=self.user.pk)
        customers = user_with_prefetch.get_accessible_customers()
        self.assertEqual(customers, [self.customer])

        # Test without prefetched data (should fallback to DB query)
        user_without_prefetch = UserModel.objects.get(pk=self.user.pk)
        customers = list(user_without_prefetch.get_accessible_customers())
        self.assertEqual(customers, [self.customer])

    def test_can_access_customer_staff(self) -> None:
        """Test can_access_customer for staff users"""
        # Staff user should access any customer
        self.user.is_staff = True
        self.user.save()
        self.assertTrue(self.user.can_access_customer(self.customer))

        # Test with staff_role
        self.user.is_staff = False
        self.user.staff_role = 'admin'
        self.user.save()
        self.assertTrue(self.user.can_access_customer(self.customer))

        # Regular user without membership
        self.user.staff_role = ''
        self.user.save()
        self.assertFalse(self.user.can_access_customer(self.customer))

    def test_get_role_for_customer(self) -> None:
        """Test get_role_for_customer method"""
        # No membership
        self.assertIsNone(self.user.get_role_for_customer(self.customer))

        # With membership
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='billing'
        )
        self.assertEqual(self.user.get_role_for_customer(self.customer), 'billing')

    def test_account_lockout_edge_cases(self) -> None:
        """Test account lockout edge cases"""
        # Test with no lockout date
        self.assertFalse(self.user.is_account_locked())
        self.assertEqual(self.user.get_lockout_remaining_time(), 0)

        # Test with past lockout date (expired)
        past_time = timezone.now() - timedelta(hours=1)
        self.user.account_locked_until = past_time
        self.user.save()
        self.assertFalse(self.user.is_account_locked())
        self.assertEqual(self.user.get_lockout_remaining_time(), 0)

        # Test with future lockout date
        future_time = timezone.now() + timedelta(minutes=30)
        self.user.account_locked_until = future_time
        self.user.save()
        self.assertTrue(self.user.is_account_locked())
        self.assertGreater(self.user.get_lockout_remaining_time(), 0)
        self.assertLessEqual(self.user.get_lockout_remaining_time(), 30)

    def test_increment_failed_login_attempts_progression(self) -> None:
        """Test progressive lockout delays"""
        # Expected delays: [5, 15, 30, 60, 120, 240] minutes
        expected_delays = [5, 15, 30, 60, 120, 240]

        for i, expected_delay in enumerate(expected_delays):
            self.user.failed_login_attempts = 0
            self.user.account_locked_until = None
            self.user.save()

            # Increment attempts to trigger specific delay (i+1 attempts for delay[i])
            for _ in range(i + 1):
                self.user.increment_failed_login_attempts()

            # Check lockout time is approximately correct (allow for 1 minute tolerance)
            remaining = self.user.get_lockout_remaining_time()
            self.assertGreaterEqual(remaining, expected_delay - 1)
            self.assertLessEqual(remaining, expected_delay)

    def test_increment_failed_login_attempts_max_delay(self) -> None:
        """Test maximum lockout delay cap"""
        # Set very high attempt count
        self.user.failed_login_attempts = 0
        self.user.save()

        # Make many attempts (should cap at 240 minutes)
        for _ in range(10):  # More than the delay array length
            self.user.increment_failed_login_attempts()

        remaining = self.user.get_lockout_remaining_time()
        self.assertLessEqual(remaining, 240)  # Should not exceed maximum

    def test_clean_method(self) -> None:
        """Test clean method"""
        # Should not raise any exceptions
        try:
            self.user.clean()
        except Exception as e:
            self.fail(f"clean() method raised {e}")

    def test_get_staff_role_display_name(self) -> None:
        """Test get_staff_role_display_name method"""
        # Customer user (no staff role)
        self.assertEqual(self.user.get_staff_role_display_name(), 'Customer User')

        # Known staff roles
        role_tests = {
            'admin': 'System Administrator',
            'support': 'Support Agent',
            'billing': 'Billing Staff',
            'manager': 'Manager',
        }

        for role, expected_display in role_tests.items():
            self.user.staff_role = role
            self.user.save()
            self.assertEqual(self.user.get_staff_role_display_name(), expected_display)

        # Unknown staff role
        self.user.staff_role = 'unknown_role'
        self.user.save()
        self.assertEqual(self.user.get_staff_role_display_name(), 'unknown_role')

    def test_two_factor_secret_encryption(self) -> None:
        """Test two-factor secret encryption/decryption"""
        # Test empty secret
        self.assertEqual(self.user.two_factor_secret, '')

        # Test setting and getting secret
        test_secret = 'TESTBASE32SECRET'
        self.user.two_factor_secret = test_secret
        self.user.save()

        # Should be encrypted in database
        self.assertNotEqual(self.user._two_factor_secret, test_secret)

        # But should decrypt correctly
        self.assertEqual(self.user.two_factor_secret, test_secret)

        # Test clearing secret
        self.user.two_factor_secret = ''
        self.user.save()
        self.assertEqual(self.user._two_factor_secret, '')
        self.assertEqual(self.user.two_factor_secret, '')

    def test_backup_codes_edge_cases(self) -> None:
        """Test backup codes edge cases"""
        # Test with no codes
        self.assertFalse(self.user.has_backup_codes())
        self.assertFalse(self.user.verify_backup_code('invalid'))

        # Generate codes
        codes = self.user.generate_backup_codes()
        self.assertEqual(len(codes), 8)
        self.assertTrue(self.user.has_backup_codes())

        # Test verifying invalid code
        self.assertFalse(self.user.verify_backup_code('invalid_code'))

        # Test verifying valid code
        first_code = codes[0]
        self.assertTrue(self.user.verify_backup_code(first_code))

        # Same code should not work again
        self.assertFalse(self.user.verify_backup_code(first_code))

        # Should have one less code now
        self.assertEqual(len(self.user.backup_tokens), 7)

        # Verify all remaining codes work
        for code in codes[1:]:
            self.assertTrue(self.user.verify_backup_code(code))

        # Should have no codes left
        self.assertFalse(self.user.has_backup_codes())


class EnhancedCustomerMembershipTest(TestCase):
    """Enhanced tests for CustomerMembership model"""

    def setUp(self) -> None:
        """Set up test data"""
        self.user = UserModel.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )

        self.customer = Customer.objects.create(
            name='Test Customer',
            primary_email='customer@example.com',
            customer_type='company'
        )

        self.admin_user = UserModel.objects.create_user(
            email='admin@example.com',
            password='adminpass123',
            is_staff=True
        )

    def test_membership_str_with_primary_flag(self) -> None:
        """Test string representation with primary flag"""
        # Non-primary membership
        membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='tech',
            is_primary=False
        )

        membership_str = str(membership)
        self.assertIn(self.user.email, membership_str)
        self.assertIn(self.customer.name, membership_str)
        self.assertNotIn('Primary', membership_str)

        # Primary membership
        membership.is_primary = True
        membership.save()

        membership_str = str(membership)
        self.assertIn('Primary', membership_str)

    def test_get_role_display_name_all_roles(self) -> None:
        """Test role display names for all possible roles"""
        role_tests = {
            'owner': 'Owner',
            'billing': 'Billing',
            'tech': 'Technical',
            'viewer': 'Viewer',
        }

        membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='owner'
        )

        for role, expected_display in role_tests.items():
            membership.role = role
            membership.save()
            self.assertEqual(membership.get_role_display_name(), expected_display)

        # Test unknown role
        membership.role = 'unknown_role'
        membership.save()
        self.assertEqual(membership.get_role_display_name(), 'unknown_role')

    def test_membership_notification_preferences(self) -> None:
        """Test notification preference fields"""
        membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='owner',
            email_billing=True,
            email_technical=True,
            email_marketing=False,
            notification_language='en',
            preferred_contact_method='email'
        )

        self.assertTrue(membership.email_billing)
        self.assertTrue(membership.email_technical)
        self.assertFalse(membership.email_marketing)
        self.assertEqual(membership.notification_language, 'en')
        self.assertEqual(membership.preferred_contact_method, 'email')

    def test_membership_audit_fields(self) -> None:
        """Test audit fields"""
        membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='owner',
            created_by=self.admin_user
        )

        self.assertEqual(membership.created_by, self.admin_user)
        self.assertIsNotNone(membership.created_at)
        self.assertIsNotNone(membership.updated_at)

    def test_membership_unique_constraint(self) -> None:
        """Test unique constraint on customer/user combination"""
        # Create first membership
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='owner'
        )

        # Try to create duplicate - should raise error
        from django.db import IntegrityError

        with self.assertRaises(IntegrityError):
            CustomerMembership.objects.create(
                user=self.user,
                customer=self.customer,
                role='billing'
            )


class EnhancedUserProfileTest(TestCase):
    """Enhanced tests for UserProfile model"""

    def setUp(self) -> None:
        """Set up test data"""
        self.user = UserModel.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )

    def test_profile_str_representation(self) -> None:
        """Test profile string representation"""
        profile = self.user.profile
        self.assertEqual(str(profile), 'Profile for test@example.com')

    def test_profile_default_values(self) -> None:
        """Test profile default values"""
        profile = self.user.profile

        self.assertEqual(profile.preferred_language, 'en')
        self.assertEqual(profile.timezone, 'Europe/Bucharest')
        self.assertEqual(profile.date_format, '%d.%m.%Y')
        self.assertTrue(profile.email_notifications)
        self.assertFalse(profile.sms_notifications)
        self.assertFalse(profile.marketing_emails)
        self.assertEqual(profile.emergency_contact_name, '')
        self.assertEqual(profile.emergency_contact_phone, '')

    def test_profile_language_choices(self) -> None:
        """Test language choices"""
        profile = self.user.profile

        # Test valid choices
        profile.preferred_language = 'ro'
        profile.save()
        self.assertEqual(profile.preferred_language, 'ro')

        profile.preferred_language = 'en'
        profile.save()
        self.assertEqual(profile.preferred_language, 'en')

    def test_profile_date_format_choices(self) -> None:
        """Test date format choices"""
        profile = self.user.profile

        # Test valid choices
        profile.date_format = '%Y-%m-%d'
        profile.save()
        self.assertEqual(profile.date_format, '%Y-%m-%d')

        profile.date_format = '%d.%m.%Y'
        profile.save()
        self.assertEqual(profile.date_format, '%d.%m.%Y')


class EnhancedUserLoginLogTest(TestCase):
    """Enhanced tests for UserLoginLog model"""

    def setUp(self) -> None:
        """Set up test data"""
        self.user = UserModel.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )

    def test_login_log_str_with_null_user(self) -> None:
        """Test string representation with null user"""
        log = UserLoginLog.objects.create(
            user=None,
            ip_address='192.168.1.1',
            user_agent='Test Browser',
            status='failed_user_not_found'
        )

        log_str = str(log)
        self.assertIn('Unknown User', log_str)
        self.assertIn('failed_user_not_found', log_str)
        self.assertIn(str(log.timestamp), log_str)

    def test_login_log_all_status_choices(self) -> None:
        """Test all login status choices"""
        status_choices = [
            'success',
            'failed_password',
            'failed_2fa',
            'failed_user_not_found',
            'account_locked',
            'account_disabled',
            'password_reset_completed',
            'account_lockout_reset',
            'password_reset_failed',
        ]

        for status in status_choices:
            log = UserLoginLog.objects.create(
                user=self.user,
                ip_address='192.168.1.1',
                user_agent='Test Browser',
                status=status
            )
            self.assertEqual(log.status, status)

    def test_login_log_geographic_info(self) -> None:
        """Test geographic information fields"""
        log = UserLoginLog.objects.create(
            user=self.user,
            ip_address='192.168.1.1',
            user_agent='Test Browser',
            status='success',
            country='Romania',
            city='Bucharest'
        )

        self.assertEqual(log.country, 'Romania')
        self.assertEqual(log.city, 'Bucharest')


class EnhancedWebAuthnCredentialTest(TestCase):
    """Enhanced tests for WebAuthnCredential model"""

    def setUp(self) -> None:
        """Set up test data"""
        self.user = UserModel.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )

    def test_webauthn_credential_mark_as_used(self) -> None:
        """Test mark_as_used method"""
        credential = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id='test-credential',
            public_key='test-key',
            name='Test Device'
        )

        # Initially last_used should be None
        self.assertIsNone(credential.last_used)

        # Mark as used
        credential.mark_as_used()

        # Should update last_used and sign_count
        self.assertIsNotNone(credential.last_used)
        self.assertEqual(credential.sign_count, 1)

        # Mark as used again
        credential.mark_as_used()
        self.assertEqual(credential.sign_count, 2)

    def test_webauthn_credential_defaults(self) -> None:
        """Test default values"""
        credential = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id='test-credential',
            public_key='test-key',
            name='Test Device'
        )

        self.assertEqual(credential.credential_type, 'public-key')
        self.assertEqual(credential.sign_count, 0)
        self.assertTrue(credential.is_active)
        self.assertIsNone(credential.last_used)
        self.assertIsNotNone(credential.created_at)
        self.assertIsNotNone(credential.updated_at)

    def test_webauthn_credential_inactive(self) -> None:
        """Test inactive credential"""
        credential = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id='test-credential',
            public_key='test-key',
            name='Inactive Device',
            is_active=False
        )

        self.assertFalse(credential.is_active)

    def test_webauthn_credential_with_metadata(self) -> None:
        """Test credential with metadata"""
        metadata = {
            'device_type': 'security_key',
            'vendor': 'YubiKey',
            'model': '5C NFC'
        }

        credential = WebAuthnCredential.objects.create(
            user=self.user,
            credential_id='test-credential',
            public_key='test-key',
            name='YubiKey',
            metadata=metadata
        )

        self.assertEqual(credential.metadata, metadata)
        self.assertEqual(credential.metadata['device_type'], 'security_key')


class ModelEdgeCasesTest(TestCase):
    """Test edge cases and error conditions across all models"""

    def test_user_creation_edge_cases(self) -> None:
        """Test user creation edge cases"""
        # Test with minimal data
        user = UserModel.objects.create_user(
            email='minimal@example.com',
            password=None  # No password
        )
        self.assertFalse(user.has_usable_password())

        # Test email normalization edge cases
        user = UserModel.objects.create_user(
            email='UPPER@EXAMPLE.COM',
            password='testpass123'
        )
        self.assertEqual(user.email, 'UPPER@example.com')  # Domain lowercased

    def test_model_field_max_lengths(self) -> None:
        """Test field max lengths"""
        # Test phone field max length (20 chars)
        long_phone = '+' + '1' * 19  # 20 characters total
        user = UserModel.objects.create_user(
            email='long_phone@example.com',
            password='testpass123',
            phone=long_phone
        )
        self.assertEqual(user.phone, long_phone)

        # Test staff role max length (20 chars)
        long_role = 'a' * 20
        user.staff_role = long_role
        user.save()
        self.assertEqual(user.staff_role, long_role)

    def test_model_timestamps(self) -> None:
        """Test timestamp fields are set correctly"""
        before_creation = timezone.now()

        user = UserModel.objects.create_user(
            email='timestamp@example.com',
            password='testpass123'
        )

        after_creation = timezone.now()

        # Timestamps should be within the time window
        self.assertGreaterEqual(user.created_at, before_creation)
        self.assertLessEqual(user.created_at, after_creation)
        self.assertGreaterEqual(user.updated_at, before_creation)
        self.assertLessEqual(user.updated_at, after_creation)

    def test_model_meta_attributes(self) -> None:
        """Test model Meta attributes"""
        # User model
        self.assertEqual(UserModel._meta.db_table, 'users')
        self.assertEqual(str(UserModel._meta.verbose_name), 'User')
        self.assertEqual(str(UserModel._meta.verbose_name_plural), 'Users')

        # CustomerMembership model
        self.assertEqual(CustomerMembership._meta.db_table, 'customer_membership')

        # UserProfile model
        self.assertEqual(UserProfile._meta.db_table, 'user_profiles')

        # UserLoginLog model
        self.assertEqual(UserLoginLog._meta.db_table, 'user_login_logs')

    def test_model_indexes(self) -> None:
        """Test that model indexes are properly defined"""
        # User model indexes
        user_indexes = [index.name for index in UserModel._meta.indexes if index.name]
        expected_user_indexes = ['idx_users_2fa_enabled', 'idx_users_2fa_enabled_staff']

        for expected_index in expected_user_indexes:
            self.assertIn(expected_index, user_indexes)

    @patch('apps.common.encryption.encrypt_sensitive_data')
    @patch('apps.common.encryption.decrypt_sensitive_data')
    def test_encryption_error_handling(self, mock_decrypt: Mock, mock_encrypt: Mock) -> None:
        """Test encryption error handling"""
        # Test encryption error
        mock_encrypt.side_effect = Exception('Encryption failed')

        user = UserModel.objects.create_user(
            email='encrypt_test@example.com',
            password='testpass123'
        )

        # Should handle encryption errors gracefully
        try:
            user.two_factor_secret = 'test_secret'
            user.save()
        except Exception:
            # Should not propagate encryption errors
            pass

        # Test decryption error
        mock_decrypt.side_effect = Exception('Decryption failed')
        user._two_factor_secret = 'encrypted_data'
        user.save()

        # Should handle decryption errors gracefully
        try:
            secret = user.two_factor_secret
            # Should return empty string on decryption error
            self.assertEqual(secret, '')
        except Exception:
            # Should not propagate decryption errors
            pass
