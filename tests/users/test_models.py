"""
Minimal working comprehensive test for users models to boost coverage.
Handles the actual model structure properly.
"""

from django.test import TestCase

from apps.common.request_ip import get_safe_client_ip

from apps.customers.models import Customer
from apps.users.mfa import WebAuthnCredential
from apps.users.models import CustomerMembership, User, UserLoginLog, UserProfile


class MinimalUserModelTestCase(TestCase):
    """Minimal test case for User model to boost coverage"""

    def test_user_creation_and_methods(self):
        """Test user creation and key methods"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Test string representation
        self.assertEqual(str(user), 'Test User (test@example.com)')
        
        # Test staff properties
        self.assertFalse(user.is_staff_user)
        user.staff_role = 'admin'
        user.save()
        self.assertTrue(user.is_staff_user)
        
        # Test customer properties (initially false)
        self.assertFalse(user.is_customer_user)
        self.assertIsNone(user.primary_customer)

    def test_account_lockout_functionality(self):
        """Test account lockout methods"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        # Initially not locked
        self.assertFalse(user.is_account_locked())
        self.assertEqual(user.get_lockout_remaining_time(), 0)
        
        # Trigger lockout
        user.increment_failed_login_attempts()
        self.assertTrue(user.is_account_locked())
        self.assertGreater(user.get_lockout_remaining_time(), 0)
        
        # Reset lockout
        user.reset_failed_login_attempts()
        self.assertFalse(user.is_account_locked())
        self.assertEqual(user.failed_login_attempts, 0)

    def test_two_factor_auth_methods(self):
        """Test 2FA related methods"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        # Test secret property
        self.assertEqual(user.two_factor_secret, '')
        user.two_factor_secret = 'TESTSECRET123456'
        user.save()
        self.assertEqual(user.two_factor_secret, 'TESTSECRET123456')
        
        # Test backup codes
        self.assertFalse(user.has_backup_codes())
        codes = user.generate_backup_codes()
        self.assertEqual(len(codes), 8)
        self.assertTrue(user.has_backup_codes())
        
        # Test backup code verification
        self.assertTrue(user.verify_backup_code(codes[0]))
        self.assertFalse(user.verify_backup_code(codes[0]))  # Already used
        self.assertFalse(user.verify_backup_code('invalid'))

    def test_customer_relationships(self):
        """Test customer relationship methods"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        customer = Customer.objects.create(
            name='Test Company',
            customer_type='company'
        )
        
        # Test access before membership
        self.assertFalse(user.can_access_customer(customer))
        self.assertIsNone(user.get_role_for_customer(customer))
        
        # Create membership
        CustomerMembership.objects.create(
            user=user,
            customer=customer,
            role='owner',
            is_primary=True
        )
        
        # Test access after membership
        self.assertTrue(user.can_access_customer(customer))
        self.assertEqual(user.get_role_for_customer(customer), 'owner')
        self.assertTrue(user.is_customer_user)
        self.assertEqual(user.primary_customer, customer)

    def test_get_accessible_customers(self):
        """Test get_accessible_customers method"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        # Staff can see all customers
        user.is_staff = True
        user.save()
        customers = user.get_accessible_customers()
        self.assertIsNotNone(customers)  # Should return Customer queryset
        
        # Regular user sees only their customers
        user.is_staff = False
        user.save()
        customers = list(user.get_accessible_customers())
        self.assertEqual(len(customers), 0)  # No memberships yet

    def test_user_profile_creation(self):
        """Test that UserProfile is auto-created via signal"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        # Profile should be auto-created
        self.assertTrue(hasattr(user, 'profile'))
        profile = user.profile
        self.assertEqual(str(profile), 'Profile for test@example.com')
        self.assertEqual(profile.preferred_language, 'en')
        self.assertEqual(profile.timezone, 'Europe/Bucharest')


class MinimalCustomerMembershipTestCase(TestCase):
    """Minimal test for CustomerMembership"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.customer = Customer.objects.create(
            name='Test Company',
            customer_type='company'
        )

    def test_membership_creation_and_display(self):
        """Test membership creation and display methods"""
        membership = CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role='billing'
        )
        
        # Test string representation - uses role display value
        # The display text might be translated, so check the basic structure
        membership_str = str(membership)
        self.assertIn(self.user.email, membership_str)
        self.assertIn(self.customer.name, membership_str)
        # Check that the role display is present (could be "Billing" or "Facturare")
        role_display = str(membership.get_role_display())  # Force to string
        self.assertIn(role_display, membership_str)
        
        # Test role display (just verify it's not empty)
        self.assertTrue(len(role_display) > 0)
        
        # Test defaults
        self.assertFalse(membership.is_primary)
        self.assertTrue(membership.email_billing)
        self.assertTrue(membership.email_technical)
        self.assertEqual(membership.notification_language, 'ro')


class MinimalUserLoginLogTestCase(TestCase):
    """Minimal test for UserLoginLog"""

    def test_login_log_creation(self):
        """Test login log creation and display"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        log = UserLoginLog.objects.create(
            user=user,
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            status='success'
        )
        
        # Test string representation
        expected_str = f"{user.email} - success at {log.timestamp}"
        self.assertEqual(str(log), expected_str)
        
        # Test null user (failed login of non-existent user)
        null_log = UserLoginLog.objects.create(
            user=None,
            ip_address='192.168.1.2',
            user_agent='Mozilla/5.0',
            status='failed_user_not_found'
        )
        
        self.assertIsNone(null_log.user)
        self.assertEqual(null_log.status, 'failed_user_not_found')


class MinimalWebAuthnCredentialTestCase(TestCase):
    """Minimal test for WebAuthnCredential"""

    def test_webauthn_credential_creation(self):
        """Test WebAuthn credential creation and methods"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        credential = WebAuthnCredential.objects.create(
            user=user,
            credential_id='test-credential-id',
            public_key='test-public-key',
            name='Test Device'
        )
        
        # Test string representation
        expected_str = f"Test Device ({user.email})"
        self.assertEqual(str(credential), expected_str)
        
        # Test defaults
        self.assertEqual(credential.credential_type, 'public-key')
        self.assertEqual(credential.sign_count, 0)
        self.assertTrue(credential.is_active)
        self.assertIsNone(credential.last_used)
        
        # Test mark as used
        credential.mark_as_used()
        self.assertIsNotNone(credential.last_used)

    def test_webauthn_with_empty_name(self):
        """Test WebAuthn credential with empty name"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        credential = WebAuthnCredential.objects.create(
            user=user,
            credential_id='test-credential-id',
            public_key='test-public-key',
            name=''  # Empty name
        )
        
        # Should still work with empty name
        self.assertEqual(credential.name, '')
        expected_str = f" ({user.email})"
        self.assertEqual(str(credential), expected_str)


class MinimalModelIntegrationTestCase(TestCase):
    """Test model integration and cascade behavior"""

    def test_cascade_deletion(self):
        """Test that related models are properly deleted when user is deleted"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        customer = Customer.objects.create(
            name='Test Company',
            customer_type='company'
        )
        
        # Create related objects
        membership = CustomerMembership.objects.create(
            user=user,
            customer=customer,
            role='owner'
        )
        
        login_log = UserLoginLog.objects.create(
            user=user,
            ip_address='192.168.1.1',
            user_agent='Mozilla/5.0',
            status='success'
        )
        
        credential = WebAuthnCredential.objects.create(
            user=user,
            credential_id='test-credential',
            public_key='test-key',
            name='Test Device'
        )
        
        # Get the profile (auto-created)
        profile = user.profile
        
        # Store IDs for checking after deletion
        profile_id = profile.id
        membership_id = membership.id
        login_log_id = login_log.id
        credential_id = credential.id
        customer_id = customer.id
        
        # Delete user
        user.delete()
        
        # Related objects should be deleted (CASCADE)
        self.assertFalse(UserProfile.objects.filter(id=profile_id).exists())
        self.assertFalse(CustomerMembership.objects.filter(id=membership_id).exists())
        self.assertFalse(UserLoginLog.objects.filter(id=login_log_id).exists())
        self.assertFalse(WebAuthnCredential.objects.filter(id=credential_id).exists())
        
        # Customer should remain (not deleted)
        self.assertTrue(Customer.objects.filter(id=customer_id).exists())

    def test_user_manager_methods(self):
        """Test user manager methods"""
        # Test create_user
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        
        # Test create_superuser
        superuser = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpass123'
        )
        self.assertTrue(superuser.is_staff)
        self.assertTrue(superuser.is_superuser)
        
        # Test email normalization
        user2 = User.objects.create_user(
            email='TEST@EXAMPLE.COM',
            password='testpass123'
        )
        self.assertEqual(user2.email, 'TEST@example.com')  # Domain should be lowercased
        
        # Test email required
        with self.assertRaises(ValueError):
            User.objects.create_user(email='', password='testpass123')

    def test_get_full_name_fallback(self):
        """Test get_full_name method fallback"""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpass123'
        )
        
        # With no name, should fall back to email
        self.assertEqual(user.get_full_name(), 'test@example.com')
        
        # With first name only
        user.first_name = 'Test'
        user.save()
        self.assertEqual(user.get_full_name(), 'Test')
        
        # With full name
        user.last_name = 'User'
        user.save()
        self.assertEqual(user.get_full_name(), 'Test User')
