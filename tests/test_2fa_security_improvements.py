"""
Comprehensive tests for 2FA security improvements in PRAHO Platform.
Tests encryption, backup codes, recovery flows, and admin tools.
"""

import os
from unittest.mock import patch, MagicMock
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.contrib.admin.sites import AdminSite
from django.contrib.messages import get_messages
import pyotp

from apps.common.encryption import (
    encrypt_sensitive_data, decrypt_sensitive_data, 
    generate_backup_codes, hash_backup_code, verify_backup_code,
    get_encryption_key
)
from apps.users.models import UserLoginLog
from apps.users.admin import UserAdmin

User = get_user_model()


class EncryptionUtilsTestCase(TestCase):
    """Test encryption utilities for sensitive data"""
    
    @override_settings(ENCRYPTION_KEY='test-key-32-chars-long-exactly!!!')
    def test_encrypt_decrypt_sensitive_data(self):
        """Test encryption and decryption of sensitive data"""
        original_data = "JBSWY3DPEHPK3PXP"  # Base32 secret
        
        # Encrypt data
        encrypted = encrypt_sensitive_data(original_data)
        self.assertNotEqual(encrypted, original_data)
        self.assertTrue(len(encrypted) > 0)
        
        # Decrypt data
        decrypted = decrypt_sensitive_data(encrypted)
        self.assertEqual(decrypted, original_data)
    
    def test_encrypt_empty_string(self):
        """Test encryption of empty string"""
        encrypted = encrypt_sensitive_data('')
        self.assertEqual(encrypted, '')
        
        decrypted = decrypt_sensitive_data('')
        self.assertEqual(decrypted, '')
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('apps.common.encryption.settings')
    def test_missing_encryption_key_raises_error(self, mock_settings):
        """Test that missing encryption key raises proper error"""
        mock_settings.ENCRYPTION_KEY = None
        
        with self.assertRaises(ImproperlyConfigured):
            get_encryption_key()
    
    def test_generate_backup_codes(self):
        """Test backup codes generation"""
        codes = generate_backup_codes(count=8)
        
        self.assertEqual(len(codes), 8)
        for code in codes:
            self.assertEqual(len(code), 8)
            self.assertTrue(code.isdigit())
        
        # Ensure codes are unique
        self.assertEqual(len(set(codes)), 8)
    
    def test_backup_code_hashing_and_verification(self):
        """Test backup code hashing and verification"""
        code = "12345678"
        
        # Hash the code
        hashed = hash_backup_code(code)
        self.assertNotEqual(hashed, code)
        self.assertTrue(len(hashed) > 20)  # Hashed should be much longer
        
        # Verify correct code
        self.assertTrue(verify_backup_code(code, hashed))
        
        # Verify incorrect code
        self.assertFalse(verify_backup_code("87654321", hashed))


@override_settings(DJANGO_ENCRYPTION_KEY='test-key-32-chars-long-exactly!!!')
class UserModel2FATestCase(TestCase):
    """Test User model 2FA security improvements"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
    
    def test_2fa_secret_encryption_property(self):
        """Test that 2FA secrets are encrypted when stored"""
        secret = "JBSWY3DPEHPK3PXP"
        
        # Set secret via property
        self.user.two_factor_secret = secret
        self.user.save()
        
        # Verify it's encrypted in database
        self.user.refresh_from_db()
        self.assertNotEqual(self.user._two_factor_secret, secret)
        self.assertTrue(len(self.user._two_factor_secret) > len(secret))
        
        # Verify it decrypts correctly via property
        self.assertEqual(self.user.two_factor_secret, secret)
    
    def test_empty_2fa_secret_handling(self):
        """Test handling of empty 2FA secrets"""
        self.user.two_factor_secret = ""
        self.user.save()
        
        self.assertEqual(self.user._two_factor_secret, "")
        self.assertEqual(self.user.two_factor_secret, "")
    
    def test_generate_backup_codes(self):
        """Test backup codes generation on User model"""
        codes = self.user.generate_backup_codes()
        
        self.assertEqual(len(codes), 8)
        self.assertEqual(len(self.user.backup_tokens), 8)
        
        # Verify codes are hashed in database
        for plain_code, hashed_code in zip(codes, self.user.backup_tokens):
            self.assertNotEqual(plain_code, hashed_code)
            self.assertTrue(verify_backup_code(plain_code, hashed_code))
    
    def test_verify_backup_code(self):
        """Test backup code verification and consumption"""
        codes = self.user.generate_backup_codes()
        test_code = codes[0]
        
        # Verify code works
        self.assertTrue(self.user.verify_backup_code(test_code))
        
        # Verify code is consumed (only 7 remaining)
        self.assertEqual(len(self.user.backup_tokens), 7)
        
        # Verify same code doesn't work again
        self.assertFalse(self.user.verify_backup_code(test_code))
        
        # Verify wrong code doesn't work
        self.assertFalse(self.user.verify_backup_code("99999999"))
    
    def test_has_backup_codes(self):
        """Test backup codes existence check"""
        self.assertFalse(self.user.has_backup_codes())
        
        self.user.generate_backup_codes()
        self.assertTrue(self.user.has_backup_codes())
        
        # Use all codes
        codes = generate_backup_codes(8)  # Get fresh codes for testing
        for _ in range(8):
            if self.user.backup_tokens:
                # Simulate using a code
                self.user.backup_tokens.pop()
        self.user.save()
        
        self.assertFalse(self.user.has_backup_codes())


class TwoFactor2FAViewsTestCase(TestCase):
    """Test enhanced 2FA views with backup codes and recovery"""
    
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
        self.client.login(email='test@example.com', password='TestPassword123!')
    
    @patch.dict(os.environ, {'DJANGO_ENCRYPTION_KEY': 'test-key-32-chars-long-exactly!!!'})
    def test_2fa_setup_generates_backup_codes(self):
        """Test that 2FA setup generates backup codes"""
        # Start 2FA setup
        setup_url = reverse('users:two_factor_setup')
        response = self.client.get(setup_url)
        self.assertEqual(response.status_code, 200)
        
        # Get secret from session
        secret = self.client.session['2fa_secret']
        totp = pyotp.TOTP(secret)
        
        # Complete setup with valid token
        response = self.client.post(setup_url, {
            'token': totp.now()
        })
        
        # Should redirect to backup codes display
        self.assertRedirects(response, reverse('users:two_factor_backup_codes'))
        
        # Verify user has 2FA enabled and backup codes
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
        self.assertTrue(self.user.has_backup_codes())
        self.assertEqual(len(self.user.backup_tokens), 8)
    
    def test_backup_codes_display_view(self):
        """Test backup codes display after generation"""
        # Put backup codes in session
        test_codes = ['12345678', '87654321', '11111111', '22222222',
                     '33333333', '44444444', '55555555', '66666666']
        session = self.client.session
        session['new_backup_codes'] = test_codes
        session.save()
        
        # Visit backup codes page
        response = self.client.get(reverse('users:two_factor_backup_codes'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Your 8 Backup Codes')
        
        for code in test_codes:
            self.assertContains(response, code)
        
        # Verify codes are cleared from session
        self.assertNotIn('new_backup_codes', self.client.session)
    
    def test_backup_codes_display_without_codes_redirects(self):
        """Test backup codes page redirects if no codes in session"""
        response = self.client.get(reverse('users:two_factor_backup_codes'))
        self.assertRedirects(response, reverse('users:user_profile'))
    
    @patch.dict(os.environ, {'DJANGO_ENCRYPTION_KEY': 'test-key-32-chars-long-exactly!!!'})
    def test_regenerate_backup_codes(self):
        """Test backup codes regeneration"""
        # Enable 2FA first
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = 'JBSWY3DPEHPK3PXP'
        self.user.save()
        
        # Generate initial codes
        old_codes = self.user.generate_backup_codes()
        
        # Regenerate codes
        response = self.client.post(reverse('users:two_factor_regenerate_backup_codes'))
        self.assertRedirects(response, reverse('users:two_factor_backup_codes'))
        
        # Verify new codes in session
        new_codes = self.client.session['new_backup_codes']
        self.assertEqual(len(new_codes), 8)
        self.assertNotEqual(set(old_codes), set(new_codes))
    
    def test_regenerate_backup_codes_requires_2fa_enabled(self):
        """Test backup codes regeneration requires 2FA to be enabled"""
        response = self.client.post(reverse('users:two_factor_regenerate_backup_codes'))
        self.assertRedirects(response, reverse('users:user_profile'))
    
    @patch.dict(os.environ, {'DJANGO_ENCRYPTION_KEY': 'test-key-32-chars-long-exactly!!!'})
    def test_2fa_disable_view(self):
        """Test 2FA disable functionality"""
        # Enable 2FA first
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = 'JBSWY3DPEHPK3PXP'
        codes = self.user.generate_backup_codes()
        
        # Disable 2FA with correct password
        response = self.client.post(reverse('users:two_factor_disable'), {
            'password': 'TestPassword123!'
        })
        
        self.assertRedirects(response, reverse('users:user_profile'))
        
        # Verify 2FA is disabled
        self.user.refresh_from_db()
        self.assertFalse(self.user.two_factor_enabled)
        self.assertEqual(self.user.two_factor_secret, '')
        self.assertFalse(self.user.has_backup_codes())
        
        # Verify action was logged
        log_entry = UserLoginLog.objects.filter(
            user=self.user,
            action='two_factor_disabled'
        ).last()
        self.assertIsNotNone(log_entry)
    
    def test_2fa_disable_wrong_password(self):
        """Test 2FA disable with wrong password"""
        self.user.two_factor_enabled = True
        self.user.save()
        
        response = self.client.post(reverse('users:two_factor_disable'), {
            'password': 'WrongPassword'
        })
        
        # Should stay on same page with error
        self.assertEqual(response.status_code, 200)
        
        # 2FA should still be enabled
        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
    
    @patch.dict(os.environ, {'DJANGO_ENCRYPTION_KEY': 'test-key-32-chars-long-exactly!!!'})
    def test_2fa_verify_with_backup_code(self):
        """Test 2FA verification using backup codes"""
        # Setup user with 2FA and backup codes
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = 'JBSWY3DPEHPK3PXP'
        backup_codes = self.user.generate_backup_codes()
        test_backup_code = backup_codes[0]
        
        # Logout and start login process
        self.client.logout()
        
        # Simulate partial login (password successful, need 2FA)
        session = self.client.session
        session['pre_2fa_user_id'] = self.user.id
        session.save()
        
        # Use backup code for 2FA verification
        response = self.client.post(reverse('users:two_factor_verify'), {
            'token': test_backup_code
        })
        
        # Should complete login successfully
        self.assertRedirects(response, reverse('dashboard'))
        
        # Verify user is logged in
        self.assertTrue('_auth_user_id' in self.client.session)
        
        # Verify backup code was consumed
        self.user.refresh_from_db()
        self.assertEqual(len(self.user.backup_tokens), 7)
        
        # Verify login was logged
        log_entry = UserLoginLog.objects.filter(
            user=self.user,
            action='success_2fa_backup_code'
        ).last()
        self.assertIsNotNone(log_entry)


class TwoFactorAdminTestCase(TestCase):
    """Test admin tools for 2FA management"""
    
    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            email='admin@example.com',
            password='AdminPassword123!',
            first_name='Admin',
            last_name='User'
        )
        self.test_user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
        self.client = Client()
        self.client.login(email='admin@example.com', password='AdminPassword123!')
        
        self.site = AdminSite()
        self.admin = UserAdmin(User, self.site)
    
    @patch.dict(os.environ, {'DJANGO_ENCRYPTION_KEY': 'test-key-32-chars-long-exactly!!!'})
    def test_admin_backup_codes_count_display(self):
        """Test admin display of backup codes count"""
        # User with no 2FA
        result = self.admin.backup_codes_count(self.test_user)
        self.assertEqual(result, '-')
        
        # User with 2FA and backup codes
        self.test_user.two_factor_enabled = True
        self.test_user.two_factor_secret = 'JBSWY3DPEHPK3PXP'
        self.test_user.generate_backup_codes()
        
        result = self.admin.backup_codes_count(self.test_user)
        self.assertIn('8', result)
        self.assertIn('color: green', result)
        
        # User with low backup codes
        # Use 6 codes (leaving 2)
        for _ in range(6):
            if self.test_user.backup_tokens:
                self.test_user.backup_tokens.pop()
        self.test_user.save()
        
        result = self.admin.backup_codes_count(self.test_user)
        self.assertIn('2', result)
        self.assertIn('color: orange', result)
        
        # User with no backup codes
        self.test_user.backup_tokens = []
        self.test_user.save()
        
        result = self.admin.backup_codes_count(self.test_user)
        self.assertIn('0', result)
        self.assertIn('color: red', result)
    
    @patch.dict(os.environ, {'DJANGO_ENCRYPTION_KEY': 'test-key-32-chars-long-exactly!!!'})
    def test_admin_disable_2fa_action(self):
        """Test admin action to disable 2FA"""
        # Enable 2FA for test user
        self.test_user.two_factor_enabled = True
        self.test_user.two_factor_secret = 'JBSWY3DPEHPK3PXP'
        self.test_user.generate_backup_codes()
        
        # Disable via admin action
        request = MagicMock()
        request.user = self.admin_user
        request.META = {'REMOTE_ADDR': '127.0.0.1'}
        
        response = self.admin.disable_2fa_view(request, self.test_user.id)
        
        # Verify redirect
        expected_url = reverse('admin:users_user_change', args=[self.test_user.id])
        self.assertEqual(response.status_code, 302)
        
        # Verify 2FA was disabled
        self.test_user.refresh_from_db()
        self.assertFalse(self.test_user.two_factor_enabled)
        self.assertEqual(self.test_user.two_factor_secret, '')
        self.assertFalse(self.test_user.has_backup_codes())
        
        # Verify action was logged
        log_entry = UserLoginLog.objects.filter(
            user=self.test_user,
            action='admin_2fa_disabled'
        ).last()
        self.assertIsNotNone(log_entry)
        self.assertIn('admin user', log_entry.notes)
    
    @patch.dict(os.environ, {'DJANGO_ENCRYPTION_KEY': 'test-key-32-chars-long-exactly!!!'})
    def test_admin_reset_backup_codes_action(self):
        """Test admin action to reset backup codes"""
        # Enable 2FA for test user
        self.test_user.two_factor_enabled = True
        self.test_user.two_factor_secret = 'JBSWY3DPEHPK3PXP'
        old_codes = self.test_user.generate_backup_codes()
        
        # Reset codes via admin action
        request = MagicMock()
        request.user = self.admin_user
        request.META = {'REMOTE_ADDR': '127.0.0.1'}
        
        response = self.admin.reset_backup_codes_view(request, self.test_user.id)
        
        # Verify redirect
        expected_url = reverse('admin:users_user_change', args=[self.test_user.id])
        self.assertEqual(response.status_code, 302)
        
        # Verify new backup codes were generated
        self.test_user.refresh_from_db()
        self.assertEqual(len(self.test_user.backup_tokens), 8)
        
        # Verify action was logged
        log_entry = UserLoginLog.objects.filter(
            user=self.test_user,
            action='admin_backup_codes_reset'
        ).last()
        self.assertIsNotNone(log_entry)
        self.assertIn('admin user', log_entry.notes)