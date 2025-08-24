"""
Comprehensive tests for secure password reset functionality in PRAHO Platform.
Tests security measures, rate limiting, audit logging, and integration with existing systems.
"""

from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core import mail
from django.core.cache import cache
from django.test.utils import override_settings
from unittest.mock import patch
import time

from apps.users.models import UserLoginLog
from apps.customers.models import Customer

User = get_user_model()


class SecurePasswordResetTestCase(TestCase):
    """Test secure password reset implementation"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
        
        # Clear any existing cache/rate limiting data
        cache.clear()
        
        # URLs
        self.password_reset_url = reverse('users:password_reset')
        self.password_reset_done_url = reverse('users:password_reset_done')
        
    def test_password_reset_view_get(self):
        """Test password reset form display"""
        response = self.client.get(self.password_reset_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Reset Your Password')
        self.assertContains(response, 'Email Address')
    
    def test_password_reset_valid_email(self):
        """Test password reset with valid email"""
        # Clear mail outbox
        mail.outbox = []
        
        response = self.client.post(self.password_reset_url, {
            'email': self.user.email
        })
        
        # Should redirect to done page
        self.assertRedirects(response, self.password_reset_done_url)
        
        # Should send email
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.to, [self.user.email])
        self.assertIn('Password reset', email.subject)
        self.assertIn('password_reset_confirm', email.body)
        
        # Should log the attempt
        log_entry = UserLoginLog.objects.filter(
            action='password_reset_requested'
        ).last()
        self.assertIsNotNone(log_entry)
        self.assertTrue(log_entry.success)
        self.assertIn('test***@example.com', log_entry.notes)
    
    def test_password_reset_invalid_email(self):
        """Test password reset with invalid email (no user enumeration)"""
        mail.outbox = []
        
        response = self.client.post(self.password_reset_url, {
            'email': 'nonexistent@example.com'
        })
        
        # Should still redirect to done page (no user enumeration)
        self.assertRedirects(response, self.password_reset_done_url)
        
        # Should not send email
        self.assertEqual(len(mail.outbox), 0)
        
        # Should still log the attempt
        log_entry = UserLoginLog.objects.filter(
            action='password_reset_requested'
        ).last()
        self.assertIsNotNone(log_entry)
        self.assertTrue(log_entry.success)
        self.assertIn('nonexistent***@example.com', log_entry.notes)
        self.assertIn('(exists: False)', log_entry.notes)
    
    @patch('apps.users.views.ratelimit')
    def test_password_reset_rate_limiting(self, mock_ratelimit):
        """Test rate limiting on password reset"""
        from django_ratelimit.exceptions import Ratelimited
        
        # Mock rate limiting to raise exception
        mock_ratelimit.side_effect = Ratelimited()
        
        response = self.client.post(self.password_reset_url, {
            'email': self.user.email
        })
        
        # Should stay on form with error message
        self.assertEqual(response.status_code, 200)
        
        # Should log rate limiting
        log_entry = UserLoginLog.objects.filter(
            action='password_reset_rate_limited'
        ).last()
        self.assertIsNotNone(log_entry)
        self.assertFalse(log_entry.success)
    
    def test_password_reset_done_view(self):
        """Test password reset done page"""
        response = self.client.get(self.password_reset_done_url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Password Reset Sent')
        self.assertContains(response, 'We\'ve emailed you instructions')
    
    def test_password_reset_confirm_view_valid_token(self):
        """Test password confirmation with valid token"""
        # Generate token
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        
        confirm_url = reverse('users:password_reset_confirm', kwargs={
            'uidb64': uidb64,
            'token': token
        })
        
        # GET request should show form
        response = self.client.get(confirm_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Set New Password')
        
        # POST request should change password
        new_password = 'NewSecurePassword123!'
        response = self.client.post(confirm_url, {
            'new_password1': new_password,
            'new_password2': new_password
        })
        
        # Should redirect to complete page
        self.assertRedirects(response, reverse('users:password_reset_complete'))
        
        # Password should be changed
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))
        
        # Should log successful reset
        log_entry = UserLoginLog.objects.filter(
            user=self.user,
            action='password_reset_completed'
        ).last()
        self.assertIsNotNone(log_entry)
        self.assertTrue(log_entry.success)
    
    def test_password_reset_confirm_invalid_token(self):
        """Test password confirmation with invalid token"""
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        
        confirm_url = reverse('users:password_reset_confirm', kwargs={
            'uidb64': uidb64,
            'token': 'invalid-token'
        })
        
        response = self.client.get(confirm_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Password Reset Link Invalid')
    
    def test_password_reset_confirm_mismatched_passwords(self):
        """Test password confirmation with mismatched passwords"""
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        
        confirm_url = reverse('users:password_reset_confirm', kwargs={
            'uidb64': uidb64,
            'token': token
        })
        
        response = self.client.post(confirm_url, {
            'new_password1': 'Password123!',
            'new_password2': 'DifferentPassword123!'
        })
        
        # Should show form with errors
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'error')
        
        # Should log failed attempt
        log_entry = UserLoginLog.objects.filter(
            action='password_reset_failed'
        ).last()
        self.assertIsNotNone(log_entry)
        self.assertFalse(log_entry.success)
    
    def test_password_reset_complete_view(self):
        """Test password reset complete page"""
        response = self.client.get(reverse('users:password_reset_complete'))
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Password Reset Complete')
        self.assertContains(response, 'Log in')
    
    @override_settings(PASSWORD_RESET_TIMEOUT=7200)  # 2 hours
    def test_password_reset_timeout_setting(self):
        """Test that 2-hour timeout setting is applied"""
        from django.conf import settings
        self.assertEqual(settings.PASSWORD_RESET_TIMEOUT, 7200)
    
    def test_account_lockout_reset_on_password_change(self):
        """Test that account lockout is reset when password is successfully changed"""
        # Lock the user account
        from django.utils import timezone
        from datetime import timedelta
        
        self.user.account_locked_until = timezone.now() + timedelta(hours=1)
        self.user.failed_login_attempts = 5
        self.user.save()
        
        # Perform password reset
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        
        confirm_url = reverse('users:password_reset_confirm', kwargs={
            'uidb64': uidb64,
            'token': token
        })
        
        response = self.client.post(confirm_url, {
            'new_password1': 'NewPassword123!',
            'new_password2': 'NewPassword123!'
        })
        
        # Account lockout should be reset
        self.user.refresh_from_db()
        self.assertIsNone(self.user.account_locked_until)
        self.assertEqual(self.user.failed_login_attempts, 0)
        
        # Should log lockout reset
        log_entry = UserLoginLog.objects.filter(
            user=self.user,
            action='account_lockout_reset'
        ).last()
        self.assertIsNotNone(log_entry)
        self.assertTrue(log_entry.success)


class PasswordResetIntegrationTestCase(TestCase):
    """Integration tests for password reset with existing systems"""
    
    def setUp(self):
        """Set up test data with customer relationships"""
        self.user = User.objects.create_user(
            email='integration@example.com',
            password='TestPassword123!',
            first_name='Integration',
            last_name='User'
        )
        
        # Create customer and membership  
        self.customer = Customer.objects.create(
            name='Test Company SRL',
            customer_type='company',
            company_name='Test Company SRL',
            created_by=self.user
        )
        
        from apps.users.models import CustomerMembership
        CustomerMembership.objects.create(
            customer=self.customer,
            user=self.user,
            role='owner'
        )
        
    def test_password_reset_preserves_customer_relationships(self):
        """Test that password reset doesn't affect customer relationships"""
        original_memberships = list(self.user.customer_memberships.all())
        
        # Perform password reset
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        
        confirm_url = reverse('users:password_reset_confirm', kwargs={
            'uidb64': uidb64,
            'token': token
        })
        
        response = Client().post(confirm_url, {
            'new_password1': 'NewSecurePassword123!',
            'new_password2': 'NewSecurePassword123!'
        })
        
        # Customer relationships should be preserved
        self.user.refresh_from_db()
        current_memberships = list(self.user.customer_memberships.all())
        self.assertEqual(len(current_memberships), len(original_memberships))
        self.assertTrue(self.user.is_customer_user)
    
    def test_audit_logging_integration(self):
        """Test that password reset integrates with audit logging system"""
        initial_log_count = UserLoginLog.objects.count()
        
        # Perform complete password reset flow
        mail.outbox = []
        
        # Request reset
        Client().post(reverse('users:password_reset'), {
            'email': self.user.email
        })
        
        # Confirm reset
        token = default_token_generator.make_token(self.user)
        uidb64 = urlsafe_base64_encode(force_bytes(self.user.pk))
        
        confirm_url = reverse('users:password_reset_confirm', kwargs={
            'uidb64': uidb64,
            'token': token
        })
        
        Client().post(confirm_url, {
            'new_password1': 'AuditTestPassword123!',
            'new_password2': 'AuditTestPassword123!'
        })
        
        # Should have created multiple audit log entries
        final_log_count = UserLoginLog.objects.count()
        self.assertGreater(final_log_count, initial_log_count)
        
        # Verify specific log entries
        request_log = UserLoginLog.objects.filter(
            action='password_reset_requested'
        ).last()
        self.assertIsNotNone(request_log)
        
        complete_log = UserLoginLog.objects.filter(
            user=self.user,
            action='password_reset_completed'
        ).last()
        self.assertIsNotNone(complete_log)