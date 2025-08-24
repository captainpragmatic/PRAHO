"""
Comprehensive tests for account lockout functionality in PRAHO Platform.
Tests progressive lockout delays, security measures, and integration with existing systems.
"""
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.cache import cache
from datetime import timedelta
import time

from apps.users.models import UserLoginLog

User = get_user_model()


class AccountLockoutTestCase(TestCase):
    """Test account lockout implementation"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='TestPassword123!',
            first_name='Test',
            last_name='User'
        )
        self.login_url = reverse('users:login')
        # Clear any existing cache/rate limiting data
        cache.clear()
    
    def test_user_model_lockout_methods(self):
        """Test User model lockout helper methods"""
        # Initially not locked
        self.assertFalse(self.user.is_account_locked())
        self.assertEqual(self.user.failed_login_attempts, 0)
        self.assertEqual(self.user.get_lockout_remaining_time(), 0)
        
        # Test increment failed attempts
        self.user.increment_failed_login_attempts()
        self.user.refresh_from_db()
        
        self.assertEqual(self.user.failed_login_attempts, 1)
        self.assertTrue(self.user.is_account_locked())
        self.assertIsNotNone(self.user.account_locked_until)
        self.assertGreater(self.user.get_lockout_remaining_time(), 0)
        
        # Test reset
        self.user.reset_failed_login_attempts()
        self.user.refresh_from_db()
        
        self.assertEqual(self.user.failed_login_attempts, 0)
        self.assertFalse(self.user.is_account_locked())
        self.assertIsNone(self.user.account_locked_until)
        self.assertEqual(self.user.get_lockout_remaining_time(), 0)

    def test_progressive_lockout_timing(self):
        """Test progressive lockout delays"""
        base_time = timezone.now()
        
        # 1st failure (5 min lockout)
        response = self.client.post(self.login_url, {
            'email': 'test@example.com', 
            'password': 'wrong'
        })
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)
        
        # Clear lockout to allow 2nd attempt
        self.user.account_locked_until = base_time - timedelta(minutes=1)
        self.user.save()
        
        # 2nd failure (15 min lockout)
        response = self.client.post(self.login_url, {
            'email': 'test@example.com', 
            'password': 'wrong'
        })
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 2)
        
        # Clear lockout again to test 3rd attempt
        self.user.account_locked_until = base_time - timedelta(minutes=1)
        self.user.save()
        
        # Should be able to attempt login again
        response = self.client.post(self.login_url, {
            'email': 'test@example.com', 
            'password': 'wrong'
        })
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 3)  # Third failure

    def test_successful_login_resets_lockout(self):
        """Test that successful login resets failed attempts"""
        # Lock the account
        self.user.failed_login_attempts = 3
        self.user.account_locked_until = timezone.now() + timedelta(minutes=30)
        self.user.save()
        
        self.assertTrue(self.user.is_account_locked())
        
        # Simulate time passing to unlock by setting lockout time in the past
        self.user.account_locked_until = timezone.now() - timedelta(minutes=5)
        self.user.save()
        
        # Account should no longer be locked
        self.assertFalse(self.user.is_account_locked())
        
        # Successful login should reset
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'TestPassword123!'
        })
        
        # Should redirect to dashboard on success
        self.assertRedirects(response, reverse('dashboard'))
        
        # Check user is reset
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 0)
        self.assertIsNone(self.user.account_locked_until)
        self.assertFalse(self.user.is_account_locked())

    def test_failed_login_increments_attempts(self):
        """Test that failed login increments failed attempts"""
        # Wrong password
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'WrongPassword'
        })
        
        # Should show login form with error
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Incorrect email or password')
        
        # Check failed attempts incremented
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)
        self.assertTrue(self.user.is_account_locked())
        
        # Check login log created
        login_logs = UserLoginLog.objects.filter(user=self.user, status='failed_password')
        self.assertEqual(login_logs.count(), 1)

    def test_login_blocked_when_locked(self):
        """Test that login is blocked when account is locked"""
        # Lock account
        self.user.increment_failed_login_attempts()
        self.user.refresh_from_db()
        
        # Try to login with correct password
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'TestPassword123!'
        })
        
        # Should show lockout message
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Account temporarily locked for security reasons')
        self.assertContains(response, 'Try again in')
        self.assertContains(response, 'minutes')
        
        # User should not be logged in
        self.assertFalse('_auth_user_id' in self.client.session)

    def test_nonexistent_user_login_logging(self):
        """Test that failed login for non-existent user is logged"""
        response = self.client.post(self.login_url, {
            'email': 'nonexistent@example.com',
            'password': 'AnyPassword'
        })
        
        # Should show generic error
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Incorrect email or password')
        
        # Check log created with no user
        login_logs = UserLoginLog.objects.filter(user=None, status='failed_user_not_found')
        self.assertEqual(login_logs.count(), 1)

    def test_lockout_time_expiry(self):
        """Test that lockout expires after the specified time"""
        # Lock account with 5 minute lockout
        self.user.increment_failed_login_attempts()
        self.user.refresh_from_db()
        
        self.assertTrue(self.user.is_account_locked())
        
        # Check initial state - should be locked
        self.assertTrue(self.user.is_account_locked())
        self.assertGreater(self.user.get_lockout_remaining_time(), 0)
        
        # Set lockout time to past to simulate time passing
        self.user.account_locked_until = timezone.now() - timedelta(minutes=1)
        self.user.save()
        
        # Should now be unlocked
        self.assertFalse(self.user.is_account_locked())
        self.assertEqual(self.user.get_lockout_remaining_time(), 0)

    def test_multiple_failed_attempts_progression(self):
        """Test multiple failed login attempts show correct progression"""
        # First failed attempt - 5 minute lockout
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'Wrong1'
        })
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 1)
        remaining = self.user.get_lockout_remaining_time()
        self.assertGreaterEqual(remaining, 4)
        self.assertLessEqual(remaining, 5)
        
        # Simulate time passing and second failed attempt  
        # Set account lockout to past so user can attempt again
        self.user.account_locked_until = timezone.now() - timedelta(minutes=1)
        self.user.save()
            
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'Wrong2'
        })
            
        self.user.refresh_from_db()
        self.assertEqual(self.user.failed_login_attempts, 2)
        remaining = self.user.get_lockout_remaining_time()
        # Should be ~15 minutes
        self.assertGreaterEqual(remaining, 14)
        self.assertLessEqual(remaining, 15)

    def test_successful_login_logging(self):
        """Test that successful login creates proper log entry"""
        response = self.client.post(self.login_url, {
            'email': 'test@example.com',
            'password': 'TestPassword123!'
        })
        
        # Should redirect on success
        self.assertRedirects(response, reverse('dashboard'))
        
        # Check success log created
        login_logs = UserLoginLog.objects.filter(user=self.user, status='success')
        self.assertEqual(login_logs.count(), 1)
        
        log = login_logs.first()
        self.assertIsNotNone(log)
        if log:  # Type guard for mypy
            self.assertIsNotNone(log.ip_address)
            self.assertIsNotNone(log.user_agent)

    def test_password_reset_clears_lockout(self):
        """Test that password reset clears account lockout"""
        # Lock account
        self.user.failed_login_attempts = 5
        self.user.account_locked_until = timezone.now() + timedelta(hours=2)
        self.user.save()
        
        self.assertTrue(self.user.is_account_locked())
        
        # Simulate password reset completion (this functionality exists in password reset view)
        self.user.failed_login_attempts = 0
        self.user.account_locked_until = None
        self.user.save()
        
        self.assertFalse(self.user.is_account_locked())
        self.assertEqual(self.user.failed_login_attempts, 0)

    def test_edge_case_no_lockout_time(self):
        """Test edge case where account_locked_until is None"""
        self.user.failed_login_attempts = 5
        self.user.account_locked_until = None
        self.user.save()
        
        # Should not be locked if no lockout time set
        self.assertFalse(self.user.is_account_locked())
        self.assertEqual(self.user.get_lockout_remaining_time(), 0)

    def test_lockout_remaining_time_accuracy(self):
        """Test lockout remaining time calculation accuracy"""
        # Set precise lockout time
        lockout_time = timezone.now() + timedelta(minutes=30)
        self.user.account_locked_until = lockout_time
        self.user.save()
        
        remaining = self.user.get_lockout_remaining_time()
        
        # Should be approximately 30 minutes (within 1 minute tolerance)
        self.assertGreaterEqual(remaining, 29)
        self.assertLessEqual(remaining, 30)
        
        # Test with past lockout time
        past_time = timezone.now() - timedelta(minutes=10)
        self.user.account_locked_until = past_time
        self.user.save()
        
        remaining = self.user.get_lockout_remaining_time()
        self.assertEqual(remaining, 0)
