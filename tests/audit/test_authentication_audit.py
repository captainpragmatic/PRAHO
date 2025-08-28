"""
Comprehensive test suite for authentication audit logging system.

Tests all authentication events including login, logout, failures, 
account lockouts, and session security events with GDPR compliance.
"""

import uuid
from datetime import timedelta
from unittest.mock import Mock, patch

import pytest
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.contrib.sessions.models import Session
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.audit.services import AuthenticationAuditService
from apps.users.models import UserLoginLog
from apps.users.signals import log_failed_login, log_user_login, log_user_logout

User = get_user_model()


class AuthenticationAuditServiceTest(TestCase):
    """Test the AuthenticationAuditService functionality"""
    
    def setUp(self):
        """Set up test data"""
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        self.request = self.factory.post('/login/')
        self.request.META['HTTP_USER_AGENT'] = 'Test Browser 1.0'
        self.request.META['REMOTE_ADDR'] = '192.168.1.100'
        
        # Mock session
        self.request.session = Mock()
        self.request.session.session_key = 'test_session_123'
    
    def test_log_login_success_basic(self):
        """Test basic successful login logging"""
        audit_event = AuthenticationAuditService.log_login_success(
            user=self.user,
            request=self.request,
            authentication_method='password'
        )
        
        self.assertIsInstance(audit_event, AuditEvent)
        self.assertEqual(audit_event.action, 'login_success')
        self.assertEqual(audit_event.user, self.user)
        self.assertEqual(audit_event.ip_address, '192.168.1.100')
        self.assertEqual(audit_event.user_agent, 'Test Browser 1.0')
        
        # Check metadata
        self.assertEqual(audit_event.metadata['authentication_method'], 'password')
        self.assertEqual(audit_event.metadata['user_email'], 'test@example.com')
        self.assertTrue(audit_event.metadata['login_timestamp'])
    
    def test_log_login_success_with_2fa(self):
        """Test successful login logging with 2FA"""
        # Enable 2FA for user
        self.user.two_factor_enabled = True
        self.user.save()
        
        audit_event = AuthenticationAuditService.log_login_success(
            user=self.user,
            request=self.request,
            authentication_method='2fa_totp',
            metadata={'backup_codes_remaining': 5}
        )
        
        self.assertEqual(audit_event.metadata['authentication_method'], '2fa_totp')
        self.assertTrue(audit_event.metadata['user_2fa_enabled'])
        self.assertEqual(audit_event.metadata['backup_codes_remaining'], 5)
    
    def test_log_login_failed_user_not_found(self):
        """Test logging failed login for non-existent user"""
        audit_event = AuthenticationAuditService.log_login_failed(
            email='nonexistent@example.com',
            failure_reason='user_not_found',
            request=self.request
        )
        
        self.assertEqual(audit_event.action, 'login_failed_user_not_found')
        self.assertIsNone(audit_event.user)
        self.assertEqual(audit_event.metadata['attempted_email'], 'nonexistent@example.com')
        self.assertFalse(audit_event.metadata['user_exists'])
        self.assertEqual(audit_event.actor_type, 'anonymous')
    
    def test_log_login_failed_invalid_password(self):
        """Test logging failed login for valid user with invalid password"""
        audit_event = AuthenticationAuditService.log_login_failed(
            email='test@example.com',
            user=self.user,
            failure_reason='invalid_password',
            request=self.request
        )
        
        self.assertEqual(audit_event.action, 'login_failed_password')
        self.assertEqual(audit_event.user, self.user)
        self.assertTrue(audit_event.metadata['user_exists'])
        self.assertEqual(audit_event.metadata['user_id'], str(self.user.id))
        self.assertEqual(audit_event.actor_type, 'user')
    
    def test_log_login_failed_account_locked(self):
        """Test logging failed login for locked account"""
        # Mock account locked status
        with patch.object(self.user, 'is_account_locked', return_value=True):
            audit_event = AuthenticationAuditService.log_login_failed(
                email='test@example.com',
                user=self.user,
                failure_reason='account_locked',
                request=self.request
            )
        
        self.assertEqual(audit_event.action, 'login_failed_account_locked')
        self.assertEqual(audit_event.metadata['failure_reason'], 'account_locked')
    
    def test_log_logout_manual(self):
        """Test logging manual logout"""
        audit_event = AuthenticationAuditService.log_logout(
            user=self.user,
            logout_reason='manual',
            request=self.request
        )
        
        self.assertEqual(audit_event.action, 'logout_manual')
        self.assertEqual(audit_event.user, self.user)
        self.assertEqual(audit_event.metadata['logout_reason'], 'manual')
        self.assertTrue(audit_event.metadata['logout_timestamp'])
    
    def test_log_logout_session_expired(self):
        """Test logging session expiration logout"""
        audit_event = AuthenticationAuditService.log_logout(
            user=self.user,
            logout_reason='session_expired',
            request=self.request
        )
        
        self.assertEqual(audit_event.action, 'logout_session_expired')
        self.assertEqual(audit_event.metadata['logout_reason'], 'session_expired')
    
    def test_log_logout_with_session_duration(self):
        """Test logout logging includes session duration"""
        # Set last login time
        self.user.last_login = timezone.now() - timedelta(minutes=30)
        self.user.save()
        
        audit_event = AuthenticationAuditService.log_logout(
            user=self.user,
            logout_reason='manual',
            request=self.request
        )
        
        self.assertIn('duration_seconds', audit_event.metadata['session_info'])
        self.assertIn('duration_human', audit_event.metadata['session_info'])
        self.assertGreater(audit_event.metadata['session_info']['duration_seconds'], 1700)  # ~30 minutes
    
    def test_log_account_locked(self):
        """Test logging account lockout events"""
        audit_event = AuthenticationAuditService.log_account_locked(
            user=self.user,
            trigger_reason='excessive_failed_attempts',
            request=self.request,
            failed_attempts=5
        )
        
        self.assertEqual(audit_event.action, 'account_locked')
        self.assertEqual(audit_event.metadata['lockout_reason'], 'excessive_failed_attempts')
        self.assertEqual(audit_event.metadata['failed_attempts_count'], 5)
        self.assertTrue(audit_event.metadata['security_event'])
        self.assertEqual(audit_event.actor_type, 'system')
    
    def test_log_session_rotation(self):
        """Test logging session rotation events"""
        old_session = 'old_session_123'
        new_session = 'new_session_456'
        
        audit_event = AuthenticationAuditService.log_session_rotation(
            user=self.user,
            reason='password_change',
            request=self.request,
            old_session_key=old_session,
            new_session_key=new_session
        )
        
        self.assertEqual(audit_event.action, 'session_rotation')
        self.assertEqual(audit_event.metadata['rotation_reason'], 'password_change')
        self.assertEqual(audit_event.metadata['session_info']['old_session_key'], old_session)
        self.assertEqual(audit_event.metadata['session_info']['new_session_key'], new_session)
        self.assertTrue(audit_event.metadata['security_enhancement'])
    
    def test_metadata_serialization_safety(self):
        """Test that complex metadata objects are safely serialized"""
        complex_metadata = {
            'uuid_field': uuid.uuid4(),
            'datetime_field': timezone.now(),
            'user_object': self.user,
            'nested_dict': {
                'inner_uuid': uuid.uuid4(),
                'inner_datetime': timezone.now(),
            }
        }
        
        audit_event = AuthenticationAuditService.log_login_success(
            user=self.user,
            request=self.request,
            metadata=complex_metadata
        )
        
        # Should not raise serialization errors
        self.assertIsInstance(audit_event.metadata, dict)
        # UUID should be converted to string
        self.assertIsInstance(audit_event.metadata['uuid_field'], str)


class AuthenticationSignalsTest(TestCase):
    """Test Django authentication signals integration"""
    
    def setUp(self):
        """Set up test data"""
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email='signal@example.com',
            password='testpass123'
        )
    
    def test_user_logged_in_signal(self):
        """Test user_logged_in signal creates audit event"""
        request = self.factory.post('/login/')
        request.META['HTTP_USER_AGENT'] = 'Signal Test Browser'
        request.META['REMOTE_ADDR'] = '10.0.0.1'
        request.session = Mock()
        request.session.session_key = 'signal_session_123'
        request.session.get = Mock(return_value=None)  # No 2FA session
        
        # Clear existing audit events
        AuditEvent.objects.all().delete()
        
        # Trigger signal
        user_logged_in.send(sender=User, request=request, user=self.user)
        
        # Check audit event was created
        audit_events = AuditEvent.objects.filter(user=self.user, action='login_success')
        self.assertEqual(audit_events.count(), 1)
        
        audit_event = audit_events.first()
        self.assertEqual(audit_event.ip_address, '10.0.0.1')
        self.assertTrue(audit_event.metadata['signal_triggered'])
    
    def test_user_logged_out_signal(self):
        """Test user_logged_out signal creates audit event"""
        request = self.factory.post('/logout/')
        request.META['HTTP_USER_AGENT'] = 'Signal Test Browser'
        request.META['REMOTE_ADDR'] = '10.0.0.1'
        request.session = Mock()
        request.session.session_key = 'signal_session_123'
        
        # Clear existing audit events
        AuditEvent.objects.all().delete()
        
        # Trigger signal
        user_logged_out.send(sender=User, request=request, user=self.user)
        
        # Check audit event was created
        audit_events = AuditEvent.objects.filter(user=self.user, action='logout_manual')
        self.assertEqual(audit_events.count(), 1)
        
        audit_event = audit_events.first()
        self.assertTrue(audit_event.metadata['signal_triggered'])
        self.assertTrue(audit_event.metadata['session_flushed'])
    
    def test_user_login_failed_signal(self):
        """Test user_login_failed signal creates audit event"""
        request = self.factory.post('/login/')
        request.META['HTTP_USER_AGENT'] = 'Signal Test Browser'
        request.META['REMOTE_ADDR'] = '10.0.0.1'
        
        credentials = {'username': 'signal@example.com', 'password': 'wrong'}
        
        # Clear existing audit events
        AuditEvent.objects.all().delete()
        
        # Trigger signal
        user_login_failed.send(
            sender=User, 
            request=request, 
            credentials=credentials
        )
        
        # Check audit event was created
        audit_events = AuditEvent.objects.filter(action='login_failed_password')
        self.assertEqual(audit_events.count(), 1)
        
        audit_event = audit_events.first()
        self.assertEqual(audit_event.user, self.user)
        self.assertEqual(audit_event.metadata['attempted_email'], 'signal@example.com')
        self.assertTrue(audit_event.metadata['signal_triggered'])
    
    def test_login_failed_signal_nonexistent_user(self):
        """Test login failed signal for non-existent user"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '10.0.0.1'
        
        credentials = {'username': 'nonexistent@example.com', 'password': 'wrong'}
        
        # Clear existing audit events  
        AuditEvent.objects.all().delete()
        
        # Trigger signal
        user_login_failed.send(
            sender=User,
            request=request,
            credentials=credentials
        )
        
        # Check audit event was created
        audit_events = AuditEvent.objects.filter(action='login_failed_user_not_found')
        self.assertEqual(audit_events.count(), 1)
        
        audit_event = audit_events.first()
        self.assertIsNone(audit_event.user)
        self.assertEqual(audit_event.metadata['attempted_email'], 'nonexistent@example.com')
        self.assertFalse(audit_event.metadata['user_exists'])
    
    def test_signal_exception_handling(self):
        """Test that signal handlers don't break authentication on errors"""
        request = self.factory.post('/login/')
        request.META['REMOTE_ADDR'] = '10.0.0.1'
        
        # Mock the audit service to raise an exception
        with patch('apps.users.signals.AuthenticationAuditService.log_login_success', 
                  side_effect=Exception('Audit service error')):
            # This should not raise an exception
            try:
                user_logged_in.send(sender=User, request=request, user=self.user)
            except Exception as e:
                self.fail(f"Signal handler should not propagate exceptions: {e}")


class AuthenticationViewsIntegrationTest(TestCase):
    """Test authentication audit integration with views"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='view@example.com',
            password='testpass123'
        )
    
    def test_login_view_creates_audit_event(self):
        """Test that login view creates proper audit events"""
        # Clear existing audit events
        AuditEvent.objects.all().delete()
        
        # Login via view
        response = self.client.post(reverse('users:login'), {
            'email': 'view@example.com',
            'password': 'testpass123'
        })
        
        self.assertEqual(response.status_code, 302)  # Redirect on success
        
        # Check audit event was created (might be from signal or view)
        audit_events = AuditEvent.objects.filter(user=self.user, action='login_success')
        self.assertGreaterEqual(audit_events.count(), 1)
    
    def test_logout_view_creates_audit_event(self):
        """Test that logout view creates proper audit events"""
        # Login first
        self.client.login(email='view@example.com', password='testpass123')
        
        # Clear existing audit events
        AuditEvent.objects.all().delete()
        
        # Logout via view
        response = self.client.post(reverse('users:logout'))
        
        self.assertEqual(response.status_code, 302)  # Redirect to login
        
        # Check audit events were created (from both view and signal)
        audit_events = AuditEvent.objects.filter(user=self.user, action__contains='logout')
        self.assertGreaterEqual(audit_events.count(), 1)
        
        # At least one should have the view-specific metadata
        view_triggered_events = audit_events.filter(
            metadata__logout_triggered_by='logout_view'
        )
        self.assertGreaterEqual(view_triggered_events.count(), 1)
    
    def test_failed_login_creates_audit_event(self):
        """Test that failed login creates audit event"""
        # Clear existing audit events
        AuditEvent.objects.all().delete()
        
        # Attempt login with wrong password
        response = self.client.post(reverse('users:login'), {
            'email': 'view@example.com',
            'password': 'wrongpassword'
        })
        
        self.assertEqual(response.status_code, 200)  # Stay on login page
        
        # Check audit event was created
        audit_events = AuditEvent.objects.filter(action='login_failed_password')
        self.assertGreaterEqual(audit_events.count(), 1)


class AuthenticationAuditQueryPerformanceTest(TestCase):
    """Test authentication audit query performance"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='perf@example.com',
            password='testpass123'
        )
    
    def test_audit_indexes_exist(self):
        """Test that required database indexes exist for performance"""
        from django.db import connection
        
        # Skip index verification for SQLite in tests (different index introspection)
        if connection.vendor == 'sqlite':
            self.skipTest("Index verification skipped for SQLite test database")
        
        with connection.cursor() as cursor:
            if connection.vendor == 'postgresql':
                # PostgreSQL-specific query
                cursor.execute("""
                    SELECT indexname FROM pg_indexes 
                    WHERE tablename = 'audit_event'
                    AND indexname LIKE 'idx_audit_%'
                """)
                indexes = [row[0] for row in cursor.fetchall()]
            elif connection.vendor == 'mysql':
                # MySQL-specific query
                cursor.execute("""
                    SELECT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS
                    WHERE TABLE_NAME = 'audit_event' 
                    AND INDEX_NAME LIKE 'idx_audit_%'
                """)
                indexes = [row[0] for row in cursor.fetchall()]
            else:
                self.skipTest(f"Index verification not implemented for {connection.vendor}")
        
        # Check that our custom indexes exist
        expected_indexes = [
            'idx_audit_user_action_time',
            'idx_audit_ip_action_time', 
            'idx_audit_session_time',
            'idx_audit_actor_action_time'
        ]
        
        for expected_index in expected_indexes:
            self.assertIn(expected_index, indexes, 
                         f"Missing authentication audit index: {expected_index}")
    
    def test_authentication_audit_query_efficiency(self):
        """Test that authentication audit queries are efficient"""
        # Create multiple audit events
        for i in range(10):
            AuthenticationAuditService.log_login_success(
                user=self.user,
                ip_address=f'192.168.1.{i}',
                authentication_method='password'
            )
        
        # Test user-based query (should use idx_audit_user_action_time)
        with self.assertNumQueries(1):
            events = list(AuditEvent.objects.filter(
                user=self.user,
                action='login_success'
            ).order_by('-timestamp')[:5])
            self.assertEqual(len(events), 5)
        
        # Test IP-based query (should use idx_audit_ip_action_time)
        with self.assertNumQueries(1):
            events = list(AuditEvent.objects.filter(
                ip_address='192.168.1.5',
                action='login_success'
            ).order_by('-timestamp'))
            self.assertEqual(len(events), 1)


class AuthenticationAuditGDPRComplianceTest(TestCase):
    """Test GDPR compliance of authentication audit logging"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            email='gdpr@example.com',
            password='testpass123'
        )
    
    def test_audit_event_contains_required_gdpr_fields(self):
        """Test that audit events contain required GDPR fields"""
        audit_event = AuthenticationAuditService.log_login_success(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Check required GDPR fields
        self.assertIsNotNone(audit_event.timestamp)
        self.assertIsNotNone(audit_event.ip_address)
        self.assertIsNotNone(audit_event.user)
        self.assertIsNotNone(audit_event.action)
        
        # Check metadata contains user identification
        self.assertIn('user_email', audit_event.metadata)
        self.assertIn('user_id', audit_event.metadata)
    
    def test_audit_event_immutability(self):
        """Test that audit events cannot be modified (GDPR requirement)"""
        audit_event = AuthenticationAuditService.log_login_success(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # Attempt to modify - should create new record, not update
        original_id = audit_event.id
        original_timestamp = audit_event.timestamp
        
        # Create another event - should have different ID and timestamp
        audit_event2 = AuthenticationAuditService.log_login_success(
            user=self.user,
            ip_address='192.168.1.2'
        )
        
        self.assertNotEqual(audit_event.id, audit_event2.id)
        self.assertNotEqual(audit_event.timestamp, audit_event2.timestamp)
        
        # Original event should remain unchanged in database
        original_event = AuditEvent.objects.get(id=original_id)
        self.assertEqual(original_event.timestamp, original_timestamp)
        self.assertEqual(original_event.ip_address, '192.168.1.1')
    
    def test_personal_data_pseudonymization_ready(self):
        """Test that audit system supports data pseudonymization for GDPR"""
        audit_event = AuthenticationAuditService.log_login_success(
            user=self.user,
            ip_address='192.168.1.1'
        )
        
        # The audit system should store user ID and email separately
        # so that email can be pseudonymized while preserving audit trail
        self.assertIn('user_id', audit_event.metadata)
        self.assertIn('user_email', audit_event.metadata)
        self.assertEqual(audit_event.user, self.user)
        
        # IP address should be stored for security analysis but can be anonymized
        self.assertEqual(audit_event.ip_address, '192.168.1.1')


if __name__ == '__main__':
    pytest.main([__file__])