"""
Tests for Session Security functionality in PRAHO Platform
Comprehensive security testing for Romanian hosting provider compliance.
"""

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.sessions.models import Session
from django.core.cache import cache
from django.test import Client, RequestFactory, TestCase

from apps.audit.models import AuditEvent
from apps.common.middleware import SessionSecurityMiddleware
from apps.common.request_ip import get_safe_client_ip
from apps.users.models import UserSession
from apps.users.services import SessionSecurityService

User = get_user_model()


class SessionSecurityServiceTestCase(TestCase):
    """Test SessionSecurityService functionality"""

    def setUp(self):
        cache.clear()  # Clear cache before each test
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
        self.user.set_password('testpass123')
        self.user.save()

        # Create admin user for role testing
        self.admin_user = User.objects.create_user(
            email='admin@example.com',
            first_name='Admin',
            last_name='User',
            staff_role='admin'
        )
        self.admin_user.set_password('adminpass123')
        self.admin_user.save()

    def _get_authenticated_request(self, path='/', method='GET', user=None):
        """Helper to create authenticated request with session"""
        request = self.factory.get(path) if method == 'GET' else self.factory.post(path)

        request.user = user or self.user

        # Add session middleware
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()

        return request

    def test_timeout_policies_defined(self):
        """Test that timeout policies are properly defined"""
        policies = SessionSecurityService._DEFAULT_TIMEOUT_POLICIES

        self.assertIn('standard', policies)
        self.assertIn('sensitive', policies)
        self.assertIn('remember_me', policies)
        self.assertNotIn('shared_device', policies)  # the mode was removed: nothing switched it on

        # Verify timeout values are reasonable
        self.assertEqual(policies['standard'], 3600)  # 1 hour
        self.assertEqual(policies['sensitive'], 1800)  # 30 min
        self.assertEqual(policies['remember_me'], 86400 * 7)  # 7 days

    def test_get_appropriate_timeout_standard(self):
        """Test standard timeout for regular users"""
        request = self._get_authenticated_request()
        timeout = SessionSecurityService.get_appropriate_timeout(request)
        self.assertEqual(timeout, 3600)

    def test_get_appropriate_timeout_admin(self):
        """Test sensitive timeout for admin users"""
        request = self._get_authenticated_request(user=self.admin_user)
        timeout = SessionSecurityService.get_appropriate_timeout(request)
        self.assertEqual(timeout, 1800)  # Admin gets shorter timeout

    def test_get_appropriate_timeout_remember_me(self):
        """Test remember me timeout"""
        request = self._get_authenticated_request()
        request.session['remember_me'] = True

        timeout = SessionSecurityService.get_appropriate_timeout(request)
        self.assertEqual(timeout, 86400 * 7)  # Remember me gets longest timeout

    @patch('apps.users.services.log_security_event')
    def test_update_session_timeout(self, mock_log):
        """Test session timeout update with logging"""
        request = self._get_authenticated_request()

        SessionSecurityService.update_session_timeout(request)

        # Check that session expiry was set
        self.assertIsNotNone(request.session.get_expiry_age())

        # Check that security event was logged
        mock_log.assert_called_once()
        args = mock_log.call_args[0]
        self.assertEqual(args[0], 'session_timeout_updated')

    @patch('apps.users.services.log_security_event')
    @patch('apps.users.services.cache')  # Mock the cache to control behavior
    def test_detect_suspicious_activity_multiple_ips(self, mock_cache, mock_log):
        """Test detection of suspicious activity with multiple IPs"""
        request = self._get_authenticated_request()

        # Mock cache to simulate storing/retrieving IP history, whatever shape the service stores
        stored: dict[str, object] = {}
        def mock_cache_get(key, default=None):
            if key.startswith('recent_ips:'):
                return stored.get(key, default)
            return default

        def mock_cache_set(key, value, timeout=None):
            if key.startswith('recent_ips:'):
                stored[key] = value

        mock_cache.get.side_effect = mock_cache_get
        mock_cache.set.side_effect = mock_cache_set

        # Simulate multiple IP addresses in quick succession
        with patch('apps.users.services.get_safe_client_ip') as mock_ip:
            # First IP
            mock_ip.return_value = '192.168.1.1'
            is_suspicious = SessionSecurityService.detect_suspicious_activity(request)
            self.assertFalse(is_suspicious)

            # Second IP
            mock_ip.return_value = '192.168.1.2'
            is_suspicious = SessionSecurityService.detect_suspicious_activity(request)
            self.assertFalse(is_suspicious)

            # Third IP - should trigger suspicious activity
            mock_ip.return_value = '192.168.1.3'
            is_suspicious = SessionSecurityService.detect_suspicious_activity(request)
            self.assertTrue(is_suspicious)

        # Check that suspicious activity was logged
        mock_log.assert_called()
        logged_event = None
        for call_args in mock_log.call_args_list:
            if call_args[0][0] == 'suspicious_activity_detected':
                logged_event = call_args
                break

        self.assertIsNotNone(logged_event)
        event_data = logged_event[0][1]
        self.assertEqual(event_data['pattern'], 'multiple_ips')
        self.assertEqual(event_data['ip_count'], 3)

    @patch('apps.users.services.log_security_event')
    def test_rotate_session_on_password_change(self, mock_log):
        """Test session rotation after password change"""
        request = self._get_authenticated_request()
        old_session_key = request.session.session_key

        SessionSecurityService.rotate_session_on_password_change(request)

        new_session_key = request.session.session_key

        # Session key should have changed
        self.assertNotEqual(old_session_key, new_session_key)

        # Security event should be logged
        mock_log.assert_called()
        args = mock_log.call_args[0]
        self.assertEqual(args[0], 'session_rotated_password_change')

    @patch('apps.users.services.log_security_event')
    def test_rotate_session_on_2fa_change(self, mock_log):
        """Test session rotation after 2FA change"""
        request = self._get_authenticated_request()
        old_session_key = request.session.session_key

        SessionSecurityService.rotate_session_on_2fa_change(request)

        new_session_key = request.session.session_key

        # Session key should have changed
        self.assertNotEqual(old_session_key, new_session_key)

        # Security event should be logged
        mock_log.assert_called()
        args = mock_log.call_args[0]
        self.assertEqual(args[0], 'session_rotated_2fa_change')

    @patch('apps.users.services.log_security_event')
    def test_password_reset_keeps_enrolled_2fa(self, mock_log):
        """A password reset keeps enrolled 2FA (#595).

        This asserted the opposite: that recovery cleared the secret and backup codes, so a
        reset link alone yielded a login with no second factor. The API reset already kept it.
        """
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = 'test_secret'
        self.user.backup_tokens = ['token1', 'token2']
        self.user.save()

        SessionSecurityService.secure_account_after_password_reset(self.user, '192.168.1.1')

        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
        self.assertEqual(self.user.two_factor_secret, 'test_secret')
        self.assertEqual(self.user.backup_tokens, ['token1', 'token2'])

        mock_log.assert_called()
        args = mock_log.call_args[0]
        self.assertEqual(args[0], 'sessions_revoked_password_reset')

    def testget_safe_client_ip_x_forwarded_for(self):
        """Test IP extraction from X-Forwarded-For header"""
        request = self.factory.get('/')
        request.META['HTTP_X_FORWARDED_FOR'] = '192.168.1.1, 10.0.0.1'
        request.META['REMOTE_ADDR'] = '127.0.0.1'

        # SessionSecurityService uses get_safe_client_ip from apps.common.request_ip
        ip = get_safe_client_ip(request)
        # In development mode, X-Forwarded-For is ignored for security
        self.assertEqual(ip, '127.0.0.1')

    def testget_safe_client_ip_remote_addr(self):
        """Test IP extraction from REMOTE_ADDR"""
        request = self.factory.get('/')
        request.META['REMOTE_ADDR'] = '192.168.1.1'

        # SessionSecurityService uses get_safe_client_ip from apps.common.request_ip
        ip = get_safe_client_ip(request)
        self.assertEqual(ip, '192.168.1.1')

    def test_invalidate_other_user_sessions(self) -> None:
        first, second = Client(), Client()
        first.force_login(self.user)
        second.force_login(self.user)
        old_keys = {first.session.session_key, second.session.session_key}
        request = self.factory.get("/")
        request.user = self.user
        request.session = first.session

        SessionSecurityService.rotate_session_on_2fa_change(request)

        current_key = request.session.session_key
        self.assertNotIn(current_key, old_keys)
        self.assertFalse(Session.objects.filter(session_key__in=old_keys).exists())
        self.assertTrue(Session.objects.filter(session_key=current_key).exists())
        self.assertEqual(
            list(UserSession.objects.filter(user=self.user).values_list("session_key", flat=True)),
            [current_key],
        )


class SessionSecurityMiddlewareTestCase(TestCase):
    """Test SessionSecurityMiddleware functionality"""

    def setUp(self):
        self.factory = RequestFactory()
        self.middleware = SessionSecurityMiddleware(lambda r: MagicMock())
        self.user = User.objects.create_user(
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )
        self.user.set_password('testpass123')
        self.user.save()

    def _get_authenticated_request(self, path='/', user=None):
        """Helper to create authenticated request"""
        request = self.factory.get(path)
        request.user = user or self.user

        # Add session middleware
        session_middleware = SessionMiddleware(lambda r: None)
        session_middleware.process_request(request)
        request.session.save()

        return request

    def test_middleware_processes_authenticated_users(self):
        """Test middleware only processes authenticated users"""
        # Unauthenticated request
        request = self.factory.get('/')
        request.user = MagicMock(is_authenticated=False)

        with patch.object(self.middleware, '_process_session_security') as mock_process:
            self.middleware(request)
            mock_process.assert_not_called()

    @patch('apps.users.services.SessionSecurityService.update_session_timeout')
    @patch('apps.users.services.SessionSecurityService.detect_suspicious_activity')
    def test_middleware_processes_session_security(self, mock_detect, mock_timeout):
        """The timeout and the multiple-address check run on each request (#622)."""
        request = self._get_authenticated_request('/users/profile/')
        mock_detect.return_value = False

        self.middleware(request)

        mock_timeout.assert_called_once_with(request)
        mock_detect.assert_called_once_with(request)

    def test_no_path_or_method_logs_session_activity(self):
        """Replaces the tests of the removed path and activity-type helpers (#622).

        Those helpers chose which requests wrote a `session_activity_*` audit row. Every path
        they matched, and the public ones they skipped, now pass without one, for any method.
        """
        paths = [
            '/users/profile/', '/billing/invoices/', '/customers/list/', '/admin/users/',
            '/api/customers/', '/settings/security/', '/tickets/create/', '/', '/pricing/',
        ]
        for path in paths:
            for method in ('get', 'post', 'put', 'patch', 'delete'):
                with self.subTest(path=path, method=method):
                    request = getattr(self.factory, method)(path)
                    request.user = self.user
                    SessionMiddleware(lambda r: None).process_request(request)
                    request.session.save()

                    self.middleware(request)

        self.assertFalse(AuditEvent.objects.filter(action__startswith='session_activity_').exists())

    def test_add_security_headers(self):
        """Test addition of security headers"""
        request = self._get_authenticated_request()
        request.session.set_expiry(1800)  # 30 minutes

        response = MagicMock()
        self.middleware._add_security_headers(request, response)

        header_names = [call[0][0] for call in response.__setitem__.call_args_list]
        self.assertEqual(header_names, ['X-Session-Timeout'])


class SessionSecurityIntegrationTest(TestCase):
    """Integration tests for complete session security workflow"""

    def setUp(self):
        self.user = User.objects.create_user(
            email='integration@example.com',
            first_name='Integration',
            last_name='Test'
        )
        self.user.set_password('integrationpass123')
        self.user.save()

        # Enable 2FA for testing
        self.user.two_factor_enabled = True
        self.user.two_factor_secret = 'test_secret'
        self.user.backup_tokens = ['backup1', 'backup2']
        self.user.save()

    def test_password_reset_workflow(self):
        """A password reset keeps enrolled 2FA (#595); it used to assert that 2FA was cleared."""
        # Test the service directly without mocking
        SessionSecurityService.secure_account_after_password_reset(self.user)

        self.user.refresh_from_db()
        self.assertTrue(self.user.two_factor_enabled)
        self.assertEqual(self.user.backup_tokens, ['backup1', 'backup2'])

    @patch('apps.users.services.log_security_event')
    def test_complete_session_security_lifecycle(self, mock_log):
        """Test complete session security lifecycle"""
        client = Client()

        # 1. Login (creates session)
        client.force_login(self.user)

        # 2. A request on that session
        request = RequestFactory().get('/')
        request.user = self.user
        middleware = SessionMiddleware(lambda r: None)
        middleware.process_request(request)
        request.session.save()

        # 3. Detect suspicious activity
        SessionSecurityService.detect_suspicious_activity(request)

        # 4. Update timeouts
        SessionSecurityService.update_session_timeout(request)

        # 5. Rotate session
        SessionSecurityService.rotate_session_on_2fa_change(request)

        # The exact events, in order. Step 4 sets the timeout for the first time, so it is
        # audited (#553); step 3 saw one IP, below the suspicious-activity threshold.
        logged_events = [call[0][0] for call in mock_log.call_args_list]
        self.assertEqual(logged_events, ['session_timeout_updated', 'session_rotated_2fa_change'])


# Test cleanup function
def clear_test_cache():
    """Clear cache between tests to avoid interference"""
    cache.clear()
