"""
Test suite for users.urls module

This module tests URL patterns and routing in apps.users.urls to achieve 100% coverage.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import resolve, reverse


class UsersURLsTest(TestCase):
    """Test URL patterns for users app"""
    
    def test_login_url(self) -> None:
        """Test login URL pattern"""
        url = reverse('users:login')
        self.assertEqual(url, '/users/login/')
        
        resolver = resolve('/users/login/')
        self.assertEqual(resolver.view_name, 'users:login')
        self.assertEqual(resolver.func.__name__, 'login_view')
    
    def test_logout_url(self) -> None:
        """Test logout URL pattern"""
        url = reverse('users:logout')
        self.assertEqual(url, '/users/logout/')
        
        resolver = resolve('/users/logout/')
        self.assertEqual(resolver.view_name, 'users:logout')
        self.assertEqual(resolver.func.__name__, 'logout_view')
    
    def test_register_url(self) -> None:
        """Test register URL pattern"""
        url = reverse('users:register')
        self.assertEqual(url, '/users/register/')
        
        resolver = resolve('/users/register/')
        self.assertEqual(resolver.view_name, 'users:register')
        self.assertEqual(resolver.func.__name__, 'register_view')
    
    def test_password_reset_urls(self) -> None:
        """Test password reset URL patterns"""
        # Password reset request
        url = reverse('users:password_reset')
        self.assertEqual(url, '/users/password-reset/')
        
        # Password reset done
        url = reverse('users:password_reset_done')
        self.assertEqual(url, '/users/password-reset/done/')
        
        # Password reset confirm
        url = reverse('users:password_reset_confirm', kwargs={'uidb64': 'test', 'token': 'test'})
        self.assertEqual(url, '/users/password-reset-confirm/test/test/')
        
        # Password reset complete
        url = reverse('users:password_reset_complete')
        self.assertEqual(url, '/users/password-reset-complete/')
    
    def test_password_change_url(self) -> None:
        """Test password change URL pattern"""
        url = reverse('users:password_change')
        self.assertEqual(url, '/users/password-change/')
    
    def test_two_factor_urls(self) -> None:
        """Test two-factor authentication URL patterns"""
        # Method selection
        url = reverse('users:two_factor_setup')
        self.assertEqual(url, '/users/2fa/setup/')
        
        # TOTP setup
        url = reverse('users:two_factor_setup_totp')
        self.assertEqual(url, '/users/2fa/setup/totp/')
        
        # WebAuthn setup
        url = reverse('users:two_factor_setup_webauthn')
        self.assertEqual(url, '/users/2fa/setup/webauthn/')
        
        # Verify
        url = reverse('users:two_factor_verify')
        self.assertEqual(url, '/users/2fa/verify/')
        
        # Backup codes
        url = reverse('users:two_factor_backup_codes')
        self.assertEqual(url, '/users/2fa/backup-codes/')
        
        # Regenerate backup codes
        url = reverse('users:two_factor_regenerate_backup_codes')
        self.assertEqual(url, '/users/2fa/regenerate-backup-codes/')
        
        # Disable
        url = reverse('users:two_factor_disable')
        self.assertEqual(url, '/users/2fa/disable/')
    
    def test_profile_url(self) -> None:
        """Test user profile URL pattern"""
        url = reverse('users:user_profile')
        self.assertEqual(url, '/users/profile/')
        
        resolver = resolve('/users/profile/')
        self.assertEqual(resolver.view_name, 'users:user_profile')
        self.assertEqual(resolver.func.__name__, 'user_profile')
    
    def test_user_management_urls(self) -> None:
        """Test user management URL patterns"""
        # User list
        url = reverse('users:user_list')
        self.assertEqual(url, '/users/users/')
        
        resolver = resolve('/users/users/')
        self.assertEqual(resolver.view_name, 'users:user_list')
        
        # User detail
        url = reverse('users:user_detail', kwargs={'pk': 1})
        self.assertEqual(url, '/users/users/1/')
        
        resolver = resolve('/users/users/1/')
        self.assertEqual(resolver.view_name, 'users:user_detail')
        self.assertEqual(resolver.kwargs, {'pk': 1})
    
    def test_api_urls(self) -> None:
        """Test API endpoint URL patterns"""
        url = reverse('users:api_check_email')
        self.assertEqual(url, '/users/api/check-email/')
        
        resolver = resolve('/users/api/check-email/')
        self.assertEqual(resolver.view_name, 'users:api_check_email')
        self.assertEqual(resolver.func.__name__, 'api_check_email')
    
    def test_app_name(self) -> None:
        """Test app_name is set correctly"""
        # This is tested implicitly in the reverse() calls above
        # but we can also test it explicitly
        from apps.users.urls import app_name
        self.assertEqual(app_name, 'users')
    
    def test_all_urls_resolvable(self) -> None:
        """Test all URL patterns are resolvable"""
        url_patterns = [
            'users:login',
            'users:logout', 
            'users:register',
            'users:password_reset',
            'users:password_reset_done',
            'users:password_reset_complete',
            'users:password_change',
            'users:two_factor_setup',
            'users:two_factor_setup_totp',
            'users:two_factor_setup_webauthn',
            'users:two_factor_verify',
            'users:two_factor_backup_codes',
            'users:two_factor_regenerate_backup_codes',
            'users:two_factor_disable',
            'users:user_profile',
            'users:user_list',
            'users:api_check_email',
        ]
        
        for pattern in url_patterns:
            try:
                url = reverse(pattern)
                self.assertIsNotNone(url)
            except Exception as e:
                self.fail(f"URL pattern {pattern} is not resolvable: {e}")
        
        # URLs with parameters
        parameterized_patterns = [
            ('users:password_reset_confirm', {'uidb64': 'test', 'token': 'test'}),
            ('users:user_detail', {'pk': 1}),
        ]
        
        for pattern, kwargs in parameterized_patterns:
            try:
                url = reverse(pattern, kwargs=kwargs if isinstance(kwargs, dict) else None)
                self.assertIsNotNone(url)
            except Exception as e:
                self.fail(f"URL pattern {pattern} with kwargs {kwargs} is not resolvable: {e}")
