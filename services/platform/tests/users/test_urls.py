"""
Test suite for users.urls module

This module tests URL patterns and routing in apps.users.urls to achieve 100% coverage.

Note: Registration and password reset URLs were moved to Portal service in the
app-separation architecture. Platform only handles authenticated user operations.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import resolve, reverse


class UsersURLsTest(TestCase):
    """Test URL patterns for users app"""

    def test_login_url(self) -> None:
        """Test login URL pattern"""
        url = reverse('users:login')
        self.assertEqual(url, '/auth/login/')

        resolver = resolve('/auth/login/')
        self.assertEqual(resolver.view_name, 'users:login')
        self.assertEqual(resolver.func.__name__, 'login_view')

    def test_logout_url(self) -> None:
        """Test logout URL pattern"""
        url = reverse('users:logout')
        self.assertEqual(url, '/auth/logout/')

        resolver = resolve('/auth/logout/')
        self.assertEqual(resolver.view_name, 'users:logout')
        self.assertEqual(resolver.func.__name__, 'logout_view')

    def test_password_change_url(self) -> None:
        """Test password change URL pattern"""
        url = reverse('users:password_change')
        self.assertEqual(url, '/auth/password-change/')

    def test_two_factor_urls(self) -> None:
        """Test two-factor authentication URL patterns"""
        # Method selection
        url = reverse('users:mfa_setup')
        self.assertEqual(url, '/auth/mfa/setup/')

        # TOTP setup
        url = reverse('users:mfa_setup_totp')
        self.assertEqual(url, '/auth/mfa/setup/totp/')

        # WebAuthn setup
        url = reverse('users:mfa_setup_webauthn')
        self.assertEqual(url, '/auth/mfa/setup/webauthn/')

        # Verify
        url = reverse('users:mfa_verify')
        self.assertEqual(url, '/auth/mfa/verify/')

        # Backup codes
        url = reverse('users:mfa_backup_codes')
        self.assertEqual(url, '/auth/mfa/backup-codes/')

        # Regenerate backup codes
        url = reverse('users:mfa_regenerate_backup_codes')
        self.assertEqual(url, '/auth/mfa/regenerate-backup-codes/')

        # Disable
        url = reverse('users:mfa_disable')
        self.assertEqual(url, '/auth/mfa/disable/')

    def test_profile_url(self) -> None:
        """Test user profile URL pattern"""
        url = reverse('users:user_profile')
        self.assertEqual(url, '/auth/profile/')

        resolver = resolve('/auth/profile/')
        self.assertEqual(resolver.view_name, 'users:user_profile')
        self.assertEqual(resolver.func.__name__, 'user_profile')

    def test_user_management_urls(self) -> None:
        """Test user management URL patterns"""
        # User list
        url = reverse('users:user_list')
        self.assertEqual(url, '/auth/users/')

        resolver = resolve('/auth/users/')
        self.assertEqual(resolver.view_name, 'users:user_list')

        # User detail
        url = reverse('users:user_detail', kwargs={'pk': 1})
        self.assertEqual(url, '/auth/users/1/')

        resolver = resolve('/auth/users/1/')
        self.assertEqual(resolver.view_name, 'users:user_detail')
        self.assertEqual(resolver.kwargs, {'pk': 1})

    def test_api_urls(self) -> None:
        """Test API endpoint URL patterns"""
        url = reverse('users:api_check_email')
        self.assertEqual(url, '/auth/api/check-email/')

        resolver = resolve('/auth/api/check-email/')
        self.assertEqual(resolver.view_name, 'users:api_check_email')
        self.assertEqual(resolver.func.__name__, 'api_check_email')

    def test_app_name(self) -> None:
        """Test app_name is set correctly"""
        from apps.users.urls import app_name
        self.assertEqual(app_name, 'users')

    def test_all_urls_resolvable(self) -> None:
        """Test all URL patterns are resolvable"""
        url_patterns = [
            'users:login',
            'users:logout',
            'users:password_change',
            'users:mfa_setup',
            'users:mfa_setup_totp',
            'users:mfa_setup_webauthn',
            'users:mfa_verify',
            'users:mfa_backup_codes',
            'users:mfa_regenerate_backup_codes',
            'users:mfa_disable',
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
            ('users:user_detail', {'pk': 1}),
        ]

        for pattern, kwargs in parameterized_patterns:
            try:
                url = reverse(pattern, kwargs=kwargs if isinstance(kwargs, dict) else None)
                self.assertIsNotNone(url)
            except Exception as e:
                self.fail(f"URL pattern {pattern} with kwargs {kwargs} is not resolvable: {e}")
