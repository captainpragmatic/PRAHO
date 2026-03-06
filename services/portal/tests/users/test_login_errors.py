"""
Portal Login & Auth Error Tests

Verifies that the login and password-change views return correct error feedback
for invalid credentials vs rate-limiting scenarios.
"""

import unittest
from unittest.mock import patch

from django.contrib.messages import get_messages
from django.test import SimpleTestCase, RequestFactory, override_settings
from django.urls import reverse


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class LoginErrorsTestCase(SimpleTestCase):
    """Test that invalid login credentials produce form non_field_errors."""

    def test_invalid_credentials_add_form_error(self):
        """form.add_error(None, ...) is called when authenticate_customer returns falsy."""
        with patch('apps.users.views.api_client') as mock_api:
            mock_api.authenticate_customer.return_value = None

            response = self.client.post(
                reverse('users:login'),
                data={'email': 'wrong@example.com', 'password': 'badpassword'},
            )

        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        non_field_errors = form.non_field_errors()
        self.assertTrue(
            len(non_field_errors) > 0,
            "Expected non_field_errors on the form after invalid login, got none.",
        )

    def test_invalid_credentials_error_text(self):
        """The error message contains the expected text about invalid credentials."""
        with patch('apps.users.views.api_client') as mock_api:
            mock_api.authenticate_customer.return_value = None

            response = self.client.post(
                reverse('users:login'),
                data={'email': 'wrong@example.com', 'password': 'badpassword'},
            )

        form = response.context['form']
        error_text = ' '.join(str(e) for e in form.non_field_errors())
        self.assertIn('Invalid email address or password', error_text)

    def test_invalid_credentials_error_appears_in_html(self):
        """The error text is rendered in the response HTML so users see it."""
        with patch('apps.users.views.api_client') as mock_api:
            mock_api.authenticate_customer.return_value = None

            response = self.client.post(
                reverse('users:login'),
                data={'email': 'wrong@example.com', 'password': 'badpassword'},
            )

        self.assertContains(response, 'Invalid email address or password')

    def test_auth_response_valid_false_adds_form_error(self):
        """When authenticate_customer returns a response but valid=False, form error is added."""
        with patch('apps.users.views.api_client') as mock_api:
            mock_api.authenticate_customer.return_value = {'valid': False}

            response = self.client.post(
                reverse('users:login'),
                data={'email': 'wrong@example.com', 'password': 'badpassword'},
            )

        form = response.context['form']
        self.assertTrue(len(form.non_field_errors()) > 0)

    def test_get_request_returns_empty_form(self):
        """GET request renders the login form with no errors."""
        response = self.client.get(reverse('users:login'))

        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertEqual(len(form.non_field_errors()), 0)

    def test_platform_api_error_does_not_add_form_error(self):
        """PlatformAPIError shows a messages.error() instead of a form error."""
        from apps.api_client.services import PlatformAPIError

        with patch('apps.users.views.api_client') as mock_api:
            mock_api.authenticate_customer.side_effect = PlatformAPIError('unavailable')

            response = self.client.post(
                reverse('users:login'),
                data={'email': 'test@example.com', 'password': 'pass'},
            )

        self.assertEqual(response.status_code, 200)
        # Form itself should have no non_field_errors — the view uses messages.error() instead
        form = response.context['form']
        self.assertEqual(len(form.non_field_errors()), 0)

    def test_rate_limited_login_shows_throttle_message_not_invalid_credentials(self):
        """When Platform returns 429, login should show rate-limit message, NOT 'Invalid email or password'."""
        from apps.api_client.services import PlatformAPIError

        with patch('apps.users.views.api_client') as mock_api:
            mock_api.authenticate_customer.side_effect = PlatformAPIError(
                "Too many requests",
                status_code=429,
                retry_after=30,
                is_rate_limited=True,
            )

            response = self.client.post(
                reverse('users:login'),
                data={'email': 'test@example.com', 'password': 'pass123'},
            )

        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        non_field_errors = form.non_field_errors()
        # Must show rate-limit message, not "Invalid email address or password"
        error_text = ' '.join(str(e) for e in non_field_errors)
        self.assertNotIn('Invalid email address or password', error_text)
        self.assertIn('Too many login attempts', error_text)

    def test_rate_limited_login_includes_retry_after_seconds(self):
        """Rate-limited login error should include the retry-after seconds."""
        from apps.api_client.services import PlatformAPIError

        with patch('apps.users.views.api_client') as mock_api:
            mock_api.authenticate_customer.side_effect = PlatformAPIError(
                "Too many requests",
                status_code=429,
                retry_after=45,
                is_rate_limited=True,
            )

            response = self.client.post(
                reverse('users:login'),
                data={'email': 'test@example.com', 'password': 'pass123'},
            )

        form = response.context['form']
        error_text = ' '.join(str(e) for e in form.non_field_errors())
        self.assertIn('45', error_text)

    def test_missing_password_field_shows_field_error(self):
        """Submitting without a password triggers a field-level validation error."""
        response = self.client.post(
            reverse('users:login'),
            data={'email': 'test@example.com', 'password': ''},
        )

        self.assertEqual(response.status_code, 200)
        form = response.context['form']
        self.assertFalse(form.is_valid())
        self.assertIn('password', form.errors)


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class ChangePasswordRateLimitTestCase(SimpleTestCase):
    """Test that password-change distinguishes 429 from wrong-password."""

    def _login_session(self):
        """Set session keys to simulate an authenticated user."""
        session = self.client.session
        session['customer_id'] = 1
        session['user_id'] = 1
        session['email'] = 'test@example.com'
        session.save()

    def test_password_change_rate_limited_shows_throttle_message(self):
        """When authenticate_customer raises rate-limited PlatformAPIError, show throttle msg."""
        from apps.api_client.services import PlatformAPIError

        self._login_session()
        with patch('apps.users.views.api_client') as mock_api:
            mock_api.authenticate_customer.side_effect = PlatformAPIError(
                "Too many requests",
                status_code=429,
                retry_after=60,
                is_rate_limited=True,
            )

            response = self.client.post(
                reverse('users:change_password'),
                data={
                    'current_password': 'oldpass',
                    'new_password': 'NewStr0ng!Pass',
                    'confirm_password': 'NewStr0ng!Pass',
                },
            )

        self.assertEqual(response.status_code, 200)
        # Should show rate-limit message via messages framework, not "incorrect password"
        msg_texts = [str(m) for m in get_messages(response.wsgi_request)]
        all_text = ' '.join(msg_texts)
        self.assertNotIn('Current password is incorrect', all_text)
        self.assertIn('Too many', all_text)
