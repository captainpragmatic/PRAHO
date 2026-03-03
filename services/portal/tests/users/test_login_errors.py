"""
Portal Login Error Tests

Verifies that the login view returns form errors (not just messages) when
credentials are invalid, so templates can render field-level error feedback.
"""

import unittest
from unittest.mock import patch

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
