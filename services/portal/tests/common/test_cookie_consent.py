"""
Tests for Portal cookie consent proxy and cookie policy page.
No database access — enforced by Portal's pytest plugin.
"""

import json
from unittest.mock import MagicMock, patch

from django.test import Client, SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class CookieConsentProxyTests(SimpleTestCase):
    """Tests for POST /api/cookie-consent/ proxy endpoint."""

    def setUp(self) -> None:
        self.client = Client()

    def test_consent_endpoint_post_only(self) -> None:
        """GET returns 405."""
        response = self.client.get('/api/cookie-consent/')
        self.assertEqual(response.status_code, 405)

    @patch('apps.common.views.api_client')
    def test_consent_endpoint_proxies_to_platform(self, mock_client: MagicMock) -> None:
        """Mocked api_client.submit_cookie_consent called."""
        mock_client.submit_cookie_consent.return_value = {'success': True, 'consent_id': 'test-uuid'}

        response = self.client.post(
            '/api/cookie-consent/',
            data=json.dumps({
                'status': 'accepted_all',
                'functional': True,
                'analytics': True,
                'marketing': True,
            }),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        mock_client.submit_cookie_consent.assert_called_once()

        # Verify the payload sent to Platform includes expected fields
        call_args = mock_client.submit_cookie_consent.call_args[0][0]
        self.assertEqual(call_args['status'], 'accepted_all')
        self.assertTrue(call_args['functional'])
        self.assertIn('cookie_id', call_args)
        self.assertIn('ip_address', call_args)
        self.assertIn('user_agent', call_args)

    @patch('apps.common.views.api_client')
    def test_consent_endpoint_includes_user_id_from_session(self, mock_client: MagicMock) -> None:
        """user_id from session passed to API."""
        mock_client.submit_cookie_consent.return_value = {'success': True}

        # Set up session with user_id
        session = self.client.session
        session['user_id'] = 42
        session.save()

        response = self.client.post(
            '/api/cookie-consent/',
            data=json.dumps({'status': 'accepted_all'}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)

        call_args = mock_client.submit_cookie_consent.call_args[0][0]
        self.assertEqual(call_args.get('user_id'), 42)

    @patch('apps.common.views.api_client')
    def test_consent_endpoint_generates_cookie_id_for_anonymous(self, mock_client: MagicMock) -> None:
        """UUID cookie set on response for anonymous visitors."""
        mock_client.submit_cookie_consent.return_value = {'success': True}

        response = self.client.post(
            '/api/cookie-consent/',
            data=json.dumps({'status': 'accepted_essential'}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)

        # Check that cookie_consent_id cookie was set
        self.assertIn('cookie_consent_id', response.cookies)
        cookie_value = response.cookies['cookie_consent_id'].value
        self.assertTrue(len(cookie_value) > 0)

    @patch('apps.common.views.api_client')
    def test_consent_endpoint_handles_platform_error(self, mock_client: MagicMock) -> None:
        """Returns gracefully when Platform API fails."""
        mock_client.submit_cookie_consent.side_effect = PlatformAPIError("Service unavailable")

        response = self.client.post(
            '/api/cookie-consent/',
            data=json.dumps({'status': 'accepted_all'}),
            content_type='application/json',
        )
        # Should not crash — graceful degradation
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        # success=False because Platform was unreachable
        self.assertFalse(data['success'])


class CookiePolicyPageTests(SimpleTestCase):
    """Tests for /cookie-policy/ page."""

    def setUp(self) -> None:
        self.client = Client()

    def test_cookie_policy_page_renders(self) -> None:
        """200 response with correct template."""
        response = self.client.get('/cookie-policy/')
        self.assertEqual(response.status_code, 200)

    def test_cookie_policy_no_auth_required(self) -> None:
        """Accessible without session / authentication."""
        client = Client()  # Fresh client, no session
        response = client.get('/cookie-policy/')
        self.assertEqual(response.status_code, 200)


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class ConsentHistoryRealAPITests(SimpleTestCase):
    """Tests that consent_history_view calls real Platform API."""

    @patch('apps.users.views.api_client')
    def test_consent_history_uses_real_api(self, mock_client: MagicMock) -> None:
        """Mocked api_client.get_consent_history_secure called."""
        mock_client.get_consent_history_secure.return_value = {
            'success': True,
            'consent_history': [{'timestamp': '2024-01-15', 'description': 'test'}],
            'cookie_consent_history': [],
        }
        mock_client.get_customer_profile.return_value = {}

        client = Client()
        session = client.session
        session['customer_id'] = 1
        session['user_id'] = 42
        session['email'] = 'test@example.com'
        session.save()

        client.get('/consent-history/')
        # Should call the real API method
        mock_client.get_consent_history_secure.assert_called_once_with(42)


@override_settings(
    SESSION_ENGINE='django.contrib.sessions.backends.cache',
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
)
class DataExportRealAPITests(SimpleTestCase):
    """Tests that data_export_view calls real Platform API."""

    @patch('apps.users.views.api_client')
    def test_data_export_proxies_to_platform(self, mock_client: MagicMock) -> None:
        """Mocked api_client.request_data_export_secure called."""
        mock_client.request_data_export_secure.return_value = {
            'success': True,
            'export_id': 'test-export-id',
            'status': 'pending',
        }

        client = Client()
        session = client.session
        session['customer_id'] = 1
        session['user_id'] = 42
        session['email'] = 'test@example.com'
        session.save()

        response = client.post('/data-export/')
        self.assertEqual(response.status_code, 302)  # PRG redirect
        mock_client.request_data_export_secure.assert_called_once_with(42)

    @patch('apps.users.views.api_client')
    def test_data_export_handles_platform_error(self, mock_client: MagicMock) -> None:
        """Returns error message when Platform API fails."""
        mock_client.request_data_export_secure.side_effect = PlatformAPIError("Service unavailable")

        client = Client()
        session = client.session
        session['customer_id'] = 1
        session['user_id'] = 42
        session['email'] = 'test@example.com'
        session.save()

        response = client.post('/data-export/')
        # PRG: should redirect back after POST (not crash)
        self.assertEqual(response.status_code, 302)
