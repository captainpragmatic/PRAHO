"""
Tests for Platform GDPR API endpoints.

Endpoints tested:
- POST /api/gdpr/cookie-consent/
- POST /api/gdpr/consent-history/
- POST /api/gdpr/data-export/
"""

import time

from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory
from tests.factories.core_factories import UserCreationRequest, create_user

from apps.api.gdpr.views import consent_history_api, cookie_consent_api, data_export_api
from apps.audit.models import CookieConsent


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class CookieConsentAPITests(TestCase):
    """Tests for POST /api/gdpr/cookie-consent/"""

    def setUp(self) -> None:
        self.factory = APIRequestFactory()
        self.user = create_user(UserCreationRequest(
            username='gdpr_user',
            email='gdpr@test.com',
        ))

    def _make_request(self, data: dict, authenticated: bool = True):
        """Create HMAC-authenticated DRF request."""
        if 'timestamp' not in data:
            data['timestamp'] = time.time()
        request = self.factory.post(
            '/api/gdpr/cookie-consent/',
            data=data,
            format='json',
        )
        if authenticated:
            request._portal_authenticated = True
        return request

    def test_cookie_consent_anonymous(self) -> None:
        """CookieConsent created with cookie_id, no user."""
        request = self._make_request({
            'cookie_id': 'anon-test-id-123',
            'status': 'accepted_all',
            'functional': True,
            'analytics': True,
            'marketing': True,
        })
        response = cookie_consent_api(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['success'])
        consent = CookieConsent.objects.get(cookie_id='anon-test-id-123')
        self.assertIsNone(consent.user)
        self.assertEqual(consent.status, 'accepted_all')
        self.assertTrue(consent.functional_cookies)
        self.assertTrue(consent.analytics_cookies)
        self.assertTrue(consent.marketing_cookies)

    def test_cookie_consent_authenticated(self) -> None:
        """CookieConsent linked to user when user_id provided."""
        request = self._make_request({
            'cookie_id': 'auth-test-id',
            'status': 'customized',
            'functional': True,
            'analytics': False,
            'marketing': False,
            'user_id': self.user.id,
        })
        response = cookie_consent_api(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['success'])
        consent = CookieConsent.objects.get(user=self.user)
        self.assertEqual(consent.status, 'customized')
        self.assertTrue(consent.functional_cookies)
        self.assertFalse(consent.analytics_cookies)

    def test_cookie_consent_anonymous_to_user_linkage(self) -> None:
        """Anonymous records linked when user_id provided with same cookie_id."""
        # Step 1: anonymous consent
        req1 = self._make_request({
            'cookie_id': 'linkage-test-id',
            'status': 'accepted_all',
            'functional': True,
            'analytics': True,
            'marketing': True,
        })
        cookie_consent_api(req1)
        anon_consent = CookieConsent.objects.get(cookie_id='linkage-test-id', user__isnull=True)
        self.assertIsNotNone(anon_consent)

        # Step 2: authenticated consent with same cookie_id
        req2 = self._make_request({
            'cookie_id': 'linkage-test-id',
            'status': 'customized',
            'functional': True,
            'analytics': False,
            'marketing': False,
            'user_id': self.user.id,
        })
        cookie_consent_api(req2)

        # The anonymous record should now be linked to the user
        anon_consent.refresh_from_db()
        self.assertEqual(anon_consent.user, self.user)

    def test_cookie_consent_update_replaces_previous(self) -> None:
        """update_or_create semantics: second call updates, not duplicates."""
        data = {
            'cookie_id': 'update-test-id',
            'status': 'accepted_essential',
            'functional': False,
            'analytics': False,
            'marketing': False,
        }
        cookie_consent_api(self._make_request(data))
        self.assertEqual(CookieConsent.objects.filter(cookie_id='update-test-id').count(), 1)

        data['status'] = 'accepted_all'
        data['functional'] = True
        data['analytics'] = True
        data['marketing'] = True
        cookie_consent_api(self._make_request(data))
        self.assertEqual(CookieConsent.objects.filter(cookie_id='update-test-id').count(), 1)
        consent = CookieConsent.objects.get(cookie_id='update-test-id')
        self.assertEqual(consent.status, 'accepted_all')

    def test_no_duplicate_when_linking_then_resubmitting(self) -> None:
        """Regression: anonymous→user link + re-submit must not raise MultipleObjectsReturned."""
        # Step 1: anonymous consent
        cookie_consent_api(self._make_request({
            'cookie_id': 'regression-test-id',
            'status': 'accepted_all',
            'functional': True, 'analytics': True, 'marketing': True,
        }))

        # Step 2: same cookie_id, now authenticated
        cookie_consent_api(self._make_request({
            'cookie_id': 'regression-test-id',
            'status': 'customized',
            'functional': True, 'analytics': False, 'marketing': False,
            'user_id': self.user.id,
        }))

        # Step 3: re-submit as same user (would have raised MultipleObjectsReturned
        # if lookup used user= instead of cookie_id=)
        response = cookie_consent_api(self._make_request({
            'cookie_id': 'regression-test-id',
            'status': 'accepted_all',
            'functional': True, 'analytics': True, 'marketing': True,
            'user_id': self.user.id,
        }))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['success'])
        self.assertEqual(
            CookieConsent.objects.filter(cookie_id='regression-test-id').count(), 1,
        )

    def test_cookie_consent_invalid_data_400(self) -> None:
        """Missing required fields return 400."""
        request = self._make_request({
            'status': 'accepted_all',
            # Missing cookie_id
        })
        response = cookie_consent_api(request)
        self.assertEqual(response.status_code, 400)

    def test_cookie_consent_no_hmac_401(self) -> None:
        """Request without HMAC auth returns 401."""
        request = self._make_request(
            {'cookie_id': 'test', 'status': 'accepted_all'},
            authenticated=False,
        )
        response = cookie_consent_api(request)
        self.assertEqual(response.status_code, 401)


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class ConsentHistoryAPITests(TestCase):
    """Tests for POST /api/gdpr/consent-history/"""

    def setUp(self) -> None:
        self.factory = APIRequestFactory()
        self.user = create_user(UserCreationRequest(
            username='history_user',
            email='history@test.com',
        ))

    def _make_request(self, data: dict, authenticated: bool = True):
        if 'timestamp' not in data:
            data['timestamp'] = time.time()
        request = self.factory.post(
            '/api/gdpr/consent-history/',
            data=data,
            format='json',
        )
        if authenticated:
            request._portal_authenticated = True
        return request

    def test_consent_history_returns_data(self) -> None:
        """Returns consent history structure for valid user."""
        request = self._make_request({'user_id': self.user.id})
        response = consent_history_api(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['success'])
        self.assertIn('consent_history', response.data)
        self.assertIn('cookie_consent_history', response.data)

    def test_consent_history_requires_user_id(self) -> None:
        """Returns 400 without user_id."""
        request = self._make_request({})
        response = consent_history_api(request)
        self.assertEqual(response.status_code, 400)

    def test_consent_history_no_hmac_401(self) -> None:
        """Unauthenticated request rejected."""
        request = self._make_request(
            {'user_id': self.user.id},
            authenticated=False,
        )
        response = consent_history_api(request)
        self.assertEqual(response.status_code, 401)


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class DataExportAPITests(TestCase):
    """Tests for POST /api/gdpr/data-export/"""

    def setUp(self) -> None:
        self.factory = APIRequestFactory()
        self.user = create_user(UserCreationRequest(
            username='export_user',
            email='export@test.com',
        ))

    def _make_request(self, data: dict, authenticated: bool = True):
        if 'timestamp' not in data:
            data['timestamp'] = time.time()
        request = self.factory.post(
            '/api/gdpr/data-export/',
            data=data,
            format='json',
        )
        if authenticated:
            request._portal_authenticated = True
        return request

    def test_data_export_creates_request(self) -> None:
        """DataExport created via GDPRExportService."""
        request = self._make_request({'user_id': self.user.id})
        response = data_export_api(request)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['success'])
        self.assertIn('export_id', response.data)
        self.assertEqual(response.data['status'], 'pending')

    def test_data_export_requires_user_id(self) -> None:
        """Returns 400 without user_id."""
        request = self._make_request({})
        response = data_export_api(request)
        self.assertEqual(response.status_code, 400)

    def test_data_export_no_hmac_401(self) -> None:
        """Unauthenticated request rejected."""
        request = self._make_request(
            {'user_id': self.user.id},
            authenticated=False,
        )
        response = data_export_api(request)
        self.assertEqual(response.status_code, 401)
