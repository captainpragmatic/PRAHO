"""Smoke tests for legal views (privacy, terms, cookie, data processors).

Validates that all 4 legal views return HTTP 200 with correct datetime usage.
"""

from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase

from apps.common.legal_views import cookie_policy, data_processors, privacy_policy, terms_of_service


class LegalViewsSmokeTestCase(TestCase):
    """Smoke tests verifying all legal views return HTTP 200."""

    def setUp(self):
        self.factory = RequestFactory()

    def _make_request(self, path):
        """Create a GET request with an anonymous user attached."""
        request = self.factory.get(path)
        request.user = AnonymousUser()
        return request

    def test_privacy_policy_returns_200(self):
        request = self._make_request("/privacy-policy/")
        response = privacy_policy(request)
        self.assertEqual(response.status_code, 200)

    def test_terms_of_service_returns_200(self):
        request = self._make_request("/terms-of-service/")
        response = terms_of_service(request)
        self.assertEqual(response.status_code, 200)

    def test_cookie_policy_returns_200(self):
        request = self._make_request("/cookie-policy/")
        response = cookie_policy(request)
        self.assertEqual(response.status_code, 200)

    def test_data_processors_returns_200(self):
        request = self._make_request("/data-processors/")
        response = data_processors(request)
        self.assertEqual(response.status_code, 200)
