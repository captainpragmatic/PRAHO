"""
Tests for the CookieConsent model.
Verifies model creation, status choices, properties, and indexes.
"""

from django.test import TestCase, override_settings

from apps.audit.models import CookieConsent
from tests.factories.core_factories import UserCreationRequest, create_user


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class CookieConsentModelTests(TestCase):
    """Tests for CookieConsent model."""

    def setUp(self) -> None:
        self.user = create_user(UserCreationRequest(
            username='cookie_user',
            email='cookie@test.com',
        ))

    def test_create_consent_authenticated(self) -> None:
        """Model creation with user FK."""
        consent = CookieConsent.objects.create(
            user=self.user,
            status='accepted_all',
            essential_cookies=True,
            functional_cookies=True,
            analytics_cookies=True,
            marketing_cookies=True,
        )
        self.assertEqual(consent.user, self.user)
        self.assertEqual(consent.status, 'accepted_all')
        self.assertTrue(consent.essential_cookies)

    def test_create_consent_anonymous(self) -> None:
        """Model creation with cookie_id (no user)."""
        consent = CookieConsent.objects.create(
            cookie_id='anon-12345',
            status='accepted_essential',
            essential_cookies=True,
        )
        self.assertIsNone(consent.user)
        self.assertEqual(consent.cookie_id, 'anon-12345')
        self.assertEqual(consent.status, 'accepted_essential')

    def test_consent_status_choices(self) -> None:
        """All 5 statuses are valid."""
        valid_statuses = ['pending', 'accepted_all', 'accepted_essential', 'customized', 'withdrawn']
        for status in valid_statuses:
            consent = CookieConsent.objects.create(
                cookie_id=f'status-test-{status}',
                status=status,
            )
            self.assertEqual(consent.status, status)

    def test_has_analytics_consent_property(self) -> None:
        """Property returns correct bool based on status + flag."""
        consent = CookieConsent(status='accepted_all', analytics_cookies=True)
        self.assertTrue(consent.has_analytics_consent)

        consent2 = CookieConsent(status='accepted_essential', analytics_cookies=True)
        self.assertFalse(consent2.has_analytics_consent)

        consent3 = CookieConsent(status='customized', analytics_cookies=False)
        self.assertFalse(consent3.has_analytics_consent)

    def test_has_functional_consent_property(self) -> None:
        """Property returns correct bool based on status + flag."""
        consent = CookieConsent(status='customized', functional_cookies=True)
        self.assertTrue(consent.has_functional_consent)

        consent2 = CookieConsent(status='pending', functional_cookies=True)
        self.assertFalse(consent2.has_functional_consent)

    def test_has_marketing_consent_property(self) -> None:
        """Property returns correct bool based on status + flag."""
        consent = CookieConsent(status='accepted_all', marketing_cookies=True)
        self.assertTrue(consent.has_marketing_consent)

        consent2 = CookieConsent(status='withdrawn', marketing_cookies=True)
        self.assertFalse(consent2.has_marketing_consent)

    def test_consent_indexes_exist(self) -> None:
        """3 composite indexes present in Meta."""
        indexes = CookieConsent._meta.indexes
        self.assertEqual(len(indexes), 3)
        index_fields = [tuple(idx.fields) for idx in indexes]
        self.assertIn(('user', '-updated_at'), index_fields)
        self.assertIn(('cookie_id', '-updated_at'), index_fields)
        self.assertIn(('status', '-created_at'), index_fields)

    def test_str_authenticated(self) -> None:
        """String representation for authenticated consent."""
        consent = CookieConsent(user=self.user, status='accepted_all')
        self.assertIn(self.user.email, str(consent))
        self.assertIn('accepted_all', str(consent))

    def test_str_anonymous(self) -> None:
        """String representation for anonymous consent."""
        consent = CookieConsent(cookie_id='abcdef1234567890', status='customized')
        self.assertIn('cookie:abcdef12', str(consent))
