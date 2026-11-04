"""Real signed customer preference requests update the customer, never user-profile flags."""

from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone, translation

from apps.customers.models import Customer
from apps.notifications.models import EmailPreference
from apps.notifications.services import EmailPreferenceService
from apps.users import portal_sessions
from apps.users.models import CustomerMembership, PortalSession, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.portal_session import BoundSessionMixin, bound_fields


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class QuotaWarningPreferenceTests(BoundSessionMixin, HMACTestMixin, TestCase):
    path = "/api/customers/notification-preferences/"

    def setUp(self):
        self.customer = Customer.objects.create(name="Preference owner", primary_email="quota@example.test")
        self.user = User.objects.create_user("quota@example.test", "fixture-password")
        self.membership = CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner")
        self.body = {"customer_id": self.customer.pk, "user_id": self.user.pk}

    def test_existing_service_maps_actual_quota_and_global_preferences(self):
        preference = EmailPreference.objects.create(customer=self.customer, quota_warnings=False)
        self.assertFalse(EmailPreferenceService.get_preferences(self.customer)["quota_warnings"])
        self.assertFalse(EmailPreferenceService.can_send_category(self.customer, "quota_warnings"))
        EmailPreferenceService.update_preferences(self.customer, {"quota_warnings": True})
        preference.refresh_from_db()
        self.assertTrue(preference.quota_warnings)
        preference.global_unsubscribe = True
        preference.save(update_fields=["global_unsubscribe"])
        self.assertFalse(EmailPreferenceService.can_send_category(self.customer, "quota_warnings"))

    def test_owner_can_read_then_disable_optional_warnings_without_disabling_critical(self):
        response = self.portal_post(self.path, {**self.body, "action": "get"})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(
            response.json()["data"],
            {
                "quota_warnings": True,
                "global_unsubscribe": False,
                "critical_notices": True,
            },
        )
        response = self.portal_post(self.path, {**self.body, "action": "update", "quota_warnings": False})
        self.assertEqual(response.status_code, 200, response.content)
        preference = EmailPreference.objects.get(customer=self.customer)
        self.assertFalse(preference.quota_warnings)
        self.assertFalse(preference.global_unsubscribe)
        self.assertTrue(response.json()["data"]["critical_notices"])
        self.assertIn("no-store", response["Cache-Control"])

    def test_live_owner_or_billing_session_may_change_optional_preferences_after_the_identity_window(self):
        preference = EmailPreference.objects.create(customer=self.customer, global_unsubscribe=True)
        session = portal_sessions.open_session(self.user)
        stale = timezone.now() - timedelta(seconds=301)
        PortalSession.objects.filter(pk=session.pk).update(reauth_at=stale)
        session.refresh_from_db()
        self.assertEqual(session.reauth_at, stale)
        for role in ("owner", "billing"):
            with self.subTest(role=role):
                self.membership.role = role
                self.membership.save(update_fields=["role"])
                response = self.portal_post(
                    self.path,
                    {**self.body, **bound_fields(session), "action": "update", "quota_warnings": False},
                )
                self.assertEqual(response.status_code, 200, response.content)
                preference.refresh_from_db()
                self.assertFalse(preference.quota_warnings)
                self.assertTrue(preference.global_unsubscribe)
                self.assertTrue(response.json()["data"]["critical_notices"])

    def test_real_billing_role_may_edit_but_viewer_tech_inactive_and_other_customer_may_not(self):
        for role, active, expected in (
            ("billing", True, 200),
            ("viewer", True, 403),
            ("tech", True, 403),
            ("owner", False, 403),
        ):
            with self.subTest(role=role, active=active):
                self.membership.role, self.membership.is_active = role, active
                self.membership.save(update_fields=["role", "is_active"])
                response = self.portal_post(self.path, {**self.body, "action": "update", "quota_warnings": False})
                self.assertEqual(response.status_code, expected, response.content)
        other = Customer.objects.create(name="Other preference owner")
        self.assertEqual(
            self.portal_post(self.path, {**self.body, "customer_id": other.pk, "action": "get"}).status_code, 403
        )
        self.assertFalse(EmailPreference.objects.filter(customer=other).exists())

    def test_update_requires_an_explicit_boolean_and_rejects_critical_or_global_changes(self):
        for value in ("false", "true", 0, 1, None):
            with self.subTest(value=value):
                response = self.portal_post(self.path, {**self.body, "action": "update", "quota_warnings": value})
                self.assertEqual(response.status_code, 400, response.content)
        for extra in ({"critical_notices": False}, {"global_unsubscribe": False}):
            response = self.portal_post(self.path, {**self.body, "action": "update", "quota_warnings": True, **extra})
            self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(EmailPreference.objects.filter(customer=self.customer).exists())

    @translation.override("en")
    def test_signed_refusals_follow_request_language_without_changing_preferences(self):
        preference = EmailPreference.objects.create(
            customer=self.customer, quota_warnings=True, global_unsubscribe=True
        )
        cases = (
            (
                {"quota_warnings": False, "critical_notices": False},
                "This form changes optional hosting warnings only.",
                "Acest formular modifică numai avertizările opționale privind găzduirea.",
            ),
            (
                {"quota_warnings": "false"},
                "Submit an explicit boolean quota warning preference.",
                "Trimiteți o valoare booleană explicită pentru preferința avertizărilor privind resursele de găzduire.",
            ),
        )
        for language in ("en", "ro"):
            for fields, english, romanian in cases:
                with self.subTest(language=language, fields=fields):
                    response = self.portal_post(
                        self.path,
                        {**self.body, "action": "update", **fields},
                        HTTP_ACCEPT_LANGUAGE=language,
                    )
                    self.assertEqual(response.status_code, 400, response.content)
                    self.assertEqual(response["Content-Language"], language)
                    self.assertEqual(response.json(), {"non_field_errors": [romanian if language == "ro" else english]})
                    preference.refresh_from_db()
                    self.assertTrue(preference.quota_warnings)
                    self.assertTrue(preference.global_unsubscribe)
        response = self.portal_post(
            self.path,
            {**self.body, "action": "update", "quota_warnings": False},
            HTTP_ACCEPT_LANGUAGE="ro",
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response["Content-Language"], "ro")
        preference.refresh_from_db()
        self.assertFalse(preference.quota_warnings)
        self.assertTrue(preference.global_unsubscribe)
        self.assertTrue(response.json()["data"]["critical_notices"])
