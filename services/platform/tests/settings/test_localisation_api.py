"""Portal defaults are allowlisted and profile writes remain atomic."""

import time
from unittest.mock import patch

from django.db import DatabaseError
from django.test import TestCase, override_settings
from rest_framework.test import APIRequestFactory

from apps.api.customers.serializers import CustomerProfileSerializer
from apps.api.localisation.views import localisation_defaults
from apps.api.users.views import customer_profile_api
from apps.settings.services import SettingsService
from apps.users.models import UserProfile
from tests.factories.core_factories import create_staff_user
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


class LocalisationAPITests(TestCase):
    def request(self, path, data=None, *, authenticated=True, method="post"):
        request = getattr(APIRequestFactory(), method)(
            path, {"timestamp": int(time.time()), **(data or {})}, format="json"
        )
        request._portal_authenticated = authenticated
        return request

    def test_defaults_require_hmac_service_authentication(self) -> None:
        response = localisation_defaults(self.request("/api/localisation/", authenticated=False))
        self.assertEqual(response.status_code, 401)

    def test_defaults_are_allowlisted_and_available_without_user_identity(self) -> None:
        SettingsService.update_setting("system.customer_date_format", "%Y-%m-%d")
        response = localisation_defaults(self.request("/api/localisation/"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["localisation"],
            {
                "default_language": "en",
                "default_country": "RO",
                "timezone": "Europe/Bucharest",
                "customer_date_format": "%Y-%m-%d",
            },
        )

    def test_invalid_profile_does_not_save_user_fields(self) -> None:
        user = create_staff_user(username="api_localisation", staff_role="support")
        response = customer_profile_api(
            self.request(
                "/api/users/profile/",
                {"user_id": user.pk, "timezone": "invalid", "first_name": "Changed"},
                method="put",
            )
        )
        self.assertEqual(response.status_code, 400)
        previous = user.first_name
        user.refresh_from_db()
        self.assertEqual(user.first_name, previous)

    def test_profile_partial_update_and_effective_legacy_fields(self) -> None:
        user = create_staff_user(username="api_localisation", staff_role="support")
        profile = UserProfile.objects.get(user=user)
        profile.timezone = "UTC"
        profile.save()
        response = customer_profile_api(
            self.request("/api/users/profile/", {"user_id": user.pk, "date_format": "%Y-%m-%d"}, method="put")
        )
        self.assertEqual(response.status_code, 200)
        response = customer_profile_api(self.request("/api/users/profile/", {"user_id": user.pk}))
        values = response.data["profile"]["profile"]
        self.assertEqual(values["timezone"], "UTC")
        self.assertEqual(values["preferred_language"], "en")
        self.assertEqual(
            values["localisation_preferences"], {"preferred_language": "", "timezone": "UTC", "date_format": "%Y-%m-%d"}
        )


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
class LocalisationHMACIntegrationTests(HMACTestMixin, TestCase):
    def test_real_service_signature_reaches_defaults_without_user(self):
        response = self.portal_post("/api/localisation/")
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(response.json()["localisation"]["default_language"], "en")

    def test_tampered_signature_is_rejected(self):
        response = self.portal_post("/api/localisation/", HTTP_X_SIGNATURE="0" * 64)
        self.assertEqual(response.status_code, 401)


class LegacyProfileLocalisationTests(TestCase):
    def setUp(self):
        self.user = create_staff_user(username="legacy_localisation", staff_role="support")

    def test_legacy_profile_reads_effective_defaults_and_raw_inheritance(self):
        data = CustomerProfileSerializer(self.user).data
        self.assertEqual(data["preferred_language"], "en")
        self.assertEqual(data["timezone"], "Europe/Bucharest")
        self.assertEqual(data["date_format"], "%d.%m.%Y")
        self.assertEqual(
            data["localisation_preferences"], {"preferred_language": "", "timezone": "", "date_format": ""}
        )

    def test_legacy_partial_save_accepts_timezone_and_date_overrides_then_inheritance(self):
        for values in ({"timezone": "Asia/Tokyo", "date_format": "%m/%d/%Y"}, {"timezone": "", "date_format": ""}):
            serializer = CustomerProfileSerializer(self.user, data=values, partial=True)
            self.assertTrue(serializer.is_valid(), serializer.errors)
            serializer.save()
            profile = UserProfile.objects.get(user=self.user)
            self.assertEqual((profile.timezone, profile.date_format), (values["timezone"], values["date_format"]))
            self.assertTrue(profile.email_notifications)

    def test_profile_save_failure_rolls_back_user_changes(self):
        original_name = self.user.first_name
        serializer = CustomerProfileSerializer(
            self.user, data={"first_name": "Changed", "timezone": "UTC"}, partial=True
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        with (
            patch.object(UserProfile, "save", side_effect=DatabaseError("save failed")),
            self.assertRaises(DatabaseError),
        ):
            serializer.save()
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, original_name)
