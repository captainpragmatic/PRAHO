"""Portal default propagation and graceful failure without platform DB access."""

import time
from unittest.mock import patch

from django.core.cache import cache
from django.template import Context, Template
from django.test import RequestFactory, SimpleTestCase, override_settings

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.localisation import LocalisationDefaults
from apps.common.localisation_services import get_localisation_defaults, store_localisation_preferences
from apps.users.forms import CustomerRegistrationForm


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class PortalLocalisationTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def payload(self, **values):
        return {"success": True, "localisation": {**LocalisationDefaults().customer_payload(), **values}}

    def test_cached_defaults_then_refresh_change_rendered_values(self) -> None:
        now = time.time()
        with patch.object(
            api_client,
            "get_localisation_defaults",
            side_effect=[self.payload(default_country="DE"), self.payload(default_country="FR")],
        ) as reader:
            with patch("time.time", return_value=now):
                self.assertEqual(CustomerRegistrationForm().initial["country"], "Germany")
                self.assertEqual(get_localisation_defaults().default_country, "DE")
                reader.assert_called_once()
            with patch("time.time", return_value=now + 61):
                self.assertEqual(CustomerRegistrationForm().initial["country"], "France")
                self.assertEqual(reader.call_count, 2)

    def test_outage_uses_last_good_until_one_hour_then_built_in_defaults(self) -> None:
        now = time.time()
        with patch.object(
            api_client,
            "get_localisation_defaults",
            side_effect=[self.payload(default_language="ro"), PlatformAPIError("offline"), PlatformAPIError("offline")],
        ) as reader:
            with patch("time.time", return_value=now):
                self.assertEqual(get_localisation_defaults().default_language, "ro")
            with patch("time.time", return_value=now + 61):
                self.assertEqual(get_localisation_defaults().default_language, "ro")
                self.assertEqual(get_localisation_defaults().default_language, "ro")
                self.assertEqual(reader.call_count, 2)
            with patch("time.time", return_value=now + 3601):
                self.assertEqual(get_localisation_defaults().default_language, "en")

    def test_malformed_response_does_not_replace_last_good(self) -> None:
        now = time.time()
        with patch.object(
            api_client,
            "get_localisation_defaults",
            side_effect=[self.payload(timezone="UTC"), self.payload(timezone="invalid")],
        ):
            with patch("time.time", return_value=now):
                self.assertEqual(get_localisation_defaults().timezone, "UTC")
            with patch("time.time", return_value=now + 61):
                self.assertEqual(get_localisation_defaults().timezone, "UTC")

    def test_cache_is_scoped_to_platform_and_portal(self) -> None:
        with patch.object(
            api_client,
            "get_localisation_defaults",
            side_effect=[
                self.payload(default_country="DE"),
                self.payload(default_country="FR"),
                self.payload(default_country="IT"),
            ],
        ):
            self.assertEqual(get_localisation_defaults().default_country, "DE")
            with patch.object(api_client, "base_url", "https://another.example/api"):
                self.assertEqual(get_localisation_defaults().default_country, "FR")
            with patch.object(api_client, "portal_id", "portal-002"):
                self.assertEqual(get_localisation_defaults().default_country, "IT")

    def test_profile_inheritance_and_override_render_without_per_date_requests(self) -> None:
        request = RequestFactory().get("/")
        request.session = {}
        store_localisation_preferences(request, {"date_format": "", "timezone": "UTC"})
        template = Template(
            '{% load localisation_tags %}{% for value in dates %}{% localised_date value "datetime" %};{% endfor %}'
        )
        with patch.object(
            api_client, "get_localisation_defaults", return_value=self.payload(customer_date_format="%Y-%m-%d")
        ) as reader:
            result = template.render(Context({"request": request, "dates": ["2025-12-31T22:30:00Z"] * 10}))
        self.assertEqual(result, "2025-12-31 22:30;" * 10)
        reader.assert_called_once()
