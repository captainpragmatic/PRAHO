"""A Platform 429 renders actionable signup feedback through the real portal client."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings
from django.utils import timezone

MESSAGE = "Too many registration attempts. Please try again later."
UNAVAILABLE = "Registration is temporarily unavailable. Please try again in a few minutes."


@override_settings(
    DEBUG=False,
    DEBUG_TOOLBAR_CONFIG={"SHOW_TOOLBAR_CALLBACK": lambda _request: False},
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    LANGUAGE_CODE="en",
    RATE_LIMITING_ENABLED=False,
    PLATFORM_API_BASE_URL="http://localhost:8700/api",
    PLATFORM_API_READ_MAX_RETRIES=0,
)
class RegistrationRateLimitViewTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.client = Client()
        now = timezone.now()
        session = self.client.session
        session.update(
            {
                "session_auth_hash": "test-session",
                "validated_at": now.isoformat(),
                "next_validate_at": (now + timedelta(minutes=10)).isoformat(),
            }
        )
        # Signup is anonymous: adding customer_id would redirect before the form is processed.
        session.save()

    def test_platform_429_shows_signup_message_and_preserves_only_non_password_values(self) -> None:
        self.assert_refusal_keeps_the_form(429, MESSAGE)

    def test_platform_503_shows_temporarily_unavailable_not_check_your_information(self) -> None:
        self.assert_refusal_keeps_the_form(503, UNAVAILABLE)

    def assert_refusal_keeps_the_form(self, status: int, expected: str) -> None:
        data = {
            "email": "signup@example.test",
            "first_name": "Ana",
            "last_name": "Pop",
            "phone": "",
            "password1": "CorrectHorse12!",
            "password2": "CorrectHorse12!",
            "customer_type": "srl",
            "company_name": "FX Signup SRL",
            "address_line1": "Str. Test 1",
            "city": "București",
            "county": "București",
            "postal_code": "010001",
            "country": "RO",
            "data_processing_consent": "on",
            "marketing_consent": "on",
            "terms_accepted": "on",
        }

        def platform_response(method: str, url: str, **_kwargs: object) -> requests.Response:
            response = requests.Response()
            response.status_code = status if url.rstrip("/").endswith("/customers/register") else 200
            payload: dict[str, object] = {"success": False, "error": expected} if response.status_code == status else {}
            response._content = json.dumps(payload).encode()
            response.headers["Content-Type"] = "application/json"
            if response.status_code == 429:
                response.headers["Retry-After"] = "3600"
            return response

        with patch("apps.common.outbound_http._send", side_effect=platform_response):
            response = self.client.post("/register/", data)

        self.assertContains(response, expected)
        self.assertNotContains(response, "An unexpected error occurred during registration.")
        self.assertNotContains(response, "Registration failed. Please check your information")
        self.assertNotIn("Location", response)
        form = response.context["form"]
        self.assertTrue(form.is_bound)
        for name, value in data.items():
            if name.startswith("password"):
                self.assertNotIn(name, form.data)
                self.assertNotIn(name, form.cleaned_data)
                self.assertIsNone(form[name].value())
            else:
                self.assertEqual(form.data[name], value)
        self.assertNotContains(response, data["password1"])
