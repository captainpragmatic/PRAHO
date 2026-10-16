"""A staff-minted registration link opens the form with a company's details filled in.

The portal only forwards the token; Platform reads it. The token leaves the address bar at once (a
redirect, sent with no referrer), the details only fill in the form and stay editable, and a token
Platform does not accept fills in nothing.
"""

from __future__ import annotations

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.api_client.services import PlatformAPIError
from apps.users.constants import REGISTRATION_INTENT_SESSION_KEY, REGISTRATION_PREFILL_SESSION_KEY

FIELDS = {"email": "ana@quill.example", "company_name": "Quill Lantern SRL", "cui": "14399840"}


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    RATE_LIMITING_ENABLED=False,
)
class RegistrationPrefillLinkTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.api = self.enterContext(patch("apps.users.views.api_client"))

    def test_the_link_fills_in_the_form_and_leaves_the_address_bar(self) -> None:
        self.api.read_registration_prefill.return_value = {
            "success": True,
            "prefill": {"fields": FIELDS, "intent": {"product": "web-hosting"}},
        }
        response = self.client.get("/register/?p=aes:v2:sealed")
        self.assertRedirects(response, "/register/", fetch_redirect_response=False)
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertEqual(self.api.read_registration_prefill.call_args.args, ("aes:v2:sealed",))
        self.assertEqual(self.client.session[REGISTRATION_INTENT_SESSION_KEY], {"product": "web-hosting"})

        page = self.client.get("/register/").content.decode()
        self.assertIn('value="Quill Lantern SRL"', page)
        self.assertIn('value="ana@quill.example"', page)
        self.assertNotIn("aes:v2:sealed", page)

    def test_a_token_platform_refuses_fills_in_nothing(self) -> None:
        for answer in ({"success": True, "prefill": {}}, PlatformAPIError("down", status_code=503)):
            with self.subTest(answer=type(answer).__name__):
                if isinstance(answer, Exception):
                    self.api.read_registration_prefill.side_effect = answer
                else:
                    self.api.read_registration_prefill.return_value = answer
                response = self.client.get("/register/?p=aes:v2:forged")
                self.assertRedirects(response, "/register/", fetch_redirect_response=False)
                self.assertNotIn(REGISTRATION_PREFILL_SESSION_KEY, self.client.session)

    def test_a_completed_registration_forgets_the_details(self) -> None:
        self.api.read_registration_prefill.return_value = {"success": True, "prefill": {"fields": FIELDS}}
        self.client.get("/register/?p=aes:v2:sealed")
        with patch("apps.users.forms.CustomerRegistrationForm.register_customer", return_value={"accepted": True}):
            self.client.post(
                "/register/",
                {
                    "email": "ana@quill.example",
                    "first_name": "Ana",
                    "last_name": "Pop",
                    "customer_type": "srl",
                    "company_name": "Quill Lantern SRL",
                    "cui": "14399840",
                    "address_line1": "Str. Test 1",
                    "city": "Bucuresti",
                    "county": "Bucuresti",
                    "postal_code": "010001",
                    "country": "România",
                    "terms_accepted": "on",
                },
            )
        self.assertNotIn(REGISTRATION_PREFILL_SESSION_KEY, self.client.session)
