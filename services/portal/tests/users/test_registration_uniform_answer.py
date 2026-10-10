"""Registering always ends with the same message: the email decides what happens next."""

from unittest.mock import patch

from django.contrib.messages import get_messages
from django.core.cache import cache
from django.test import TestCase, override_settings

FORM = {
    "email": "someone@example.test",
    "first_name": "Ana",
    "last_name": "Pop",
    "phone": "",
    "customer_type": "srl",
    "company_name": "Uniform Answer SRL",
    "address_line1": "Str. Test 1",
    "city": "București",
    "county": "București",
    "postal_code": "010001",
    "country": "RO",
    "data_processing_consent": "on",
    "terms_accepted": "on",
}


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    RATE_LIMITING_ENABLED=False,
)
class RegistrationUniformAnswerTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.api = self.enterContext(patch("apps.users.forms.api_client"))
        self.api.register_customer.return_value = {"success": True, "message": "Accepted"}

    def test_an_accepted_registration_says_check_your_email_and_creates_nothing_here(self) -> None:
        response = self.client.post("/register/", FORM)
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
        shown = [str(m) for m in get_messages(response.wsgi_request)]
        self.assertEqual(shown, ["Thank you. Check your email for a message with the next step."])
        self.assertFalse(any("can now login" in m for m in shown))
        payload = self.api.register_customer.call_args.args[0]
        self.assertEqual(payload["user_data"]["email"], "someone@example.test")
        self.assertEqual(self.api.register_customer.call_args.kwargs, {"client_ip": "127.0.0.1"})
        self.assertNotIn("customer_id", self.client.session)

    def test_the_page_language_goes_with_the_registration(self) -> None:
        self.client.post("/register/", FORM, HTTP_ACCEPT_LANGUAGE="ro")
        self.assertEqual(self.api.register_customer.call_args.args[0]["language"], "ro")
        self.client.post("/register/", FORM, HTTP_ACCEPT_LANGUAGE="en")
        self.assertEqual(self.api.register_customer.call_args.args[0]["language"], "en")

    def test_the_form_asks_for_no_password(self) -> None:
        page = self.client.get("/register/")
        self.assertNotContains(page, 'type="password"')
        self.assertNotContains(page, 'name="marketing_consent"')
