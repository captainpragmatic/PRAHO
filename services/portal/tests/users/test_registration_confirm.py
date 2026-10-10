"""The holder of a registration link checks the details and chooses the password on the portal."""

from unittest.mock import patch

from django.contrib.messages import get_messages
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.api_client.services import PlatformAPIError
from apps.common import counters

REGISTRATION_ID = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b"
LINK = f"/register/confirm/{REGISTRATION_ID}/correct-token/"
PAGE = "/register/confirm/"
CHOSEN = " Chosen-at-confirm-2026! "
DETAILS = {
    "registration": {
        "email": "new@example.test",
        "first_name": "Zedrick",
        "last_name": "Marlowe",
        "company_name": "Quill Lantern SRL",
        "vat_number": "RO12345678",
    }
}


def form(**overrides: object) -> dict[str, object]:
    return {
        "registration_id": REGISTRATION_ID,
        "new_password": CHOSEN,
        "confirm_password": CHOSEN,
        "data_processing_consent": "on",
        **overrides,
    }


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    RATE_LIMITING_ENABLED=False,
)
class RegistrationConfirmViewTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.api = self.enterContext(patch("apps.users.views.api_client"))
        self.api.get_pending_registration.return_value = DETAILS

    def test_the_link_is_stored_and_scrubbed_without_calling_platform(self) -> None:
        response = self.client.get(LINK)
        self.assertRedirects(response, PAGE, fetch_redirect_response=False)
        self.assertEqual(response["Referrer-Policy"], "no-referrer")
        self.assertIn("no-store", response["Cache-Control"])
        self.api.get_pending_registration.assert_not_called()
        self.api.confirm_registration.assert_not_called()

    def test_the_page_shows_the_submitted_details_without_the_token(self) -> None:
        self.client.get(LINK)
        page = self.client.get(PAGE)
        self.assertEqual(page.status_code, 200)
        self.assertEqual(page["Referrer-Policy"], "same-origin")
        for shown in ("new@example.test", "Zedrick Marlowe", "Quill Lantern SRL", "RO12345678", 'name="new_password"'):
            self.assertContains(page, shown)
        self.assertNotContains(page, "correct-token")
        self.api.get_pending_registration.assert_called_once_with(
            REGISTRATION_ID, "correct-token", client_ip="127.0.0.1"
        )

    def test_confirming_sends_the_session_link_password_and_consent(self) -> None:
        self.client.get(LINK)
        self.api.confirm_registration.return_value = {"success": True}
        response = self.client.post(PAGE, form(marketing_consent="on", token="forged-token"))
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)
        self.api.confirm_registration.assert_called_once_with(
            REGISTRATION_ID,
            "correct-token",
            CHOSEN,
            CHOSEN,
            data_processing_consent=True,
            marketing_consent=True,
            client_ip="127.0.0.1",
        )
        self.assertTrue(any("can sign in now" in str(m) for m in get_messages(response.wsgi_request)))
        self.assertNotContains(self.client.get(PAGE), 'name="new_password"', status_code=200)

    def test_a_tab_left_on_an_earlier_link_confirms_nothing(self) -> None:
        self.client.get(LINK)
        self.client.get(PAGE)
        other = "0b1c2d3e-4f50-4a6b-8c7d-8e9f0a1b2c3d"
        self.client.get(f"/register/confirm/{other}/later-token/")
        response = self.client.post(PAGE, form())
        self.assertContains(response, "for an earlier link", status_code=409)
        self.assertContains(response, f'value="{other}"', status_code=409)
        self.api.confirm_registration.assert_not_called()

    def test_the_details_are_fetched_once_per_link(self) -> None:
        self.client.get(LINK)
        self.client.get(PAGE)
        self.client.get(PAGE)
        self.api.confirm_registration.side_effect = PlatformAPIError(
            "weak", status_code=400, response_data={"code": "validation_failed", "errors": {}}
        )
        self.client.post(PAGE, form())
        self.assertEqual(self.api.get_pending_registration.call_count, 1)

    def test_an_outage_when_opening_the_page_is_not_a_crash(self) -> None:
        self.client.get(LINK)
        for error, status, shown in (
            (PlatformAPIError("down", status_code=503), 503, "temporarily unavailable"),
            (PlatformAPIError("slow down", status_code=429, retry_after=30), 429, "30"),
        ):
            with self.subTest(status=status):
                self.api.get_pending_registration.side_effect = error
                response = self.client.get(PAGE)
                self.assertContains(response, shown, status_code=status)
                self.assertNotContains(response, "expired", status_code=status)
                self.assertIn("registration_confirm_link", self.client.session)

    def test_a_success_answer_must_say_success(self) -> None:
        self.client.get(LINK)
        self.api.confirm_registration.return_value = {}
        response = self.client.post(PAGE, form())
        self.assertContains(response, "temporarily unavailable", status_code=503)
        self.assertIn("registration_confirm_link", self.client.session)

    def test_consent_is_required_before_calling_platform(self) -> None:
        self.client.get(LINK)
        response = self.client.post(PAGE, form(data_processing_consent=""))
        self.assertEqual(response.status_code, 400)
        self.api.confirm_registration.assert_not_called()

    def test_a_rejected_password_keeps_the_link(self) -> None:
        self.client.get(LINK)
        self.api.confirm_registration.side_effect = PlatformAPIError(
            "weak",
            status_code=400,
            response_data={"code": "validation_failed", "errors": {"password": ["This password is too common."]}},
        )
        response = self.client.post(PAGE, form())
        self.assertContains(response, "This password is too common.", status_code=400)
        self.assertContains(response, 'name="new_password"', status_code=400)

    def test_a_used_link_or_taken_details_end_the_flow(self) -> None:
        for code, status, shown in (
            ("invalid_link", 400, "This link has expired or was already used."),
            ("details_unavailable", 409, "These details are no longer available. Please register again."),
        ):
            with self.subTest(code=code):
                self.client.get(LINK)
                self.api.confirm_registration.side_effect = PlatformAPIError(
                    code, status_code=status, response_data={"code": code}
                )
                response = self.client.post(PAGE, form())
                self.assertContains(response, shown, status_code=status)
                self.assertNotContains(response, 'name="new_password"', status_code=status)
                self.assertNotIn("registration_confirm_link", self.client.session)

    def test_a_link_platform_refuses_shows_no_form(self) -> None:
        self.client.get(LINK)
        self.api.get_pending_registration.side_effect = PlatformAPIError(
            "invalid", status_code=400, response_data={"code": "invalid_link"}
        )
        response = self.client.get(PAGE)
        self.assertContains(response, "This link has expired or was already used.", status_code=400)
        self.assertNotContains(response, "Quill Lantern", status_code=400)
        self.assertNotContains(response, 'name="new_password"', status_code=400)
        self.assertNotIn("registration_confirm_link", self.client.session)

    def test_no_link_in_the_session_shows_no_form(self) -> None:
        response = self.client.get(PAGE)
        self.assertContains(response, "This link has expired or was already used.")
        self.assertNotContains(response, 'name="new_password"')
        self.api.get_pending_registration.assert_not_called()

    def test_an_outage_is_not_called_an_expired_link(self) -> None:
        self.client.get(LINK)
        self.api.confirm_registration.side_effect = PlatformAPIError("down", status_code=503)
        response = self.client.post(PAGE, form())
        self.assertContains(response, "temporarily unavailable", status_code=503)
        self.assertNotContains(response, "expired", status_code=503)
        self.assertIn("registration_confirm_link", self.client.session)


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    RATE_LIMITING_ENABLED=True,
)
class RegistrationConfirmBudgetTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.api = self.enterContext(patch("apps.users.views.api_client"))
        self.api.get_pending_registration.return_value = DETAILS
        self.api.confirm_registration.side_effect = PlatformAPIError(
            "weak", status_code=400, response_data={"code": "validation_failed", "errors": {}}
        )

    def test_confirmations_have_their_own_per_link_budget_outside_registration(self) -> None:
        self.client.get(LINK)
        statuses = [self.client.post(PAGE, form()).status_code for _ in range(6)]
        self.assertEqual(statuses[:5], [400] * 5)
        self.assertEqual(statuses[5], 429)
        refused = self.client.post(PAGE, form())
        self.assertContains(refused, "Too many attempts", status_code=429)
        self.assertEqual(self.api.confirm_registration.call_count, 5)
        self.assertEqual(counters.peek("auth_volume_ip_127.0.0.1"), 0)

    def test_a_counter_store_failure_keeps_the_page(self) -> None:
        self.client.get(LINK)
        with patch("apps.common.rate_limiting.counters.increment", side_effect=RuntimeError("store offline")):
            response = self.client.post(PAGE, form())
        self.assertEqual(response.status_code, 503)
        self.assertContains(response, "Finish creating your account", status_code=503)
        self.assertIn("Retry-After", response)
        self.assertIn("no-store", response["Cache-Control"])
        self.api.confirm_registration.assert_not_called()

    def test_the_link_budget_holds_when_clients_cannot_be_told_apart(self) -> None:
        self.client.get(LINK)
        with patch("apps.common.rate_limiting._client_ip_is_distinguishable", return_value=False):
            statuses = [self.client.post(PAGE, form()).status_code for _ in range(6)]
        self.assertEqual(statuses, [400] * 5 + [429])
