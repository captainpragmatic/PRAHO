"""The confirmation page asks for the Terms of Service, and sends the version it showed.

Platform records the version the confirmer accepted and refuses one that is no longer current
(`terms_changed`). The page takes the version from the details it fetched for the link, and on
`terms_changed` forgets those details, so the next submit sends the current version.
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.api_client.services import PlatformAPIError
from tests.users.test_registration_confirm import CHOSEN, LINK, PAGE, REGISTRATION_ID, form

VERSION = "2024-12-27"
NEW_VERSION = "2026-10-01"


def details(version: str = VERSION) -> dict[str, object]:
    return {
        "registration": {
            "email": "new@example.test",
            "first_name": "Zedrick",
            "last_name": "Marlowe",
            "company_name": "Quill Lantern SRL",
            "vat_number": "",
            "cui": "14399840",
            "registration_number": "J40/1234/2020",
            "terms_version": version,
        }
    }


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    RATE_LIMITING_ENABLED=False,
)
class ConfirmTermsTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.api = self.enterContext(patch("apps.users.views.api_client"))
        self.api.get_pending_registration.return_value = details()
        self.client.get(LINK)

    def test_the_page_shows_the_company_identifiers_and_links_the_terms(self) -> None:
        page = self.client.get(PAGE)
        # The footer links the terms too; the page's own link opens beside the form.
        for shown in ("14399840", "J40/1234/2020", 'name="terms_accepted"', 'href="/terms/" target="_blank"'):
            self.assertContains(page, shown)

    def test_the_terms_must_be_accepted_before_calling_platform(self) -> None:
        response = self.client.post(PAGE, form(terms_accepted=""))
        self.assertEqual(response.status_code, 400)
        self.assertIn("terms_accepted", response.context["form"].errors)
        self.api.confirm_registration.assert_not_called()

    def test_acceptance_is_sent_with_the_version_the_page_showed(self) -> None:
        self.client.get(PAGE)
        self.api.confirm_registration.return_value = {"success": True}
        self.client.post(PAGE, form(terms_accepted="on"))
        self.api.confirm_registration.assert_called_once_with(
            REGISTRATION_ID,
            "correct-token",
            CHOSEN,
            CHOSEN,
            data_processing_consent=True,
            marketing_consent=False,
            terms_accepted=True,
            terms_version=VERSION,
            client_ip="127.0.0.1",
        )

    def test_changed_terms_are_fetched_again_and_the_next_submit_sends_them(self) -> None:
        self.client.get(PAGE)
        self.api.confirm_registration.side_effect = PlatformAPIError(
            "changed", status_code=409, response_data={"code": "terms_changed"}
        )
        response = self.client.post(PAGE, form(terms_accepted="on"))
        self.assertContains(response, "have changed", status_code=409)

        self.api.get_pending_registration.return_value = details(NEW_VERSION)
        self.api.confirm_registration.side_effect = None
        self.api.confirm_registration.return_value = {"success": True}
        self.client.post(PAGE, form(terms_accepted="on"))
        self.assertEqual(self.api.get_pending_registration.call_count, 2)
        self.assertEqual(self.api.confirm_registration.call_args.kwargs["terms_version"], NEW_VERSION)
