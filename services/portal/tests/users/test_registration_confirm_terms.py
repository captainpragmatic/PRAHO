"""The confirmation page asks for the Terms of Service, and sends the release it linked.

Platform names the release in force in the preview, records the one the confirmer accepted, and
refuses one that is no longer in force (`terms_changed`). The page links that exact release and, on
`terms_changed`, forgets the details, so the next page names the release now in force (ADR-0061).
"""

import re
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.api_client.services import PlatformAPIError
from tests.users.test_registration_confirm import CHOSEN, LINK, PAGE, REGISTRATION_ID, form
from tests.users.test_registration_confirm import TERMS_DOCUMENT_ID as TERMS_ID

NEW_TERMS_ID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
TERMS_UNAVAILABLE = PlatformAPIError("no terms", status_code=409, response_data={"code": "terms_unavailable"})


def details(document_id: str = TERMS_ID) -> dict[str, object]:
    terms = {"document_id": document_id, "kind": "terms", "language": "en", "release": "2024-12-27.1", "sha256": "0" * 64}
    return {
        "registration": {
            "email": "new@example.test",
            "first_name": "Zedrick",
            "last_name": "Marlowe",
            "company_name": "Quill Lantern SRL",
            "vat_number": "",
            "cui": "14399840",
            "registration_number": "J40/1234/2020",
            "terms_document": terms,
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

    def test_the_page_shows_the_company_identifiers_and_links_the_release_to_accept(self) -> None:
        page = self.client.get(PAGE)
        # The footer links the terms in force; the page's own link opens the exact release beside the form.
        for shown in ("14399840", "J40/1234/2020", 'name="terms_accepted"', f'href="/legal/{TERMS_ID}/" target="_blank"'):
            self.assertContains(page, shown)

    def test_the_terms_must_be_accepted_before_calling_platform(self) -> None:
        response = self.client.post(PAGE, form(terms_accepted=""))
        self.assertEqual(response.status_code, 400)
        self.assertIn("terms_accepted", response.context["form"].errors)
        self.api.confirm_registration.assert_not_called()

    def test_acceptance_is_sent_with_the_release_the_page_linked(self) -> None:
        self.client.get(PAGE)
        self.api.confirm_registration.return_value = {"success": True}
        self.client.post(PAGE, form(terms_accepted="on"))
        self.api.confirm_registration.assert_called_once_with(
            REGISTRATION_ID,
            "correct-token",
            CHOSEN,
            CHOSEN,
            marketing_consent=False,
            terms_accepted=True,
            terms_document_id=TERMS_ID,
            client_ip="127.0.0.1",
        )

    def test_changed_terms_redraw_the_page_with_the_new_release_which_the_next_submit_sends(self) -> None:
        self.client.get(PAGE)
        self.api.confirm_registration.side_effect = PlatformAPIError(
            "changed", status_code=409, response_data={"code": "terms_changed"}
        )
        self.api.get_pending_registration.return_value = details(NEW_TERMS_ID)
        response = self.client.post(PAGE, form(terms_accepted="on"))
        # The page now links the release in force and carries it, never the one it replaced.
        self.assertContains(response, "have changed", status_code=409)
        self.assertContains(response, f'href="/legal/{NEW_TERMS_ID}/"', status_code=409)
        self.assertContains(response, f'value="{NEW_TERMS_ID}"', status_code=409)
        self.assertNotContains(response, TERMS_ID, status_code=409)

        self.api.confirm_registration.side_effect = None
        self.api.confirm_registration.return_value = {"success": True}
        self.client.post(PAGE, form(terms_accepted="on", terms_document_id=NEW_TERMS_ID))
        self.assertEqual(self.api.get_pending_registration.call_count, 2)
        self.assertEqual(self.api.confirm_registration.call_args.kwargs["terms_document_id"], NEW_TERMS_ID)

    def test_the_release_the_page_showed_is_sent_whatever_the_session_holds_now(self) -> None:
        # Another tab drew the page again with a newer release; this tab still shows the old one.
        self.client.get(PAGE)
        self.api.confirm_registration.return_value = {"success": True}
        self.client.post(PAGE, form(terms_accepted="on", terms_document_id=NEW_TERMS_ID))
        self.assertEqual(self.api.confirm_registration.call_args.kwargs["terms_document_id"], NEW_TERMS_ID)

    def test_after_changed_terms_the_box_must_be_ticked_again(self) -> None:
        self.client.get(PAGE)
        self.api.confirm_registration.side_effect = PlatformAPIError(
            "changed", status_code=409, response_data={"code": "terms_changed"}
        )
        html = self.client.post(PAGE, form(terms_accepted="on")).content.decode()
        [checkbox] = re.findall(r"<input[^>]*name=\"terms_accepted\"[^>]*>", html, re.S)
        self.assertNotIn("checked", checkbox)

    def test_while_no_terms_are_in_force_there_is_no_form_and_the_details_are_fetched_again(self) -> None:
        self.api.get_pending_registration.side_effect = TERMS_UNAVAILABLE
        self.client.get(LINK)
        response = self.client.post(PAGE, form(terms_accepted="on"))
        self.assertContains(response, "once the Terms of Service are published", status_code=409)
        self.assertNotContains(response, 'name="terms_accepted"', status_code=409)
        self.api.confirm_registration.assert_not_called()

        self.api.get_pending_registration.side_effect = None
        self.api.confirm_registration.return_value = {"success": True}
        self.client.post(PAGE, form(terms_accepted="on"))
        self.assertEqual(self.api.confirm_registration.call_args.kwargs["terms_document_id"], TERMS_ID)

    def test_terms_no_longer_in_force_meanwhile_end_on_the_same_notice(self) -> None:
        self.client.get(PAGE)
        self.api.confirm_registration.side_effect = TERMS_UNAVAILABLE
        self.api.get_pending_registration.side_effect = TERMS_UNAVAILABLE
        response = self.client.post(PAGE, form(terms_accepted="on"))
        self.assertContains(response, "once the Terms of Service are published", status_code=409)
        self.assertNotContains(response, 'name="terms_accepted"', status_code=409)
