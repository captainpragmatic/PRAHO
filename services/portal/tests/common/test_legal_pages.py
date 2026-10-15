"""The portal shows the legal documents the operator published on Platform (ADR-0061).

PRAHO ships no legal text: /terms/, /privacy-policy/ and /cookie-policy/ show the release in force in
the visitor's language, and /legal/<id>/ shows the release an acceptance names. The HTML is
sanitised again here and must match the hash Platform published with it.
"""

from __future__ import annotations

import hashlib
import uuid
from html import unescape
from typing import Any
from unittest.mock import patch

from django.conf import settings
from django.core.cache import cache
from django.test import Client, SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import translation
from django.utils.html import strip_tags

from apps.api_client.services import PlatformAPIError, api_client
from apps.common.localisation import LocalisationDefaults
from apps.common.localisation_services import platform_cache_key

IDENTITY = {
    "legal_name": "Legal Test SRL",
    "email_support": "help@legal.example.test",
    "email_privacy": "privacy@legal.example.test",
    "email_finance": "",
    "phone": "+40721000000",
}
NOT_PUBLISHED = PlatformAPIError("not published", status_code=404, response_data={"code": "not_published"})


def release(kind: str = "terms", html: str = "<h2>Scope</h2><p>Sample terms.</p>", **fields: str) -> dict[str, Any]:
    document = {
        "id": str(uuid.uuid4()),
        "kind": kind,
        "language": "en",
        "release": "2024-12-27.1",
        "effective_on": "2024-12-27",
        "html": html,
        "sha256": hashlib.sha256(html.encode()).hexdigest(),
        **fields,
    }
    return {"success": True, "document": document}


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class LegalPagesTests(SimpleTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        payload = {"success": True, "localisation": LocalisationDefaults().customer_payload(), "company": IDENTITY}
        identity = patch.object(api_client, "get_localisation_defaults", return_value=payload)
        identity.start()
        self.addCleanup(identity.stop)

    def serve(self, *answers: Any) -> Any:
        documents = patch.object(api_client, "get_legal_document", side_effect=list(answers))
        self.addCleanup(documents.stop)
        return documents.start()

    def test_anonymous_visitors_read_the_release_in_force_with_its_date(self) -> None:
        for path, kind in (("/terms/", "terms"), ("/privacy-policy/", "privacy"), ("/cookie-policy/", "cookies")):
            with self.subTest(path):
                cache.clear()
                platform = self.serve(release(kind))
                response = Client().get(path)
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, "<h2>Scope</h2>", html=True)
                self.assertContains(response, "2024-12-27.1")
                self.assertContains(response, "27.12.2024")
                platform.assert_called_once_with({"kind": kind, "language": "en"})

    def test_the_visitor_language_is_asked_for(self) -> None:
        platform = self.serve(release())
        with translation.override(None):  # The request activates Romanian; put the language back after.
            Client(headers={"Accept-Language": "ro"}).get("/terms/")
        platform.assert_called_once_with({"kind": "terms", "language": "ro"})

    def test_the_effective_date_is_the_published_calendar_date_in_any_timezone(self) -> None:
        payload = {
            "success": True,
            "localisation": {**LocalisationDefaults().customer_payload(), "timezone": "America/New_York"},
            "company": IDENTITY,
        }
        self.serve(release())
        with patch.object(api_client, "get_localisation_defaults", return_value=payload):
            cache.clear()
            html = Client().get("/terms/").content.decode()
        self.assertIn("27.12.2024", html)
        self.assertNotIn("26.12.2024", html)

    def test_before_anything_is_published_the_page_says_so(self) -> None:
        self.serve(NOT_PUBLISHED)
        response = Client().get("/terms/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "This document has not been published yet.")

    def test_markup_outside_the_allowlist_is_removed_again(self) -> None:
        self.serve(release(html='<p>Terms</p><script>alert(1)</script><a href="javascript:x()">x</a>'))
        html = Client().get("/terms/").content.decode()
        self.assertIn("<p>Terms</p>", html)
        self.assertNotIn("<script>alert(1)", html)
        self.assertNotIn("javascript:x()", html)

    def test_an_answer_whose_hash_does_not_match_or_of_another_kind_is_refused(self) -> None:
        for answer in (
            {**release(), "document": {**release()["document"], "html": "<p>Tampered</p>"}},
            release("privacy"),
        ):
            with self.subTest(answer["document"]["kind"]):
                cache.clear()
                self.serve(answer)
                response = Client().get("/terms/")
                self.assertEqual(response.status_code, 503)
                self.assertNotContains(response, "Tampered", status_code=503)

    def test_an_outage_shows_the_last_answer_read_and_otherwise_a_notice(self) -> None:
        self.serve(release(), PlatformAPIError("down", status_code=503))
        Client().get("/terms/")
        cache.delete(f"{platform_cache_key('legal')}:current:terms:en")  # The minute passed; last good stands in
        self.assertContains(Client().get("/terms/"), "Sample terms.")
        cache.clear()
        self.serve(PlatformAPIError("down", status_code=503))
        response = Client().get("/terms/")
        self.assertEqual(response.status_code, 503)
        self.assertContains(response, "cannot be shown right now", status_code=503)

    def test_a_release_is_shown_by_its_id_even_once_superseded_and_an_unknown_one_is_not_found(self) -> None:
        answer = release(html="<p>The release I accepted.</p>")
        document_id = answer["document"]["id"]
        platform = self.serve(answer, NOT_PUBLISHED)
        response = Client().get(reverse("legal_document", args=[document_id]))
        self.assertContains(response, "The release I accepted.")
        self.assertContains(response, "Terms of Service")
        platform.assert_called_once_with({"id": document_id})
        self.assertEqual(Client().get(reverse("legal_document", args=[uuid.uuid4()])).status_code, 404)

    def test_only_the_pages_themselves_are_public(self) -> None:
        for path in ("/terms/accept/", "/privacy-policy/other/"):
            with self.subTest(path):
                response = Client().get(path)
                self.assertEqual(response.status_code, 302)
                self.assertTrue(response["Location"].startswith("/login/"))

    def test_the_cookie_page_lists_what_praho_stores_and_the_privacy_page_links_the_dashboard(self) -> None:
        self.serve(release("cookies"), release("privacy"))
        cookies = Client().get("/cookie-policy/").content.decode()
        for name in (settings.SESSION_COOKIE_NAME, settings.CSRF_COOKIE_NAME, "cookie_consent_id"):
            self.assertIn(name, cookies)
        self.assertIn('data-action="cookie-prefs"', cookies)
        privacy = Client().get("/privacy-policy/").content.decode()
        self.assertIn(f'href="{reverse("users:privacy_dashboard")}"', privacy)

    def test_each_page_names_the_operator_and_the_privacy_page_its_privacy_contacts(self) -> None:
        published = {**IDENTITY, "registration_number": "J40/1234/2020", "address": "Str. Exemplu 1", "email_dpo": "dpo@legal.example.test"}
        payload = {"success": True, "localisation": LocalisationDefaults().customer_payload(), "company": published}
        self.serve(release("terms"), release("privacy"))
        with patch.object(api_client, "get_localisation_defaults", return_value=payload):
            cache.clear()
            terms = " ".join(Client().get("/terms/").content.decode().split())
            privacy = " ".join(Client().get("/privacy-policy/").content.decode().split())
        for shown in ("Legal Test SRL · J40/1234/2020 · Str. Exemplu 1", "help@legal.example.test · +40721000000"):
            self.assertIn(shown, terms)
        self.assertNotIn("privacy@legal.example.test", terms)
        self.assertIn("privacy@legal.example.test · Data Protection Officer: dpo@legal.example.test", privacy)

    def test_the_operator_name_is_escaped_once_in_en_and_ro(self) -> None:
        for name in ("A & B SRL", 'A "Quoted" SRL', "A 'Quoted' <Partners> SRL"):
            payload = {
                "success": True,
                "localisation": LocalisationDefaults().customer_payload(),
                "company": {**IDENTITY, "legal_name": name},
            }
            for language in ("en", "ro"):
                with self.subTest(name=name, language=language):
                    cache.clear()
                    self.serve(release())
                    identity = patch.object(api_client, "get_localisation_defaults", return_value=payload)
                    with identity, translation.override(None):
                        html = Client(headers={"Accept-Language": language}).get("/terms/").content.decode()
                    # Decode entities once, as a browser does; a second decode would hide the bug.
                    self.assertIn(name, " ".join(unescape(strip_tags(html)).split()))
                    self.assertNotIn("<Partners>", html)

    def test_the_footer_links_the_pages(self) -> None:
        self.serve(release("cookies"))
        html = Client().get("/cookie-policy/").content.decode()
        for name in ("terms_of_service", "privacy_policy"):
            self.assertIn(f'href="{reverse(name)}"', html)
