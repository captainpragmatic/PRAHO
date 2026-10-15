"""A cookie choice records the Cookie Policy release it was made under (ADR-0061).

It recorded the constant "1.0" whatever the policy said. It now names the release in force in the
visitor's language, falling back to the default language's, and none before one is published.
"""

from __future__ import annotations

from django.test import TestCase

from apps.audit.services import GDPRConsentService
from tests.helpers.legal import publish_release


class CookieConsentPolicyReleaseTests(TestCase):
    def record(self, cookie_id: str, language: str) -> object:
        return GDPRConsentService.record_cookie_consent(
            cookie_id=cookie_id, status="accepted_essential", language=language
        ).unwrap()

    def test_a_choice_records_the_release_in_force_in_the_visitors_language(self) -> None:
        english = publish_release(kind="cookies", body_markdown="Sample cookie policy.")
        romanian = publish_release(kind="cookies", language="ro", body_markdown="Politică de exemplu.")
        consent = self.record("visitor-ro", "ro")
        self.assertEqual((consent.cookie_document, consent.consent_version), (romanian, romanian.release))
        consent = self.record("visitor-unknown-language", "de")
        self.assertEqual((consent.cookie_document, consent.consent_version), (english, english.release))

    def test_before_a_cookie_policy_is_published_the_choice_names_none(self) -> None:
        consent = self.record("visitor-early", "en")
        self.assertEqual((consent.cookie_document, consent.consent_version), (None, ""))
