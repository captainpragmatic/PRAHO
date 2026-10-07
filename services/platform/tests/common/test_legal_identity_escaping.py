"""Legal prose escapes configured names once in both supported languages."""

from __future__ import annotations

from html import unescape

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.html import strip_tags
from django.utils.translation import override

from apps.settings.services import SettingsService


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class LegalIdentityEscapingTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def assert_sentences(self, url_name: str, sentences: dict[str, tuple[str, ...]]) -> None:
        for name in ("A & B SRL", 'A "Quoted" SRL', "A 'Quoted' <Partners> SRL"):
            with self.captureOnCommitCallbacks(execute=True):
                result = SettingsService.update_setting("company.legal_name", name)
            self.assertTrue(result.is_ok(), result)
            for language, fragments in sentences.items():
                with self.subTest(name=name, language=language), override(language):
                    response = self.client.get(reverse(url_name), HTTP_ACCEPT_LANGUAGE=language)
                    self.assertEqual(response.status_code, 200)
                    html = response.content.decode()
                    # Decode entities once, as a browser does; a second decode would hide the bug.
                    text = " ".join(unescape(strip_tags(html)).split())
                    for fragment in fragments:
                        with self.subTest(sentence=fragment):
                            self.assertIn(fragment.format(name=name), text)
                    self.assertNotIn("<Partners>", html)

    def test_terms_name_is_escaped_once_in_every_sentence_in_en_and_ro(self) -> None:
        self.assert_sentences(
            "terms_of_service",
            {
                "en": (
                    "services provided by {name}",
                    "a legally binding agreement between you and {name}.",
                    "{name} provides web hosting and related services",
                    "{name} and protected by intellectual property laws.",
                ),
                "ro": (
                    "serviciilor PRAHO Platform furnizate de {name}",
                    "un acord legal obligatoriu între dvs. și {name}.",
                    "{name} oferă servicii de găzduire web și servicii conexe",
                    "{name} și protejată de legile de proprietate intelectuală.",
                ),
            },
        )

    def test_privacy_name_is_escaped_once_in_en_and_ro(self) -> None:
        self.assert_sentences(
            "privacy_policy",
            {
                "en": ('{name} ("we", "us", "our") is committed to protecting your privacy',),
                "ro": ('{name} ("noi", "ne", "noastre") este angajată să vă protejeze intimitatea',),
            },
        )
