"""Catalog portability must preserve suppression display and language selection."""

from django.test import SimpleTestCase
from django.utils.translation import override

from apps.notifications.models import EmailSuppression


class SuppressionDisplayTests(SimpleTestCase):
    def test_opt_out_only_display_uses_the_current_english_or_romanian_language(self) -> None:
        suppression = EmailSuppression(email_hash="0123456789abcdef", reason="")
        for language, label in (("en", "Marketing opt-out"), ("ro", "Dezabonare de la marketing")):
            with self.subTest(language=language), override(language):
                self.assertEqual(str(suppression), f"Suppressed: 01234567... ({label})")

    def test_a_delivery_block_still_uses_its_translated_reason(self) -> None:
        suppression = EmailSuppression(email_hash="0123456789abcdef", reason="hard_bounce")
        for language, label in (("en", "Hard Bounce"), ("ro", "Returnare permanentă")):
            with self.subTest(language=language), override(language):
                self.assertEqual(str(suppression), f"Suppressed: 01234567... ({label})")
