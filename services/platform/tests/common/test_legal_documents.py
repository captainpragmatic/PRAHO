"""Legal documents the operator publishes: immutable releases, current by effective date (ADR-0061)."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.legal import (
    LegalDocument,
    LegalDocumentImmutableError,
    current_legal_document,
    publish_legal_document,
)
from apps.common.legal_html import sanitize_legal_html
from apps.common.utils import operator_local_date
from apps.settings.services import SettingsService
from apps.users.models import User
from tests.helpers.legal import publish_release


class LegalDocumentStoreTests(TestCase):
    def test_document_is_immutable_via_save_update_and_delete_and_current_follows_effective_date(self) -> None:
        today = operator_local_date(timezone.now())
        staff = User.objects.create_user(email="legal@example.test", password="x" * 16, is_staff=True)
        first = publish_release(published_by=staff)
        upcoming = publish_release(effective_on=today + timedelta(days=7), body_markdown="Upcoming.")

        # Nothing changes a published release, through any ORM path.
        first.body_markdown = "Rewritten."
        attempts = {
            "save": first.save,
            "save(update_fields)": lambda: first.save(update_fields=["body_markdown"]),
            "delete": first.delete,
            "queryset update": lambda: LegalDocument.objects.filter(pk=first.pk).update(body_html="x"),
            "queryset delete": lambda: LegalDocument.objects.filter(pk=first.pk).delete(),
            "bulk_update": lambda: LegalDocument.objects.bulk_update([first], ["body_markdown"]),
            "bulk_create upsert": lambda: LegalDocument.objects.bulk_create(
                [first], update_conflicts=True, unique_fields=["id"], update_fields=["body_markdown"]
            ),
        }
        for name, attempt in attempts.items():
            with self.subTest(name), self.assertRaises(LegalDocumentImmutableError):
                attempt()
        stored = LegalDocument.objects.get(pk=first.pk)
        self.assertEqual(stored.body_markdown, "Sample terms, not legal text.")

        # The publisher may leave; the document stays.
        staff.delete()
        self.assertIsNone(LegalDocument.objects.get(pk=first.pk).published_by)

        # A release takes effect on its date; until then the previous one is current.
        self.assertEqual(current_legal_document("terms", "en"), stored)
        with patch("apps.common.legal.operator_local_date", return_value=today + timedelta(days=7)):
            self.assertEqual(current_legal_document("terms", "en"), upcoming)

        # Releases on one date count up past 9, and the latest published is current.
        for _ in range(9):
            latest = publish_release(body_markdown="Again.")
        self.assertEqual(latest.release, f"{today.isoformat()}.10")
        self.assertEqual(current_legal_document("terms", "en"), latest)

    def test_publishing_renders_sanitised_html_hashes_it_and_is_audited(self) -> None:
        body = "## Scope\n\n<script>alert(1)</script>[site](javascript:alert(1))\n\n| a | b |\n|---|---|\n| 1 | 2 |"
        document = publish_release(body_markdown=body)
        self.assertIn("<h2>Scope</h2>", document.body_html)
        self.assertIn("<table>", document.body_html)
        self.assertNotIn("<script", document.body_html)
        self.assertNotIn("javascript:", document.body_html)
        self.assertEqual(len(document.sha256), 64)
        event = AuditEvent.objects.get(action="legal_document_published", object_id=str(document.pk))
        self.assertEqual(event.metadata["reference"], document.reference())

    def test_a_language_without_its_own_release_falls_back_to_the_default_language(self) -> None:
        english = publish_release()
        self.assertEqual(current_legal_document("terms", "ro"), english)
        romanian = publish_release(language="ro")
        self.assertEqual(current_legal_document("terms", "ro"), romanian)
        self.assertIsNone(current_legal_document("privacy", "ro"))

    def test_a_release_cannot_take_effect_in_the_past_or_in_an_unknown_kind_or_language(self) -> None:
        today = operator_local_date(timezone.now())
        for overrides in (
            {"effective_on": today - timedelta(days=1)},
            {"kind": "refunds"},
            {"language": "de"},
            {"body_markdown": "   "},
        ):
            with self.subTest(overrides):
                values = {"kind": "terms", "language": "en", "effective_on": today, "body_markdown": "Text."}
                self.assertTrue(publish_legal_document(**{**values, **overrides}, published_by=None).is_err())
        self.assertFalse(LegalDocument.objects.exists())


class DefaultLanguageEffectTests(TestCase):
    """system.default_language decides which release a language without its own release shows."""

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def set_default_language(self, language: str) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting("system.default_language", language)
        self.assertTrue(result.is_ok(), result)

    def test_a_language_without_a_release_shows_the_default_languages(self) -> None:
        romanian = publish_release(language="ro")
        self.set_default_language("ro")
        self.assertEqual(current_legal_document("terms", "en"), romanian)
        self.set_default_language("en")
        self.assertIsNone(current_legal_document("terms", "en"))


class LegalHTMLTests(SimpleTestCase):
    def test_sanitising_is_idempotent_and_keeps_the_legal_structure(self) -> None:
        html = (
            '<h1>T</h1><h2>S</h2><p>A <a href="https://example.com" title="t" onclick="x()">link</a>, '
            '<a href="mailto:legal@example.com">mail</a>, <strong>b</strong> <em>i</em></p>'
            "<ul><li>x</li></ul><ol><li>y</li></ol><blockquote>q</blockquote><hr>"
            "<table><thead><tr><th>h</th></tr></thead><tbody><tr><td>d</td></tr></tbody></table>"
            '<img src="x" onerror="alert(1)"><iframe src="https://evil.example"></iframe>'
        )
        once = sanitize_legal_html(html)
        self.assertEqual(sanitize_legal_html(once), once)
        for kept in ("<h1>", "<h2>", 'href="https://example.com"', 'href="mailto:legal@example.com"', "<table>", "<hr>"):
            self.assertIn(kept, once)
        for dropped in ("onclick", "<img", "onerror", "<iframe"):
            self.assertNotIn(dropped, once)
