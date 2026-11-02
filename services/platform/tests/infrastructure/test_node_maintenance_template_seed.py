"""A freshly migrated installation can render every maintenance event in either supported language."""

from importlib import import_module
from types import SimpleNamespace

from django.apps import apps
from django.db import connection
from django.template import Context, Template
from django.test import TestCase

from apps.notifications.models import EmailTemplate


class NodeMaintenanceTemplateSeedTests(TestCase):
    def setUp(self) -> None:
        # A prior TransactionTestCase may have flushed data while preserving the
        # migration record in a kept PG database; restore the actual default seed.
        import_module("apps.infrastructure.migrations.0008_node_maintenance_templates").seed_templates(
            apps, SimpleNamespace(connection=connection)
        )
        import_module("apps.infrastructure.migrations.0012_maintenance_hosting_dependency_copy").seed_neutral_templates(
            apps, SimpleNamespace(connection=connection)
        )

    def test_all_notice_templates_are_seeded_in_romanian_and_english(self) -> None:
        keys = {"maintenance_scheduled", "maintenance_completed", "maintenance_correction"}
        actual = set(EmailTemplate.objects.filter(key__in=keys).values_list("key", "locale", "category", "is_active"))
        expected = {(key, locale, "maintenance", True) for key in keys for locale in ("ro", "en")}
        self.assertEqual(actual, expected)

    def test_seeded_copy_is_truthful_for_retained_mail_and_dns(self) -> None:
        phrases = {
            "en": "a server supporting your hosting services",
            "ro": "un server care susține serviciile dumneavoastră de găzduire",
        }
        context = Context({"is_emergency": True, "expects_downtime": True, "customer_note": "Mail & DNS <checked>"})
        for locale, phrase in phrases.items():
            for kind in ("scheduled", "completed"):
                with self.subTest(locale=locale, kind=kind):
                    expected_phrase = phrase
                    if kind == "completed":
                        expected_phrase = (
                            "affecting your hosting services"
                            if locale == "en"
                            else "pentru serviciile dumneavoastră de găzduire"
                        )
                    template = EmailTemplate.objects.get(key=f"maintenance_{kind}", locale=locale)
                    for content in (template.body_text, template.body_html):
                        rendered = Template(content).render(context)
                        self.assertIn(expected_phrase, rendered)
                        self.assertNotIn("your site runs on", rendered)
                        self.assertNotIn("găzduiește site-ul", rendered)
                        if kind == "scheduled":
                            interruption = (
                                "Some hosting functions may be briefly unavailable."
                                if locale == "en"
                                else "Unele funcții de găzduire pot fi indisponibile pentru scurt timp."
                            )
                            self.assertIn(interruption, rendered)
