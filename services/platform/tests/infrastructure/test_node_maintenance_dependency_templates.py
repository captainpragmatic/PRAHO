"""Forward neutral-copy migration preserves operator-owned template authority."""

from importlib import import_module
from types import SimpleNamespace

from django.apps import apps
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase

from apps.notifications.models import EmailTemplate
from apps.users.models import User

INITIAL = import_module("apps.infrastructure.migrations.0008_node_maintenance_templates")
NEUTRAL = import_module("apps.infrastructure.migrations.0012_maintenance_hosting_dependency_copy")


class HostingDependencyTemplateTests(TestCase):
    def seed(self) -> None:
        NEUTRAL.seed_neutral_templates(apps, SimpleNamespace(connection=connection))

    def test_absent_defaults_are_seeded_and_repeat_application_is_idempotent(self) -> None:
        EmailTemplate.objects.filter(key__startswith="maintenance_").delete()

        self.seed()
        before = list(EmailTemplate.objects.filter(key__startswith="maintenance_").order_by("key", "locale").values())
        self.seed()

        self.assertEqual(len(before), 6)
        self.assertTrue(all(row["version"] == 2 for row in before))
        self.assertEqual(
            before,
            list(EmailTemplate.objects.filter(key__startswith="maintenance_").order_by("key", "locale").values()),
        )

    def test_each_operator_content_or_metadata_edit_is_preserved(self) -> None:
        edits = {
            "subject": "Operator subject",
            "body_text": "Operator plaintext",
            "body_html": "<p>Operator HTML</p>",
            "description": "Operator description",
            "version": 7,
            "is_active": False,
            "variables": {"custom": "Operator variable contract"},
        }
        for field, value in edits.items():
            for locale in ("en", "ro"):
                with self.subTest(field=field, locale=locale):
                    EmailTemplate.objects.filter(key="maintenance_scheduled", locale=locale).delete()
                    INITIAL.seed_templates(apps, SimpleNamespace(connection=connection))
                    template = EmailTemplate.objects.get(key="maintenance_scheduled", locale=locale)
                    setattr(template, field, value)
                    template.save(update_fields=[field])
                    before = EmailTemplate.objects.filter(pk=template.pk).values().get()

                    self.seed()

                    self.assertEqual(before, EmailTemplate.objects.filter(pk=template.pk).values().get())

    def test_an_operator_owned_template_is_preserved_even_when_its_content_matches_the_default(self) -> None:
        EmailTemplate.objects.filter(key="maintenance_scheduled", locale="en").delete()
        INITIAL.seed_templates(apps, SimpleNamespace(connection=connection))
        owner = User.objects.create_user(email="template-owner@example.test", password=None)
        template = EmailTemplate.objects.get(key="maintenance_scheduled", locale="en")
        template.created_by = owner
        template.save(update_fields=["created_by"])
        before = EmailTemplate.objects.filter(pk=template.pk).values().get()

        self.seed()

        self.assertEqual(before, EmailTemplate.objects.filter(pk=template.pk).values().get())


class HostingDependencyTemplateMigrationTests(TransactionTestCase):
    def test_actual_forward_reverse_and_repeat_preserve_custom_notice(self) -> None:
        previous = ("infrastructure", "0011_merge_cloud_destroy_maintenance")
        current = ("infrastructure", "0012_maintenance_hosting_dependency_copy")
        MigrationExecutor(connection).migrate([previous])
        try:
            INITIAL.seed_templates(apps, SimpleNamespace(connection=connection))
            custom = EmailTemplate.objects.get(key="maintenance_scheduled", locale="ro")
            custom.subject = "Subiect personalizat de operator"
            custom.save(update_fields=["subject"])
            # Missing defaults also need the forward migration, not only fresh installs.
            EmailTemplate.objects.filter(key="maintenance_completed", locale="en").delete()

            MigrationExecutor(connection).migrate([current])

            self.assertEqual(EmailTemplate.objects.get(pk=custom.pk).subject, custom.subject)
            self.assertIn(
                "supporting your hosting services",
                EmailTemplate.objects.get(key="maintenance_scheduled", locale="en").body_text,
            )
            self.assertIn(
                "affecting your hosting services",
                EmailTemplate.objects.get(key="maintenance_completed", locale="en").body_text,
            )
            self.assertIn(("infrastructure", current[1]), MigrationExecutor(connection).loader.applied_migrations)
            MigrationExecutor(connection).migrate([previous])
            MigrationExecutor(connection).migrate([current])
            self.assertEqual(EmailTemplate.objects.get(pk=custom.pk).subject, custom.subject)
            self.assertEqual(EmailTemplate.objects.filter(key__startswith="maintenance_").count(), 6)
        finally:
            MigrationExecutor(connection).migrate([current])
