"""A freshly migrated installation can render every maintenance event in either supported language."""

from django.test import TestCase

from apps.notifications.models import EmailTemplate


class NodeMaintenanceTemplateSeedTests(TestCase):
    def test_all_notice_templates_are_seeded_in_romanian_and_english(self) -> None:
        keys = {"maintenance_scheduled", "maintenance_completed", "maintenance_correction"}
        actual = set(EmailTemplate.objects.filter(key__in=keys).values_list("key", "locale", "category", "is_active"))
        expected = {(key, locale, "maintenance", True) for key in keys for locale in ("ro", "en")}
        self.assertEqual(actual, expected)
