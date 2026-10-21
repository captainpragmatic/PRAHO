"""Restore-time SQL can insert ordinary settings without knowing the context column."""

import uuid

from django.db import connection
from django.test import TestCase

from apps.settings.models import SystemSetting


class RawSettingContextTests(TestCase):
    def test_database_assigns_distinct_contexts_to_raw_setting_inserts(self) -> None:
        for key in ("test.raw_first", "test.raw_second"):
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO setting_entries "
                    "(key, category, name, description, help_text, data_type, value, default_value, "
                    "is_required, is_sensitive, is_active, requires_restart, created_at, updated_at, revision) "
                    "VALUES (%s, 'system', 'Raw setting', '', '', 'string', %s, %s, "
                    "false, false, true, false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)",
                    [key, '"public"', '""'],
                )
        first = SystemSetting.objects.get(key="test.raw_first")
        second = SystemSetting.objects.get(key="test.raw_second")
        self.assertIsInstance(first.encryption_context_id, uuid.UUID)
        self.assertNotEqual(first.encryption_context_id, second.encryption_context_id)
        self.assertEqual(first.get_typed_value(), "public")
