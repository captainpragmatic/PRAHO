"""Audit actor lookup is part of the optional settings audit effect."""

from unittest.mock import patch

from django.db import transaction

from apps.settings.models import SystemSetting
from apps.users.models import User
from tests.common._signal_isolation import SignalIsolationTestCase


class SettingSignalIsolationTests(SignalIsolationTestCase):
    def test_actor_lookup_failure_preserves_setting(self) -> None:
        user = User.objects.create_user(email="setting-isolation@example.com", password="test")
        setting = SystemSetting(
            key="test.isolation", value="saved", default_value="", data_type="string", category="general"
        )
        setting._audit_context = {"user_id": user.pk}
        with patch.object(User.objects, "filter", side_effect=self.fail_write), transaction.atomic():
            setting.save()
        self.assertTrue(SystemSetting.objects.filter(pk=setting.pk).exists())
