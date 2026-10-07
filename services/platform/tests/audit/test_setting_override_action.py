"""Cleared settings overrides have a selectable action and a readable audit badge."""

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.audit.models import AuditEvent
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_admin_user
from tests.helpers.task_queue import quiet_task_queue


@override_settings(
    LANGUAGE_CODE="en",
    DISABLE_AUDIT_SIGNALS=False,
    EFACTURA_COMPANY_NAME="Deployment supplier",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class SettingOverrideActionTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        quiet_task_queue(self)
        self.admin = create_admin_user(username="override_action_admin")
        self.admin.profile.preferred_language = "en"
        self.admin.profile.save(update_fields=["preferred_language"])
        self.client.force_login(self.admin)
        key = "efactura.company.name"
        result = SettingsService.update_setting(key, "Stored supplier", user_id=self.admin.pk)
        self.assertTrue(result.is_ok(), result)
        row = SystemSetting.objects.get(key=key)
        cleared = SettingsService.apply_change_set(
            {key: None},
            {key: row.updated_at.isoformat()},
            user_id=self.admin.pk,
            reason="Return to deployment supplier",
        )
        self.assertTrue(cleared.is_ok(), cleared)
        self.event = AuditEvent.objects.get(action="setting_override_cleared", metadata__setting_key=key)

    def test_rendered_action_filter_lists_cleared_overrides(self) -> None:
        response = self.client.get(reverse("audit:logs"))
        self.assertContains(
            response,
            '<option value="setting_override_cleared">Setting override cleared</option>',
            html=True,
        )

    def test_filtered_event_badge_displays_the_registered_label(self) -> None:
        response = self.client.get(
            reverse("audit:logs_list"),
            {"action": "setting_override_cleared"},
            HTTP_HX_REQUEST="true",
        )
        self.assertContains(response, "<span>Setting override cleared</span>", html=True)
        self.assertEqual([event.pk for event in response.context["audit_events"]], [self.event.pk])
        self.assertNotContains(response, "<span>setting_override_cleared</span>", html=True)
