"""Customer-scoped warning preference page with only the Platform boundary doubled."""

from unittest.mock import patch

from django.test import TestCase, override_settings

from tests.customers.test_customers_views import SESSION_DEFAULTS


@override_settings(
    SESSION_ENGINE="django.contrib.sessions.backends.cache",
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
)
class NotificationPreferencePageTests(TestCase):
    path = "/company/notifications/"

    def setUp(self):
        session = self.client.session
        session.update(SESSION_DEFAULTS)
        session.save()

    @patch("apps.api_client.services.PlatformAPIClient.post")
    def test_selected_customer_form_renders_actual_preference_and_protected_critical_copy(self, platform):
        platform.return_value = {
            "success": True,
            "data": {
                "quota_warnings": False,
                "global_unsubscribe": True,
                "critical_notices": True,
            },
        }
        response = self.client.get(self.path)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'name="quota_warnings"')
        self.assertContains(response, "Critical allowance notices remain enabled")
        self.assertContains(response, "global email opt-out")
        self.assertNotContains(response, 'name="critical_notices"')
        self.assertNotContains(response, 'name="global_unsubscribe"')
        calls = [call for call in platform.call_args_list if call.args[0] == "customers/notification-preferences/"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].kwargs, {"data": {"customer_id": 1, "action": "get"}, "user_id": 10})

    @patch("apps.api_client.services.PlatformAPIClient.post")
    def test_form_sends_explicit_boolean_for_selected_customer_and_shows_saved_state(self, platform):
        platform.return_value = {
            "success": True,
            "data": {
                "quota_warnings": False,
                "global_unsubscribe": False,
                "critical_notices": True,
            },
        }
        response = self.client.post(self.path, {})
        self.assertEqual(response.status_code, 302)
        platform.assert_called_once_with(
            "customers/notification-preferences/",
            data={"customer_id": 1, "action": "update", "quota_warnings": False},
            user_id=10,
        )

    @patch("apps.api_client.services.PlatformAPIClient.post")
    def test_switched_customer_is_used_and_tech_or_viewer_cannot_edit(self, platform):
        session = self.client.session
        session["selected_customer_id"] = "2"
        session["user_memberships"] = [{"customer_id": 2, "role": "billing"}]
        session.save()
        platform.return_value = {
            "success": True,
            "data": {
                "quota_warnings": True,
                "global_unsubscribe": False,
                "critical_notices": True,
            },
        }
        self.assertEqual(self.client.post(self.path, {"quota_warnings": "on"}).status_code, 302)
        platform.assert_called_once_with(
            "customers/notification-preferences/",
            data={"customer_id": 2, "action": "update", "quota_warnings": True},
            user_id=10,
        )
        for role in ("viewer", "tech"):
            session = self.client.session
            session["user_memberships"] = [{"customer_id": 2, "role": role}]
            session.save()
            platform.reset_mock()
            self.assertEqual(self.client.post(self.path, {"quota_warnings": "on"}).status_code, 403)
            self.assertFalse(
                any(call.args[0] == "customers/notification-preferences/" for call in platform.call_args_list)
            )

    @patch("apps.api_client.services.PlatformAPIClient.post")
    def test_platform_failure_keeps_form_unsaved_and_does_not_announce_success(self, platform):
        platform.return_value = {"success": False, "error": "Preference unavailable"}
        response = self.client.post(self.path, {"quota_warnings": "on"})
        self.assertEqual(response.status_code, 503)
        self.assertContains(response, "could not be saved", status_code=503)
