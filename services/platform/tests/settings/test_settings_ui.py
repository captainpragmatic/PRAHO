"""
Settings UI tests (C3): three-surface pages, change-set endpoint contract,
write-only secrets, role gating, search, history, automation.
"""

from __future__ import annotations

import html as html_lib
import json
import re

from django.template.loader import render_to_string
from django.test import Client, TestCase
from django.urls import reverse

from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_admin_user, create_staff_user


def _json_post(client: Client, url: str, payload: dict) -> object:
    return client.post(url, data=json.dumps(payload), content_type="application/json")


class SettingsPagesTests(TestCase):
    def setUp(self) -> None:
        self.staff = create_staff_user(username="ui_staff", staff_role="support")
        self.admin = create_admin_user(username="ui_admin")

    def test_home_renders_for_staff(self) -> None:
        self.client.force_login(self.staff)
        response = self.client.get(reverse("settings:home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Settings")

    def test_business_group_renders_with_rows(self) -> None:
        self.client.force_login(self.staff)
        response = self.client.get(reverse("settings:group", args=["billing"]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "billing.invoice_payment_terms_days")

    def test_unknown_group_is_404(self) -> None:
        self.client.force_login(self.staff)
        self.assertEqual(self.client.get("/settings/not-a-group/").status_code, 404)

    def test_integration_and_advanced_pages_require_admin(self) -> None:
        self.client.force_login(self.staff)
        for slug in ("stripe", "advanced"):
            self.assertEqual(self.client.get(reverse("settings:group", args=[slug])).status_code, 403, slug)
        self.client.force_login(self.admin)
        for slug in ("stripe", "advanced"):
            self.assertEqual(self.client.get(reverse("settings:group", args=[slug])).status_code, 200, slug)

    def test_secret_values_never_rendered(self) -> None:
        result = SettingsService.update_setting("integrations.stripe_secret_key", "sk_live_supersecret")
        self.assertTrue(result.is_ok())
        row = SystemSetting.objects.get(key="integrations.stripe_secret_key")

        self.client.force_login(self.admin)
        response = self.client.get(reverse("settings:group", args=["stripe"]))
        content = response.content.decode()
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("sk_live_supersecret", content)
        self.assertNotIn(str(row.value), content)  # not even ciphertext
        self.assertContains(response, "Configured")

    def test_automation_page_renders(self) -> None:
        self.client.force_login(self.staff)
        response = self.client.get(reverse("settings:automation"))
        self.assertEqual(response.status_code, 200)

    def test_search_returns_grouped_anchors(self) -> None:
        self.client.force_login(self.staff)
        response = self.client.get(reverse("settings:search"), {"q": "payment terms"})
        self.assertContains(response, "billing.invoice_payment_terms_days")

    def test_history_drawer_renders(self) -> None:
        SettingsService.update_setting("billing.proforma_validity_days", 45, user_id=self.staff.id, reason="ui test")
        self.client.force_login(self.staff)
        response = self.client.get(reverse("settings:setting_history", args=["billing.proforma_validity_days"]))
        self.assertContains(response, "ui test")


class ChangeSetEndpointTests(TestCase):
    def setUp(self) -> None:
        self.staff = create_staff_user(username="cs_staff", staff_role="support")
        self.admin = create_admin_user(username="cs_admin")
        self.row = SystemSetting.objects.create(
            key="billing.recurring_auto_collection_enabled",
            name="x",
            description="x",
            category="billing",
            value=True,
            default_value=False,
            data_type="boolean",
        )

    def _baseline(self) -> str:
        self.row.refresh_from_db()
        return self.row.updated_at.isoformat()

    def test_boolean_can_be_turned_off_via_change_set(self) -> None:
        """The legacy category form could never submit an unchecked box — the change set can."""
        self.client.force_login(self.staff)
        response = _json_post(
            self.client,
            reverse("settings:save_change_set"),
            {
                "changes": {"billing.recurring_auto_collection_enabled": False},
                "baselines": {"billing.recurring_auto_collection_enabled": self._baseline()},
            },
        )
        self.assertEqual(response.status_code, 200, response.content)
        self.row.refresh_from_db()
        self.assertIs(self.row.get_typed_value(), False)

    def test_two_consecutive_edits_without_reload(self) -> None:
        """The success payload rebaselines the client so a second save does not self-conflict."""
        self.client.force_login(self.staff)
        first = _json_post(
            self.client,
            reverse("settings:save_change_set"),
            {
                "changes": {"billing.recurring_auto_collection_enabled": False},
                "baselines": {"billing.recurring_auto_collection_enabled": self._baseline()},
            },
        ).json()
        new_baseline = first["saved"]["billing.recurring_auto_collection_enabled"]["baseline"]

        second = _json_post(
            self.client,
            reverse("settings:save_change_set"),
            {
                "changes": {"billing.recurring_auto_collection_enabled": True},
                "baselines": {"billing.recurring_auto_collection_enabled": new_baseline},
            },
        )
        self.assertEqual(second.status_code, 200, second.content)

    def test_stale_baseline_returns_conflict(self) -> None:
        self.client.force_login(self.staff)
        stale = self._baseline()
        SettingsService.update_setting("billing.recurring_auto_collection_enabled", False)
        response = _json_post(
            self.client,
            reverse("settings:save_change_set"),
            {
                "changes": {"billing.recurring_auto_collection_enabled": True},
                "baselines": {"billing.recurring_auto_collection_enabled": stale},
            },
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(
            response.json()["conflicts"][0]["key"], "billing.recurring_auto_collection_enabled"
        )

    def test_non_business_keys_require_admin(self) -> None:
        self.client.force_login(self.staff)
        response = _json_post(
            self.client,
            reverse("settings:save_change_set"),
            {"changes": {"virtualmin.rate_limit_qps": 5}, "baselines": {"virtualmin.rate_limit_qps": None}},
        )
        self.assertEqual(response.status_code, 403)

        self.client.force_login(self.admin)
        response = _json_post(
            self.client,
            reverse("settings:save_change_set"),
            {"changes": {"virtualmin.rate_limit_qps": 5}, "baselines": {"virtualmin.rate_limit_qps": None}},
        )
        self.assertEqual(response.status_code, 200, response.content)

    def test_csrf_is_enforced(self) -> None:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.staff)
        response = client.post(
            reverse("settings:save_change_set"),
            data='{"changes": {}, "baselines": {}}',
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)


class SecretEndpointTests(TestCase):
    def setUp(self) -> None:
        self.staff = create_staff_user(username="sec_staff", staff_role="support")
        self.admin = create_admin_user(username="sec_admin")

    def test_secret_set_requires_admin(self) -> None:
        self.client.force_login(self.staff)
        response = _json_post(
            self.client,
            reverse("settings:secret_set", args=["integrations.stripe_secret_key"]),
            {"value": "sk_test_x"},
        )
        self.assertIn(response.status_code, (302, 403))

    def test_secret_set_and_clear_flow(self) -> None:
        self.client.force_login(self.admin)
        set_response = _json_post(
            self.client,
            reverse("settings:secret_set", args=["integrations.stripe_secret_key"]),
            {"value": "sk_test_flow"},
        )
        self.assertEqual(set_response.status_code, 200, set_response.content)
        self.assertEqual(SettingsService.get_setting("integrations.stripe_secret_key"), "sk_test_flow")

        # Empty submissions are rejected — an untouched form can never wipe a secret
        empty = _json_post(
            self.client, reverse("settings:secret_set", args=["integrations.stripe_secret_key"]), {"value": "  "}
        )
        self.assertEqual(empty.status_code, 400)

        # Clearing requires a reason
        no_reason = _json_post(
            self.client, reverse("settings:secret_clear", args=["integrations.stripe_secret_key"]), {}
        )
        self.assertEqual(no_reason.status_code, 400)

        cleared = _json_post(
            self.client,
            reverse("settings:secret_clear", args=["integrations.stripe_secret_key"]),
            {"reason": "rotation drill"},
        )
        self.assertEqual(cleared.status_code, 200)
        self.assertEqual(SettingsService.get_setting("integrations.stripe_secret_key"), "")

    def test_non_sensitive_key_is_not_a_secret_endpoint(self) -> None:
        self.client.force_login(self.admin)
        response = _json_post(
            self.client,
            reverse("settings:secret_set", args=["billing.proforma_validity_days"]),
            {"value": "45"},
        )
        self.assertEqual(response.status_code, 404)


class SettingRowDefaultAttributeTests(TestCase):
    """data-default must always be the JSON-encoded CATALOG default: the reset
    control JSON.parses it unconditionally (review of #377). A bare string
    throws, and a baseline-sourced value resets to the modified value."""

    def setUp(self) -> None:
        self.admin = create_admin_user(username="default_attr_admin")
        self.client.force_login(self.admin)

    def _data_default_for(self, content: str, key: str) -> object:
        match = re.search(rf'id="field-{re.escape(key)}"[^>]*data-default=(\'[^\']*\'|"[^"]*")', content)
        self.assertIsNotNone(match, f"no data-default found for {key}")
        raw = html_lib.unescape(match.group(1)[1:-1])
        return json.loads(raw)

    def test_select_default_is_valid_json(self) -> None:
        response = self.client.get(reverse("settings:group", args=["efactura"]))

        value = self._data_default_for(response.content.decode(), "efactura.environment")
        self.assertEqual(value, "test")

    def test_list_default_is_the_catalog_default_not_the_current_value(self) -> None:
        SettingsService.update_setting("tickets.allowed_file_extensions", [".zip"])
        response = self.client.get(reverse("settings:group", args=["support"]))

        value = self._data_default_for(response.content.decode(), "tickets.allowed_file_extensions")
        self.assertEqual(value, [".pdf", ".txt", ".png", ".jpg", ".jpeg", ".doc", ".docx"])


class HistoryDrawerFalsyDiffTests(TestCase):
    """A True→False or 10→0 change must still render its diff (review of #377)."""

    def test_falsy_new_value_still_renders_the_diff(self) -> None:
        html = render_to_string(
            "settings/partials/history_drawer.html",
            {"events": [{"old_values": {"value": "True"}, "new_values": {"value": "False"}}]},
        )
        self.assertIn("True", html)
        self.assertIn("False", html)

    def test_zero_transition_still_renders_the_diff(self) -> None:
        html = render_to_string(
            "settings/partials/history_drawer.html",
            {"events": [{"old_values": {"value": 10}, "new_values": {"value": 0}}]},
        )
        self.assertIn("10", html)


class MaintenanceBannerTests(TestCase):
    """The staff banner must actually render when maintenance mode is active
    (review of #377): the template read a context variable nothing provided."""

    def test_staff_sees_the_banner_when_maintenance_is_active(self) -> None:
        admin = create_admin_user(username="banner_admin")
        self.client.force_login(admin)
        SettingsService.update_setting("system.maintenance_mode", True)

        response = self.client.get(reverse("settings:home"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Maintenance mode is active")

    def test_banner_renders_on_non_settings_pages_too(self) -> None:
        """The banner must warn staff EVERYWHERE, not only inside the settings
        module — its variable must come from a registered context processor."""
        admin = create_admin_user(username="banner_admin_global")
        self.client.force_login(admin)
        SettingsService.update_setting("system.maintenance_mode", True)

        response = self.client.get(reverse("dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Maintenance mode is active")

    def test_no_banner_when_maintenance_is_off(self) -> None:
        admin = create_admin_user(username="banner_admin_off")
        self.client.force_login(admin)

        response = self.client.get(reverse("settings:home"))

        self.assertNotContains(response, "Maintenance mode is active")
