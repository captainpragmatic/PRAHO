"""The settings pages' buttons are the button component, with no server data or translation inside an expression.

They were hand-written because the component took no Alpine binding. Now they use alpine_click/alpine_disabled/
alpine_show/alpine_text: expressions are template literals, a row's key reaches its handler through data-key (read
as $el.dataset.key), and busy labels come from data-* attributes on the component root.
"""

from __future__ import annotations

import re
from pathlib import Path

from django.test import TestCase
from django.urls import reverse

from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.models import SystemSetting
from tests.factories.core_factories import create_admin_user
from tests.helpers.task_queue import quiet_task_queue
from tests.ui.node_harness import Markup

TEMPLATES = Path(__file__).resolve().parents[2] / "templates" / "settings"


class SettingsButtonsTests(TestCase):
    def setUp(self) -> None:
        quiet_task_queue(self)
        SystemSetting.objects.filter(
            key__in=[definition.key for definition in CATALOG_BY_KEY.values() if definition.deployment_fallback]
        ).delete()
        self.client.force_login(create_admin_user(username="settings-buttons-admin"))

    def page(self, group: str) -> Markup:
        response = self.client.get(reverse("settings:group", args=[group]))
        self.assertEqual(response.status_code, 200)
        return Markup(response.content.decode())

    def test_no_hand_written_buttons_are_left_in_the_settings_rows(self) -> None:
        for name in ("group.html", "partials/secret_row.html", "partials/setting_row.html"):
            with self.subTest(template=name):
                self.assertNotIn("tmpl-allow TMPL002", (TEMPLATES / name).read_text(encoding="utf-8"))

    def test_handlers_read_the_row_key_from_data_not_from_the_expression(self) -> None:
        page = self.page("efactura")
        handlers = [a for t, a in page.elements if t == "button" and "Field(" in a.get("@click", "")]
        self.assertTrue(handlers, "no override/inherit/reset buttons rendered")
        for attrs in handlers:
            self.assertIn("$el.dataset.key", attrs["@click"])
            self.assertTrue(attrs.get("data-key"), attrs)
            self.assertIn("ui-btn", attrs.get("class", ""))

    def test_busy_labels_come_from_data_attributes(self) -> None:
        page = self.page("stripe")
        root = page.find("data-settings-form", "")
        self.assertTrue(root.get("data-save-label") and root.get("data-saving-label"))
        labels = [a for t, a in page.elements if t == "span" and a.get("x-text") in ("saveLabel", "testLabel")]
        self.assertEqual({a["x-text"] for a in labels}, {"saveLabel", "testLabel"})
        spliced = [
            str(path.relative_to(TEMPLATES))
            for path in TEMPLATES.rglob("*.html")
            if re.search(r"""x-text="[^"]*\{%\s*trans""", path.read_text(encoding="utf-8"))
        ]
        self.assertEqual(spliced, [], "a translation inside an x-text expression")

    def test_the_secret_rows_cancel_is_a_named_icon_button(self) -> None:
        page = self.page("stripe")
        cancels = [a for t, a in page.elements if t == "button" and a.get("@click") == "cancelReplacement()"]
        self.assertTrue(cancels)
        for attrs in cancels:
            self.assertTrue(attrs.get("aria-label"))
            self.assertIn("ui-btn", attrs.get("class", ""))
