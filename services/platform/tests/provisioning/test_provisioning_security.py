"""H6: services_list must keep service_name XSS-safe.

#284 moved the suspend/reactivate controls from inline onclick handlers (a JS
string context that required |escapejs) to delegated data-action buttons that
carry service_name in a data-* attribute (an HTML attribute context, where
Django's default autoescape is the correct — and sufficient — protection, and
|escapejs would be WRONG). This guards the new contract: no JS-context sink for
service_name survives, and the data-* sink stays autoescaped.
"""
import re
from pathlib import Path

from django.test import SimpleTestCase

_TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "templates/provisioning/partials/services_list.html"
)


class ServicesListXSSTests(SimpleTestCase):
    def test_no_service_name_in_js_onclick_context(self) -> None:
        """The old JS-injection surface (service_name inside onclick) must be gone."""
        content = _TEMPLATE.read_text()
        onclick_matches = re.findall(
            r"onclick=\"[^\"]*\{\{[^}]*service\.service_name[^}]*\}\}[^\"]*\"",
            content,
        )
        self.assertEqual(
            onclick_matches,
            [],
            f"service_name must not appear in an onclick JS context: {onclick_matches}",
        )

    def test_service_name_sink_is_autoescaped_data_attribute(self) -> None:
        """service_name now rides the data-confirm attribute of the delegated
        confirm-navigate action; autoescape (no |safe, no |escapejs) is the
        correct HTML-attribute-context protection."""
        content = _TEMPLATE.read_text()
        data_matches = re.findall(
            r'data-confirm="[^"]*\{\{\s*service\.service_name([^}]*)\}\}[^"]*"',
            content,
        )
        self.assertTrue(
            len(data_matches) > 0,
            "Expected service_name to be carried in an autoescaped data-confirm attribute",
        )
        for filters in data_matches:
            self.assertNotIn("safe", filters, "service_name must stay autoescaped (no |safe)")
            self.assertNotIn("escapejs", filters, "data-attribute context must not use |escapejs")
