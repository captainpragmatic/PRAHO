"""
Alert Component Tests — Phase C.2 (completion)

Tests for the {% alert %} inclusion tag in apps.ui.templatetags.ui_components.
Verifies variant CSS, message rendering, title, dismissible state, and role=alert.
No database access.
"""

# ===============================================================================
# IMPORTS
# ===============================================================================

from django.template import Context, Template
from django.test import SimpleTestCase


def _render(template_str: str, context: dict | None = None) -> str:
    """Render a template string using Django's template system."""
    t = Template("{% load ui_components %}" + template_str)
    return t.render(Context(context or {}))


# ===============================================================================
# VARIANT CSS TESTS
# ===============================================================================


class AlertVariantTests(SimpleTestCase):
    """Tests that each variant maps to correct Tailwind colour classes."""

    def test_success_variant_has_green_classes(self) -> None:
        result = _render('{% alert "Saved!" variant="success" %}')
        self.assertIn("bg-green-50", result)
        self.assertIn("text-green-800", result)

    def test_warning_variant_has_yellow_classes(self) -> None:
        result = _render('{% alert "Watch out" variant="warning" %}')
        self.assertIn("bg-yellow-50", result)
        self.assertIn("text-yellow-800", result)

    def test_danger_variant_has_red_classes(self) -> None:
        result = _render('{% alert "Error!" variant="danger" %}')
        self.assertIn("bg-red-50", result)
        self.assertIn("text-red-800", result)

    def test_error_alias_matches_danger(self) -> None:
        danger = _render('{% alert "x" variant="danger" %}')
        error = _render('{% alert "x" variant="error" %}')
        # Both should produce red classes
        self.assertIn("bg-red-50", danger)
        self.assertIn("bg-red-50", error)

    def test_info_variant_has_blue_classes(self) -> None:
        result = _render('{% alert "Info" variant="info" %}')
        self.assertIn("bg-blue-50", result)
        self.assertIn("text-blue-800", result)

    def test_default_variant_is_info_blue(self) -> None:
        """AlertConfig defaults variant to 'info' → blue classes."""
        result = _render('{% alert "Notice" %}')
        self.assertIn("bg-blue-50", result)


# ===============================================================================
# ROLE & ACCESSIBILITY TESTS
# ===============================================================================


class AlertAccessibilityTests(SimpleTestCase):
    """Tests ARIA and accessibility attributes."""

    def test_has_role_alert(self) -> None:
        result = _render('{% alert "Test" %}')
        self.assertIn('role="alert"', result)

    def test_html_id_attribute_rendered(self) -> None:
        result = _render('{% alert "Test" html_id="my-alert" %}')
        self.assertIn('id="my-alert"', result)

    def test_without_html_id_no_id_attribute(self) -> None:
        result = _render('{% alert "Test" %}')
        self.assertNotIn("id=", result)


# ===============================================================================
# MESSAGE & TITLE RENDERING TESTS
# ===============================================================================


class AlertContentTests(SimpleTestCase):
    """Tests message body and title rendering."""

    def test_message_text_appears_in_output(self) -> None:
        result = _render('{% alert "Invoice paid successfully." variant="success" %}')
        self.assertIn("Invoice paid successfully.", result)

    def test_title_renders_in_h3(self) -> None:
        result = _render('{% alert "Body text" title="Heads up" %}')
        self.assertIn("Heads up", result)
        self.assertIn("<h3", result)

    def test_no_title_no_h3_rendered(self) -> None:
        result = _render('{% alert "Body only" %}')
        self.assertNotIn("<h3", result)

    def test_css_class_appended(self) -> None:
        result = _render('{% alert "Test" css_class="mt-4" %}')
        self.assertIn("mt-4", result)


# ===============================================================================
# DISMISSIBLE TESTS
# ===============================================================================


class AlertDismissibleTests(SimpleTestCase):
    """Tests for the dismissible/auto-dismiss behaviour."""

    def test_dismissible_adds_alpine_x_data(self) -> None:
        result = _render('{% alert "Test" dismissible=True %}')
        self.assertIn("x-data", result)
        self.assertIn("x-show", result)
