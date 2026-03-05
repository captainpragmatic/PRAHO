"""
Toast Component Tests — Phase C.2 (completion)

Tests for the {% toast %} inclusion tag in apps.ui.templatetags.ui_components.
Verifies variant CSS classes, role=alert, Alpine.js bindings, auto-dismiss,
and dismissible behaviour. No database access.
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


class ToastVariantTests(SimpleTestCase):
    """Tests each variant maps to correct Tailwind colour classes."""

    def test_success_variant_green(self) -> None:
        result = _render('{% toast "Saved!" variant="success" %}')
        self.assertIn("bg-green-50", result)
        self.assertIn("text-green-800", result)

    def test_error_variant_red(self) -> None:
        result = _render('{% toast "Failed!" variant="error" %}')
        self.assertIn("bg-red-50", result)
        self.assertIn("text-red-800", result)

    def test_warning_variant_yellow(self) -> None:
        result = _render('{% toast "Warning!" variant="warning" %}')
        self.assertIn("bg-yellow-50", result)
        self.assertIn("text-yellow-800", result)

    def test_default_variant_info_blue(self) -> None:
        result = _render('{% toast "Note" %}')
        self.assertIn("bg-blue-50", result)


# ===============================================================================
# ROLE & ACCESSIBILITY TESTS
# ===============================================================================


class ToastAccessibilityTests(SimpleTestCase):
    """Tests that toast has proper ARIA role."""

    def test_has_role_alert(self) -> None:
        result = _render('{% toast "Test" %}')
        self.assertIn('role="alert"', result)

    def test_toast_id_attribute(self) -> None:
        result = _render('{% toast "Test" toast_id="t1" %}')
        self.assertIn('id="t1"', result)


# ===============================================================================
# ALPINE.JS BINDING TESTS
# ===============================================================================


class ToastAlpineTests(SimpleTestCase):
    """Tests Alpine.js x-data and x-show bindings are present."""

    def test_has_x_data(self) -> None:
        result = _render('{% toast "Test" %}')
        self.assertIn("x-data", result)

    def test_has_x_show(self) -> None:
        result = _render('{% toast "Test" %}')
        self.assertIn("x-show", result)

    def test_has_x_transition(self) -> None:
        result = _render('{% toast "Test" %}')
        self.assertIn("x-transition", result)


# ===============================================================================
# AUTO-DISMISS TESTS
# ===============================================================================


class ToastAutoDismissTests(SimpleTestCase):
    """Tests auto-dismiss setTimeout generation."""

    def test_auto_dismiss_emits_settimeout(self) -> None:
        result = _render('{% toast "Test" auto_dismiss=3000 %}')
        self.assertIn("3000", result)
        self.assertIn("setTimeout", result)

    def test_zero_auto_dismiss_disables_timeout(self) -> None:
        """When auto_dismiss=0, the setTimeout removal code is not emitted."""
        result = _render('{% toast "Test" auto_dismiss=0 %}')
        # 0 means disabled: the conditional in toast.html skips the setTimeout
        self.assertNotIn("setTimeout(() => { show = false", result)

    def test_default_auto_dismiss_is_5000ms(self) -> None:
        """Default auto_dismiss is 5000ms (5 seconds)."""
        result = _render('{% toast "Test" %}')
        self.assertIn("5000", result)


# ===============================================================================
# MESSAGE CONTENT TESTS
# ===============================================================================


class ToastMessageTests(SimpleTestCase):
    """Tests the toast message text is rendered."""

    def test_message_text_in_output(self) -> None:
        result = _render('{% toast "Invoice sent successfully." variant="success" %}')
        self.assertIn("Invoice sent successfully.", result)

    def test_dismissible_shows_close_button(self) -> None:
        result = _render('{% toast "Test" dismissible=True %}')
        self.assertIn("button", result)
