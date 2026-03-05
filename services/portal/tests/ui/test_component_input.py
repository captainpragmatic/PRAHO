"""
Input Component Tests — Phase C.2 (completion)

Tests for the {% input_field %} inclusion tag in apps.ui.templatetags.ui_components.
Verifies label, required indicator, error state, help text, aria-describedby,
variant correctness, and HTMX attribute passthrough. No database access.
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
# LABEL TESTS
# ===============================================================================


class InputLabelTests(SimpleTestCase):
    """Tests label rendering and required indicator."""

    def test_label_renders_for_attribute(self) -> None:
        result = _render('{% input_field "email" html_id="email" label="Email" %}')
        self.assertIn('for="email"', result)
        self.assertIn("Email", result)

    def test_required_shows_asterisk(self) -> None:
        result = _render('{% input_field "name" html_id="f" label="Name" required=True %}')
        self.assertIn("*", result)

    def test_optional_no_asterisk(self) -> None:
        result = _render('{% input_field "name" html_id="f" label="Name" %}')
        # No required asterisk class
        self.assertNotIn("text-red-500", result)

    def test_label_omitted_when_not_provided(self) -> None:
        result = _render('{% input_field "field" %}')
        self.assertNotIn("<label", result)


# ===============================================================================
# ERROR STATE TESTS
# ===============================================================================


class InputErrorTests(SimpleTestCase):
    """Tests error message rendering and aria-invalid."""

    def test_error_message_rendered(self) -> None:
        result = _render('{% input_field "f" html_id="f" error="This field is required." %}')
        self.assertIn("This field is required.", result)

    def test_error_state_has_red_border(self) -> None:
        result = _render('{% input_field "f" html_id="f" error="Bad!" %}')
        self.assertIn("border-red-500", result)

    def test_no_error_has_normal_border(self) -> None:
        result = _render('{% input_field "f" html_id="f" %}')
        self.assertIn("border-slate-600", result)

    def test_aria_invalid_on_error(self) -> None:
        result = _render('{% input_field "f" html_id="f" error="bad" %}')
        self.assertIn('aria-invalid="true"', result)

    def test_no_aria_invalid_without_error(self) -> None:
        result = _render('{% input_field "f" html_id="f" %}')
        self.assertNotIn("aria-invalid", result)

    def test_error_gets_id_for_aria_describedby(self) -> None:
        result = _render('{% input_field "f" html_id="f" error="Required." %}')
        self.assertIn('id="f-error"', result)


# ===============================================================================
# ARIA-DESCRIBEDBY TESTS (Finding 1 regression guard)
# ===============================================================================


class InputAriaDescribedByTests(SimpleTestCase):
    """
    Regression tests for the double aria-describedby bug fixed in Finding 1.
    Verifies single combined attribute is emitted correctly.
    """

    def test_error_only_references_error_id(self) -> None:
        result = _render('{% input_field "name" html_id="name" error="Required." %}')
        self.assertIn('aria-describedby="name-error"', result)
        # Only ONE aria-describedby attribute
        self.assertEqual(result.count("aria-describedby="), 1)

    def test_help_only_references_help_id(self) -> None:
        result = _render('{% input_field "name" html_id="name" help_text="Enter full name." %}')
        self.assertIn('aria-describedby="name-help"', result)
        self.assertEqual(result.count("aria-describedby="), 1)

    def test_both_error_and_help_combined_into_one_attribute(self) -> None:
        result = _render('{% input_field "name" html_id="name" error="Required." help_text="Enter name." %}')
        # Single combined attribute with both IDs space-separated
        self.assertIn('aria-describedby="name-error name-help"', result)
        # Crucially: only ONE aria-describedby attribute (not two)
        self.assertEqual(result.count("aria-describedby="), 1)

    def test_help_text_element_has_correct_id(self) -> None:
        result = _render('{% input_field "name" html_id="name" help_text="Hint text here." %}')
        self.assertIn('id="name-help"', result)
        self.assertIn("Hint text here.", result)

    def test_neither_no_aria_describedby(self) -> None:
        result = _render('{% input_field "name" html_id="name" label="Name" %}')
        self.assertNotIn("aria-describedby", result)


# ===============================================================================
# INPUT TYPE TESTS
# ===============================================================================


class InputTypeTests(SimpleTestCase):
    """Tests different input_type parameter values."""

    def test_default_renders_text_input(self) -> None:
        result = _render('{% input_field "f" %}')
        self.assertIn('<input', result)
        self.assertIn('type="text"', result)

    def test_textarea_renders_textarea_element(self) -> None:
        result = _render('{% input_field "f" input_type="textarea" %}')
        self.assertIn("<textarea", result)
        self.assertNotIn("<input", result)

    def test_select_renders_select_element(self) -> None:
        result = _render('{% input_field "f" input_type="select" %}')
        self.assertIn("<select", result)

    def test_password_type_attribute(self) -> None:
        result = _render('{% input_field "f" input_type="password" %}')
        self.assertIn('type="password"', result)

    def test_email_type_attribute(self) -> None:
        result = _render('{% input_field "f" input_type="email" %}')
        self.assertIn('type="email"', result)
