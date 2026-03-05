"""
Modal Component Tests — Phase C.2 (completion)

Tests for the {% modal %} inclusion tag in apps.ui.templatetags.ui_components.
Verifies role/aria attributes, title, size variants, close button, hidden state.
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
# ROLE & ARIA TESTS
# ===============================================================================


class ModalAriaTests(SimpleTestCase):
    """Tests ARIA attributes required for modal dialogs."""

    def test_has_role_dialog(self) -> None:
        result = _render('{% modal "confirm" title="Confirm?" %}')
        self.assertIn('role="dialog"', result)

    def test_has_aria_modal_true(self) -> None:
        result = _render('{% modal "confirm" title="Confirm?" %}')
        self.assertIn('aria-modal="true"', result)

    def test_title_has_aria_labelledby(self) -> None:
        result = _render('{% modal "confirm" title="Confirm?" %}')
        self.assertIn("aria-labelledby", result)
        self.assertIn("modal-title", result)

    def test_close_button_has_aria_label(self) -> None:
        result = _render('{% modal "confirm" title="Confirm?" %}')
        self.assertIn('aria-label=', result)


# ===============================================================================
# ID TESTS
# ===============================================================================


class ModalIdTests(SimpleTestCase):
    """Tests that modal ID is correctly applied."""

    def test_html_id_applied_to_wrapper(self) -> None:
        """modal_id is passed as first arg, wrapper gets id="modal-{modal_id}"."""
        result = _render('{% modal "my-modal" title="Test" %}')
        self.assertIn('id="modal-my-modal"', result)

    def test_explicit_html_id_overrides_default(self) -> None:
        """When html_id kwarg is provided, it takes precedence over default."""
        result = _render('{% modal "m" title="T" html_id="custom-id" %}')
        self.assertIn('id="custom-id"', result)


# ===============================================================================
# TITLE TESTS
# ===============================================================================


class ModalTitleTests(SimpleTestCase):
    """Tests title text rendering."""

    def test_title_text_appears_in_output(self) -> None:
        result = _render('{% modal "m" title="Delete Invoice" %}')
        self.assertIn("Delete Invoice", result)

    def test_title_in_h3_element(self) -> None:
        result = _render('{% modal "m" title="Confirm" %}')
        self.assertIn("<h3", result)

    def test_no_title_no_h3_rendered(self) -> None:
        """Passing empty string title means no h3 element rendered."""
        result = _render('{% modal "m" title="" %}')
        self.assertNotIn("<h3", result)


# ===============================================================================
# SIZE TESTS
# ===============================================================================


class ModalSizeTests(SimpleTestCase):
    """Tests size variant CSS classes."""

    def test_small_size(self) -> None:
        result = _render('{% modal "m" title="T" size="sm" %}')
        self.assertIn("sm:max-w-sm", result)

    def test_large_size(self) -> None:
        result = _render('{% modal "m" title="T" size="lg" %}')
        self.assertIn("sm:max-w-4xl", result)

    def test_default_size_is_medium(self) -> None:
        result = _render('{% modal "m" title="T" %}')
        self.assertIn("sm:max-w-lg", result)


# ===============================================================================
# HIDDEN STATE TESTS
# ===============================================================================


class ModalHiddenStateTests(SimpleTestCase):
    """Tests that modals start hidden by default."""

    def test_modal_hidden_by_default(self) -> None:
        result = _render('{% modal "m" title="T" %}')
        self.assertIn("display: none", result)
