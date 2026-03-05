"""
Button Component Tests — Phase C.2

Tests for the {% button %} inclusion tag in apps.ui.templatetags.ui_components.
Verifies label rendering, variant CSS, size classes, link vs button element,
HTMX attribute emission, disabled state, and type attribute. No database access.
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
# LABEL RENDERING TESTS
# ===============================================================================


class ButtonLabelTests(SimpleTestCase):
    """Tests that the button label text is rendered correctly."""

    def test_label_appears_in_span(self) -> None:
        result = _render('{% button "Submit" %}')
        self.assertIn("Submit", result)
        self.assertIn("btn-label", result)

    def test_variable_label_interpolated(self) -> None:
        result = _render("{% button btn_text %}", {"btn_text": "Save Changes"})
        self.assertIn("Save Changes", result)

    def test_empty_label_renders_button(self) -> None:
        result = _render('{% button "" %}')
        self.assertIn("<button", result)


# ===============================================================================
# ELEMENT TYPE TESTS
# ===============================================================================


class ButtonElementTests(SimpleTestCase):
    """Tests that the correct HTML element is rendered based on href."""

    def test_no_href_renders_button_element(self) -> None:
        result = _render('{% button "Click" %}')
        self.assertIn("<button", result)
        self.assertNotIn("<a ", result)

    def test_href_renders_anchor_element(self) -> None:
        result = _render('{% button "Go" href="/dashboard/" %}')
        self.assertIn("<a ", result)
        self.assertNotIn("<button", result)

    def test_href_url_in_anchor(self) -> None:
        result = _render('{% button "Go" href="/billing/" %}')
        self.assertIn('href="/billing/"', result)

    def test_no_href_uses_button_type_attribute(self) -> None:
        result = _render('{% button "Submit" type="submit" %}')
        self.assertIn('type="submit"', result)

    def test_default_button_type_is_button(self) -> None:
        result = _render('{% button "Click" %}')
        self.assertIn('type="button"', result)


# ===============================================================================
# VARIANT TESTS
# ===============================================================================


class ButtonVariantTests(SimpleTestCase):
    """Tests that each variant maps to the expected CSS colour classes."""

    def _button(self, variant: str) -> str:
        return _render(f'{{% button "Test" variant="{variant}" %}}')

    def test_primary_variant_uses_red_bg(self) -> None:
        """Primary buttons use brand red (PragmaticHost brand colour)."""
        self.assertIn("bg-red-600", self._button("primary"))

    def test_secondary_variant_uses_slate_bg(self) -> None:
        self.assertIn("bg-slate-600", self._button("secondary"))

    def test_success_variant_uses_green_bg(self) -> None:
        self.assertIn("bg-green-600", self._button("success"))

    def test_danger_variant_uses_red_bg(self) -> None:
        self.assertIn("bg-red-600", self._button("danger"))

    def test_warning_variant_uses_yellow_bg(self) -> None:
        self.assertIn("bg-yellow-500", self._button("warning"))

    def test_info_variant_uses_blue_bg(self) -> None:
        self.assertIn("bg-blue-600", self._button("info"))

    def test_default_variant_is_primary(self) -> None:
        """ButtonConfig.variant defaults to 'primary', which uses bg-red-600."""
        result = _render('{% button "Default" %}')
        self.assertIn("bg-red-600", result)

    def test_unknown_variant_falls_back_to_slate(self) -> None:
        """An unrecognized variant string falls through to the else/slate branch."""
        result = _render('{% button "Custom" variant="custom_unknown" %}')
        self.assertIn("bg-slate-600", result)


# ===============================================================================
# SIZE TESTS
# ===============================================================================


class ButtonSizeTests(SimpleTestCase):
    """Tests for the size= parameter."""

    def _button(self, size: str) -> str:
        return _render(f'{{% button "S" size="{size}" %}}')

    def test_size_xs(self) -> None:
        self.assertIn("px-2", self._button("xs"))
        self.assertIn("text-xs", self._button("xs"))

    def test_size_sm(self) -> None:
        self.assertIn("px-3", self._button("sm"))
        self.assertIn("text-sm", self._button("sm"))

    def test_size_lg(self) -> None:
        self.assertIn("px-4", self._button("lg"))
        self.assertIn("py-2.5", self._button("lg"))

    def test_size_xl(self) -> None:
        self.assertIn("px-6", self._button("xl"))
        self.assertIn("py-3", self._button("xl"))

    def test_default_size_is_md(self) -> None:
        """Default size should render px-4 py-2 text-sm."""
        result = _render('{% button "Default" %}')
        self.assertIn("px-4", result)
        self.assertIn("py-2 ", result)
        self.assertIn("text-sm", result)


# ===============================================================================
# DISABLED STATE TESTS
# ===============================================================================


class ButtonDisabledTests(SimpleTestCase):
    """Tests for the disabled= parameter."""

    def test_disabled_button_has_disabled_attr(self) -> None:
        result = _render('{% button "Locked" disabled=True %}')
        # Check for the HTML boolean attribute form (not the CSS "disabled:" prefix)
        self.assertIn("disabled>", result)

    def test_disabled_anchor_uses_aria_disabled(self) -> None:
        result = _render('{% button "Go" href="/path/" disabled=True %}')
        self.assertIn('aria-disabled="true"', result)
        self.assertIn('tabindex="-1"', result)

    def test_enabled_button_has_no_disabled_attr(self) -> None:
        # Tailwind uses "disabled:opacity-50" CSS class — check for the HTML
        # boolean attribute form ("disabled>") rather than the substring " disabled".
        result = _render('{% button "Active" disabled=False %}')
        self.assertNotIn("disabled>", result)


# ===============================================================================
# HTMX ATTRIBUTE TESTS
# ===============================================================================


class ButtonHtmxTests(SimpleTestCase):
    """Tests that HTMX attributes are emitted correctly."""

    def test_hx_get_attribute(self) -> None:
        result = _render('{% button "Load" hx_get="/api/data/" %}')
        self.assertIn('hx-get="/api/data/"', result)

    def test_hx_post_attribute(self) -> None:
        result = _render('{% button "Submit" hx_post="/api/submit/" %}')
        self.assertIn('hx-post="/api/submit/"', result)

    def test_hx_target_attribute(self) -> None:
        result = _render('{% button "Update" hx_get="/api/" hx_target="#result" %}')
        self.assertIn('hx-target="#result"', result)

    def test_hx_confirm_attribute(self) -> None:
        result = _render('{% button "Delete" hx_delete="/api/del/" hx_confirm="Are you sure?" %}')
        self.assertIn("hx-confirm=", result)
        self.assertIn("Are you sure?", result)

    def test_hx_swap_attribute(self) -> None:
        result = _render('{% button "Swap" hx_get="/api/" hx_swap="outerHTML" %}')
        self.assertIn("hx-swap=", result)

    def test_hx_loading_spinner_on_htmx_action(self) -> None:
        """A button with hx_get should include the loading spinner span."""
        result = _render('{% button "Load" hx_get="/api/" %}')
        self.assertIn("btn-spinner", result)
        self.assertIn("htmx-indicator", result)

    def test_no_spinner_without_htmx(self) -> None:
        """A plain button with no HTMX attributes should not have a spinner."""
        result = _render('{% button "Static" %}')
        self.assertNotIn("btn-spinner", result)


# ===============================================================================
# CUSTOM CLASS TESTS
# ===============================================================================


class ButtonCustomClassTests(SimpleTestCase):
    """Tests for additional CSS class injection via class_=."""

    def test_extra_class_applied(self) -> None:
        result = _render('{% button "Test" class_="w-full" %}')
        self.assertIn("w-full", result)
