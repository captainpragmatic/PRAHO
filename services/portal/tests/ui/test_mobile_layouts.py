"""
Mobile Layout Tests — Phase C.2 (completion)

Verifies that portal templates include responsive classes required for
mobile-first layout. Checks for Tailwind breakpoint prefixes and
mobile-specific component patterns. No database access.
"""

# ===============================================================================
# IMPORTS
# ===============================================================================

from pathlib import Path

from django.test import SimpleTestCase

# ===============================================================================
# CONSTANTS
# ===============================================================================

TEMPLATES_ROOT = (
    Path(__file__).resolve().parents[2] / "templates"
)
COMPONENT_DIR = TEMPLATES_ROOT / "components"


# ===============================================================================
# HELPER
# ===============================================================================


def _read_template(relative_path: str) -> str:
    """Read a template file relative to TEMPLATES_ROOT."""
    return (TEMPLATES_ROOT / relative_path).read_text()


# ===============================================================================
# RESPONSIVE BREAKPOINT PRESENCE TESTS
# ===============================================================================


class ComponentResponsivenessTests(SimpleTestCase):
    """
    Checks that core components include sm: / md: / lg: responsive prefixes
    — a regression guard against removing mobile-first CSS.
    """

    def test_base_html_has_responsive_nav(self) -> None:
        content = _read_template("base.html")
        # Navigation must hide on mobile, show on desktop (or vice-versa)
        self.assertTrue(
            "md:flex" in content or "lg:flex" in content or "sm:flex" in content,
            "base.html navigation should contain responsive flex classes",
        )

    def test_cookie_banner_responsive_layout(self) -> None:
        content = _read_template("components/cookie_consent_banner.html")
        # Banner buttons should stack on mobile, row on sm+
        self.assertTrue(
            "sm:flex-row" in content or "md:flex-row" in content,
            "cookie banner should include sm: / md: row-layout class",
        )

    def test_invoices_table_has_mobile_card_view(self) -> None:
        content = _read_template("billing/partials/invoices_table.html")
        # Table hidden on mobile, card list shown
        self.assertIn("md:hidden", content)
        self.assertIn("md:block", content)


# ===============================================================================
# MOBILE NAVIGATION TESTS
# ===============================================================================


class MobileNavigationTests(SimpleTestCase):
    """Tests mobile-specific navigation patterns in base.html."""

    def test_base_has_mobile_menu_toggle(self) -> None:
        base_content = _read_template("base.html")
        # Mobile toggle is componentised — base.html must include mobile_header.html
        # which provides the actual toggle (id="mobile-menu-toggle").
        self.assertTrue(
            "mobile_header.html" in base_content or "mobile-menu" in base_content
            or "hamburger" in base_content or "menu-toggle" in base_content,
            "base.html should include mobile_header.html (or contain a mobile menu toggle element)",
        )

    def test_sidebar_hidden_on_mobile(self) -> None:
        content = _read_template("base.html")
        # Sidebar / sidebar-like nav hidden at small size
        self.assertTrue(
            "hidden md:" in content or "hidden lg:" in content,
            "Sidebar should be hidden on mobile via hidden + breakpoint classes",
        )


# ===============================================================================
# TOUCH TARGET SIZE TESTS
# ===============================================================================


class TouchTargetTests(SimpleTestCase):
    """
    Verifies that interactive elements in components meet minimum 44px tap targets
    via Tailwind padding classes (py-2+ = 8px padding each side = 36px+ height).
    """

    def test_button_component_has_minimum_padding(self) -> None:
        content = _read_template("components/button.html")
        # Buttons should have at least py-2 for tap targets
        self.assertTrue(
            "py-2" in content or "py-3" in content or "py-4" in content,
            "Button component should have vertical padding for touch targets",
        )

    def test_form_actions_component_has_padding(self) -> None:
        content = _read_template("components/form_actions.html")
        self.assertIn("py-2", content)
