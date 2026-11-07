"""In a real browser, a product's flag toggles keep the stored flag and the badge in step (#821).

The toggle endpoints invert the flag, so a click that ran twice would undo itself while the page showed one change.
`hx-sync="this:drop"` drops a second click while the first is in flight and `hx-disabled-elt` disables the control
until the answer arrives. Whatever the timing, after a rapid double click the stored flag (seen after a reload) is
the one the badge shows. The swapped-in control keeps its id, so keyboard focus comes back to it, and nothing on the
page breaks the CSP.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

from tests.e2e.helpers import PLATFORM_BASE_URL
from tests.e2e.helpers.csp import ensure_csp_capture, read_csp_violations


def _settled(page: Page, control_id: str) -> str:
    """The control's pressed state once no request is in flight."""
    control = page.locator(f"#{control_id}")
    expect(control).to_be_enabled()
    expect(control).not_to_have_class("htmx-request")
    page.wait_for_load_state("networkidle")
    expect(control).to_be_enabled()
    return control.get_attribute("aria-pressed") or ""


def test_a_rapid_double_click_leaves_the_stored_flag_as_the_badge_shows(
    monitored_staff_page: Page, e2e_scenario
) -> None:
    page = monitored_staff_page
    ensure_csp_capture(page)
    product = e2e_scenario("pricing")
    page.goto(f"{PLATFORM_BASE_URL}/products/{product['product_slug']}/")
    for field in ("active", "public", "featured"):
        control_id = f"detail-{field}-badge"
        control = page.locator(f"#{control_id}")
        expect(control).to_have_attribute("aria-pressed", "false" if field == "featured" else "true")
        control.dblclick()
        shown = _settled(page, control_id)
        page.reload()
        expect(page.locator(f"#{control_id}")).to_have_attribute("aria-pressed", shown)
    assert read_csp_violations(page) == []


def test_focus_comes_back_to_the_swapped_control(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    ensure_csp_capture(page)
    product = e2e_scenario("pricing")
    page.goto(f"{PLATFORM_BASE_URL}/products/{product['product_slug']}/")
    control = page.locator("#detail-featured-badge")
    expect(control).to_have_attribute("aria-pressed", "false")
    control.focus()
    page.keyboard.press("Enter")
    expect(control).to_have_attribute("aria-pressed", "true")
    expect(control).to_be_focused()
    expect(control).to_have_text("Featured")
    assert read_csp_violations(page) == []
