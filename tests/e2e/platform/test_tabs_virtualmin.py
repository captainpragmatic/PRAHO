"""In a real browser, the Virtualmin server and account pages' tabs work through the shared `tabs` component (#821).

Clicking and the arrow keys both move the selection; exactly one panel shows, aria-selected and the roving tabindex
follow, and nothing on the page breaks the CSP.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

from tests.e2e.helpers import PLATFORM_BASE_URL
from tests.e2e.helpers.csp import ensure_csp_capture, read_csp_violations


def _assert_selected(page: Page, group: str, names: list[str], selected: str) -> None:
    for name in names:
        tab = page.locator(f"#{group}-tab-{name}")
        panel = page.locator(f"#{group}-panel-{name}")
        if name == selected:
            expect(tab).to_have_attribute("aria-selected", "true")
            expect(tab).to_have_attribute("tabindex", "0")
            expect(panel).to_be_visible()
        else:
            expect(tab).to_have_attribute("aria-selected", "false")
            expect(tab).to_have_attribute("tabindex", "-1")
            expect(panel).to_be_hidden()


def _exercise(page: Page, group: str, names: list[str]) -> None:
    _assert_selected(page, group, names, names[0])
    page.locator(f"#{group}-tab-{names[1]}").click()
    _assert_selected(page, group, names, names[1])
    focused = page.locator(f"#{group}-tab-{names[1]}")
    focused.focus()
    page.keyboard.press("ArrowRight")
    _assert_selected(page, group, names, names[2])
    expect(page.locator(f"#{group}-tab-{names[2]}")).to_be_focused()
    page.keyboard.press("ArrowLeft")
    _assert_selected(page, group, names, names[1])
    page.keyboard.press("End")
    _assert_selected(page, group, names, names[-1])
    page.keyboard.press("ArrowRight")  # wraps
    _assert_selected(page, group, names, names[0])
    page.keyboard.press("End")
    page.keyboard.press("Home")
    _assert_selected(page, group, names, names[0])
    expect(page.locator(f"#{group}-tab-{names[0]}")).to_be_focused()
    assert read_csp_violations(page) == []


def test_the_server_page_tabs(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    ensure_csp_capture(page)
    fixture = e2e_scenario("virtualmin")
    page.goto(f"{PLATFORM_BASE_URL}/provisioning/virtualmin/servers/{fixture['server_id']}/")
    expect(page.get_by_role("tablist", name="Recent Activity")).to_be_visible()
    _exercise(page, "server", ["live-domains", "accounts", "jobs"])


def test_the_account_page_tabs(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    ensure_csp_capture(page)
    fixture = e2e_scenario("virtualmin")
    page.goto(f"{PLATFORM_BASE_URL}/provisioning/virtualmin/accounts/{fixture['account_id']}/")
    expect(page.get_by_role("tablist", name="Account Details")).to_be_visible()
    _exercise(page, "account", ["overview", "backups", "logs", "settings"])
