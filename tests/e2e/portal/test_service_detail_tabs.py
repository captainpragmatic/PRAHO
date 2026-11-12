"""In a real browser, the customer's service page tabs use the shared `tabs` component (#821).

The Usage tab exists only for an active service and the Domains tab only when there are domains; whichever are there,
click and keyboard move the one selection, and exactly one panel shows.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL
from tests.e2e.helpers.csp import ensure_csp_capture, read_csp_violations


def test_the_service_page_tabs(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    ensure_csp_capture(page)
    own = e2e_baseline["customers"][0]
    page.goto(f"{BASE_URL}/services/{own['service_id']}/")
    tablist = page.get_by_role("tablist", name="Service Details")
    expect(tablist).to_be_visible()
    tabs = tablist.get_by_role("tab")
    names = [tabs.nth(index).get_attribute("data-tab") for index in range(tabs.count())]
    assert names[:2] == ["overview", "usage"], names  # the fixture's service is active
    assert "billing" in names

    def shown(selected: str) -> None:
        for name in names:
            panel = page.locator(f"#service-panel-{name}")
            tab = page.locator(f"#service-tab-{name}")
            expect(tab).to_have_attribute("aria-selected", "true" if name == selected else "false")
            if name == selected:
                expect(panel).to_be_visible()
            else:
                expect(panel).to_be_hidden()

    shown("overview")
    page.locator("#service-tab-usage").click()
    shown("usage")
    page.locator("#service-tab-usage").focus()
    page.keyboard.press("ArrowLeft")
    shown("overview")
    expect(page.locator("#service-tab-overview")).to_be_focused()
    page.keyboard.press("End")
    shown(names[-1])
    page.keyboard.press("Home")
    shown("overview")
    assert read_csp_violations(page) == []
