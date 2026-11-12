"""In a real browser, the customer status filter is a group of pressed buttons that follow the filter value (#821)."""

from __future__ import annotations

import re

from playwright.sync_api import Page, expect

from tests.e2e.helpers import PLATFORM_BASE_URL
from tests.e2e.helpers.csp import ensure_csp_capture, read_csp_violations


def test_the_filter_request_is_sent_and_pressed_follows_the_value(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    ensure_csp_capture(page)
    page.goto(f"{PLATFORM_BASE_URL}/customers/")
    group = page.get_by_role("group", name="Customer status")
    expect(group).to_be_visible()
    all_filter = group.get_by_role("button", name="All", exact=True)
    active_filter = group.get_by_role("button", name="Active", exact=True)
    expect(page.get_by_role("tablist", name="Customer status")).to_have_count(0)
    expect(all_filter).to_have_attribute("aria-pressed", "true")
    expect(active_filter).to_have_attribute("aria-pressed", "false")

    with page.expect_response(lambda response: "status=active" in response.url) as answer:
        active_filter.click()
    assert answer.value.ok
    expect(active_filter).to_have_attribute("aria-pressed", "true")
    expect(all_filter).to_have_attribute("aria-pressed", "false")
    expect(active_filter).to_have_class(re.compile(r"\bbg-slate-600\b"))
    expect(all_filter).not_to_have_class(re.compile(r"\bbg-slate-600\b"))
    expect(page.locator('select[name="status"]')).to_have_value("active")

    with page.expect_response(lambda response: "status=" in response.url and "status=active" not in response.url):
        all_filter.click()
    expect(all_filter).to_have_attribute("aria-pressed", "true")
    expect(active_filter).to_have_attribute("aria-pressed", "false")
    assert read_csp_violations(page) == []
