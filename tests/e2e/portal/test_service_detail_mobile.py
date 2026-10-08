"""The full service name remains readable on a mobile service detail page."""

from collections.abc import Callable
from typing import TypedDict

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, ComprehensivePageMonitor, ensure_fresh_session, login_user

pytestmark = pytest.mark.e2e


class ServiceScenario(TypedDict):
    email: str
    password: str
    service_id: str
    service_name: str


def test_service_detail_shows_the_full_name_on_mobile(
    page: Page,
    e2e_scenario: Callable[[str], ServiceScenario],
) -> None:
    owner = e2e_scenario("service_request")
    page.set_viewport_size({"width": 390, "height": 844})
    ensure_fresh_session(page)
    assert login_user(page, owner["email"], owner["password"]), "Owned service customer login failed"

    with ComprehensivePageMonitor(page, "service_detail_full_name_mobile"):
        response = page.goto(f"{BASE_URL}/services/{owner['service_id']}/")
        assert response is not None and response.status == 200
        heading = page.locator("#main-content h1")
        expect(heading).to_be_visible()
        expect(heading).to_have_text(owner["service_name"])
        expect(heading).to_have_js_property("scrollWidth", heading.evaluate("el => el.clientWidth"))
        assert heading.evaluate("el => el.getBoundingClientRect().right <= window.innerWidth")

        page.get_by_role("button", name="Usage & Performance", exact=True).click()
        usage = page.locator("[x-show=\"isTab('usage')\"]")
        expect(usage).to_be_visible()
        period = page.get_by_role("combobox", name="Usage history period", exact=True)
        expect(period).to_be_visible()
        expect(period.locator("option")).to_have_text(["Last 7 days", "Last 30 days", "Last 90 days"])
        assert period.locator("option").evaluate_all("els => els.map(el => el.value)") == ["7d", "30d", "90d"]
        period.select_option("90d")
        expect(period).to_have_value("90d")
        page.get_by_role("button", name="Billing", exact=True).click()
        expect(page.locator("[x-show=\"isTab('billing')\"]")).to_be_visible()
        expect(usage).to_be_hidden()
        page.get_by_role("button", name="Overview", exact=True).click()
        expect(page.locator("[x-show=\"isTab('overview')\"]")).to_be_visible()
