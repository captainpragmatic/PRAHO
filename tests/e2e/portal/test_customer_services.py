"""Customer service reads, filters and action form against explicit fixtures.

Provisioning transitions are exercised by the real ORM workflow tests. The portal
currently offers a request form; its unimplemented action API is not a provisioning
success assertion. Usage history charts are not implemented; current usage is.
"""

import re
from datetime import date

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL
from tests.e2e.helpers.isolation import verify_isolation


def _detail(page: Page, baseline: dict) -> dict:
    own = baseline["customers"][0]
    response = page.goto(f"{BASE_URL}/services/{own['service_id']}/")
    assert response.status == 200
    expect(page.locator("h1")).to_contain_text("E2E Hosting 1-01")
    return own


def test_customer_service_detail_view(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    own = _detail(page, e2e_baseline)
    expect(page.get_by_role("button", name="Overview", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Usage & Performance", exact=True)).to_be_visible()
    expect(page.get_by_role("button", name="Billing", exact=True)).to_be_visible()
    expect(page.locator("#main-content")).to_contain_text("hosting-1-01.example")
    expect(page.locator(f'a[href="/services/{own["service_id"]}/request-action/"]').first).to_be_visible()
    page.get_by_role("link", name="Back to Services").click()
    expect(page).to_have_url(f"{BASE_URL}/services/")


def test_customer_service_plans_page(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/services/plans/")
    expect(page.get_by_role("heading", name="Available Plans")).to_be_visible()
    expect(page.get_by_role("heading", name="E2E Hosting", exact=True)).to_be_visible()
    for label in ("Create Plan", "Edit Plan", "Delete Plan"):
        expect(page.get_by_role("button", name=label)).to_have_count(0)
        expect(page.get_by_role("link", name=label)).to_have_count(0)


def test_customer_service_request_action(monitored_customer_page: Page, e2e_baseline) -> None:
    """Supported action form offers four request types and requires cancellation reasons."""
    page = monitored_customer_page
    own = _detail(page, e2e_baseline)
    page.goto(f"{BASE_URL}/services/{own['service_id']}/request-action/")
    expect(page.get_by_role("heading", name="Request Service Action")).to_be_visible()
    expect(page.locator('input[name="action"]')).to_have_count(4)
    page.locator('label[for="action_cancel_request"]').click()
    expect(page.locator("#action_cancel_request")).to_be_checked()
    expect(page.locator("#reason")).to_have_attribute("required", "")
    assert page.locator("#reason").evaluate("el => !el.checkValidity()")
    page.locator("#reason").fill("Review cancellation terms before submitting this request.")
    assert page.locator("#reason").evaluate("el => el.checkValidity()")
    expect(page.get_by_role("button", name="Submit Request")).to_be_visible()
    page.get_by_role("link", name="Cancel", exact=True).click()
    expect(page).to_have_url(f"{BASE_URL}/services/{own['service_id']}/")


def test_customer_service_usage_chart(monitored_customer_page: Page, e2e_baseline) -> None:
    """Current measured usage is visible; history charts are an explicit empty state."""
    page = monitored_customer_page
    _detail(page, e2e_baseline)
    page.get_by_role("button", name="Usage & Performance", exact=True).click()
    usage = page.locator("[x-show=\"isTab('usage')\"]")
    expect(usage).to_be_visible()
    expect(usage).to_contain_text("0.1 GB / 10 GB")
    expect(usage).to_contain_text("1.2% used")
    expect(usage).to_contain_text("0.0 GB / 100 GB")
    expect(usage).to_contain_text("Usage charts will be available soon")
    page.get_by_role("button", name="Overview", exact=True).click()
    expect(usage).to_be_hidden()
    expect(page.get_by_role("heading", name="Service Health")).to_be_visible()


def test_customer_services_dashboard_widget(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/dashboard/")
    link = page.locator('a[href="/services/"]:visible').first
    expect(link).to_be_visible()
    link.click()
    expect(page).to_have_url(f"{BASE_URL}/services/")
    expect(page.locator("tr[data-href]")).to_have_count(20)


def test_customer_services_mobile_responsiveness(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(f"{BASE_URL}/services/?q=hosting-1-01.example")
    expect(page.locator("table")).to_be_hidden()
    page.locator("div[data-href]:visible").click()
    expect(page.locator("h1")).to_contain_text("E2E Hosting 1-01")
    expect(page).to_have_url(f"{BASE_URL}/services/{e2e_baseline['customers'][0]['service_id']}/")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_customer_services_access_control(page: Page, e2e_baseline) -> None:
    verify_isolation(page, e2e_baseline, "service")


def test_services_list_page_structure(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/services/")
    expect(page.get_by_role("heading", name="My Services", exact=True)).to_be_visible()
    expect(page.get_by_role("tab")).to_have_count(8)
    expect(page.locator("#list-filter-search")).to_be_visible()
    expect(page.locator("tr[data-href]")).to_have_count(20)


def test_services_tab_filtering(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/services/")
    page.get_by_role("tab", name="Active").click()
    expect(page.locator("#list-filter-active-tab")).to_have_value("active")
    expect(page.locator("tr[data-href]")).to_have_count(20)
    for row in page.locator("tr[data-href]").all():
        expect(row.locator("td").nth(3)).to_have_text("Active")
    page.get_by_role("tab", name="Suspended").click()
    expect(page.locator("#list-filter-active-tab")).to_have_value("suspended")
    expect(page.locator("tr[data-href]")).to_have_count(0)
    expect(page.get_by_role("heading", name="No Suspended services")).to_be_visible()
    page.get_by_role("tab", name="All", exact=False).click()
    expect(page.locator("tr[data-href]")).to_have_count(20)


def test_services_search(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/services/")
    search = page.locator("#list-filter-search")
    for term, count in (("hosting-1-01.example", 1), ("ZZZNOEXISTING-SERVICE", 0), ("", 20)):
        search.fill(term)
        search.dispatch_event("keyup")
        expect(page.locator("tr[data-href]")).to_have_count(count)
        if count == 1:
            expect(page.locator("tr[data-href]")).to_contain_text("E2E Hosting 1-01")


def test_services_pagination(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/services/?page=1")
    first_page = page.locator("tr[data-href]").evaluate_all("rows => rows.map(row => row.dataset.href)")
    assert len(first_page) == 20
    page.locator('nav[aria-label*="agination"] a[href*="page=2"]').first.click()
    expect(page).to_have_url(re.compile(r"page=2"))
    second_page = page.locator("tr[data-href]").evaluate_all("rows => rows.map(row => row.dataset.href)")
    assert second_page
    assert not set(first_page) & set(second_page)


def test_service_detail_shows_actual_dates_not_calculating(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    own = _detail(page, e2e_baseline)
    day, month, year = map(int, own["service_renewal_date"].split("."))
    expected_date = date(year, month, day).strftime("%b %d, %Y")
    expect(page.locator("#main-content")).to_contain_text(expected_date)
    expect(page.locator("#main-content")).not_to_contain_text("Calculating")
    page.get_by_role("button", name="Billing", exact=True).click()
    expect(page.locator("[x-show=\"isTab('billing')\"]")).to_contain_text(expected_date)


def test_service_detail_domain_section_no_server_error(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    _detail(page, e2e_baseline)
    expect(page.locator("#main-content")).to_contain_text("hosting-1-01.example")
    expect(page.locator("#main-content")).not_to_contain_text("Server Error")
