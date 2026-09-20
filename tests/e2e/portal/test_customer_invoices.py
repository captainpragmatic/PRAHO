"""Billing list filters must change the actual documents, including later pages."""

import re

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, assert_responsive_results, run_responsive_breakpoints_test


def _list(page: Page) -> None:
    page.goto(f"{BASE_URL}/billing/invoices/")
    expect(page.get_by_role("heading", name="My Billing Documents", exact=True)).to_be_visible()


def _rows(page: Page):
    return page.locator("#invoices-content tbody tr[data-href]")


def test_invoices_list_page_structure(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _list(page)
    expect(_rows(page)).to_have_count(20)
    expect(page.locator('[role="tab"]:visible')).to_have_count(3)
    expect(page.locator("#list-filter-search")).to_be_visible()
    expect(page.locator('[name="status"]')).to_be_visible()
    expect(page.locator('a[href*="/invoices/create/"]')).to_have_count(0)


def test_invoices_tab_filtering(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _list(page)
    for value, path in [("invoice", "/invoices/"), ("proforma", "/proformas/")]:
        page.locator(f'[role="tab"][data-tab-value="{value}"]:visible').click()
        expect(page.locator("#list-filter-active-tab")).to_have_value(value)
        expect(_rows(page)).to_have_count(20)
        expect(_rows(page).first).to_have_attribute("data-href", re.compile(path))
        assert all(path in row.get_attribute("data-href") for row in _rows(page).all())


def test_invoices_search(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    _list(page)
    search = page.locator("#list-filter-search")
    number = e2e_baseline["customers"][0]["invoice_number"]
    search.fill(number)
    search.press("End")
    expect(_rows(page)).to_have_count(1)
    expect(_rows(page)).to_contain_text(number)
    search.fill("no-such-document-zzzz")
    search.press("End")
    expect(_rows(page)).to_have_count(0)
    search.fill("")
    search.press("End")
    expect(_rows(page)).to_have_count(20)


def test_invoices_status_dropdown(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _list(page)
    page.locator('[name="status"]').select_option("paid")
    expect(_rows(page)).to_have_count(12)
    assert all("Paid" in row.inner_text() for row in _rows(page).all())
    page.locator('[name="status"]').select_option("")
    expect(_rows(page)).to_have_count(20)


def test_invoices_click_through_to_detail(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _list(page)
    row = _rows(page).first
    path = row.get_attribute("data-href")
    row.click()
    expect(page).to_have_url(BASE_URL + path)
    expect(page.locator("#main-content")).to_contain_text("Test Company SRL")
    expect(page.locator('a[href$="/pdf/"]').first).to_be_visible()


def test_invoices_pagination(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _list(page)
    before = {row.get_attribute("data-href") for row in _rows(page).all()}
    page.get_by_role("link", name="Go to next page", exact=True).click()
    expect(page).to_have_url(re.compile("page=2"))
    expect(_rows(page)).to_have_count(20)
    after = {row.get_attribute("data-href") for row in _rows(page).all()}
    assert len(before) == len(after) == 20
    assert before.isdisjoint(after)


def test_invoices_mobile_responsiveness(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(f"{BASE_URL}/billing/invoices/")
    expect(page.locator("#invoices-content [data-href]:visible")).to_have_count(20)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    row = page.locator("#invoices-content [data-href]:visible").first
    path = row.get_attribute("data-href")
    row.click()
    expect(page).to_have_url(BASE_URL + path)


def test_invoices_responsive_breakpoints(monitored_customer_page: Page) -> None:
    def check(page: Page, context: str = "") -> bool:
        page.goto(f"{BASE_URL}/billing/invoices/")
        expect(page.locator("#list-filter-search")).to_be_visible()
        expect(page.locator("#invoices-content [data-href]:visible").first).to_be_visible()
        return page.evaluate("document.documentElement.scrollWidth <= innerWidth")

    assert_responsive_results(run_responsive_breakpoints_test(monitored_customer_page, check), "Billing list")


def test_invoice_detail_shows_customer_name_and_status(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    customer = e2e_baseline["customers"][0]
    page.goto(f"{BASE_URL}/billing/invoices/{customer['paid_invoice_number']}/")
    expect(page.locator("#main-content")).to_contain_text(customer["name"])
    expect(page.get_by_text("Paid", exact=True).first).to_be_visible()


def test_proforma_vat_rate_shows_percentage_not_decimal(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/billing/proformas/{e2e_baseline['customers'][0]['proforma_number']}/")
    expect(page.locator("#main-content")).to_contain_text("21%")
    expect(page.locator("#main-content")).not_to_contain_text("0.21%")
    expect(page.locator("#main-content")).to_contain_text("121,00")
