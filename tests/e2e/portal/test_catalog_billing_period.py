"""In a real browser, the catalog's billing period stays owned by `billingToggle` (#821).

The buttons are a filter group now; the period still switches the prices and every cart form's billing_period, the
choice reaches the cart, and the cart count isn't disturbed.
"""

from __future__ import annotations

from playwright.sync_api import Page, expect

from tests.e2e.helpers.csp import ensure_csp_capture, read_csp_violations
from tests.e2e.helpers.orders import add_product


def test_the_period_switches_prices_and_the_cart_form_and_keeps_the_count(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    ensure_csp_capture(page)
    add_product(page)
    count = page.locator("#cart-count").inner_text()
    group = page.get_by_role("group", name="Billing period")
    monthly = group.get_by_role("button", name="Monthly", exact=True)
    annual = group.get_by_role("button", name="Annual")
    form = page.locator("#cart-form-e2e-hosting")
    period = form.locator('input[name="billing_period"]')
    expect(monthly).to_have_attribute("aria-pressed", "true")
    expect(annual).to_have_attribute("aria-pressed", "false")
    expect(period).to_have_value("monthly")
    monthly_price = page.locator("[x-show=\"isPeriod('monthly')\"]:visible").first
    expect(monthly_price).to_be_visible()

    annual.click()
    expect(annual).to_have_attribute("aria-pressed", "true")
    expect(monthly).to_have_attribute("aria-pressed", "false")
    expect(period).to_have_value("annual")
    expect(page.locator("[x-show=\"isPeriod('annual')\"]:visible").first).to_be_visible()
    expect(page.locator("[x-show=\"isPeriod('monthly')\"]:visible")).to_have_count(0)
    expect(page.locator("#cart-count")).to_have_text(count)

    with page.expect_request(
        lambda request: request.method == "POST" and "billing_period=annual" in (request.post_data or "")
    ):
        form.get_by_role("button", name="Add to Cart", exact=True).click()
    assert read_csp_violations(page) == []
