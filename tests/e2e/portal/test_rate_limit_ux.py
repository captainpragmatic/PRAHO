"""Normal browser auth feedback; deterministic 429 rendering lives in portal view tests.

The local E2E stack intentionally disables throttling. Sending bad passwords in
that stack cannot test rate limits, and looking for 'rate' anywhere was a false positive.
"""

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, ensure_fresh_session


def test_invalid_login_displays_credentials_error(page: Page) -> None:
    ensure_fresh_session(page)
    page.goto(f"{BASE_URL}/login/")
    page.locator('input[name="email"]').fill("invalid-login@e2e.invalid")
    page.locator('input[name="password"]').fill("Wrong-password123!")
    page.locator('form button[type="submit"]').click()
    expect(page).to_have_url(f"{BASE_URL}/login/")
    expect(page.locator("#main-content")).to_contain_text("Invalid email address or password")
    expect(page.locator("#main-content")).not_to_contain_text("Too many login attempts")


def test_dashboard_loads_without_rate_limit_banner_normally(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    response = page.goto(f"{BASE_URL}/dashboard/")
    assert response.status == 200
    expect(page).to_have_url(f"{BASE_URL}/dashboard/")
    expect(page.locator("h1")).to_be_visible()
    expect(page.locator("#main-content")).not_to_contain_text("Too many requests")


def test_catalog_page_accessible_without_rate_limit(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    response = page.goto(f"{BASE_URL}/order/")
    assert response.status == 200
    expect(page.locator("#cart-form-e2e-hosting")).to_be_visible()
    expect(page.locator("#main-content")).not_to_contain_text("Too many requests")
