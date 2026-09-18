"""Navigation checks require actual clicks and all supported destinations."""

import re

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, ensure_fresh_session


def _desktop_link(page: Page, path: str) -> None:
    page.locator(f'nav a[href="{path}"]:visible').first.click()
    expect(page).to_have_url(BASE_URL + path)
    expect(page.locator("#main-content h1:visible")).to_be_visible()


def test_navigation_cross_page_flow(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    for path in ("/tickets/", "/billing/invoices/", "/services/", "/dashboard/"):
        _desktop_link(page, path)


def test_navigation_header_interactions(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _desktop_link(page, "/services/")
    _desktop_link(page, "/dashboard/")
    page.get_by_role("button", name="Logout", exact=True).click()
    expect(page).to_have_url(re.compile(r"/login/"))
    page.goto(f"{BASE_URL}/dashboard/")
    expect(page).to_have_url(re.compile(r"/login/"))


def test_navigation_menu_visibility_by_role(monitored_superuser_page: Page) -> None:
    """Portal sessions expose customer navigation even for a staff account with membership."""
    page = monitored_superuser_page
    for path in ("/tickets/", "/billing/invoices/", "/services/"):
        expect(page.locator(f'nav a[href="{path}"]:visible').first).to_be_visible()
    for path in ("/admin/", "/users/", "/infrastructure/"):
        expect(page.locator(f'nav a[href="{path}"]')).to_have_count(0)


def test_navigation_dropdown_interactions(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    toggle = page.get_by_role("button", name="My Account")
    toggle.click()
    profile = page.locator('nav a[href="/profile/"]:visible')
    expect(profile).to_be_visible()
    toggle.click()
    expect(profile).to_have_count(0)
    toggle.click()
    profile.click()
    expect(page).to_have_url(f"{BASE_URL}/profile/")


def test_mobile_navigation_responsiveness(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.set_viewport_size({"width": 375, "height": 812})
    toggle = page.locator("#mobile-menu-toggle")
    expect(toggle).to_be_visible()
    expect(page.locator("#mobile-menu")).to_be_hidden()
    toggle.click()
    expect(page.locator("#mobile-menu")).to_be_visible()
    page.locator('#mobile-menu a[href="/services/"]').click()
    expect(page).to_have_url(f"{BASE_URL}/services/")
    expect(page.locator("#mobile-menu")).to_be_hidden()


def test_navigation_responsive_breakpoints(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    for width in (320, 375, 768, 1024, 1440):
        page.set_viewport_size({"width": width, "height": 900})
        page.goto(f"{BASE_URL}/dashboard/")
        if width < 1024:
            page.locator("#mobile-menu-toggle").click()
            page.locator('#mobile-menu a[href="/tickets/"]').click()
        else:
            _desktop_link(page, "/tickets/")
        expect(page).to_have_url(f"{BASE_URL}/tickets/")
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_portal_health_check(page: Page) -> None:
    response = page.goto(f"{BASE_URL}/status/")
    assert response.status == 200
    expect(page).to_have_url(f"{BASE_URL}/status/")
    expect(page.locator("body")).to_contain_text(re.compile("healthy|operational|running|status|ok", re.I))


def test_login_shows_error_on_wrong_credentials(page: Page) -> None:
    ensure_fresh_session(page)
    page.goto(f"{BASE_URL}/login/")
    page.locator('input[name="email"]').fill("missing@e2e.invalid")
    page.locator('input[name="password"]').fill("wrong-password")
    page.locator('form button[type="submit"]').click()
    expect(page).to_have_url(f"{BASE_URL}/login/")
    expect(page.locator("#main-content")).to_contain_text(re.compile("invalid|incorrect", re.I))
    page.goto(f"{BASE_URL}/dashboard/")
    expect(page).to_have_url(re.compile(r"/login/"))
