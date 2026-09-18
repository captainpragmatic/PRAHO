"""Dashboard data and actions backed by explicit customer identity."""

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL


def _dashboard(page: Page) -> None:
    response = page.goto(f"{BASE_URL}/dashboard/")
    assert response.status == 200
    expect(page).to_have_url(f"{BASE_URL}/dashboard/")
    expect(page.locator("#main-content h1")).to_contain_text("Welcome")
    expect(page.locator("#main-content")).to_contain_text("My Services")
    expect(page.locator("#main-content")).not_to_contain_text("temporarily unavailable")


def test_superuser_dashboard_functionality(monitored_superuser_page: Page) -> None:
    _dashboard(monitored_superuser_page)
    expect(monitored_superuser_page.locator('#main-content a[href*="/billing/"]').first).to_be_visible()


def test_customer_dashboard_functionality(monitored_customer_page: Page) -> None:
    _dashboard(monitored_customer_page)
    expect(monitored_customer_page.locator('#main-content a[href*="/tickets/"]').first).to_be_visible()


def test_dashboard_role_based_content(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    _dashboard(page)
    _, other = e2e_baseline["customers"]
    expect(page.locator('#main-content a[href="/services/"]')).to_be_visible()
    expect(page.locator('#main-content a[href="/admin/"]')).to_have_count(0)
    expect(page.locator("#main-content")).not_to_contain_text(other["name"])


def test_dashboard_actions_and_interactions(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    for path in ("/tickets/create/", "/billing/invoices/", "/services/", "/profile/"):
        _dashboard(page)
        page.locator(f'#main-content a[href="{path}"]').last.click()
        expect(page).to_have_url(BASE_URL + path)
        expect(page.locator("#main-content h1:visible")).to_be_visible()


def test_dashboard_mobile_responsiveness(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    for width in (320, 375, 768, 1024, 1440):
        page.set_viewport_size({"width": width, "height": 900})
        _dashboard(page)
        expect(page.locator('#main-content a[href="/tickets/create/"]')).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_dashboard_mobile_specific_features(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.set_viewport_size({"width": 375, "height": 812})
    _dashboard(page)
    page.locator('#main-content a[href="/tickets/create/"]').click()
    expect(page).to_have_url(f"{BASE_URL}/tickets/create/")
    expect(page.locator('textarea[name="description"]')).to_be_visible()


def test_customer_dashboard_account_page(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/dashboard/account/")
    expect(page).to_have_url(f"{BASE_URL}/dashboard/account/")
    expect(page.get_by_role("heading", name="Account Overview", exact=True)).to_be_visible()
    expect(page.locator("#main-content")).to_contain_text(e2e_baseline["customers"][0]["email"])
    page.get_by_role("link", name="Edit Profile").click()
    expect(page).to_have_url(f"{BASE_URL}/profile/")


def test_account_status_card_reflects_actual_state(monitored_customer_page: Page) -> None:
    """The known active customer is shown; non-active/unknown states have CI contracts."""
    page = monitored_customer_page
    _dashboard(page)
    label = page.get_by_text("Account Status", exact=True)
    expect(label).to_be_visible()
    expect(label.locator("..")).to_contain_text("Active")


def test_account_overview_shows_customer_data(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/dashboard/account/")
    expect(page.locator("#main-content")).to_contain_text(e2e_baseline["customers"][0]["name"])
    expect(page.locator("#main-content")).to_contain_text("RO14399847")
    page.reload()
    expect(page.locator("#main-content")).to_contain_text(e2e_baseline["customers"][0]["name"])
