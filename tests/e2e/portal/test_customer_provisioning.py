"""Portal service reads and the real Platform staff boundary.

Authenticated customer role checks are also covered by Platform access-control
unit tests. A missing Portal route is not treated as proof of authorization.
"""

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, PLATFORM_BASE_URL, ensure_fresh_session
from tests.e2e.helpers.isolation import verify_isolation


def _no_management(page: Page) -> None:
    expect(page.locator('a[href*="/provisioning/"]')).to_have_count(0)
    expect(
        page.locator(
            '#main-content a[href*="/edit/"], #main-content a[href*="/suspend/"], #main-content a[href*="/activate/"]'
        )
    ).to_have_count(0)


def test_customer_can_view_own_services_but_not_manage(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/services/{e2e_baseline['customers'][0]['service_id']}/")
    expect(page.locator("#main-content h1")).to_contain_text("E2E Hosting 1-01")
    _no_management(page)


def test_customer_cannot_create_services(page: Page, e2e_baseline) -> None:
    ensure_fresh_session(page)
    customer = e2e_baseline["customers"][0]
    page.goto(f"{PLATFORM_BASE_URL}/auth/login/")
    page.locator('input[name="email"]').fill(customer["email"])
    page.locator('input[name="password"]').fill("test123")
    page.locator('form button[type="submit"]').last.click()
    expect(page.locator("body")).to_contain_text("Customers please use the customer portal")
    response = page.request.get(f"{PLATFORM_BASE_URL}/provisioning/services/create/", max_redirects=0)
    assert response.status == 302
    assert "/auth/login/" in response.headers["location"]


def test_customer_cannot_access_service_management_actions(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    service_id = e2e_baseline["customers"][0]["service_id"]
    for action in ("edit", "suspend", "activate"):
        response = page.request.get(
            f"{PLATFORM_BASE_URL}/provisioning/services/{service_id}/{action}/", max_redirects=0
        )
        assert response.status == 302
        assert "/auth/login/" in response.headers["location"]
    page.goto(f"{BASE_URL}/services/{service_id}/")
    expect(page.get_by_text("Active", exact=True).first).to_be_visible()


def test_customer_server_access_blocked_but_plans_allowed(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    response = page.request.get(f"{PLATFORM_BASE_URL}/provisioning/servers/", max_redirects=0)
    assert response.status == 302
    assert "/auth/login/" in response.headers["location"]
    page.goto(f"{BASE_URL}/services/plans/")
    expect(page.get_by_role("heading", name="E2E Hosting", exact=True)).to_be_visible()
    _no_management(page)


def test_customer_provisioning_navigation_not_available(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/dashboard/")
    _no_management(page)


def test_customer_provisioning_comprehensive_security_validation(page: Page, e2e_baseline) -> None:
    verify_isolation(page, e2e_baseline, "service")


def test_customer_provisioning_security_mobile_compatibility(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(f"{BASE_URL}/services/{e2e_baseline['customers'][0]['service_id']}/")
    expect(page.locator("#main-content h1")).to_contain_text("E2E Hosting 1-01")
    _no_management(page)
