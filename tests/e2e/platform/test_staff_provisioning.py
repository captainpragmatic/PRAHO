"""Staff manually creates and changes service state; no provider call is made."""

import re
from uuid import uuid4

from playwright.sync_api import Page, expect

from tests.e2e.helpers import PLATFORM_BASE_URL


def _create(page: Page, account: dict) -> tuple[str, str]:
    domain = f"owned-{uuid4().hex[:12]}.example"
    page.goto(f"{PLATFORM_BASE_URL}/provisioning/services/create/")
    page.locator('select[name="customer_id"]').select_option(str(account["customer_id"]))
    plan = page.locator('select[name="plan_id"] option').filter(has_text="E2E Hosting")
    expect(plan).to_have_count(1)
    page.locator('select[name="plan_id"]').select_option(plan.get_attribute("value"))
    page.locator('input[name="domain"]').fill(domain)
    page.get_by_role("button", name="Create Service", exact=True).click()
    expect(page).to_have_url(re.compile(r"/provisioning/services/\d+/$"))
    expect(page.locator("main")).to_contain_text(domain)
    expect(page.get_by_text("Pending", exact=True)).to_be_visible()
    page.reload()
    expect(page.locator("main")).to_contain_text(domain)
    return page.url, domain


def _transition(page: Page, url: str, action: str, status: str) -> None:
    page.goto(url + action + "/")
    form = page.locator('form[method="post"]').filter(has=page.locator('button[type="submit"]')).last
    form.locator('button[type="submit"]').click()
    expect(page).to_have_url(url)
    expect(page.get_by_text(status, exact=True)).to_be_visible()
    page.reload()
    expect(page.get_by_text(status, exact=True)).to_be_visible()


def _list(page: Page) -> None:
    page.goto(f"{PLATFORM_BASE_URL}/provisioning/services/")
    expect(page.locator("main h1")).to_contain_text("Services")
    expect(page.get_by_role("link", name=re.compile("New Service"))).to_be_visible()


def test_staff_provisioning_system_access_via_navigation(monitored_staff_page: Page) -> None:
    _list(monitored_staff_page)


def test_staff_provisioning_dashboard_display(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    _list(page)
    for status in ("active", "suspended", "pending"):
        expect(page.locator(f'a[href*="status={status}"]').first).to_be_visible()
    expect(page.locator("tbody tr").first).to_be_visible()


def test_staff_service_creation_workflow(monitored_staff_page: Page, e2e_scenario) -> None:
    _create(monitored_staff_page, e2e_scenario("account"))


def test_staff_service_management_actions(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    url, _ = _create(page, e2e_scenario("account"))
    _transition(page, url, "activate", "Active")
    _transition(page, url, "suspend", "Suspended")
    _transition(page, url, "activate", "Active")


def test_staff_service_status_filtering(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    url, domain = _create(page, e2e_scenario("account"))
    _transition(page, url, "activate", "Active")
    page.goto(f"{PLATFORM_BASE_URL}/provisioning/services/?status=active")
    expect(page.locator("main")).to_contain_text(domain)
    page.goto(f"{PLATFORM_BASE_URL}/provisioning/services/?status=suspended")
    expect(page.locator("main")).not_to_contain_text(domain)


def test_staff_servers_and_plans_access(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    for path, heading in (("servers", "Server Infrastructure"), ("plans", "Planuri de găzduire disponibile")):
        _list(page)
        page.locator(f'main a[href="/provisioning/{path}/"]').click()
        expect(page).to_have_url(f"{PLATFORM_BASE_URL}/provisioning/{path}/")
        expect(page.locator("main h1")).to_contain_text(heading)


def test_staff_provisioning_system_mobile_responsiveness(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.set_viewport_size({"width": 375, "height": 812})
    _list(page)
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_staff_provisioning_system_responsive_breakpoints(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    for width in (375, 768, 1024, 1440):
        page.set_viewport_size({"width": width, "height": 900})
        _list(page)
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_staff_complete_provisioning_workflow(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    url, domain = _create(page, e2e_scenario("account"))
    _transition(page, url, "activate", "Active")
    page.goto(url + "edit/")
    updated_domain = domain.replace("owned-", "renamed-")
    page.locator('input[name="domain"]').fill(updated_domain)
    page.get_by_role("button", name="Update Service", exact=True).click()
    expect(page).to_have_url(url)
    page.reload()
    expect(page.locator("main")).to_contain_text(updated_domain)
    _transition(page, url, "suspend", "Suspended")
    _transition(page, url, "activate", "Active")
