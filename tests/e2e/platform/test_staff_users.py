"""Staff user directory: real search, role filters, detail and membership reads.

User creation takes place through customer registration. This directory has no
bulk mutation or staff account-creation endpoint; the audit records that limit.
"""

from playwright.sync_api import Page, expect

from tests.e2e.helpers import (
    PLATFORM_BASE_URL,
    MobileTestContext,
    assert_responsive_results,
    run_responsive_breakpoints_test,
    run_standard_mobile_test,
)


def _directory(page: Page) -> None:
    response = page.goto(f"{PLATFORM_BASE_URL}/auth/users/")
    assert response.status == 200
    expect(page.get_by_role("heading", name="Users", exact=True)).to_be_visible()
    expect(page.locator("table tbody tr").first).to_be_visible()


def _search(page: Page, email: str) -> None:
    _directory(page)
    page.get_by_role("searchbox", name="Search", exact=True).fill(email)
    page.get_by_role("button", name="Filter", exact=True).click()
    expect(page.locator("table tbody tr")).to_have_count(1)
    expect(page.locator("table tbody tr")).to_contain_text(email)


def test_staff_user_management_access_via_navigation(monitored_staff_page: Page) -> None:
    _directory(monitored_staff_page)
    expect(monitored_staff_page.get_by_role("combobox", name="Staff role")).to_be_visible()


def test_staff_user_list_display_and_filtering(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    _directory(page)
    page.get_by_role("combobox", name="Staff role").select_option("admin")
    page.get_by_role("button", name="Filter", exact=True).click()
    rows = page.locator("table tbody tr")
    assert rows.count() >= 2
    for row in rows.all():
        expect(row).to_contain_text("Superuser")
    expect(page.locator("main")).not_to_contain_text("e2e-customer@test.local")


def test_staff_user_detail_view_and_management(monitored_staff_page: Page, e2e_baseline) -> None:
    page = monitored_staff_page
    customer = e2e_baseline["customers"][0]
    _search(page, customer["email"])
    page.get_by_role("link", name="View", exact=True).click()
    expect(page).to_have_url(f"{PLATFORM_BASE_URL}/auth/users/{customer['user_id']}/")
    expect(page.locator("main")).to_contain_text(customer["email"])
    expect(page.locator("main")).to_contain_text("Member (1 organizations)")


def test_staff_can_view_new_customer_user(monitored_staff_page: Page, e2e_scenario) -> None:
    account = e2e_scenario("account")
    page = monitored_staff_page
    _search(page, account["email"])
    expect(page.locator("table tbody tr")).to_contain_text("Customer")
    page.get_by_role("link", name="View", exact=True).click()
    expect(page.locator("main")).to_contain_text(account["email"])
    expect(page.locator("main")).to_contain_text("Member (1 organizations)")


def test_staff_user_search_empty_result(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    _directory(page)
    page.get_by_role("searchbox", name="Search", exact=True).fill("missing-directory-user@e2e.invalid")
    page.get_by_role("button", name="Filter", exact=True).click()
    expect(page.locator("main")).to_contain_text("No users found.")
    expect(page.locator("table tbody tr")).to_have_count(0)


def test_staff_user_membership_summary(monitored_staff_page: Page, e2e_baseline) -> None:
    page = monitored_staff_page
    for customer in e2e_baseline["customers"]:
        page.goto(f"{PLATFORM_BASE_URL}/auth/users/{customer['user_id']}/")
        expect(page.locator("main")).to_contain_text(customer["email"])
        expect(page.locator("main")).to_contain_text("Member (1 organizations)")


def test_staff_user_management_mobile_responsiveness(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    _directory(page)
    with MobileTestContext(page, "mobile_medium") as mobile:
        run_standard_mobile_test(page, mobile, context_label="staff users")
        expect(page.get_by_role("button", name="Filter", exact=True)).to_be_visible()


def test_staff_complete_user_directory_workflow(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    account = e2e_scenario("account")
    _search(page, account["email"])
    page.get_by_role("link", name="View", exact=True).click()
    page.reload()
    expect(page.locator("main")).to_contain_text(account["email"])
    expect(page.locator("main")).to_contain_text("Member (1 organizations)")


def test_staff_user_management_responsive_breakpoints(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    _directory(page)

    def verify(page):
        _directory(page)
        return True

    results = run_responsive_breakpoints_test(page, verify)
    assert_responsive_results(results)
