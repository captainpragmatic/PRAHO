"""Staff ticket actions must persist and internal comments remain private."""

import re
from uuid import uuid4

from playwright.sync_api import Page, expect

from tests.e2e.helpers import (
    BASE_URL,
    PLATFORM_BASE_URL,
    assert_responsive_results,
    ensure_fresh_session,
    login_user,
    run_responsive_breakpoints_test,
)


def _create(page: Page, customer: dict) -> str:
    subject = f"E2E support {uuid4().hex[:12]}"
    page.goto(f"{PLATFORM_BASE_URL}/tickets/create/")
    page.locator('select[name="customer_id"]').select_option(str(customer["customer_id"]))
    page.locator('input[name="subject"]').fill(subject)
    page.locator('textarea[name="description"]').fill("Investigate this owned customer support request.")
    page.locator('select[name="priority"]').select_option("high")
    page.get_by_role("button", name="Create Ticket", exact=True).click()
    expect(page).to_have_url(re.compile(r"/tickets/\d+/$"))
    expect(page.locator("#ticket-status-and-comments")).to_contain_text(subject)
    expect(page.locator("#ticket-status-and-comments")).to_contain_text(customer["name"])
    page.reload()
    expect(page.locator("#ticket-status-and-comments")).to_contain_text(subject)
    return page.url


def _reply(page: Page, message: str, action: str = "reply") -> None:
    form = page.locator("#reply-form")
    form.locator('textarea[name="reply"]').fill(message)
    form.locator('select[name="reply_action"]').select_option(action)
    if action == "close_with_resolution":
        form.locator('select[name="resolution_code"]').select_option("fixed")
    with page.expect_response(re.compile(r"/tickets/\d+/reply/$")) as result:
        form.locator('button[type="submit"]').click()
    assert result.value.status == 200
    expect(page.locator("#comments-container")).to_contain_text(message)
    # Verify persistence and start the next action with the completed HTMX swap.
    page.reload()
    expect(page.locator("#comments-container")).to_contain_text(message)


def _close_and_reopen(page: Page) -> None:
    _reply(page, "Confirmed resolution from the complete workflow.", "close_with_resolution")
    expect(page.locator("#ticket-status-and-comments")).to_contain_text("Closed")
    expect(page.locator("#ticket-status-and-comments")).to_contain_text("Fixed")
    page.locator('form[action*="/reopen/"] button[type="submit"]').click()
    expect(page.locator("#ticket-status-and-comments")).to_contain_text("In Progress")
    page.reload()
    expect(page.locator("#ticket-status-and-comments")).to_contain_text("In Progress")


def test_staff_ticket_system_access_via_navigation(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/tickets/")
    expect(page.get_by_role("heading", name="Support Tickets", exact=True)).to_be_visible()
    expect(page.get_by_role("link", name="New Ticket", exact=True).first).to_be_visible()


def test_staff_ticket_list_dashboard_display(monitored_staff_page: Page, e2e_baseline) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/tickets/?search=E2E-1-01")
    expect(page.locator("tr[data-href]")).to_have_count(1)
    expect(page.locator("tr[data-href]")).to_contain_text("E2E hosting help 1-01")
    expect(page.locator("#list-filter-search")).to_be_visible()


def test_staff_ticket_creation_workflow(monitored_staff_page: Page, e2e_scenario) -> None:
    _create(monitored_staff_page, e2e_scenario("account"))


def test_staff_ticket_detail_and_management_features(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    _create(page, e2e_scenario("account"))
    expect(page.locator('select[name="reply_action"] option')).to_have_count(4)
    expect(page.locator('input[type="file"]')).to_have_count(1)
    _reply(page, "Investigating server logs.", "internal_note")
    expect(page.locator("#comments-container")).to_contain_text("STAFF INTERNAL NOTE")


def test_staff_ticket_comments_and_internal_notes(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    account = e2e_scenario("account")
    url = _create(page, account)
    public = "Public update: investigation has started."
    private = "Internal financial detail must remain private."
    _reply(page, public)
    _reply(page, private, "internal_note")
    ensure_fresh_session(page)
    assert login_user(page, account["email"], account["password"])
    page.goto(url.replace(PLATFORM_BASE_URL, BASE_URL))
    expect(page.locator("#main-content")).to_contain_text(public)
    expect(page.locator("#main-content")).not_to_contain_text(private)


def test_staff_ticket_status_management(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    _create(page, e2e_scenario("account"))
    _reply(page, "Please provide the log excerpt.", "reply_and_wait")
    expect(page.locator("#ticket-status-and-comments")).to_contain_text("Waiting on Customer")
    _close_and_reopen(page)


def test_staff_ticket_access_control_permissions(monitored_staff_page: Page, e2e_baseline) -> None:
    page = monitored_staff_page
    for customer in e2e_baseline["customers"]:
        response = page.goto(f"{PLATFORM_BASE_URL}/tickets/{customer['ticket_id']}/")
        assert response.status == 200
        expect(page.locator("#ticket-status-and-comments")).to_contain_text(customer["name"])
        expect(page.locator('select[name="reply_action"]')).to_be_visible()


def test_staff_ticket_system_mobile_responsiveness(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.set_viewport_size({"width": 375, "height": 812})
    page.goto(f"{PLATFORM_BASE_URL}/tickets/")
    expect(page.get_by_role("link", name="New Ticket", exact=True).first).to_be_visible()
    expect(page.locator("div[data-href]:visible").first).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_staff_complete_ticket_management_workflow(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    _create(page, e2e_scenario("account"))
    _reply(page, "Customer-facing investigation update.")
    _reply(page, "Private internal investigation note.", "internal_note")
    _close_and_reopen(page)


def test_staff_ticket_system_responsive_breakpoints(monitored_staff_page: Page) -> None:
    def check(page: Page, context: str = "") -> bool:
        page.goto(f"{PLATFORM_BASE_URL}/tickets/")
        expect(page.get_by_role("link", name="New Ticket", exact=True).first).to_be_visible()
        return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")

    assert_responsive_results(run_responsive_breakpoints_test(monitored_staff_page, check), "Staff tickets")
