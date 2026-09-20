"""Customer support: persisted replies/files, closed tickets, search and isolation."""

import re

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, assert_responsive_results, run_responsive_breakpoints_test
from tests.e2e.helpers.isolation import verify_isolation
from tests.e2e.helpers.tickets import create_ticket, reply


def _no_staff_controls(page: Page) -> None:
    expect(
        page.locator('[name="is_internal"], [name="assigned_to"], [name="reply_action"], [name="resolution_code"]')
    ).to_have_count(0)


def _list(page: Page) -> None:
    page.goto(f"{BASE_URL}/tickets/")
    expect(page.get_by_role("heading", name="Tickets", exact=True).first).to_be_visible()
    expect(page.locator('a[href="/tickets/create/"]:visible').first).to_be_visible()


def test_customer_ticket_system_access_via_navigation(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/dashboard/")
    page.locator('nav a[href="/tickets/"]:visible').first.click()
    expect(page).to_have_url(re.compile(r"/tickets/$"))
    expect(page.locator('a[href="/tickets/create/"]:visible').first).to_be_visible()


def test_customer_ticket_list_display_own_tickets_only(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _list(page)
    rows = page.locator("#tickets-content tbody tr")
    expect(rows).to_have_count(20)
    expect(page.locator("#tickets-content")).to_contain_text("E2E-1-25")
    expect(page.locator("#tickets-content")).not_to_contain_text("E2E-2-")
    _no_staff_controls(page)
    expect(page.locator('[role="tab"]:visible')).to_have_text(
        ["All", "Open", "In Progress", "Waiting on You", "Closed"]
    )


def test_customer_ticket_creation_workflow(account_page) -> None:
    page, _ = account_page
    _, title = create_ticket(page)
    _no_staff_controls(page)
    page.goto(f"{BASE_URL}/tickets/")
    expect(page.locator("#tickets-content tbody tr")).to_have_count(1)
    expect(page.locator("#tickets-content")).to_contain_text(title)


def test_customer_ticket_detail_and_comments(account_page) -> None:
    page, _ = account_page
    create_ticket(page)
    _no_staff_controls(page)
    reply(page, "The gateway timeout also occurs on the account page.")
    expect(page.locator("#comments-container")).to_contain_text("Customer")
    expect(page.locator("#ticket-status-and-comments")).to_contain_text("Open")


def test_customer_ticket_file_attachments(account_page) -> None:
    page, _ = account_page
    create_ticket(page)
    content = b"Timeout at 12:00 UTC; request id e2e-attachment\n"
    page.locator('input[name="attachments"]').set_input_files(
        {"name": "diagnostics.txt", "mimeType": "text/plain", "buffer": content}
    )
    expect(page.locator("#file-list")).to_contain_text("diagnostics.txt")
    reply(page, "Please inspect the attached diagnostic excerpt.")
    link = page.get_by_role("link", name="diagnostics.txt", exact=False)
    expect(link).to_be_visible()
    response = page.request.get(BASE_URL + link.get_attribute("href"))
    assert response.status == 200
    assert response.body() == content
    assert "attachment;" in response.headers["content-disposition"]
    assert response.headers["cache-control"] == "private, no-store"


def test_customer_ticket_status_visibility_and_actions(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    customer = e2e_baseline["customers"][0]
    for field, status in [("ticket_id", "Open"), ("closed_ticket_id", "Closed")]:
        page.goto(f"{BASE_URL}/tickets/{customer[field]}/")
        expect(page.locator("#ticket-status-and-comments")).to_contain_text(status)
        _no_staff_controls(page)
        if status == "Open":
            expect(page.locator('[name="message"]')).to_be_visible()
        else:
            expect(page.locator('#reply-form, [name="message"]')).to_have_count(0)
            expect(page.locator("#main-content")).to_contain_text("closed")


def test_customer_ticket_access_control_security(account_page) -> None:
    page, _ = account_page
    create_ticket(page)
    _no_staff_controls(page)
    expect(page.locator("#comments-container")).not_to_contain_text("Internal")
    expect(page.locator('a[href*="/close/"], a[href*="/reopen/"]')).to_have_count(0)


@pytest.mark.expect_server_errors("Ticket not found", "access denied")
def test_customer_ticket_isolation_comprehensive_security(page: Page, e2e_baseline) -> None:
    verify_isolation(page, e2e_baseline, "ticket")


def test_customer_ticket_system_mobile_responsiveness(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.set_viewport_size({"width": 320, "height": 812})
    _list(page)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    page.locator("#tickets-content [data-href]:visible").first.click()
    expect(page.locator('[name="message"]')).to_be_visible()
    _no_staff_controls(page)


def test_customer_complete_ticket_workflow(account_page) -> None:
    page, _ = account_page
    url, title = create_ticket(page)
    reply(page, "The failure occurred again after restarting the browser.")
    page.goto(f"{BASE_URL}/tickets/")
    page.get_by_role("cell", name=title, exact=False).click()
    expect(page).to_have_url(url)
    expect(page.locator("#comments-container")).to_contain_text("again after restarting")


def test_customer_ticket_system_responsive_breakpoints(monitored_customer_page: Page) -> None:
    def check(page: Page, context: str = "") -> bool:
        _list(page)
        return page.evaluate("document.documentElement.scrollWidth <= innerWidth")

    assert_responsive_results(run_responsive_breakpoints_test(monitored_customer_page, check), "Customer tickets")


def test_customer_ticket_htmx_search(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _list(page)
    search = page.locator("#list-filter-search")
    search.fill("E2E-1-01")
    search.press("End")
    expect(page.locator("#tickets-content tbody tr")).to_have_count(1)
    expect(page.locator("#tickets-content")).to_contain_text("E2E-1-01")
    search.fill("no-ticket-with-this-title")
    search.press("End")
    expect(page.locator("#tickets-content tbody tr")).to_have_count(0)
    search.fill("")
    search.press("End")
    expect(page.locator("#tickets-content tbody tr")).to_have_count(20)
    page.locator('[role="tab"][data-tab-value="closed"]:visible').click()
    expect(page.locator("#tickets-content tbody tr")).to_have_count(1)
    expect(page.locator("#tickets-content")).to_contain_text("E2E-1-02")


def test_customer_ticket_dashboard_widget(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/dashboard/")
    expect(page.get_by_text("My Open Tickets", exact=True)).to_be_visible()
    expect(page.get_by_role("heading", name="My Recent Tickets")).to_be_visible()
    recent = page.locator('#main-content a[href^="/tickets/"]').filter(has=page.locator("p"))
    expect(recent).to_have_count(4)
    title = recent.first.locator("p").first.inner_text().strip()
    destination = recent.first.get_attribute("href")
    assert title
    recent.first.click()
    expect(page).to_have_url(BASE_URL + destination)
    expect(page.locator("#main-content")).to_contain_text(title)


def test_ticket_subjects_have_no_status_prefix(monitored_customer_page: Page) -> None:
    page = monitored_customer_page
    _list(page)
    rows = page.locator("#tickets-content tbody tr")
    expect(rows).to_have_count(20)
    assert not re.search(r"\[(OPEN|CLOSED|PENDING|IN.PROGRESS|RESOLVED)\]", " ".join(rows.all_text_contents()), re.I)


def test_ticket_detail_back_link_is_at_top(monitored_customer_page: Page, e2e_baseline) -> None:
    page = monitored_customer_page
    page.goto(f"{BASE_URL}/tickets/{e2e_baseline['customers'][0]['ticket_id']}/")
    back = page.get_by_role("link", name=re.compile("Back to Tickets"))
    expect(back).to_be_visible()
    assert back.bounding_box()["y"] < page.locator("h1").bounding_box()["y"]
    back.click()
    expect(page).to_have_url(re.compile(r"/tickets/$"))
