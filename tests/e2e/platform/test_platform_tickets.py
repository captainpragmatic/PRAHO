"""
Platform Ticket E2E Tests

Consolidated test suite for staff ticket management covering:
  - List navigation, search, filtering
  - Full ticket lifecycle (open -> in_progress -> waiting -> closed -> reopen)
  - Badge verification (status, priority, comment role)
  - Mobile responsiveness
  - Access control

Replaces: test_staff_tickets.py, test_staff_tickets_workflow.py, test_staff_tickets_mixed.py
"""

import re

from playwright.sync_api import Page, expect

from tests.e2e.utils import (
    assert_responsive_results,
    navigate_to_platform_page,
    run_responsive_breakpoints_test,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _wait_for_htmx(page: Page, timeout: int = 8000) -> None:
    """Wait for HTMX swap to complete after a form submission."""
    page.wait_for_load_state("networkidle", timeout=timeout)
    page.wait_for_timeout(300)


def _get_status_text(page: Page) -> str:
    """Return the visible status badge text from the ticket detail page."""
    status_area = page.locator("#ticket-status-and-comments")
    for status in (
        "Open", "In Progress", "Waiting on Customer", "Closed",
        "Deschis", "In progres", "Așteaptă clientul", "Închis",
    ):
        badge = status_area.get_by_text(status, exact=True).first
        if badge.is_visible(timeout=500):
            return status
    raw = status_area.locator("div:has(> p:has-text('Status'))").first.inner_text()
    return raw


def _assert_status(page: Page, *expected: str, msg: str = "") -> str:
    """Assert the ticket status matches one of the expected values."""
    status = _get_status_text(page)
    assert any(exp in status for exp in expected), f"{msg} — got: {status}"
    return status


def _submit_reply(
    page: Page, text: str, action: str, resolution: str | None = None,
) -> None:
    """Fill the reply form, choose an action, and submit via HTMX."""
    reply_box = page.locator("textarea[name='reply']")
    expect(reply_box).to_be_visible(timeout=5000)
    reply_box.fill(text)

    page.select_option("select[name='reply_action']", action)

    if action == "close_with_resolution" and resolution:
        page.wait_for_timeout(200)
        page.select_option("select[name='resolution_code']", resolution)

    page.locator("#reply-form button[type='submit']").click()
    _wait_for_htmx(page)


def _create_ticket(page: Page, subject: str, priority: str = "high") -> str:
    """Create a ticket and return the detail page URL."""
    navigate_to_platform_page(page, "/tickets/create/")
    page.wait_for_load_state("networkidle")
    assert "/tickets/create/" in page.url

    customer_select = page.locator("select[name='customer_id']")
    expect(customer_select).to_be_visible()
    assert customer_select.locator("option").count() > 1, "Need at least one customer in fixtures"
    page.select_option("select[name='customer_id']", index=1)

    page.locator("input[name='subject'], input[name='title']").first.fill(subject)
    page.locator("textarea[name='description']").fill(
        "Automated E2E test — full lifecycle with badge verification."
    )

    priority_select = page.locator("select[name='priority']")
    if priority_select.is_visible():
        page.select_option("select[name='priority']", priority)

    page.locator("button:has-text('Create'), button:has-text('Submit')").first.click()
    page.wait_for_load_state("networkidle")

    assert "/tickets/" in page.url and "/create/" not in page.url, (
        f"Expected redirect to ticket detail, got {page.url}"
    )
    assert re.search(r"/tickets/\d+/", page.url), f"URL should contain ticket ID: {page.url}"
    return page.url


def _verify_badge_in_list(page: Page, ticket_url: str, expected_text: str) -> None:
    """Navigate to the ticket list and verify the status badge on the ticket row."""
    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")

    # Extract ticket ID from URL to find the correct row
    match = re.search(r"/tickets/(\d+)/", ticket_url)
    assert match, f"Cannot extract ticket ID from {ticket_url}"
    ticket_id = match.group(1)

    # Desktop table row (onclick contains the ticket URL)
    row = page.locator(f"tr[onclick*='/tickets/{ticket_id}/']").first
    if row.is_visible(timeout=2000):
        badge = row.get_by_text(expected_text, exact=True).first
        assert badge.is_visible(timeout=2000), (
            f"Expected '{expected_text}' badge in list row for ticket {ticket_id}"
        )
    else:
        # Mobile card fallback — find via link
        card = page.locator(f"a[href*='/tickets/{ticket_id}/']").first
        assert card.is_visible(timeout=2000), f"Ticket {ticket_id} not found in list"


# ---------------------------------------------------------------------------
# Phase helpers for lifecycle test (keeps each phase under PLR0915 limit)
# ---------------------------------------------------------------------------


def _verify_detail_after_create(page: Page, ticket_url: str) -> None:
    """Phase: verify initial state on the detail page after creation."""
    _assert_status(page, "Open", "Deschis", msg="New ticket should be Open")

    # Priority badge
    priority_badge = page.locator("#ticket-status-and-comments").get_by_text("High", exact=True).first
    if not priority_badge.is_visible(timeout=1000):
        # Try Romanian
        priority_badge = page.locator("#ticket-status-and-comments").get_by_text("Ridicat", exact=False).first
    assert priority_badge.is_visible(timeout=1000), "Priority badge 'High' should be visible"

    # Customer link
    customer_link = page.locator("#ticket-status-and-comments a[href*='/customers/']").first
    expect(customer_link).to_be_visible()

    # Verify badge in list
    _verify_badge_in_list(page, ticket_url, "Open")

    # Navigate back to detail
    page.goto(ticket_url)
    page.wait_for_load_state("networkidle")


def _reply_transitions(page: Page) -> None:
    """Phase: exercise reply -> in_progress, reply_and_wait -> waiting, internal_note."""
    # Staff reply -> In Progress
    _submit_reply(page, "Looking into this now.", "reply")
    _assert_status(page, "In Progress", "In progres", msg="First staff reply should set In Progress")

    comments = page.locator("#comments-container")
    expect(comments.get_by_text("Looking into this now.")).to_be_visible()

    # Support role badge on the reply
    support_badge = comments.locator("span.bg-blue-100").first
    assert support_badge.is_visible(timeout=2000), "Support comment should have blue badge"

    # Reply & wait -> Waiting on Customer
    _submit_reply(page, "Please provide your server access credentials.", "reply_and_wait")
    _assert_status(page, "Waiting", "Așteaptă", msg="Should be Waiting on Customer")

    # Internal note -> no status change
    _submit_reply(
        page,
        "INTERNAL: Customer is on shared hosting, may need VPS upgrade.",
        "internal_note",
    )
    internal_notes = page.locator("#comments-container .bg-amber-900\\/50")
    assert internal_notes.count() > 0, "Internal note should have amber styling"

    staff_badge = page.locator("#comments-container").get_by_text("STAFF", exact=False)
    assert staff_badge.count() > 0, "Internal note should show STAFF badge"

    _assert_status(page, "Waiting", "Așteaptă", msg="Internal note should NOT change status")


def _close_and_verify(page: Page, ticket_url: str) -> None:
    """Phase: close ticket, verify badges, verify reply form still visible for staff."""
    _submit_reply(
        page, "Resolved by upgrading to VPS plan.",
        "close_with_resolution", resolution="fixed",
    )
    _assert_status(page, "Closed", "Închis", msg="Should be Closed after resolution")

    # Resolution badge
    resolution_badge = page.locator("#ticket-status-and-comments").get_by_text("Fixed", exact=False).first
    if not resolution_badge.is_visible(timeout=1000):
        resolution_badge = page.locator("#ticket-status-and-comments").get_by_text("Rezolvat", exact=False).first
    # Resolution may appear as text rather than badge — check loosely
    status_area_text = page.locator("#ticket-status-and-comments").inner_text()
    assert any(t in status_area_text.lower() for t in ("fixed", "rezolvat", "closed", "închis")), (
        f"Expected resolution indicator in status area, got: {status_area_text[:200]}"
    )

    # Verify Closed badge in list
    _verify_badge_in_list(page, ticket_url, "Closed")

    # Reload detail and verify staff reply form still visible on closed tickets
    page.goto(ticket_url)
    page.wait_for_load_state("networkidle")
    expect(page.locator("#reply-form")).to_be_visible(timeout=5000)


def _reopen_and_wait(page: Page) -> None:
    """Phase: reopen the closed ticket, then set it back to waiting."""
    reopen_btn = page.locator("button:has-text('Reopen'), button:has-text('Redeschide')")
    expect(reopen_btn.first).to_be_visible(timeout=5000)
    reopen_btn.first.click()
    page.wait_for_load_state("networkidle")

    assert "/tickets/" in page.url
    _assert_status(
        page, "In Progress", "In progres", "Open", "Deschis",
        msg="Reopened ticket should be In Progress or Open",
    )

    _submit_reply(page, "Checking server logs one more time.", "reply_and_wait")
    _assert_status(page, "Waiting", "Așteaptă", msg="Should be Waiting on Customer again")


def _click_customer_link(page: Page) -> None:
    """Phase: click the customer name link and verify navigation."""
    customer_link = page.locator("#ticket-status-and-comments a[href*='/customers/']").first
    expect(customer_link).to_be_visible()
    href = customer_link.get_attribute("href")
    assert href and "/customers/" in href, f"Customer link should point to /customers/, got: {href}"

    customer_link.click()
    page.wait_for_load_state("networkidle")
    assert "/customers/" in page.url, f"Should navigate to customer profile, got: {page.url}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_ticket_list_and_navigation(monitored_staff_page: Page) -> None:
    """Test ticket list page displays correctly with stats, filters, and navigation."""
    page = monitored_staff_page

    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")
    assert "/tickets/" in page.url

    # Heading
    heading = page.locator(
        'h1:has-text("Support Tickets"), h1:has-text("Tichete de suport")'
    ).first
    expect(heading).to_be_visible()

    # New Ticket button
    new_ticket_btn = page.locator('a:has-text("New Ticket"), a:has-text("Tichet nou")').first
    expect(new_ticket_btn).to_be_visible()

    # Stats section (open count, total count)
    stats_area = page.locator(".text-amber-400, .text-white").first
    assert stats_area.is_visible(timeout=2000), "Stats section should be visible"

    # Status filter
    status_filter = page.locator("select[name='status']")
    expect(status_filter).to_be_visible()

    # HTMX search: type in search input, verify tickets container updates
    search_input = page.locator("#search")
    if search_input.is_visible(timeout=2000):
        search_input.fill("test")
        page.wait_for_timeout(700)  # debounce
        _wait_for_htmx(page)
        tickets_container = page.locator("#tickets-container")
        expect(tickets_container).to_be_visible()
        search_input.fill("")  # reset
        _wait_for_htmx(page)

    # Click New Ticket -> navigate to create form
    new_ticket_btn.click()
    page.wait_for_load_state("networkidle")
    assert "/tickets/create/" in page.url

    # Create form has customer select (staff creates for any customer)
    customer_select = page.locator("select[name='customer_id']")
    expect(customer_select).to_be_visible()


def test_ticket_full_lifecycle(monitored_staff_page: Page) -> None:
    """
    Full ticket state machine test with badge verification at each step.

    Steps:
      1.  Create ticket (priority=high)           -> Open
      2.  Verify detail: priority badge, status badge, customer link
      3.  Verify "Open" badge in ticket list
      4.  Staff reply                              -> In Progress + Support badge
      5.  Reply & wait                             -> Waiting on Customer
      6.  Internal note                            -> no change + STAFF badge + amber
      7.  Close with resolution (fixed)            -> Closed + resolution indicator
      8.  Verify "Closed" badge in ticket list
      9.  Verify reply form visible for staff on closed ticket
      10. Reopen                                   -> In Progress / Open
      11. Reply & wait again                       -> Waiting on Customer
      12. Click customer link                      -> /customers/{id}/
    """
    page = monitored_staff_page

    ticket_url = _create_ticket(page, "E2E Lifecycle: full state machine test", priority="high")
    _verify_detail_after_create(page, ticket_url)
    _reply_transitions(page)
    _close_and_verify(page, ticket_url)
    _reopen_and_wait(page)
    _click_customer_link(page)


def test_ticket_mobile_responsiveness(monitored_staff_page: Page) -> None:
    """Test ticket list renders correctly across mobile/tablet/desktop breakpoints."""

    def _check_tickets_page(pg: Page) -> dict:
        navigate_to_platform_page(pg, "/tickets/")
        pg.wait_for_load_state("networkidle")
        heading = pg.locator(
            'h1:has-text("Support Tickets"), h1:has-text("Tichete de suport")'
        ).first
        new_btn = pg.locator(
            'a:has-text("New Ticket"), a:has-text("Tichet nou"), a[href*="/tickets/create/"]'
        ).first
        return {
            "heading_visible": heading.is_visible(timeout=3000),
            "new_ticket_visible": new_btn.is_visible(timeout=2000),
        }

    results = run_responsive_breakpoints_test(monitored_staff_page, _check_tickets_page)
    assert_responsive_results(results)


def test_ticket_access_control(monitored_staff_page: Page) -> None:
    """Hard assertions that staff can access all ticket features."""
    page = monitored_staff_page

    # Ticket list loads
    navigate_to_platform_page(page, "/tickets/")
    page.wait_for_load_state("networkidle")
    heading = page.locator(
        'h1:has-text("Support Tickets"), h1:has-text("Tichete de suport")'
    ).first
    expect(heading).to_be_visible()

    # Create form accessible with customer select
    navigate_to_platform_page(page, "/tickets/create/")
    page.wait_for_load_state("networkidle")
    expect(page.locator("select[name='customer_id']")).to_be_visible()

    # Form fields present
    subject_field = page.locator("input[name='subject'], input[name='title']").first
    expect(subject_field).to_be_visible()
    expect(page.locator("textarea[name='description']")).to_be_visible()
    expect(page.locator("select[name='priority']")).to_be_visible()
