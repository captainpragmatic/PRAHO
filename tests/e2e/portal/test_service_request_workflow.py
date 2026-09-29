"""Service requests become tickets with a private, manually completed staff review."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest
from django.conf import settings
from playwright.sync_api import Browser, Locator, Page, expect

from services.platform.tests.helpers.hmac import hmac_headers
from tests.e2e.helpers import (
    BASE_URL,
    PLATFORM_BASE_URL,
    ComprehensivePageMonitor,
    apply_storage_state,
    ensure_fresh_platform_session,
    ensure_fresh_session,
    login_platform_user,
    login_user,
)
from tests.e2e.helpers.constants import PROJECT_ROOT

pytestmark = pytest.mark.e2e


@pytest.fixture
def monitored_staff_page(
    browser: Browser,
    browser_context_args: dict[str, Any],
    request: pytest.FixtureRequest,
    _staff_storage_state: str | None,
) -> Iterator[Page]:
    """Use the existing staff auth/monitor helpers in a separate browser context.

    The sibling Platform fixture uses pytest's default page, already occupied by
    the customer fixture here. A separate context keeps both sessions independent.
    """
    context = browser.new_context(**browser_context_args)
    page = context.new_page()
    try:
        with ComprehensivePageMonitor(
            page,
            f"{request.node.name}-staff",
            check_console=True,
            check_network=True,
            check_html=True,
            check_css=True,
            check_accessibility=False,
            allow_accessibility_skip=True,
        ):
            if not apply_storage_state(page, _staff_storage_state, f"{PLATFORM_BASE_URL}/dashboard/", "/auth/login/"):
                ensure_fresh_platform_session(page)
                assert login_platform_user(page), "Staff could not authenticate against the local E2E Platform"
            yield page
    finally:
        context.close()


def _customer_api_data(
    page: Page, owner: dict[str, Any], path: str, filters: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Read the real customer API through its HMAC authentication boundary."""
    assert settings.E2E_FIXTURES_ENABLED, "This workflow must use the isolated E2E stack"
    timestamp = str(int(time.time()))
    body = json.dumps(
        {"customer_id": owner["id"], "user_id": owner["user_id"], "timestamp": int(timestamp)}
        | (filters or {})
    ).encode()
    signed = hmac_headers(
        "POST", path, body, portal_id="portal-001", timestamp=timestamp, secret=settings.PLATFORM_API_SECRET
    )
    headers = {key.removeprefix("HTTP_").replace("_", "-"): value for key, value in signed.items()}
    headers["Content-Type"] = "application/json"
    response = page.request.post(f"{PLATFORM_BASE_URL}{path}", data=body, headers=headers)
    assert response.status == 200, f"Customer ticket API returned {response.status}: {response.text()}"
    payload = response.json()
    assert payload["success"] is True
    return payload["data"]


def _customer_ticket_data(page: Page, owner: dict[str, Any], ticket_id: int) -> dict[str, Any]:
    ticket = _customer_api_data(page, owner, f"/api/tickets/{ticket_id}/")["ticket"]
    assert ticket["id"] == ticket_id
    return ticket


def _assert_private_review(
    customer: Page,
    owner: dict[str, Any],
    ticket_id: int,
    private_notes: list[str],
    public_comment_count: int,
) -> None:
    response = customer.reload()
    assert response is not None and response.status == 200
    expect(customer).to_have_url(f"{BASE_URL}/tickets/{ticket_id}/")
    expect(customer.get_by_test_id("staff-service-request")).to_have_count(0)
    expect(customer.locator('[name="decision"], [name="expected_status"], #service-request-note')).to_have_count(0)
    for label in ("Approve", "Reject", "Mark completed", "Open service"):
        expect(customer.get_by_role("button", name=label, exact=True)).to_have_count(0)
        expect(customer.get_by_role("link", name=label, exact=True)).to_have_count(0)
    expect(customer.locator("#main-content")).not_to_contain_text("Approved; awaiting manual completion")

    ticket = _customer_ticket_data(customer, owner, ticket_id)
    assert len(ticket["comments"]) == public_comment_count
    listing = _customer_api_data(customer, owner, "/api/tickets/", {"search": ticket["ticket_number"]})
    matching_tickets = [item for item in listing["tickets"] if item["id"] == ticket_id]
    assert len(matching_tickets) == 1
    assert matching_tickets[0]["comments_count"] == public_comment_count
    assert not {
        "service_request", "service_request_status", "reviewed_by", "reviewed_at", "completed_by", "completed_at"
    }.intersection(ticket)
    for note in private_notes:
        assert note not in customer.content(), "Internal note leaked into customer HTML"
        assert note not in json.dumps(ticket), "Internal note leaked through the customer API"
        assert note not in json.dumps(listing), "Internal note leaked through the customer list API"


def _screenshot(page: Page, action: str, stage: str, case_id: str) -> None:
    directory = PROJECT_ROOT / "logs" / "recovery-service-requests" / "screenshots"
    directory.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(directory / f"{action}-{stage}-{case_id}.png"), full_page=True)


def _submit_customer_request(customer: Page, owner: dict[str, Any], action: str, reason: str) -> dict[str, Any]:
    service_id = owner["service_id"]
    response = customer.goto(f"{BASE_URL}/services/{service_id}/request-action/")
    assert response is not None and response.status == 200
    expect(customer.get_by_role("heading", name="Request Service Action")).to_be_visible()
    submission_id = customer.locator('input[name="submission_id"]').input_value()
    assert str(UUID(submission_id)) == submission_id
    customer.locator(f'label[for="action_{action}"]').click()
    expect(customer.locator(f"#action_{action}")).to_be_checked()
    customer.locator("#reason").fill(reason)
    customer.get_by_role("button", name="Submit Request", exact=True).click()
    expect(customer).to_have_url(re.compile(rf"{re.escape(BASE_URL)}/tickets/[0-9]+/$"))
    ticket_id = int(urlsplit(customer.url).path.strip("/").split("/")[-1])
    expect(customer.locator("#main-content")).to_contain_text(reason)
    expect(customer.locator("#main-content")).to_contain_text(owner["service_name"])
    ticket = _customer_ticket_data(customer, owner, ticket_id)
    assert owner["service_name"] in ticket["related_service_name"]
    expect(customer.locator("h1")).to_contain_text(ticket["ticket_number"])
    return ticket


def _open_original_service(staff: Page, service_id: str, service_name: str, ticket_url: str) -> None:
    link = staff.get_by_test_id("staff-service-request").get_by_role("link", name="Open service", exact=True)
    expect(link).to_have_attribute("href", f"/provisioning/services/{service_id}/")
    link.click()
    expect(staff).to_have_url(f"{PLATFORM_BASE_URL}/provisioning/services/{service_id}/")
    expect(staff.get_by_role("heading", name=service_name, exact=True)).to_be_visible()
    response = staff.goto(ticket_url)
    assert response is not None and response.status == 200


def _pending_staff_panel(staff: Page, ticket_url: str, action_label: str, reason: str) -> Locator:
    response = staff.goto(ticket_url)
    assert response is not None and response.status == 200
    panel = staff.get_by_test_id("staff-service-request")
    expect(panel).to_be_visible()
    expect(panel).to_contain_text(action_label)
    expect(panel).to_contain_text(reason)
    expect(panel.locator('[name="expected_status"]')).to_have_value("pending")
    expect(panel.get_by_role("button", name="Approve", exact=True)).to_be_visible()
    expect(panel.get_by_role("button", name="Reject", exact=True)).to_be_visible()
    expect(panel.get_by_role("button", name="Mark completed", exact=True)).to_have_count(0)
    return panel


@pytest.mark.parametrize(
    ("action", "action_label", "finish"),
    [
        ("upgrade_request", "Upgrade request", "complete"),
        ("downgrade_request", "Downgrade request", "complete"),
        ("suspend_request", "Suspension request", "reject"),
        ("cancel_request", "Cancellation request", "reject"),
    ],
    ids=["upgrade-approved-completed", "downgrade-approved-completed", "suspension-rejected", "cancellation-rejected"],
)
def test_customer_request_and_private_staff_decision(  # noqa: PLR0913 -- browser fixtures and explicit action cases
    monitored_customer_page: Page,
    monitored_staff_page: Page,
    e2e_scenario,
    action: str,
    action_label: str,
    finish: str,
) -> None:
    customer = monitored_customer_page
    staff = monitored_staff_page
    assert customer.context is not staff.context
    owner = e2e_scenario("service_request")
    ensure_fresh_session(customer)
    assert login_user(customer, owner["email"], owner["password"])
    service_id = owner["service_id"]
    case_id = uuid4().hex[:12]
    reason = f"Customer request {case_id}: review {action_label.lower()} for this hosting service."

    ticket = _submit_customer_request(customer, owner, action, reason)
    ticket_id = ticket["id"]
    public_comment_count = len(ticket["comments"])
    _assert_private_review(customer, owner, ticket_id, [], public_comment_count)

    staff_ticket_url = f"{PLATFORM_BASE_URL}/tickets/{ticket_id}/"
    panel = _pending_staff_panel(staff, staff_ticket_url, action_label, reason)
    _screenshot(staff, action, "pending-staff", case_id)

    _open_original_service(staff, service_id, owner["service_name"], staff_ticket_url)

    private_notes = []
    if finish == "complete":
        private_notes.append(f"PRIVATE approval {case_id}: reviewed customer and service ownership.")
        panel.locator("#service-request-note").fill(private_notes[-1])
        panel.get_by_role("button", name="Approve", exact=True).click()
        expect(panel.locator('[name="expected_status"]')).to_have_value("approved")
        expect(panel).to_contain_text("Approved; awaiting manual completion")
        expect(panel.get_by_role("button", name="Approve", exact=True)).to_have_count(0)
        expect(panel.get_by_role("button", name="Mark completed", exact=True)).to_be_visible()
        expect(staff.locator("#comments-container")).to_contain_text(private_notes[-1])
        _assert_private_review(customer, owner, ticket_id, private_notes, public_comment_count)

        private_notes.append(f"PRIVATE completion {case_id}: local workflow verification; no hosting changes executed.")
        panel.locator("#service-request-note").fill(private_notes[-1])
        panel.get_by_role("button", name="Mark completed", exact=True).click()
        expect(panel).to_contain_text("Completed")
    else:
        private_notes.append(f"PRIVATE rejection {case_id}: request declined for this local workflow test.")
        panel.locator("#service-request-note").fill(private_notes[-1])
        panel.get_by_role("button", name="Reject", exact=True).click()
        expect(panel).to_contain_text("Rejected")

    expect(staff).to_have_url(staff_ticket_url)
    expect(panel.locator('[name="decision"], [name="expected_status"], #service-request-note')).to_have_count(0)
    expect(panel.get_by_role("link", name="Open service", exact=True)).to_be_visible()
    expect(staff.locator("#ticket-status-and-comments")).to_contain_text("Closed")
    expect(staff.locator("#comments-container")).to_contain_text(private_notes[-1])
    _screenshot(staff, action, "final-staff", case_id)

    _assert_private_review(customer, owner, ticket_id, private_notes, public_comment_count)
    expect(customer.locator("#ticket-status-and-comments")).to_contain_text("Closed")
    _screenshot(customer, action, "final-customer", case_id)
