"""Ticket actions through visible forms, with persisted outcomes."""

import re
from uuid import uuid4

from playwright.sync_api import Page, expect

from tests.e2e.helpers.constants import BASE_URL


def create_ticket(page: Page, *, priority: str = "high") -> tuple[str, str]:
    title = f"E2E support {uuid4().hex[:12]}"
    page.goto(f"{BASE_URL}/tickets/create/")
    page.locator('[name="title"]').fill(title)
    page.locator('textarea[name="description"]').fill(
        "Website intermittently returns a gateway timeout. Please investigate."
    )
    page.locator('[name="priority"]').select_option(priority)
    page.locator('[name="category"]').select_option("technical")
    page.locator('form:has([name="title"]) button[type="submit"]').click()
    expect(page).to_have_url(re.compile(r"/tickets/\d+/$"))
    page.reload()
    expect(page.locator("#main-content")).to_contain_text(title)
    expect(page.locator("#ticket-status-and-comments")).to_contain_text("Open")
    expect(page.locator("#ticket-status-and-comments")).to_contain_text(priority.title())
    return page.url, title


def reply(page: Page, message: str) -> None:
    page.locator('[name="message"]').fill(message)
    with page.expect_response(
        lambda response: response.url.endswith("/reply/") and response.request.method == "POST"
    ) as response:
        page.locator('#reply-form button[type="submit"]').click()
    assert response.value.status == 200
    expect(page.locator("#comments-container")).to_contain_text(message)
    page.reload()
    expect(page.locator("#comments-container")).to_contain_text(message)
