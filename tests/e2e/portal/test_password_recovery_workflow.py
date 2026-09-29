"""Recover through the email sent by Platform, using only public Portal pages."""

import re
from email import policy
from email.parser import BytesParser
from pathlib import Path

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, ensure_fresh_session, login_user

MAIL_DIRECTORY = Path(__file__).resolve().parents[3] / "logs" / "e2e-mail"


def test_password_recovery_email_link_reset_and_login(page: Page, e2e_scenario) -> None:
    account = e2e_scenario("account")
    ensure_fresh_session(page)
    before = set(MAIL_DIRECTORY.glob("*.log"))
    page.goto(f"{BASE_URL}/password-reset/")
    page.locator('input[name="email"]').fill(account["email"])
    page.locator('form button[type="submit"]').click()
    expect(page).to_have_url(f"{BASE_URL}/login/")

    delivered = set(MAIL_DIRECTORY.glob("*.log")) - before
    messages = [BytesParser(policy=policy.default).parsebytes(path.read_bytes()) for path in delivered]
    matching = [message for message in messages if message["To"] == account["email"]]
    assert len(matching) == 1, "The real request must generate exactly one local recovery email"
    body = matching[0].get_body(preferencelist=("plain",)).get_content()
    link = re.search(r"http://localhost:8701/password-reset/confirm/[A-Za-z0-9_-]+/[A-Za-z0-9-]+/", body)
    assert link, f"Recovery message must link to public Portal: {body}"
    assert "localhost:8700" not in body

    response = page.goto(link.group())
    assert response.headers["referrer-policy"] == "same-origin"
    token_request = response.request.redirected_from
    assert token_request is not None
    assert token_request.response().headers["referrer-policy"] == "no-referrer"
    expect(page).to_have_url(f"{BASE_URL}/password-reset/confirm/")
    new_password = " Recovered-strong-pass-2026! "
    page.locator('input[name="new_password"]').fill(new_password)
    page.locator('input[name="confirm_password"]').fill(new_password)
    page.get_by_role("button", name="Reset Password", exact=True).click()
    expect(page).to_have_url(f"{BASE_URL}/login/")
    assert login_user(page, account["email"], new_password)
    expect(page).to_have_url(f"{BASE_URL}/dashboard/")
    artifact = Path(__file__).resolve().parents[3] / "logs" / "recovery-service-requests" / "screenshots"
    artifact.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(artifact / "recovered-customer-dashboard.png"), full_page=True)

    ensure_fresh_session(page)
    page.goto(f"{BASE_URL}/login/")
    page.locator('input[name="email"]').fill(account["email"])
    page.locator('input[name="password"]').fill(account["password"])
    page.locator('form button[type="submit"]').click()
    expect(page).to_have_url(re.compile(r"/login/"))

    page.goto(link.group())
    page.locator('input[name="new_password"]').fill("Another-strong-pass-2026!")
    page.locator('input[name="confirm_password"]').fill("Another-strong-pass-2026!")
    page.get_by_role("button", name="Reset Password", exact=True).click()
    expect(page.locator("#main-content")).to_contain_text(re.compile("invalid|expired", re.IGNORECASE))
