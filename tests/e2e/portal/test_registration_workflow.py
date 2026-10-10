"""Register on the public Portal, follow the emailed link, choose a password and sign in."""

import re
from email import policy
from email.parser import BytesParser
from pathlib import Path
from uuid import uuid4

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, ensure_fresh_session, login_user

MAIL_DIRECTORY = Path(__file__).resolve().parents[3] / "logs" / "e2e-mail"
DELIVER = "apps.users.tasks.deliver_registration"


def delivered_to(email: str, before: set[Path]) -> list:
    delivered = set(MAIL_DIRECTORY.glob("*.log")) - before
    messages = [BytesParser(policy=policy.default).parsebytes(path.read_bytes()) for path in delivered]
    return [message for message in messages if message["To"] == email]


def submit_registration(page: Page, email: str, company: str) -> None:
    ensure_fresh_session(page)
    page.goto(f"{BASE_URL}/register/")
    expect(page.locator('input[type="password"]')).to_have_count(0)
    page.locator('input[name="email"]').fill(email)
    page.locator('input[name="first_name"]').fill("Ana")
    page.locator('input[name="last_name"]').fill("Pop")
    page.locator('select[name="customer_type"]').select_option("srl")
    page.locator('input[name="company_name"]').fill(company)
    page.locator('input[name="address_line1"]').fill("Str. Victoriei 10")
    page.locator('input[name="city"]').fill("București")
    page.locator('input[name="county"]').fill("București")
    page.locator('input[name="postal_code"]').fill("010061")
    page.locator('input[name="data_processing_consent"]').check()
    page.locator('input[name="terms_accepted"]').check()
    page.locator('form button[type="submit"]').click()
    expect(page).to_have_url(f"{BASE_URL}/login/")
    expect(page.get_by_text("Check your email for a message with the next step.")).to_be_visible()


def test_registration_is_finished_from_the_emailed_link(page: Page, run_queued_tasks) -> None:
    key = uuid4().hex[:10]
    email = f"signup-{key}@e2e.test"
    company = f"E2E Signup {key} SRL"
    before = set(MAIL_DIRECTORY.glob("*.log"))
    submit_registration(page, email, company)
    assert not delivered_to(email, before), "The request queues the mail; only a worker sends it"
    assert {"sent": True, "kind": "confirm"} in run_queued_tasks(DELIVER)

    [message] = delivered_to(email, before)
    body = message.get_body(preferencelist=("plain",)).get_content()
    link = re.search(r"http://localhost:8701/register/confirm/[0-9a-f-]+/[0-9a-f]+/", body)
    assert link, f"The registration mail must link to the public Portal: {body}"
    assert "Ana" not in body and company not in body, "The mail must not echo submitted text"

    response = page.goto(link.group())
    assert response.request.redirected_from is not None
    assert response.request.redirected_from.response().headers["referrer-policy"] == "no-referrer"
    expect(page).to_have_url(f"{BASE_URL}/register/confirm/")
    expect(page.get_by_text(company)).to_be_visible()
    chosen = " Chosen-on-the-page-2026! "
    page.locator('input[name="new_password"]').fill(chosen)
    page.locator('input[name="confirm_password"]').fill(chosen)
    page.locator('input[name="data_processing_consent"]').check()
    page.get_by_role("button", name="Create my account").click()
    expect(page).to_have_url(f"{BASE_URL}/login/")
    expect(page.get_by_text("Your account is confirmed. You can sign in now.")).to_be_visible()
    assert login_user(page, email, chosen)
    expect(page).to_have_url(f"{BASE_URL}/dashboard/")

    # The link worked once.
    page.goto(link.group())
    expect(page.get_by_text("This link has expired or was already used.")).to_be_visible()


def test_an_address_with_an_account_gets_the_same_page_and_a_different_mail(
    page: Page, run_queued_tasks, e2e_scenario
) -> None:
    account = e2e_scenario("account")
    before = set(MAIL_DIRECTORY.glob("*.log"))
    submit_registration(page, account["email"], f"E2E Existing {uuid4().hex[:10]} SRL")
    assert {"sent": True, "kind": "existing_account"} in run_queued_tasks(DELIVER)
    [message] = delivered_to(account["email"], before)
    body = message.get_body(preferencelist=("plain",)).get_content()
    assert "/register/confirm/" not in body
    assert "http://localhost:8701/password-reset/" in body
