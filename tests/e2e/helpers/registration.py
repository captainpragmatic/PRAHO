"""Public Portal registration, in the steps a browser test can check one at a time.

Registration has two steps (#660-#672). `/register/` stores a pending registration and
answers "check your email". A worker mails a confirmation link, and the account exists only
once its holder opens that link, chooses a password and accepts the Terms of Service.

The e2e stack runs no worker, so `confirmation_link` delivers the mail with the
`run_queued_tasks` fixture and reads it from the file-based mailbox. Platform sends an
address at most one mail per ten minutes and five a day, and confirmation refuses a
company name that already exists, so every registration needs a fresh identity: use
`new_identity()`.
"""

import re
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from uuid import uuid4

from playwright.sync_api import Page, expect

from tests.e2e.helpers import BASE_URL, ensure_fresh_session, login_user

MAIL_DIRECTORY = Path(__file__).resolve().parents[3] / "logs" / "e2e-mail"
DELIVER = "apps.users.tasks.deliver_registration"
CONFIRM_LINK = re.compile(r"http://localhost:8701/register/confirm/[0-9a-f-]+/[0-9a-f]+/")
CUI = "14399840"  # valid check digit; stored as digits
PASSWORD = "Registration-E2E123!"  # test fixture, not a credential


@dataclass(frozen=True)
class Identity:
    email: str
    company: str
    password: str = PASSWORD


def new_identity(company_suffix: str = "") -> Identity:
    key = uuid4().hex[:10]
    suffix = f" {company_suffix}" if company_suffix else ""
    return Identity(email=f"signup-{key}@e2e.test", company=f"E2E Signup {key}{suffix} SRL")


# What Django's file mail backend writes after every message.
MESSAGE_SEPARATOR = b"\n" + b"-" * 79 + b"\n"


def mailbox() -> dict[Path, int]:
    """How much mail each file held so far; pass it to `delivered_to` to see only later mail.

    Django's file backend names a file once per backend instance and appends to it, so two
    mails can share a file, and a later mail can land in a file that already existed. A
    snapshot is each file's size, not just the list of files.
    """
    return {path: path.stat().st_size for path in MAIL_DIRECTORY.glob("*.log")}


def delivered_to(email: str, before: dict[Path, int]) -> list[EmailMessage]:
    """Every mail to `email` written after the snapshot, wherever the backend put it."""
    found = []
    for path in mailbox():
        with path.open("rb") as stream:
            stream.seek(before.get(path, 0))
            written = stream.read()
        for chunk in written.split(MESSAGE_SEPARATOR):
            if chunk.strip():
                message = BytesParser(policy=policy.default).parsebytes(chunk)
                if message["To"] == email:
                    found.append(message)
    return found


def fill_registration(page: Page, email: str, company: str) -> None:
    """Open `/register/` and fill in a Romanian SRL, without submitting."""
    ensure_fresh_session(page)
    page.goto(f"{BASE_URL}/register/")
    expect(page.locator('input[type="password"]')).to_have_count(0)
    page.locator('input[name="email"]').fill(email)
    page.locator('input[name="first_name"]').fill("Ana")
    page.locator('input[name="last_name"]').fill("Pop")
    page.locator('select[name="customer_type"]').select_option("srl")
    page.locator('input[name="company_name"]').fill(company)
    page.locator('input[name="cui"]').fill(CUI)  # A Romanian company gives a VAT number or a CUI
    page.locator('input[name="address_line1"]').fill("Str. Victoriei 10")
    page.locator('input[name="city"]').fill("București")
    page.locator('input[name="county"]').fill("București")
    page.locator('input[name="postal_code"]').fill("010061")
    page.locator('input[name="data_processing_consent"]').check()
    page.locator('input[name="terms_accepted"]').check()


def submit_registration(page: Page, email: str, company: str) -> None:
    """Submit `/register/`; the Portal answers the same way whether or not the address has an account."""
    fill_registration(page, email, company)
    page.locator('form button[type="submit"]').click()
    expect(page).to_have_url(f"{BASE_URL}/login/")
    expect(page.get_by_text("Check your email for a message with the next step.")).to_be_visible()


def confirmation_link(email: str, before: dict[Path, int], run_queued_tasks) -> str:
    """Deliver the queued registration mail and return the confirmation link it carries."""
    assert {"sent": True, "kind": "confirm"} in run_queued_tasks(DELIVER)
    [message] = delivered_to(email, before)
    body = message.get_body(preferencelist=("plain",)).get_content()
    link = CONFIRM_LINK.search(body)
    assert link, f"The registration mail must link to the public Portal: {body}"
    return link.group()


def open_confirmation(page: Page, link: str, company: str) -> None:
    """Open the emailed link; it lands on `/register/confirm/` showing what will be created."""
    page.goto(link)
    expect(page).to_have_url(f"{BASE_URL}/register/confirm/")
    expect(page.get_by_text(company)).to_be_visible()


def fill_confirmation(page: Page, password: str, confirm_password: str | None = None) -> None:
    page.locator('input[name="new_password"]').fill(password)
    page.locator('input[name="confirm_password"]').fill(password if confirm_password is None else confirm_password)
    page.locator('input[name="data_processing_consent"]').check()
    page.locator('input[name="terms_accepted"]').check()
    page.get_by_role("button", name="Create my account").click()


def register_customer(page: Page, run_queued_tasks, company_suffix: str = "") -> Identity:
    """Register, confirm from the emailed link, and sign in; returns the new account's identity."""
    identity = new_identity(company_suffix)
    before = mailbox()
    submit_registration(page, identity.email, identity.company)
    open_confirmation(page, confirmation_link(identity.email, before, run_queued_tasks), identity.company)
    fill_confirmation(page, identity.password)
    expect(page).to_have_url(f"{BASE_URL}/login/")
    expect(page.get_by_text("Your account is confirmed. You can sign in now.")).to_be_visible()
    assert login_user(page, identity.email, identity.password)
    return identity
