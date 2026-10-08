"""Draft invoice line controls and persistence in the live staff editor."""

from collections.abc import Callable
from typing import TypedDict

import pytest
from playwright.sync_api import Page, expect

from scripts.e2e_stack import manage
from tests.e2e.helpers import PLATFORM_BASE_URL

pytestmark = pytest.mark.e2e


class BillingScenario(TypedDict):
    customer_id: int


@pytest.fixture
def draft_invoice_id(e2e_scenario: Callable[[str], BillingScenario]) -> int:
    """Use an owned customer and the existing guarded live-database runner."""
    customer_id = int(e2e_scenario("billing")["customer_id"])
    result = manage(
        "platform",
        "shell",
        "--no-imports",
        "-c",
        f"""
from decimal import Decimal

from django.db import transaction

from apps.billing.invoice_models import Invoice, InvoiceLine
from apps.common.e2e_fixtures import OWNER, require_e2e_database

require_e2e_database()
with transaction.atomic():
    invoice = Invoice.objects.create(
        customer_id={customer_id},
        currency_id="RON",
        issuer_provider="builtin",
        meta={{"fixture_owner": OWNER, "fixture_name": "invoice-editor-{customer_id}"}},
    )
    for index in range(3):
        line = InvoiceLine(
            invoice=invoice,
            kind="service",
            description=f"E2E original line {{index}}",
            quantity=Decimal("1.000"),
            unit_price_cents=1000,
            tax_rate=Decimal("0.21"),
        )
        line.calculate_totals()
        line.save()
    invoice.recalculate_totals()
    invoice.save()
print(invoice.pk)
""",
        capture=True,
    )
    return int(result.stdout.strip())


def test_last_invoice_line_is_retained_and_edited_lines_are_saved(
    monitored_staff_page: Page, draft_invoice_id: int
) -> None:
    page = monitored_staff_page
    edit_url = f"{PLATFORM_BASE_URL}/billing/invoices/{draft_invoice_id}/edit/"
    page.goto(edit_url)
    lines = page.locator("#invoice-lines .invoice-line")
    expect(lines).to_have_count(3)

    page.get_by_role("button", name="Add Line Item", exact=True).click()
    expect(lines).to_have_count(4)
    lines.last.get_by_role("button", name="Remove Line", exact=True).click()
    expect(lines).to_have_count(3)
    for remaining in (2, 1):
        lines.first.get_by_role("button", name="Remove Line", exact=True).click()
        expect(lines).to_have_count(remaining)

    retained_id = lines.locator('input[name$="_id"]').input_value()
    notice = page.get_by_role("alert").filter(has_text="An invoice must contain at least one line.")
    for _attempt in range(2):
        lines.get_by_role("button", name="Remove Line", exact=True).click()
        expect(lines).to_have_count(1)
        expect(lines.locator('input[name$="_id"]')).to_have_value(retained_id)
        expect(notice).to_be_visible()

    lines.get_by_label("Description", exact=True).fill("E2E edited retained hosting")
    lines.get_by_label("Quantity", exact=True).fill("2")
    lines.get_by_label("Unit Price", exact=True).fill("12.34")
    page.get_by_role("button", name="Save Changes", exact=True).click()
    expect(page).to_have_url(f"{PLATFORM_BASE_URL}/billing/invoices/{draft_invoice_id}/")

    page.goto(edit_url)
    expect(lines).to_have_count(1)
    expect(lines.locator('input[name$="_id"]')).to_have_value(retained_id)
    expect(lines.get_by_label("Description", exact=True)).to_have_value("E2E edited retained hosting")
    expect(lines.get_by_label("Quantity", exact=True)).to_have_value("2.000")
    expect(lines.get_by_label("Unit Price", exact=True)).to_have_value("12.34")
    expect(notice).to_be_hidden()
