"""The staff proforma form in a real browser: the line total fits its cell, and VAT defaults follow
the customer without moving a rate the operator chose (#689).

A 100,000+ total overflowed its grid cell at md widths (narrowest at about 1024 pixels, where the
form sits in a 2/3 column). The checks measure the rendered amount itself: the `.line-total` box
does not grow with overflowing text, so its own bounding box would pass however long the text is.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import TypedDict

import pytest
from playwright.sync_api import Page, expect

from scripts.e2e_stack import manage
from tests.e2e.helpers import PLATFORM_BASE_URL

pytestmark = pytest.mark.e2e

CREATE_URL = f"{PLATFORM_BASE_URL}/billing/proformas/create/"
# 999,999.99 x 1 at the supplier's standard rate (21% in the E2E data); \s also matches no-break spaces.
GROUPED_TOTAL = re.compile(r"^1[.,\s]209[.,\s]999[.,]99$")
TOLERANCE_PX = 0.5

MEASURE_FIRST_LINE = """() => {
  const total = document.querySelector('#proforma-lines .proforma-line .line-total');
  const cell = total.parentElement;
  const row = cell.closest('.proforma-line');
  const header = document.getElementById('proforma-lines').previousElementSibling;
  const range = document.createRange();
  range.selectNodeContents(total);
  const rect = r => ({left: r.left, right: r.right, top: r.top, bottom: r.bottom});
  return {
    text: rect(range.getBoundingClientRect()),
    total: rect(total.getBoundingClientRect()),
    cell: rect(cell.getBoundingClientRect()),
    row: rect(row.getBoundingClientRect()),
    headerTotal: rect(header.children[4].getBoundingClientRect()),
    headerVisible: getComputedStyle(header).display !== 'none',
    overflowing: total.scrollWidth > total.clientWidth,
  };
}"""


class BillingScenario(TypedDict):
    customer_id: int


def _inside(inner: dict[str, float], outer: dict[str, float]) -> bool:
    return (
        inner["left"] >= outer["left"] - TOLERANCE_PX
        and inner["right"] <= outer["right"] + TOLERANCE_PX
        and inner["top"] >= outer["top"] - TOLERANCE_PX
        and inner["bottom"] <= outer["bottom"] + TOLERANCE_PX
    )


@pytest.mark.parametrize("width", [768, 1024, 1280])
def test_a_large_line_total_stays_inside_its_cell(monitored_staff_page: Page, width: int) -> None:
    page = monitored_staff_page
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(CREATE_URL)

    line = page.locator("#proforma-lines .proforma-line").first
    line.locator('input[name="line_0_quantity"]').fill("1")
    line.locator('input[name="line_0_unit_price"]').fill("999999.99")
    total = line.locator(".line-total")
    expect(total).to_have_text(GROUPED_TOTAL)

    box = total.bounding_box()
    cell_box = line.locator(".line-total").locator("xpath=..").bounding_box()
    assert box is not None and cell_box is not None
    assert box["x"] >= cell_box["x"] - TOLERANCE_PX
    assert box["x"] + box["width"] <= cell_box["x"] + cell_box["width"] + TOLERANCE_PX

    metrics = page.evaluate(MEASURE_FIRST_LINE)
    assert not metrics["overflowing"], f"the amount overflows its box at {width}px: {metrics}"
    assert _inside(metrics["text"], metrics["total"]), f"the amount leaves its box at {width}px: {metrics}"
    assert _inside(metrics["total"], metrics["cell"]), f"the box leaves its cell at {width}px: {metrics}"
    assert _inside(metrics["cell"], metrics["row"]), f"the cell leaves its row at {width}px: {metrics}"
    # The header and the row are separate grids; the shared template keeps their total columns aligned.
    assert metrics["headerVisible"]
    assert abs(metrics["headerTotal"]["left"] - metrics["cell"]["left"]) <= TOLERANCE_PX, metrics
    assert abs(metrics["headerTotal"]["right"] - metrics["cell"]["right"]) <= TOLERANCE_PX, metrics


@pytest.fixture
def custom_rate_customer_id(e2e_scenario: Callable[[str], BillingScenario]) -> int:
    """An owned customer whose tax profile carries a custom 25.5% rate."""
    customer_id = int(e2e_scenario("billing")["customer_id"])
    manage(
        "platform",
        "shell",
        "--no-imports",
        "-c",
        f"""
from decimal import Decimal

from apps.common.e2e_fixtures import OWNER, require_e2e_database
from apps.customers.models import CustomerTaxProfile

require_e2e_database()
profile = CustomerTaxProfile.objects.get(customer_id={customer_id}, customer__meta__fixture_owner=OWNER)
profile.vat_rate = Decimal("25.50")
profile.vat_rate_reason = "other"
profile.save()
""",
    )
    return customer_id


def test_new_lines_default_to_the_customers_rate_and_chosen_rates_stay(
    monitored_staff_page: Page, custom_rate_customer_id: int
) -> None:
    page = monitored_staff_page
    page.goto(CREATE_URL)
    lines = page.locator("#proforma-lines .proforma-line")
    first_vat = page.locator('select[name="line_0_vat_rate"]')
    expect(first_vat).to_have_value("21")

    # Choosing the customer moves the untouched first line, and a new line starts on their rate.
    page.select_option("#proforma-customer-select", value=str(custom_rate_customer_id))
    expect(first_vat).to_have_value("25.5")
    page.get_by_role("button", name="Add Line Item", exact=True).click()
    expect(lines).to_have_count(2)
    second_vat = page.locator('select[name="line_1_vat_rate"]')
    expect(second_vat).to_have_value("25.5")
    expect(page.locator("#proforma-summary-vat-label")).to_have_text(re.compile(r"\(25\.5%\):$"))

    # A rate the operator picks is kept when the customer changes; untouched lines follow.
    first_vat.select_option("0")
    page.select_option("#proforma-customer-select", value="")
    expect(first_vat).to_have_value("0")
    expect(second_vat).to_have_value("21")
