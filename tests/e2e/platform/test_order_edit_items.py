"""The staff order edit page: its payment method, and adding, editing and deleting items.

Every request the item script made went to /app/orders/…, which does not exist; the inline form's
own script never ran (it arrives by fetch, and fetched scripts never run); the item form crashed for
any priced product; and the chosen billing period was dropped on save. So no part of this page
worked in a browser, although each endpoint had unit tests.
"""

from collections.abc import Callable
from typing import TypedDict

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.helpers import PLATFORM_BASE_URL

pytestmark = pytest.mark.e2e


class OrderEditScenario(TypedDict):
    order_id: str
    domain_product_id: str
    domain_product_name: str
    plain_product_id: str
    plain_product_name: str


@pytest.fixture
def order_edit(e2e_scenario: Callable[[str], OrderEditScenario]) -> OrderEditScenario:
    return e2e_scenario("order_edit")


def test_items_are_added_edited_and_deleted_on_the_edit_page(
    monitored_staff_page: Page, order_edit: OrderEditScenario
) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/orders/{order_edit['order_id']}/edit/")
    expect(page.locator('select[name="payment_method"]')).to_have_value("bank_transfer")

    page.get_by_role("button", name="Add First Item", exact=True).click()
    form = page.locator("form[data-order-item-form]")
    expect(form).to_be_visible()
    domain_section = form.locator("[data-domain-section]")
    domain = form.locator('input[name="domain_name"]')
    unit = form.locator('input[name="unit_price_cents"]')
    setup = form.locator('input[name="setup_cents"]')
    expect(form.locator('select[name="billing_period"]')).to_have_value("monthly")
    expect(domain_section).to_be_hidden()

    # A product that needs a domain shows a required domain field and fills its catalog price.
    form.locator('select[name="product"]').select_option(order_edit["domain_product_id"])
    expect(domain_section).to_be_visible()
    expect(domain).to_have_attribute("required", "")
    expect(unit).to_have_value("1500")
    expect(setup).to_have_value("500")
    expect(form.locator('[data-preview="total"]')).to_have_text("RON 20.00")

    # A yearly period is priced at twelve months.
    form.locator('select[name="billing_period"]').select_option("annual")
    expect(unit).to_have_value("18000")

    # A product without a domain hides the field and is no longer required.
    form.locator('select[name="product"]').select_option(order_edit["plain_product_id"])
    expect(domain_section).to_be_hidden()
    expect(domain).not_to_have_attribute("required", "")
    expect(unit).to_have_value("3600")

    form.locator('select[name="product"]').select_option(order_edit["domain_product_id"])
    domain.fill("e2e-order-edit.ro")
    form.get_by_role("button", name="Add Item", exact=True).click()

    rows = page.locator('#order-items-section tr[id^="order-item-"]')
    expect(rows).to_have_count(1)
    row = rows.first
    expect(row).to_contain_text(order_edit["domain_product_name"])
    expect(row).to_contain_text("e2e-order-edit.ro")
    expect(row).to_contain_text("/annual")

    # The refreshed list keeps its controls: edit the quantity in place.
    row.get_by_role("button", name="Edit", exact=True).first.click()
    edit_form = page.locator('tr[id^="edit-row-"] form[data-order-item-form]')
    expect(edit_form).to_be_visible()
    expect(edit_form.locator('select[name="billing_period"]')).to_have_value("annual")
    expect(edit_form.locator("[data-domain-section]")).to_be_visible()
    edit_form.locator('input[name="quantity"]').fill("2")
    edit_form.get_by_role("button", name="Save Changes", exact=True).click()
    expect(rows.first.locator("td").nth(1)).to_have_text("2")

    # Delete asks for confirmation, then removes the row.
    page.once("dialog", lambda dialog: dialog.accept())
    rows.first.get_by_role("button", name="Delete", exact=True).first.click()
    expect(rows).to_have_count(0)

    page.reload()
    expect(page.get_by_text("No items in this order yet")).to_be_visible()


def test_the_full_page_item_form_shows_the_domain_field_for_a_domain_product(
    monitored_staff_page: Page, order_edit: OrderEditScenario
) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/orders/{order_edit['order_id']}/items/add/")
    domain_section = page.locator("#domain-section")

    page.locator("#id_product").select_option(order_edit["domain_product_id"])
    expect(domain_section).to_be_visible()
    expect(page.locator("#id_domain_name")).to_have_attribute("required", "")

    page.locator("#id_product").select_option(order_edit["plain_product_id"])
    expect(domain_section).to_be_hidden()
