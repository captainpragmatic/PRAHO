"""E2E regression tests for cart-review HTMX response/target correctness.

These drive the two customer cart-review interactions that a target/swap mismatch
broke — and that unit tests structurally cannot observe, because the Django test
client verifies *what the server returns*, not *where HTMX puts it*:

  * changing an item's quantity must update the Order Summary (#cart-totals) in
    place, not replace it with a stray cart widget;
  * removing an item must re-render the items section (#cart-items) so the count
    and empty-cart state stay correct, not turn the row into a full cart widget.

Requires the E2E stack (make dev-e2e) with catalog products seeded.
"""

from playwright.sync_api import Page, expect

from tests.e2e.helpers import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    ensure_fresh_session,
    login_user,
)
from tests.e2e.helpers.orders import add_product

CATALOG_URL = f"{BASE_URL}/order/"
CART_URL = f"{BASE_URL}/order/cart/"


def _login_customer(page: Page) -> None:
    ensure_fresh_session(page)
    if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
        raise AssertionError("Customer login failed — is the E2E service running? (make dev-e2e)")


def _add_domain_free_product_to_cart(page: Page) -> bool:

    return add_product(page)


def test_quantity_change_updates_order_summary_in_place(page: Page) -> None:
    """F-HIGH-1: a quantity change keeps the Order Summary (#cart-totals);
    the pre-fix bug replaced it with a #cart-widget and never recalculated."""
    _login_customer(page)
    _add_domain_free_product_to_cart(page)

    page.goto(CART_URL)
    page.wait_for_load_state("networkidle")

    expect(page.locator("#cart-totals")).to_be_visible()
    expect(page.locator("#cart-totals")).to_contain_text("Order Summary")

    quantity = page.locator("select[name='quantity']").first
    expect(quantity).to_be_visible()
    expect(page.locator("#cart-totals")).to_contain_text("121,00")
    quantity.select_option("2")
    page.wait_for_load_state("networkidle")

    expect(page.locator("#cart-totals")).to_contain_text("242,00")

    # The Order Summary must survive the swap (the bug replaced it with a widget).
    expect(page.locator("#cart-totals")).to_be_visible()
    expect(page.locator("#cart-totals")).to_contain_text("Order Summary")
    assert page.locator("#cart-totals #cart-widget").count() == 0, (
        "Quantity change injected a cart widget into the Order Summary."
    )


def test_remove_item_rerenders_items_section(page: Page) -> None:
    """F-HIGH-2: removing an item re-renders #cart-items with the empty-cart
    state; the pre-fix bug turned the row into a full cart widget and left a
    stale product count."""
    _login_customer(page)
    _add_domain_free_product_to_cart(page)

    page.goto(CART_URL)
    page.wait_for_load_state("networkidle")

    expect(page.locator("#cart-items")).to_be_visible()

    # The remove button carries hx-confirm → a native confirm() dialog; accept it.
    page.on("dialog", lambda dialog: dialog.accept())

    remove_button = page.locator("#cart-items button[aria-label*='Remove']").first
    expect(remove_button).to_be_visible()
    remove_button.click()
    page.wait_for_load_state("networkidle")

    # Items section re-renders: no cart widget, and the empty-cart CTA appears.
    assert page.locator("#cart-items #cart-widget").count() == 0, (
        "Removing the item turned the row into a cart widget instead of re-rendering the list."
    )
    expect(page.locator("#cart-items")).to_contain_text("Your cart is empty")
