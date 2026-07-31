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

CATALOG_URL = f"{BASE_URL}/order/"
CART_URL = f"{BASE_URL}/order/cart/"


def _login_customer(page: Page) -> None:
    ensure_fresh_session(page)
    if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
        raise AssertionError(
            "Customer login failed — is the E2E service running? (make dev-e2e)"
        )


def _add_domain_free_product_to_cart(page: Page) -> None:
    """Add one catalog product that does NOT require a domain, and assert the
    add actually persisted (the cart badge appears). Fails loudly — never
    soft-skips — because a silent empty cart is exactly the kind of gap that let
    these target bugs reach production. Domain-required products can't be added
    without a domain, so they are skipped."""
    page.goto(CATALOG_URL)
    page.wait_for_load_state("networkidle")

    forms = page.locator('form[id^="cart-form-"]')
    form_count = forms.count()
    assert form_count > 0, (
        "No products in the catalog — the E2E fixtures must seed at least one "
        "purchasable product for this regression to be meaningful."
    )

    added = False
    for index in range(form_count):
        form = forms.nth(index)
        if form.locator('input[name="domain_name"]').count() == 0:
            form.locator('button[type="submit"]').click()
            added = True
            break
    assert added, "No domain-free product available to add to the cart."

    page.wait_for_load_state("networkidle")
    # The add must have persisted — the cart count badge is rendered only when
    # the cart holds items. Otherwise cart review would redirect (empty cart).
    expect(page.locator("#cart-count")).to_be_visible()


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
    quantity.select_option("2")
    page.wait_for_load_state("networkidle")

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
