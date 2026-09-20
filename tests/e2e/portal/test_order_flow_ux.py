"""
Order Flow UX Quality Tests for PRAHO Portal

Tests verifying user-experience quality across the product catalog, cart, and checkout
pages. Each test is independent and performs a fresh customer login. No database
access is used — all assertions are made against the live rendered UI.
"""

import re

import pytest
from playwright.sync_api import Page, expect

from tests.e2e.helpers import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    ensure_fresh_session,
    login_user,
)
from tests.e2e.helpers.orders import add_product

# ===============================================================================
# CONSTANTS
# ===============================================================================

CATALOG_URL = f"{BASE_URL}/order/"
CART_URL = f"{BASE_URL}/order/cart/"
CHECKOUT_URL = f"{BASE_URL}/order/checkout/"


# ===============================================================================
# LOGIN HELPER
# ===============================================================================


def _login_customer(page: Page) -> None:
    """Log in as the test customer with a fresh session."""
    ensure_fresh_session(page)
    if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
        raise AssertionError("Customer login failed — is the E2E service running? (make dev-e2e-bg)")


# ===============================================================================
# HELPER
# ===============================================================================


def _add_first_product_to_cart(page: Page) -> bool:

    return add_product(page)


# ===============================================================================
# UX TESTS
# ===============================================================================


def test_ux1_billing_period_selector_updates_price(page: Page) -> None:
    """The billing toggle changes both the displayed price and the submitted period."""
    _login_customer(page)
    page.goto(CATALOG_URL)
    card = page.locator("div.group").filter(has=page.locator("#cart-form-e2e-hosting"))
    expect(card.locator("div.text-green-400:visible")).to_have_text("100,00 RON")
    page.get_by_role("button", name="Annual", exact=False).click()
    expect(card.locator("div.text-green-400:visible")).to_have_text("960,00 RON")
    expect(card.locator('input[name="billing_period"]')).to_have_value("annual")
    card.get_by_role("button", name="Add to Cart", exact=True).click()
    expect(page.locator("#cart-count")).to_contain_text("1")
    page.goto(CART_URL)
    expect(page.locator("#cart-items")).to_contain_text("E2E Hosting")
    expect(page.locator("#cart-items")).to_contain_text(re.compile("annual|12 months", re.I))


def test_ux2_mini_cart_opens_and_closes(page: Page) -> None:
    """UX-2: Mini cart dropdown toggles on click and closes when clicking outside.

    The cart widget button calls `toggleMiniCart()` which toggles the `hidden` class
    on `#mini-cart`. Clicking anywhere outside the `#cart-widget` container should
    re-add the `hidden` class, closing the dropdown.
    """
    print("Testing UX-2: mini cart opens and closes")

    _login_customer(page)

    page.goto(CATALOG_URL)
    page.wait_for_load_state("networkidle")

    # Locate the cart toggle button and the mini cart container
    # The cart widget uses Alpine.js: @click="miniCartOpen = !miniCartOpen" / x-show
    cart_button = page.locator("#cart-widget button")
    mini_cart = page.locator("#mini-cart")

    assert cart_button.count() > 0, "Cart toggle button should be present on catalog page"
    assert mini_cart.count() > 0, "Mini cart container (#mini-cart) should be present"

    # Initially the mini cart is not visible (Alpine.js x-show controls visibility)
    expect(mini_cart).not_to_be_visible()

    # Click the cart button to open
    cart_button.click()
    page.wait_for_timeout(300)
    expect(mini_cart).to_be_visible()
    print("  Mini cart opened successfully")

    # Click outside the cart widget to close it
    page.locator("h1").first.click()
    page.wait_for_timeout(500)
    expect(mini_cart).not_to_be_visible()
    print("  Mini cart closed after clicking outside — UX-2 passes")


def test_ux3_empty_cart_shows_empty_state(page: Page) -> None:
    _login_customer(page)
    page.goto(CART_URL)
    expect(page.locator("#main-content")).to_contain_text("Your cart is empty")
    expect(page.locator('[id^="cart-item-"]')).to_have_count(0)


def test_ux4_add_to_cart_updates_badge(page: Page) -> None:
    """UX-4: Adding a product to the cart updates the cart count badge.

    After clicking 'Add to Cart', the HTMX response replaces `#cart-widget`
    with updated HTML that includes the cart count badge (`#cart-count` with
    a non-zero count). This verifies the HTMX swap targets are correctly
    configured on the catalog page.
    """
    print("Testing UX-4: adding to cart updates count badge")

    _login_customer(page)

    page.goto(CATALOG_URL)
    page.wait_for_load_state("networkidle")

    add_buttons = page.locator('button[type="submit"]:has-text("Add to Cart")')
    if add_buttons.count() == 0:
        print("  SKIP: No products in catalog")
        pytest.fail("Required E2E step unavailable: add_buttons.count() == 0")

    # Record badge state before adding
    badge_before = page.locator("#cart-count")
    count_before = int(badge_before.inner_text()) if badge_before.is_visible() else 0
    print(f"    Cart count before add: {count_before}")

    # Click Add to Cart and wait for HTMX swap
    add_buttons.first.click()
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)  # Allow HTMX swap to complete

    # Check badge after add
    badge_after = page.locator("#cart-count")
    assert badge_after.is_visible(timeout=5000), (
        "UX-4 FAIL: Cart count badge (#cart-count) is not visible after adding a product. "
        "HTMX swap may not be targeting #cart-widget correctly."
    )

    count_after = int(badge_after.inner_text())
    assert count_after > count_before, (
        f"UX-4 FAIL: Cart count did not increase after adding a product (was {count_before}, still {count_after})."
    )

    print(f"  Cart count updated to {count_after} — UX-4 passes")


def test_ux5_checkout_shows_item_breakdown(page: Page) -> None:
    _login_customer(page)
    _add_first_product_to_cart(page)
    page.goto(CHECKOUT_URL)
    expect(page.get_by_role("heading", name="Ordered products", exact=True)).to_be_visible()
    expect(page.locator("#main-content")).to_contain_text("E2E Hosting")
    expect(page.locator("#main-content")).to_contain_text("121,00")


def test_breadcrumbs_show_correct_step(page: Page) -> None:
    _login_customer(page)
    _add_first_product_to_cart(page)
    for url, label in ((CATALOG_URL, "Product Selection"), (CART_URL, "Cart Review"), (CHECKOUT_URL, "Checkout")):
        page.goto(url)
        expect(page).to_have_url(url)
        expect(page.locator('nav[aria-label="Progress steps"] [aria-current="step"]')).to_contain_text(label)
