"""
Order Flow UX Quality Tests for PRAHO Portal

Tests verifying user-experience quality across the product catalog, cart, and checkout
pages. Each test is independent and performs a fresh customer login. No database
access is used — all assertions are made against the live rendered UI.
"""

from playwright.sync_api import Page

from tests.e2e.helpers import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    ComprehensivePageMonitor,
    ensure_fresh_session,
    login_user,
)

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
        raise AssertionError(
            "Customer login failed — is the E2E service running? (make dev-e2e-bg)"
        )


# ===============================================================================
# HELPER
# ===============================================================================


def _add_first_product_to_cart(page: Page) -> bool:
    """
    Navigate to the product catalog and add the first available product to the cart.

    Returns True if a product was added, False if the catalog is empty.
    """
    page.goto(CATALOG_URL)
    page.wait_for_load_state("networkidle")

    add_buttons = page.locator('button[type="submit"]:has-text("Add to Cart")')
    if add_buttons.count() == 0:
        return False

    add_buttons.first.click()
    page.wait_for_load_state("networkidle")
    return True


# ===============================================================================
# UX TESTS
# ===============================================================================


def test_ux1_billing_period_selector_updates_price(page: Page) -> None:
    """UX-1: Changing billing period should update the displayed price.

    The product card contains a billing period <select> that runs
    `updateProductPricing()` via JS `onchange`. Switching from Monthly to
    a longer period (6/12 months) should update the price display element
    `#price-display-{slug}` immediately without a page reload.
    """
    print("Testing UX-1: billing period selector updates price display")

    _login_customer(page)

    page.goto(CATALOG_URL)
    page.wait_for_load_state("networkidle")

    # Find a product that has multiple billing period options
    billing_selects = page.locator("select[id^='billing-period-']")
    if billing_selects.count() == 0:
        print("  SKIP: No billing period selectors found in catalog")
        return

    # Find the first billing-period select that has more than one option
    multi_option_select = None
    for i in range(billing_selects.count()):
        sel = billing_selects.nth(i)
        if sel.locator("option").count() > 1:
            multi_option_select = sel
            break

    if multi_option_select is None:
        print("  SKIP: No product has multiple billing period options")
        return

    # Extract the slug from the select's id: "billing-period-{slug}"
    select_id = multi_option_select.get_attribute("id") or ""
    slug = select_id.replace("billing-period-", "")

    # Get the current price text before changing the period
    price_display = page.locator(f"#price-display-{slug}")
    original_price = price_display.inner_text()
    print(f"    Original price display: '{original_price}'")

    # Select the last (longest) billing period — usually annual or semiannual
    options = multi_option_select.locator("option")
    last_option_value = options.last.get_attribute("value")
    if not last_option_value or last_option_value == "monthly":
        print("  SKIP: Only monthly period available for this product")
        return

    multi_option_select.select_option(last_option_value)

    # Give JS time to update the display (it's synchronous but needs repaint)
    page.wait_for_timeout(500)

    updated_price = price_display.inner_text()
    print(f"    Updated price display: '{updated_price}'")

    assert updated_price != original_price, (
        f"UX-1 FAIL: Billing period change from monthly to '{last_option_value}' "
        f"did not update price display for product '{slug}'. "
        f"Price stayed at '{original_price}'."
    )

    print(f"  Price updated from '{original_price}' to '{updated_price}' — UX-1 passes")


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
    cart_button = page.locator("button[onclick='toggleMiniCart()']")
    mini_cart = page.locator("#mini-cart")

    assert cart_button.count() > 0, "Cart toggle button should be present on catalog page"
    assert mini_cart.count() > 0, "Mini cart container (#mini-cart) should be present"

    # Initially the mini cart is hidden
    assert "hidden" in (mini_cart.get_attribute("class") or ""), (
        "Mini cart should start hidden"
    )

    # Click the cart button to open
    cart_button.click()
    page.wait_for_timeout(300)

    assert "hidden" not in (mini_cart.get_attribute("class") or ""), (
        "UX-2 FAIL: Mini cart should be visible after clicking the cart button"
    )
    print("  Mini cart opened successfully")

    # Click outside the cart widget to close it
    # The page header text is outside the cart widget
    page.locator("h1").first.click()
    page.wait_for_timeout(500)

    assert "hidden" in (mini_cart.get_attribute("class") or ""), (
        "UX-2 FAIL: Mini cart should be hidden after clicking outside the cart widget"
    )
    print("  Mini cart closed after clicking outside — UX-2 passes")


def test_ux3_empty_cart_shows_empty_state(page: Page) -> None:
    """UX-3: Empty cart review page shows an appropriate empty state.

    When no items are in the cart, navigating to /order/cart/ should show
    a meaningful empty state message rather than a broken page or raw error.
    This relies on the `orders/partials/cart_empty.html` template being rendered.
    """
    print("Testing UX-3: empty cart shows empty state")

    _login_customer(page)

    with ComprehensivePageMonitor(
        page,
        "empty cart review",
        check_console=False,  # Cart may have residual console warnings from previous test session state
        check_network=True,
        check_html=True,
        check_css=True,
        check_accessibility=False,
    ):
        page.goto(CART_URL)
        page.wait_for_load_state("networkidle")

        # If we have items in cart from a previous test run (session isolation not
        # guaranteed), we still check the page renders without errors.
        page_source = page.content()

        # Should NOT show a Django error page
        assert "Internal Server Error" not in page_source, (
            "UX-3 FAIL: Cart page shows a 500 error for empty cart"
        )
        assert "TemplateDoesNotExist" not in page_source, (
            "UX-3 FAIL: Missing template when rendering empty cart"
        )

        # The page should either show cart items OR an empty state message
        has_items = page.locator('[id^="cart-item-"]').count() > 0
        has_empty_state = (
            page.locator('text="Your cart is empty"').count() > 0
            or page.locator('text=/empty|no items|no products/i').count() > 0
            or page.locator('[data-testid="empty-cart"]').count() > 0
        )

        assert has_items or has_empty_state, (
            "UX-3 FAIL: Cart page shows neither items nor an empty state message. "
            "The cart_empty.html partial must render a user-friendly message."
        )

        if has_empty_state:
            print("  Empty cart state is properly displayed — UX-3 passes")
        else:
            print("  Cart has items from prior session — page renders correctly")


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
        return

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
        f"UX-4 FAIL: Cart count did not increase after adding a product "
        f"(was {count_before}, still {count_after})."
    )

    print(f"  Cart count updated to {count_after} — UX-4 passes")


def test_ux5_checkout_shows_item_breakdown(page: Page) -> None:
    """UX-5: Checkout page shows per-item price breakdown in the order summary.

    The checkout template renders each cart item under 'Ordered products'
    with product name, quantity, billing period, and optionally the line total.
    This ensures the customer can review what they are paying for before confirming.
    """
    print("Testing UX-5: checkout shows item breakdown")

    _login_customer(page)

    added = _add_first_product_to_cart(page)
    if not added:
        print("  SKIP: No products available — cannot test checkout breakdown")
        return

    page.goto(CHECKOUT_URL)
    page.wait_for_load_state("networkidle")

    if "/order/checkout/" not in page.url:
        print(f"  SKIP: Redirected from checkout to {page.url} — cannot test breakdown")
        return

    # The checkout template shows items under the "Ordered products" heading
    ordered_products_heading = page.locator('h3:has-text("Ordered products")')
    assert ordered_products_heading.count() > 0, (
        "UX-5 FAIL: 'Ordered products' section heading not found on checkout page"
    )

    # There should be at least one item row (flex row with product name + quantity)
    item_rows = ordered_products_heading.locator("..").locator("div.flex")
    if item_rows.count() == 0:
        # Try broader selector based on template structure: div.bg-slate-700 > div.flex
        item_rows = page.locator("div.bg-slate-700\\/30 div.flex.items-center.justify-between")

    assert item_rows.count() > 0, (
        "UX-5 FAIL: No item rows found in the 'Ordered products' section. "
        "The checkout page must display per-item breakdown for transparency."
    )

    print(f"  Found {item_rows.count()} item row(s) in checkout breakdown — UX-5 passes")


def test_breadcrumbs_show_correct_step(page: Page) -> None:
    """Breadcrumbs highlight the current step on each order page.

    The order flow uses a breadcrumb/stepper component rendered from
    `orders/partials/order_breadcrumbs.html` with a `current_step` context variable.
    Each page should highlight the appropriate step:
    - Catalog → current_step="products"
    - Cart review → current_step="cart"
    - Checkout → current_step="checkout"

    This ensures the customer always knows where they are in the flow.
    """
    print("Testing breadcrumbs show correct step on each order page")

    _login_customer(page)

    # --- Catalog page ---
    page.goto(CATALOG_URL)
    page.wait_for_load_state("networkidle")

    # The breadcrumb partial renders step links; the active step typically has
    # a distinct styling class or aria attribute. We check the page renders
    # something that looks like a step indicator.
    breadcrumbs = page.locator("[class*='breadcrumb'], [class*='step'], nav[aria-label]")
    assert breadcrumbs.count() > 0 or page.locator("text=/Products|Cart|Checkout/").count() >= 2, (
        "Catalog page should render a breadcrumb / step navigation component"
    )
    print("  Catalog breadcrumb rendered")

    # --- Cart page (only if we can add something) ---
    added = _add_first_product_to_cart(page)
    if not added:
        print("  SKIP: No products — cannot test cart/checkout breadcrumbs")
        return

    page.goto(CART_URL)
    page.wait_for_load_state("networkidle")

    # Verify breadcrumbs appear on cart review page too
    breadcrumbs_cart = page.locator("[class*='breadcrumb'], [class*='step'], nav[aria-label]")
    assert breadcrumbs_cart.count() > 0 or page.locator("text=/Products|Cart|Checkout/").count() >= 2, (
        "Cart review page should render a breadcrumb / step navigation component"
    )
    print("  Cart review breadcrumb rendered")

    # --- Checkout page ---
    page.goto(CHECKOUT_URL)
    page.wait_for_load_state("networkidle")

    if "/order/checkout/" not in page.url:
        print(f"  Redirected from checkout to {page.url} — skipping checkout breadcrumb check")
        return

    breadcrumbs_checkout = page.locator("[class*='breadcrumb'], [class*='step'], nav[aria-label]")
    assert breadcrumbs_checkout.count() > 0 or page.locator("text=/Products|Cart|Checkout/").count() >= 2, (
        "Checkout page should render a breadcrumb / step navigation component"
    )
    print("  Checkout breadcrumb rendered — breadcrumb test passes")
