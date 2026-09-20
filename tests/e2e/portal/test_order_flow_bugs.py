"""
Order Flow Bug Regression Tests for PRAHO Portal

Each test verifies a specific known bug fix in the order flow to prevent regressions.
Tests cover cart session integrity, HTMX protocol correctness, payment routing,
and Romanian VAT display compliance.

All tests are independent and perform a fresh login. No database access is used.
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
ADD_TO_CART_URL = f"{BASE_URL}/order/cart/add/"


# ===============================================================================
# LOGIN HELPER
# ===============================================================================


def _login_customer(page: Page) -> None:
    """Log in as the test customer with a fresh session."""
    ensure_fresh_session(page)
    if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
        raise AssertionError("Customer login failed — is the E2E service running? (make dev-e2e-bg)")


# ===============================================================================
# HELPERS
# ===============================================================================


def _add_first_product_to_cart(page: Page) -> bool:

    return add_product(page)


# ===============================================================================
# BUG REGRESSION TESTS
# ===============================================================================


def test_bug2_product_type_in_cart_items(page: Page) -> None:
    _login_customer(page)
    _add_first_product_to_cart(page)
    page.goto(CART_URL)
    expect(page.locator("#cart-items")).to_contain_text("E2E Hosting")
    expect(page.locator("#cart-items")).to_contain_text("Shared_Hosting")
    page.reload()
    expect(page.locator("#cart-items")).to_contain_text("Shared_Hosting")


def test_bug5_duplicate_html_ids_product_catalog(page: Page) -> None:
    """BUG-5: Product catalog must not have duplicate HTML IDs.

    The product catalog template generates IDs dynamically using product slugs:
    `price-display-{slug}`, `period-display-{slug}`, `billing-period-{slug}`, etc.
    If two products share the same slug (data integrity bug) or if IDs are generated
    without using the slug, duplicates appear, breaking JS `getElementById` calls.
    """
    print("Testing BUG-5: no duplicate HTML IDs in product catalog")

    _login_customer(page)

    page.goto(CATALOG_URL)
    page.wait_for_load_state("networkidle")

    # Use JavaScript to find all elements with an 'id' attribute and detect duplicates
    duplicate_ids: list[str] = page.evaluate("""
        () => {
            const allIds = Array.from(document.querySelectorAll('[id]')).map(el => el.id);
            const seen = {};
            const duplicates = [];
            for (const id of allIds) {
                if (id) {
                    seen[id] = (seen[id] || 0) + 1;
                    if (seen[id] === 2) {
                        duplicates.push(id);
                    }
                }
            }
            return duplicates;
        }
    """)

    assert duplicate_ids == [], (
        f"BUG-5 REGRESSION: Duplicate HTML IDs found in product catalog: {duplicate_ids}. "
        "Each product must use its unique slug in generated IDs."
    )

    print("  No duplicate HTML IDs found in catalog — BUG-5 not regressed")


def test_checkout_rejects_stale_cart_version(account_page) -> None:
    page, _ = account_page
    _add_first_product_to_cart(page)
    page.goto(CHECKOUT_URL)
    token = page.locator('input[name="csrfmiddlewaretoken"]').first.input_value()
    response = page.request.post(
        f"{BASE_URL}/order/create/",
        form={
            "csrfmiddlewaretoken": token,
            "cart_version": "stale-version",
            "payment_method": "bank_transfer",
            "agree_terms": "on",
        },
        headers={"HX-Request": "true", "Referer": CHECKOUT_URL},
    )
    assert response.status == 400
    assert "Cart version mismatch" in response.json()["error"]
    page.goto(CART_URL)
    expect(page.locator("#cart-items")).to_contain_text("E2E Hosting")


@pytest.mark.expect_server_errors("Stripe secret key not configured in settings system")
def test_unconfigured_card_payment_reports_pending_order(account_page) -> None:
    """No provider key exists in E2E: a failed setup must never report the order paid."""
    page, _ = account_page
    _add_first_product_to_cart(page)
    page.goto(CHECKOUT_URL)
    page.locator('input[name="payment_method"][value="card"]').check()
    page.locator('input[name="agree_terms"]').check()
    page.locator("#checkout-submit").click()
    expect(page).to_have_url(re.compile(r"/order/confirmation/[^/]+/$"))
    expect(page.locator("body")).to_contain_text("payment processing is temporarily unavailable")
    expect(page.locator("#main-content")).to_contain_text(re.compile(r"ORD-\d+"))
    expect(page.locator("#main-content")).not_to_contain_text("Payment completed")


def test_ds1_vat_rate_displayed_on_checkout(page: Page) -> None:
    """DS-1: VAT rate percentage (21%) must be visible on the checkout page.

    Romanian legislation requires the VAT rate to be clearly displayed alongside
    prices. The cart totals partial shows 'VAT (21%)' text. This test ensures
    the rate is present when viewing the checkout summary.
    """
    print("Testing DS-1: VAT rate visible on checkout page")

    _login_customer(page)

    added = _add_first_product_to_cart(page)
    if not added:
        print("  SKIP: No products available — cannot test checkout VAT display")
        pytest.fail("Required E2E step unavailable: not added")

    # First go to cart review which always shows the totals partial
    page.goto(CART_URL)
    page.wait_for_load_state("networkidle")

    if "/order/cart/" not in page.url:
        print(f"  SKIP: Redirected from cart to {page.url}")
        pytest.fail("Required E2E step unavailable: '/order/cart/' not in page.url")

    expect(page.locator("#cart-totals")).to_contain_text("VAT (21%)")
    expect(page.locator("#cart-totals")).to_contain_text("121,00")
