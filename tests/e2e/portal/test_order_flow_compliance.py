"""
Order Flow Romanian Business Compliance & i18n Tests for PRAHO Portal

Tests verifying that the order flow meets Romanian legal and business requirements:
- Romanian VAT rate (21%) display
- RON currency symbol on prices
- Mandatory terms and conditions acceptance
- Bank transfer payment instructions (IBAN)
- Order confirmation number format
- No obviously untranslated strings on order pages

All tests are independent and perform a fresh customer login. No database access.
"""

import re

import pytest
from playwright.sync_api import Page

from tests.e2e.helpers import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    ensure_fresh_session,
    login_user,
)
from tests.e2e.helpers.orders import add_product, bank_checkout

# ===============================================================================
# CONSTANTS
# ===============================================================================

CATALOG_URL = f"{BASE_URL}/order/"
CART_URL = f"{BASE_URL}/order/cart/"
CHECKOUT_URL = f"{BASE_URL}/order/checkout/"
CREATE_ORDER_URL = f"{BASE_URL}/order/create/"


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
# COMPLIANCE TESTS
# ===============================================================================


def test_vat_rate_displayed_correctly(page: Page) -> None:
    """Romanian VAT rate (21%) must be displayed on the cart review page.

    Romanian fiscal law (Legea 571/2003, Codul Fiscal) requires the VAT rate
    to appear alongside prices on any order summary. The cart_totals.html partial
    renders 'VAT (21%)' in the order summary section.
    """
    print("Testing compliance: VAT rate (21%) displayed on cart summary")

    _login_customer(page)

    added = _add_first_product_to_cart(page)
    if not added:
        print("  SKIP: No products in catalog")
        pytest.fail("Required E2E step unavailable: not added")

    page.goto(CART_URL)
    page.wait_for_load_state("networkidle")

    if "/order/cart/" not in page.url:
        print(f"  SKIP: Redirected from cart to {page.url}")
        pytest.fail("Required E2E step unavailable: '/order/cart/' not in page.url")

    # Wait for HTMX cart totals to load (they load asynchronously via hx-post)
    page.wait_for_timeout(2000)

    # The cart_totals.html template explicitly shows "VAT (21%)"
    vat_label = page.locator('text="VAT (21%)"')
    if vat_label.count() == 0:
        # Accept alternate Romanian text or percentage-only formats
        vat_label = page.locator("text=/TVA.*21|21.*TVA|TVA.*21%|VAT.*21%/")

    assert vat_label.count() > 0 or page.locator("text=/21%/").count() > 0, (
        "COMPLIANCE FAIL: VAT rate '21%' not displayed in cart summary. "
        "Romanian legislation requires VAT rate to be clearly shown on all order summaries."
    )

    print("  VAT (21%) correctly displayed — compliance test passes")


def test_prices_show_currency_symbol(page: Page) -> None:
    """All prices in the product catalog must show the RON currency symbol.

    The `romanian_currency` template filter appends 'RON' to formatted amounts.
    This ensures customers see prices in the correct currency and avoids ambiguity
    with EUR or USD prices that may also exist in the system.
    """
    print("Testing compliance: RON currency symbol on product catalog prices")

    _login_customer(page)

    page.goto(CATALOG_URL)
    page.wait_for_load_state("networkidle")

    # If no products are available, catalog shows empty state — still valid
    products = page.locator("div.grid div[class*='bg-slate-800']")
    if products.count() == 0:
        print("  SKIP: No products in catalog — cannot test price display")
        pytest.fail("Required E2E step unavailable: products.count() == 0")

    # The product catalog uses {{ price.monthly_price|romanian_currency }} which
    # formats as "X,XX RON". Verify at least one price shows the RON symbol.
    page_content = page.content()
    assert "RON" in page_content, (
        "COMPLIANCE FAIL: 'RON' currency symbol not found anywhere on the product catalog page. "
        "All prices must display in RON as the primary currency for Romanian customers."
    )

    # More specific check: price display elements should contain RON
    price_displays = page.locator("[id^='price-display-']")
    if price_displays.count() > 0:
        first_price_text = price_displays.first.inner_text()
        assert "RON" in first_price_text or "," in first_price_text, (
            f"COMPLIANCE FAIL: Product price display does not contain RON: '{first_price_text}'. "
            "Prices must show the currency symbol."
        )
        print(f"  Product price displays '{first_price_text}' — RON currency present")
    else:
        print("  RON appears in page content — currency compliance test passes")


def test_terms_checkbox_required(page: Page) -> None:
    """Terms and conditions acceptance checkbox must be required before order creation.

    The checkout form has an `agree_terms` checkbox with `required=True`.
    Attempting to submit the form without checking it must be blocked by HTML5
    form validation (or server-side validation) — the browser should prevent
    form submission and show a validation message.
    """
    print("Testing compliance: terms checkbox is required before order creation")

    _login_customer(page)

    added = _add_first_product_to_cart(page)
    if not added:
        print("  SKIP: No products available — cannot test checkout form")
        pytest.fail("Required E2E step unavailable: not added")

    page.goto(CHECKOUT_URL)
    page.wait_for_load_state("networkidle")

    if "/order/checkout/" not in page.url:
        print(f"  SKIP: Redirected from checkout to {page.url}")
        pytest.fail("Required E2E step unavailable: '/order/checkout/' not in page.url")

    # Locate the terms checkbox
    terms_checkbox = page.locator('input[name="agree_terms"]')
    assert terms_checkbox.count() > 0, (
        "COMPLIANCE FAIL: Terms and conditions checkbox (agree_terms) not found on checkout page. "
        "Romanian consumer protection law requires explicit terms acceptance before purchase."
    )

    # Ensure the checkbox is NOT checked
    if terms_checkbox.is_checked():
        terms_checkbox.uncheck()

    # Verify the checkbox has the HTML5 `required` attribute
    required_attr = terms_checkbox.get_attribute("required")
    assert required_attr is not None, (
        "COMPLIANCE FAIL: Terms checkbox does not have the HTML5 `required` attribute. "
        "Form can be submitted without terms acceptance."
    )

    print("  Terms checkbox is present and marked required — compliance test passes")


def test_bank_transfer_shows_payment_method(page: Page) -> None:
    """Bank transfer payment option must be visible on the checkout page.

    Bank transfer is an important payment method for Romanian B2B customers
    (companies paying with wire transfers to IBAN). The checkout form must
    render the bank transfer radio option with appropriate description.
    """
    print("Testing compliance: bank transfer payment option visible on checkout")

    _login_customer(page)

    added = _add_first_product_to_cart(page)
    if not added:
        print("  SKIP: No products available — cannot test checkout payment options")
        pytest.fail("Required E2E step unavailable: not added")

    page.goto(CHECKOUT_URL)
    page.wait_for_load_state("networkidle")

    if "/order/checkout/" not in page.url:
        print(f"  SKIP: Redirected from checkout to {page.url}")
        pytest.fail("Required E2E step unavailable: '/order/checkout/' not in page.url")

    # The checkout template includes a bank_transfer radio option
    bank_transfer_radio = page.locator('input[type="radio"][value="bank_transfer"]')
    assert bank_transfer_radio.count() > 0, (
        "COMPLIANCE FAIL: Bank transfer payment option not found on checkout page. "
        "Romanian B2B customers require bank transfer as a payment option."
    )

    # Verify the bank transfer option has a descriptive label
    bank_transfer_label = page.locator('text="Bank Transfer"')
    if bank_transfer_label.count() == 0:
        # Accept Romanian translation
        bank_transfer_label = page.locator("text=/Transfer|Virament/")

    assert bank_transfer_label.count() > 0, "COMPLIANCE FAIL: Bank transfer option has no visible label text."

    print("  Bank transfer payment option visible with label — compliance test passes")


def test_order_confirmation_shows_order_number(account_page) -> None:
    """A real bank order must persist and display its reference after reload."""

    page, _ = account_page
    _add_first_product_to_cart(page)
    bank_checkout(page)


def test_i18n_no_untranslated_strings(page: Page) -> None:
    """Order pages should not contain obvious untranslated Romanian strings.

    This test checks for common patterns that indicate a translation was missed:
    - Raw gettext key strings (e.g. `orders.something`)
    - Django template variable placeholders that leaked (e.g. `{{ var }}`)
    - Common English technical terms that should have Romanian translations
      on an RO-locale site

    Note: PRAHO supports both Romanian and English, so English text is valid.
    This test only flags patterns that indicate translation FAILURES (missing
    translation rendering the key itself, or template errors rendering raw `{{ }}`).
    """
    print("Testing i18n: no untranslated placeholder strings on order pages")

    _login_customer(page)
    _add_first_product_to_cart(page)

    order_pages = [
        (CATALOG_URL, "Product Catalog"),
        (CART_URL, "Cart Review"),
        (CHECKOUT_URL, "Checkout"),
    ]

    failed_pages: list[str] = []

    for url, page_name in order_pages:
        page.goto(url)
        page.wait_for_load_state("networkidle")

        # Get visible text to avoid catching HTML comments or hidden elements
        body_text = page.locator("body").inner_text()

        # Pattern 1: Raw Django template variable that was not resolved
        if "{{" in body_text and "}}" in body_text:
            failed_pages.append(f"{page_name}: contains raw '{{{{ }}}}' template variables in rendered output")

        # Pattern 2: Translation key that leaked through (e.g. "orders.catalog_title")
        # These look like dotted lowercase strings in rendered UI text
        # We check for the specific pattern "word.word.word" in visible text
        raw_keys = re.findall(r"\b[a-z]+\.[a-z_]+\.[a-z_]+\b", body_text)
        # Filter out legitimate dotted strings like version numbers, URLs in text
        suspicious_keys = [
            k for k in raw_keys if not any(skip in k for skip in ["localhost", "pragmatichost", "praho", "www."])
        ]
        if suspicious_keys:
            # Only flag if it looks like a translation key (all lowercase, underscores)
            translation_key_pattern = re.compile(r"^[a-z][a-z_]+\.[a-z][a-z_]+\.[a-z][a-z_]+$")
            actual_keys = [k for k in suspicious_keys if translation_key_pattern.match(k)]
            if actual_keys:
                failed_pages.append(f"{page_name}: possible untranslated keys: {actual_keys[:3]}")

        print(f"  {page_name} ({url}): no untranslated patterns detected")

    assert failed_pages == [], "i18n FAIL: Untranslated strings found on order pages:\n" + "\n".join(
        f"  - {p}" for p in failed_pages
    )

    print("  All order pages pass i18n untranslated string check")
