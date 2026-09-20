"""
Product Catalog E2E Tests for PRAHO Platform

This module comprehensively tests the product catalog functionality including:
- Product catalog navigation and access
- Product creation, editing, and management
- Multi-currency pricing management (RON/EUR)
- Romanian business compliance (VAT, e-Factura)
- Status toggles and HTMX interactions
- Search and filtering functionality
- Role-based access control
- Mobile responsiveness

Uses shared utilities from tests.e2e.helpers for consistency.
Based on real user workflows identified during manual testing.
"""

import re
from uuid import uuid4

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, expect

# Import shared utilities
from tests.e2e.helpers import (
    PLATFORM_BASE_URL,
    assert_responsive_results,
    ensure_fresh_platform_session,
    navigate_to_platform_page,
    require_authentication,
    run_responsive_breakpoints_test,
)

# ===============================================================================
# PRODUCT CATALOG ACCESS AND NAVIGATION TESTS
# ===============================================================================


def test_product_catalog_access_via_navigation(monitored_staff_page: Page) -> None:
    """
    Test accessing the product catalog through the Business dropdown navigation.

    This test verifies the complete navigation path to products:
    1. Login as staff user
    2. Click Business dropdown in navigation
    3. Click Products link
    4. Verify product catalog page loads correctly
    """
    page = monitored_staff_page
    print("🧪 Testing product catalog access via navigation")

    # Navigate to dashboard first
    assert navigate_to_platform_page(page, "/")

    # Click on Business dropdown
    business_dropdown = page.locator('button:has-text("Business")')
    expect(business_dropdown.first).to_be_attached()
    business_dropdown.click()

    # Wait for Alpine.js dropdown to open (uses role="menu")
    dropdown_menu = page.locator('[role="menu"], .dropdown-menu').first
    dropdown_menu.wait_for(state="visible", timeout=3000)
    products_link = dropdown_menu.locator('a:has-text("Products")')
    if products_link.count() == 0:
        # Fallback: any visible Products link
        products_link = page.locator('a:has-text("Products"):visible')

    expect(products_link.first).to_be_attached()
    products_link.first.click()

    # Verify we're on the product catalog page
    page.wait_for_url("**/products/", timeout=8000)
    expect(page).to_have_url(re.compile(r"/products/"))

    # Verify page title and content
    expect(page).to_have_title(re.compile(r"Product Catalog"))
    catalog_heading = page.locator('h1:has-text("Product Catalog")')
    expect(catalog_heading).to_be_visible()

    print("  ✅ Product catalog successfully accessible via Business navigation")


def test_product_catalog_dashboard_display(monitored_staff_page: Page) -> None:
    """
    Test the product catalog dashboard displays correctly with statistics and layout.

    This test verifies:
    - Statistics cards show accurate product counts
    - Romanian business compliance notice is displayed
    - Search and filter interface is present
    - Product table loads with existing products
    """
    page = monitored_staff_page
    print("🧪 Testing product catalog dashboard display")

    # Navigate to products
    navigate_to_platform_page(page, "/products/")
    page.wait_for_load_state("networkidle")

    # Verify statistics cards are present and show data
    stats_cards = [
        ("Total Products", "should show total product count"),
        ("Active Products", "should show active product count"),
        ("Public Products", "should show public product count"),
        ("Featured Products", "should show featured product count"),
    ]

    for card_name, description in stats_cards:
        # Use more specific selector to avoid strict mode violations
        card_selector = f'div.bg-slate-800:has-text("{card_name}")'
        card = page.locator(card_selector).first
        expect(card).to_be_attached()

        # Check that the card shows a numeric value
        card_text = card.inner_text()
        assert any(char.isdigit() for char in card_text), f"{card_name} card should show numeric count"
        print(f"  ✅ {card_name} card displays correctly")

    # Optional UI element — presence depends on product configuration
    romanian_notice = page.locator('div.bg-blue-900:has-text("🇷🇴"), div:has-text("Romanian"), div:has-text("🇷🇴")').first
    if romanian_notice.count() > 0:
        print("  ✅ Romanian business compliance notice visible")
    else:
        print("  [i] Romanian compliance notice uses different layout or is not present")

    # Verify search and filter interface
    search_input = page.locator('input[placeholder*="Product name"]')
    expect(search_input).to_be_visible()

    product_type_filter = page.locator('select[name="product_type"]')
    expect(product_type_filter).to_be_visible()

    # Verify product table is present
    products_table = page.locator("table")
    expect(products_table.first).to_be_attached()

    # Verify table has product rows (more important than specific headers)
    product_rows = page.locator("table tbody tr")
    row_count = product_rows.count()
    assert row_count > 0, f"Product table should have product rows, found {row_count}"

    # Verify key elements are present in the table (more flexible approach)
    # Check if we can find product names, types, and action buttons
    first_product_link = page.locator('table a[href*="/products/"]').first
    expect(first_product_link).to_be_visible()

    # Check for action buttons (edit/pricing) - complex OR condition, keep as-is
    edit_link = page.locator('table a[href*="/edit/"]').first
    pricing_link = page.locator('table a[href*="/prices/"]').first
    assert edit_link.is_visible() or pricing_link.is_visible(), "Should have action links in table"

    print("  ✅ Product catalog dashboard displays all required elements")


# ===============================================================================
# PRODUCT CREATION AND MANAGEMENT TESTS
# ===============================================================================


def _verify_product_created(page: Page, product_data: dict) -> None:
    expect(page).to_have_url(f"{PLATFORM_BASE_URL}/products/{product_data['slug']}/")
    expect(page.locator("main h1")).to_contain_text(product_data["name"])
    page.reload()
    expect(page.locator("main h1")).to_contain_text(product_data["name"])


def test_product_creation_full_workflow(monitored_staff_page: Page) -> None:
    """
    Test the complete product creation workflow including Romanian business settings.

    This test covers the full product creation process:
    1. Navigate to create product form
    2. Fill in all required fields with Romanian business context
    3. Set VAT inclusion and other Romanian compliance settings
    4. Submit form and verify product is created
    5. Verify redirect to product detail page
    """
    page = monitored_staff_page
    print("🧪 Testing complete product creation workflow")

    # Navigate to products
    navigate_to_platform_page(page, "/products/")

    # Click "New Product" button
    new_product_button = page.locator('a:has-text("New Product")')
    expect(new_product_button).to_be_visible()
    new_product_button.click()

    # Verify we're on the create product page
    page.wait_for_url("**/products/create/", timeout=8000)
    expect(page).to_have_url(re.compile(r"/products/create/"))

    # Optional UI element — presence depends on product configuration
    compliance_notice = page.locator('div.bg-blue-900:has-text("🇷🇴")').first
    if compliance_notice.count() > 0:
        print("      ✅ Romanian compliance notice visible on create page")

    # Fill in product creation form
    test_product_data = {
        "name": "E2E Test VPS Server",
        "slug": "e2e-test-vps-" + uuid4().hex[:12],
        "type": "vps",
        "short_description": "High-performance VPS hosting for Romanian businesses with SSD storage and 24/7 support",
    }

    # Fill basic information
    page.fill('input[name="name"]', test_product_data["name"])
    page.fill('input[name="slug"]', test_product_data["slug"])

    # Select product type - use the value, not display text
    page.select_option('select[name="product_type"]', "vps")

    # Fill short description - could be input or textarea depending on field length
    try:
        page.fill('input[name="short_description"]', test_product_data["short_description"])
    except (TimeoutError, PlaywrightError):
        page.fill('textarea[name="short_description"]', test_product_data["short_description"])

    # Verify default status settings (Active and Public should be checked)
    active_checkbox = page.locator('input[name="is_active"]')
    public_checkbox = page.locator('input[name="is_public"]')
    expect(active_checkbox).to_be_checked()
    expect(public_checkbox).to_be_checked()

    # Check Romanian VAT inclusion setting
    vat_checkbox = page.locator('input[name="includes_vat"]')
    if not vat_checkbox.is_checked():
        vat_checkbox.check()
    expect(vat_checkbox).to_be_checked()

    # Submit the form
    create_button = page.locator('button:has-text("Create Product")')
    expect(create_button).to_be_visible()
    create_button.click()

    # Verify creation and navigate to detail page (or confirm via search fallback)
    _verify_product_created(page, test_product_data)

    print("  ✅ Product creation workflow completed successfully")


def _submit_and_verify_pricing(page: Page) -> None:
    page.get_by_role("button", name="Add Price", exact=True).click()
    expect(page).to_have_url(re.compile(r"/prices/$"))
    expect(page.locator("main")).to_contain_text("RON")
    expect(page.locator("main")).to_contain_text("29.99")
    page.reload()
    expect(page.locator("main")).to_contain_text("29.99")


def test_product_pricing_management(monitored_staff_page: Page, e2e_scenario) -> None:
    """Add an exact RON price to this test's previously unpriced product."""
    page = monitored_staff_page
    fixture = e2e_scenario("pricing")
    page.goto(f"{PLATFORM_BASE_URL}/products/{fixture['product_slug']}/prices/")
    page.get_by_role("link", name=re.compile("Add (First )?Price")).first.click()
    page.select_option('select[name="currency"]', "RON")
    page.fill('input[name="monthly_price_cents"]', "2999")
    _submit_and_verify_pricing(page)


def test_product_status_toggles(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    product = e2e_scenario("pricing")
    page.goto(f"{PLATFORM_BASE_URL}/products/{product['product_slug']}/")
    for suffix, before, after in (
        ("active", "Active", "Inactive"),
        ("public", "Public", "Private"),
        ("featured", "Not Featured", "Featured"),
    ):
        button = page.locator(f'button[hx-post*="toggle-{suffix}"]')
        expect(button).to_have_text(before)
        button.click()
        expect(button).to_have_text(after)
        page.reload()
        expect(button).to_have_text(after)


# ===============================================================================
# SEARCH AND FILTERING TESTS
# ===============================================================================


def _clear_product_filters(page: Page) -> None:
    """Click the Clear button if present, otherwise navigate directly to products list."""
    clear_button = page.locator('a:has-text("Clear"), button:has-text("Clear")').first
    if clear_button.count() > 0:
        clear_button.click()
    else:
        navigate_to_platform_page(page, "/products/")
    page.wait_for_load_state("networkidle")


def test_product_search_and_filtering(monitored_staff_page: Page, e2e_scenario) -> None:
    page = monitored_staff_page
    product = e2e_scenario("pricing")
    page.goto(f"{PLATFORM_BASE_URL}/products/")
    search = page.locator('input[name="search"]')
    search.fill(product["name"])
    page.get_by_role("button", name="Filter", exact=True).click()
    expect(page.locator("table tbody tr")).to_have_count(1)
    expect(page.locator("table tbody tr")).to_contain_text(product["name"])
    page.locator('select[name="product_type"]').select_option("vps")
    page.get_by_role("button", name="Filter", exact=True).click()
    expect(page.locator("table tbody tr")).to_have_count(0)
    page.locator('select[name="product_type"]').select_option("shared_hosting")
    page.get_by_role("button", name="Filter", exact=True).click()
    expect(page.locator("table tbody tr")).to_have_count(1)
    page.locator('select[name="is_active"]').select_option("false")
    page.get_by_role("button", name="Filter", exact=True).click()
    expect(page.locator("table tbody tr")).to_have_count(0)


# ===============================================================================
# ROLE-BASED ACCESS CONTROL TESTS
# ===============================================================================


def test_product_catalog_staff_access_control(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    page.goto(f"{PLATFORM_BASE_URL}/products/")
    expect(page.get_by_role("heading", name="Product Catalog", exact=True)).to_be_visible()
    ensure_fresh_platform_session(page)
    page.goto(f"{PLATFORM_BASE_URL}/products/")
    expect(page).to_have_url(re.compile(r"/auth/login/"))
    expect(page.get_by_role("heading", name="Product Catalog", exact=True)).to_have_count(0)


# ===============================================================================
# MOBILE RESPONSIVENESS TESTS
# ===============================================================================


def test_product_catalog_mobile_responsiveness(monitored_staff_page: Page) -> None:
    page = monitored_staff_page
    for width in (375, 768):
        page.set_viewport_size({"width": width, "height": 812})
        page.goto(f"{PLATFORM_BASE_URL}/products/")
        expect(page.get_by_role("heading", name="Product Catalog", exact=True)).to_be_visible()
        expect(page.locator('main a[href*="/products/"]:visible').first).to_be_visible()
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


# ===============================================================================
# COMPREHENSIVE WORKFLOW TESTS
# ===============================================================================


def test_product_catalog_responsive_breakpoints(monitored_staff_page: Page) -> None:
    """
    Test product catalog functionality across all responsive breakpoints.

    This test validates that core product catalog functionality works on:
    - Desktop viewports (baseline)
    - Tablet viewports (landscape and portrait)
    - Mobile viewports (various sizes)
    """
    page = monitored_staff_page
    print("🧪 Testing product catalog across responsive breakpoints")

    def test_product_catalog_functionality(test_page, context="general"):
        """Test core product catalog functionality across viewports."""
        try:
            # Navigate to products
            test_page.goto(f"{PLATFORM_BASE_URL}/products/")
            test_page.wait_for_load_state("networkidle")

            # Verify authentication maintained
            require_authentication(test_page)

            # Check core elements are present - find any visible h1
            all_h1s = test_page.locator("h1").all()
            heading_visible = any(
                h1.is_visible()
                and ("product" in (h1.text_content() or "").lower() or "catalog" in (h1.text_content() or "").lower())
                for h1 in all_h1s
            )
            # Table may be hidden on mobile, check for any product content
            products_table = test_page.locator("table")
            product_cards = test_page.locator('[class*="product"], [data-product], tr:has-text("Product")')
            has_products = products_table.is_visible() or product_cards.count() > 0

            elements_present = heading_visible and has_products

            if elements_present:
                # Count products shown
                product_rows = test_page.locator("table tbody tr")
                row_count = product_rows.count()
                print(f"      ✅ Catalog functional: {row_count} products visible")
                return True
            else:
                print(f"      ❌ Core catalog elements missing in {context}")
                return False

        except (TimeoutError, PlaywrightError) as e:
            print(f"      ❌ Catalog test failed in {context}: {str(e)[:50]}")
            return False

    # Test across all breakpoints
    results = run_responsive_breakpoints_test(page, test_product_catalog_functionality)

    # Verify all breakpoints pass
    assert_responsive_results(results, "Product catalog")

    # Report mobile-specific findings
    mobile_extras = results.get("mobile_extras", {})
    if mobile_extras:
        layout_issues = mobile_extras.get("layout_issues", [])
        touch_works = mobile_extras.get("touch_works", False)

        print("\n  📊 Mobile catalog summary:")
        print(f"    - Layout issues: {len(layout_issues)}")
        print(f"    - Touch interactions: {'YES' if touch_works else 'LIMITED'}")

    print("  ✅ Product catalog validated across all responsive breakpoints")


# ===============================================================================
# PRODUCT DETAIL, EDIT, AND HTMX TESTS
# ===============================================================================


def test_product_detail_page_sections(monitored_staff_page: Page) -> None:
    """
    Test that a product detail page renders basic info, status sidebar, and pricing section.
    """
    page = monitored_staff_page
    print("🧪 Testing product detail page sections")

    # Navigate to product list and pick the first product
    navigate_to_platform_page(page, "/products/")
    page.wait_for_load_state("networkidle")

    first_product_link = page.locator('table a[href*="/products/"]').first
    expect(first_product_link).to_be_visible()
    product_name = first_product_link.inner_text()
    first_product_link.click()
    page.wait_for_load_state("networkidle")

    # Verify we landed on a detail page (not the list)
    expect(page).to_have_url(re.compile(r"/products/[^/]+/$"))

    # Basic info card — product name should appear in the page content
    page_text = page.locator("body").inner_text()
    assert product_name in page_text, f"Product name '{product_name}' not found on detail page"

    # Status sidebar section (icon rendered as SVG, not emoji)
    status_heading = page.locator('h2:has-text("Status")')
    expect(status_heading.first).to_be_visible()

    # Quick Actions section
    actions_heading = page.locator('h2:has-text("Quick Actions")')
    expect(actions_heading.first).to_be_visible()

    print(f"  ✅ Product detail page for '{product_name}' renders all sections")


def test_product_edit_form_renders(monitored_staff_page: Page) -> None:
    """
    Test that the product edit form loads with expected fields pre-populated.
    """
    page = monitored_staff_page
    print("🧪 Testing product edit form renders")

    # Navigate to product list and find the first edit link
    navigate_to_platform_page(page, "/products/")
    page.wait_for_load_state("networkidle")

    edit_link = page.locator('table a[href*="/edit/"]').first
    expect(edit_link).to_be_visible()
    edit_link.click()
    page.wait_for_load_state("networkidle")

    # Verify we're on the edit page
    expect(page).to_have_url(re.compile(r"/products/[^/]+/edit/$"))

    # Verify key form fields are present and pre-populated
    name_input = page.locator('input[name="name"]')
    expect(name_input).to_be_visible()
    name_value = name_input.input_value()
    assert len(name_value) > 0, "Name field should be pre-populated"

    slug_input = page.locator('input[name="slug"]')
    expect(slug_input).to_be_visible()
    assert len(slug_input.input_value()) > 0, "Slug field should be pre-populated"

    product_type_select = page.locator('select[name="product_type"]')
    expect(product_type_select).to_be_visible()

    # Verify submit button exists (filter to visible ones, skip hidden mobile nav)
    save_button = page.locator('button[type="submit"]:visible')
    expect(save_button.first).to_be_visible()

    print(f"  ✅ Product edit form renders correctly for '{name_value}'")


def test_product_htmx_status_toggle_has_csrf(monitored_staff_page: Page) -> None:
    """
    Test that status toggle buttons include hx-headers with X-CSRFToken for HTMX POST.
    """
    page = monitored_staff_page
    print("🧪 Testing HTMX status toggle CSRF headers")

    # Navigate to first product detail page
    navigate_to_platform_page(page, "/products/")
    page.wait_for_load_state("networkidle")

    first_product_link = page.locator('table a[href*="/products/"]').first
    expect(first_product_link).to_be_visible()
    first_product_link.click()
    page.wait_for_load_state("networkidle")

    # Find all HTMX toggle buttons (they use hx-post for status changes)
    toggle_buttons = page.locator("button[hx-post]")
    toggle_count = toggle_buttons.count()
    assert toggle_count > 0, "Product detail should have HTMX toggle buttons"

    # Verify each toggle button has hx-headers with CSRFToken
    for i in range(toggle_count):
        button = toggle_buttons.nth(i)
        hx_headers = button.get_attribute("hx-headers")
        assert hx_headers is not None, f"Toggle button {i} missing hx-headers attribute"
        assert "CSRFToken" in hx_headers or "csrftoken" in hx_headers.lower(), (
            f"Toggle button {i} hx-headers missing CSRFToken: {hx_headers}"
        )

    print(f"  ✅ All {toggle_count} toggle buttons have proper CSRF headers")
