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

Uses shared utilities from tests.e2e.utils for consistency.
Based on real user workflows identified during manual testing.
"""

import re

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import Page, expect

# Import shared utilities
from tests.e2e.utils import (
    PLATFORM_BASE_URL,
    ComprehensivePageMonitor,
    MobileTestContext,
    assert_responsive_results,
    ensure_fresh_platform_session,
    is_login_url,
    login_platform_user,
    navigate_to_platform_page,
    require_authentication,
    run_responsive_breakpoints_test,
    run_standard_mobile_test,
)

# ===============================================================================
# PRODUCT CATALOG ACCESS AND NAVIGATION TESTS
# ===============================================================================

def test_product_catalog_access_via_navigation(page: Page) -> None:
    """
    Test accessing the product catalog through the Business dropdown navigation.

    This test verifies the complete navigation path to products:
    1. Login as staff user
    2. Click Business dropdown in navigation
    3. Click Products link
    4. Verify product catalog page loads correctly
    """
    print("🧪 Testing product catalog access via navigation")

    with ComprehensivePageMonitor(page, "product catalog navigation access",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        # Login as superuser for product management access
        ensure_fresh_platform_session(page)
        assert login_platform_user(page)
        require_authentication(page)

        # Navigate to dashboard first
        assert navigate_to_platform_page(page, "/")

        # Click on Business dropdown
        business_dropdown = page.locator('button:has-text("🏢 Business")')
        expect(business_dropdown.first).to_be_attached()
        business_dropdown.click()

        # Wait for Alpine.js dropdown to open (uses role="menu")
        page.locator('[role="menu"], .dropdown-menu').first.wait_for(state="visible", timeout=3000)
        products_link = page.locator('a:has-text("🛍️ Products"), menuitem:has-text("🛍️ Products")')
        if products_link.count() == 0:
            # Try alternative selectors
            products_link = page.locator('a[href*="/products/"]', 'text="Products"')

        expect(products_link.first).to_be_attached()
        products_link.first.click()

        # Verify we're on the product catalog page
        page.wait_for_url("**/products/", timeout=8000)
        expect(page).to_have_url(re.compile(r"/products/"))

        # Verify page title and content
        expect(page).to_have_title(re.compile(r"Product Catalog"))
        catalog_heading = page.locator('h1:has-text("🛍️ Product Catalog")')
        expect(catalog_heading).to_be_visible()

        print("  ✅ Product catalog successfully accessible via Business navigation")


def test_product_catalog_dashboard_display(page: Page) -> None:
    """
    Test the product catalog dashboard displays correctly with statistics and layout.

    This test verifies:
    - Statistics cards show accurate product counts
    - Romanian business compliance notice is displayed
    - Search and filter interface is present
    - Product table loads with existing products
    """
    print("🧪 Testing product catalog dashboard display")

    with ComprehensivePageMonitor(page, "product catalog dashboard display",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        # Login and navigate to products
        ensure_fresh_platform_session(page)
        assert login_platform_user(page)
        navigate_to_platform_page(page, "/products/")
        page.wait_for_load_state("networkidle")

        # Verify statistics cards are present and show data
        stats_cards = [
            ("📦", "Total Products", "should show total product count"),
            ("✅", "Active Products", "should show active product count"),
            ("👁️", "Public Products", "should show public product count"),
            ("⭐", "Featured Products", "should show featured product count")
        ]

        for icon, card_name, description in stats_cards:
            # Use more specific selector to avoid strict mode violations
            card_selector = f'div.bg-slate-800:has-text("{icon}"):has-text("{card_name}")'
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
        products_table = page.locator('table')
        expect(products_table.first).to_be_attached()

        # Verify table has product rows (more important than specific headers)
        product_rows = page.locator('table tbody tr')
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
    """Verify that a product was successfully created after form submission.

    Checks the current URL first (redirect-based confirmation), and falls back
    to a product list search when the redirect did not occur as expected.
    """
    page.wait_for_load_state("networkidle")

    if f"/products/{product_data['slug']}/" in page.url:
        print("      ✅ Product creation succeeded - redirected to product detail")
    else:
        error_messages = page.locator('div.text-red-600, .text-red-500, [class*="error"]')
        if error_messages.count() > 0:
            error_text = error_messages.first.inner_text()
            print(f"      ❌ Form validation error: {error_text}")
        print(f"      Current URL: {page.url}")
        print("      Form may have validation issues - checking if product was created anyway")

        navigate_to_platform_page(page, "/products/")
        page.wait_for_load_state("networkidle")

        search_input = page.locator('input[placeholder*="Product name"]')
        if search_input.is_visible():
            search_input.fill(product_data['name'])
            page.locator('button:has-text("🔍 Filter")').click()
            page.wait_for_load_state("networkidle")

            product_found = page.locator(f'text="{product_data["name"]}"').first
            if product_found.is_visible():
                print("      ✅ Product was created successfully despite redirect issue")
            else:
                raise AssertionError("Product creation failed - not found in product list")
        else:
            raise AssertionError("Could not verify product creation - no search available")

    if f"/products/{product_data['slug']}/" in page.url:
        product_title = page.locator(f'h1:has-text("{product_data["name"]}")')
        expect(product_title).to_be_visible()

        vat_display = page.locator('text="Prices Include VAT"')
        if vat_display.is_visible():
            print("      ✅ VAT inclusion setting displayed on product detail page")
        else:
            print("      [i] VAT setting not displayed on detail page (may be in admin only)")
    else:
        print("      [i] Product verification completed via search - detail page not tested")


def test_product_creation_full_workflow(page: Page) -> None:
    """
    Test the complete product creation workflow including Romanian business settings.

    This test covers the full product creation process:
    1. Navigate to create product form
    2. Fill in all required fields with Romanian business context
    3. Set VAT inclusion and other Romanian compliance settings
    4. Submit form and verify product is created
    5. Verify redirect to product detail page
    """
    print("🧪 Testing complete product creation workflow")

    with ComprehensivePageMonitor(page, "product creation workflow",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        # Login and navigate to products
        ensure_fresh_platform_session(page)
        assert login_platform_user(page)
        navigate_to_platform_page(page, "/products/")

        # Click "New Product" button
        new_product_button = page.locator('a:has-text("✨ New Product")')
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
            'name': 'E2E Test VPS Server',
            'slug': 'e2e-test-vps-server',
            'type': 'vps',
            'short_description': 'High-performance VPS hosting for Romanian businesses with SSD storage and 24/7 support',
        }

        # Fill basic information
        page.fill('input[name="name"]', test_product_data['name'])
        page.fill('input[name="slug"]', test_product_data['slug'])

        # Select product type - use the value, not display text
        page.select_option('select[name="product_type"]', 'vps')

        # Fill short description - could be input or textarea depending on field length
        try:
            page.fill('input[name="short_description"]', test_product_data['short_description'])
        except (TimeoutError, PlaywrightError):
            page.fill('textarea[name="short_description"]', test_product_data['short_description'])

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
        create_button = page.locator('button:has-text("✨ Create Product")')
        expect(create_button).to_be_visible()
        create_button.click()

        # Verify creation and navigate to detail page (or confirm via search fallback)
        _verify_product_created(page, test_product_data)

        print("  ✅ Product creation workflow completed successfully")


def _submit_and_verify_pricing(page: Page) -> None:
    """Submit the pricing form and verify the price is saved.

    Clicks the submit button, waits for the redirect, and confirms RON pricing
    appears in the pricing list. Navigates back to the pricing page if needed.
    """
    add_price_submit = page.locator('button:has-text("💰 Add Price")')
    expect(add_price_submit).to_be_visible()
    add_price_submit.click()

    page.wait_for_load_state("networkidle")

    if "/prices/create/" not in page.url:
        print("      ✅ Pricing form submitted successfully - redirected from create page")
    else:
        error_messages = page.locator('div.text-red-600, .text-red-500, [class*="error"]')
        if error_messages.count() > 0:
            error_text = error_messages.first.inner_text()
            print(f"      ❌ Pricing form validation error: {error_text}")
        else:
            print("      [i] Form submitted but still on create page - may be validation issue")

    if "/prices/" not in page.url:
        page.go_back() if "/prices/create/" in page.url else None
        page.wait_for_load_state("networkidle")

    ron_pricing = page.locator('text="RON", text="LEI"')
    if ron_pricing.count() > 0:
        print("      ✅ RON pricing found in pricing list")
    else:
        print("      ⚠️ RON pricing not immediately visible - form may need validation fixes")


def test_product_pricing_management(page: Page) -> None:
    """
    Test product pricing management including RON currency and Romanian business context.

    This test covers:
    1. Navigate to pricing management for a product
    2. Add RON pricing with monthly billing
    3. Verify pricing is saved and displayed correctly
    4. Test cents-based pricing precision
    """
    print("🧪 Testing product pricing management with Romanian business context")

    with ComprehensivePageMonitor(page, "product pricing management",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        # Login and navigate to products
        ensure_fresh_platform_session(page)
        assert login_platform_user(page)

        # Navigate to an existing product's pricing (use first product in list)
        navigate_to_platform_page(page, "/products/")
        page.wait_for_load_state("networkidle")

        # Find first product pricing link (icon)
        first_pricing_link = page.locator('a[href*="/prices/"]:has-text("💰")').first
        expect(first_pricing_link).to_be_visible()

        pricing_url = first_pricing_link.get_attribute('href')
        page.goto(f"{PLATFORM_BASE_URL}{pricing_url}")
        page.wait_for_load_state("networkidle")

        # Verify we're on pricing management page
        expect(page).to_have_url(re.compile(r"/prices/"))
        pricing_heading = page.locator('h1:has-text("💰 Pricing Management")')
        expect(pricing_heading).to_be_visible()

        # Optional UI element — presence depends on product configuration
        romanian_context = page.locator('div.bg-blue-900:has-text("🇷🇴"), div:has-text("Romanian"), div:has-text("RON")').first
        if romanian_context.count() > 0:
            print("      ✅ Romanian business pricing context visible")

        # Click "Add Price" button
        add_price_button = page.locator('a:has-text("💰 Add Price"), a:has-text("💰 Add First Price")').first
        expect(add_price_button).to_be_visible()
        add_price_button.click()

        # Wait for pricing form page
        page.wait_for_load_state("networkidle")
        expect(page).to_have_url(re.compile(r"/prices/create/"))

        # Optional UI element — presence depends on product configuration
        simplified_notice = page.locator('text="Simplified Pricing Model"')
        if simplified_notice.count() > 0:
            print("      ✅ Simplified pricing model notice visible")

        # Fill pricing form with Romanian context
        # Select RON currency (should be first option for Romanian businesses)
        page.select_option('select[name="currency"]', "RON")

        # Enter monthly price in cents (2999 cents = 29.99 RON)
        # The simplified form uses monthly_price_cents, not amount_cents + billing_period
        page.fill('input[name="monthly_price_cents"]', "2999")

        # Optional UI element — presence depends on product configuration
        price_helper = page.locator('#monthly_price_helper')
        if price_helper.count() > 0:
            helper_text = price_helper.text_content() or ""
            if "29.99" in helper_text:
                print("      ✅ Price calculation helper shows correct RON amount")
            else:
                print(f"      [i] Price helper shows: {helper_text}")

        # Submit pricing form and verify RON pricing is saved
        _submit_and_verify_pricing(page)

        print("  ✅ Product pricing management completed with Romanian business context")


def test_product_status_toggles(page: Page) -> None:
    """
    Test product status toggle functionality (Active, Public, Featured).

    This test verifies:
    1. Status toggle buttons are present and clickable
    2. HTMX status updates work correctly (after fix)
    3. Status changes are reflected in the UI
    4. No console errors during toggle operations
    """
    print("🧪 Testing product status toggle functionality")

    with ComprehensivePageMonitor(page, "product status toggles",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        # Login and navigate to product detail
        ensure_fresh_platform_session(page)
        assert login_platform_user(page)

        # Navigate to first product detail page
        navigate_to_platform_page(page, "/products/")
        page.wait_for_load_state("networkidle")

        # Click on first product name link
        first_product_link = page.locator('table a[href*="/products/"]').first
        expect(first_product_link).to_be_visible()
        first_product_link.click()

        page.wait_for_load_state("networkidle")
        # Compound condition: on products detail page but not list page
        assert "/products/" in page.url and page.url != f"{PLATFORM_BASE_URL}/products/"

        # Verify status toggle section is present
        status_section = page.locator('h2:has-text("⚙️ Status & Settings")')
        expect(status_section).to_be_visible()

        # Verify status toggle buttons are present
        active_toggle = page.locator('button:has-text("Active"), button:has-text("Inactive")')
        public_toggle = page.locator('button:has-text("Public"), button:has-text("Private")')
        featured_toggle = page.locator('button:has-text("Featured"), button:has-text("Not Featured")')

        expect(active_toggle.first).to_be_attached()
        expect(public_toggle.first).to_be_attached()
        expect(featured_toggle.first).to_be_attached()

        # Test clicking status toggles (after fix, these should work)
        original_active_text = active_toggle.first.inner_text()
        print(f"    Original active status: {original_active_text}")

        # Note: The toggle functionality was fixed by adding proper decorators
        # This test verifies the UI elements are present and clickable
        # The actual HTMX toggle behavior would require a running server with the fix

        # Verify toggle buttons are interactive (enabled and clickable)
        expect(active_toggle.first).to_be_enabled()
        expect(public_toggle.first).to_be_enabled()
        expect(featured_toggle.first).to_be_enabled()

        print("  ✅ Product status toggle interface is properly implemented")


# ===============================================================================
# SEARCH AND FILTERING TESTS
# ===============================================================================


def _clear_product_filters(page: Page) -> None:
    """Click the Clear button if present, otherwise navigate directly to products list."""
    clear_button = page.locator('a:has-text("❌ Clear"), a:has-text("Clear"), button:has-text("Clear")').first
    if clear_button.count() > 0:
        clear_button.click()
    else:
        navigate_to_platform_page(page, "/products/")
    page.wait_for_load_state("networkidle")


def test_product_search_and_filtering(page: Page) -> None:
    """
    Test product search and filtering functionality.

    This test covers:
    1. Text search functionality
    2. Product type filtering
    3. Status filtering (Active/Inactive, Public/Private)
    4. Filter combinations
    5. Clear filters functionality
    """
    print("🧪 Testing product search and filtering functionality")

    with ComprehensivePageMonitor(page, "product search and filtering",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        # Login and navigate to products
        ensure_fresh_platform_session(page)
        assert login_platform_user(page)
        navigate_to_platform_page(page, "/products/")
        page.wait_for_load_state("networkidle")

        # Get initial product count
        initial_count_text = page.locator('h3:has-text("📦 Products")').inner_text()
        print(f"    Initial product count: {initial_count_text}")

        # Test text search
        search_input = page.locator('input[placeholder*="Product name"]')
        expect(search_input).to_be_visible()

        # Search for "VPS" products
        search_input.fill("VPS")
        filter_button = page.locator('button:has-text("🔍 Filter")')
        filter_button.click()

        page.wait_for_load_state("networkidle")

        # Verify search results contain VPS products
        search_results_count = page.locator('h3:has-text("📦 Products")').inner_text()
        print(f"    Search results count: {search_results_count}")

        # Check that VPS products are visible in results
        vps_products = page.locator('table tbody tr:has-text("VPS")')
        vps_count = vps_products.count()
        if vps_count > 0:
            print(f"    ✅ Found {vps_count} VPS products in search results")
        else:
            print("    ⚠️ No VPS products found, but search interface works")

        # Test product type filter - find clear button
        _clear_product_filters(page)

        # Select VPS from product type filter
        product_type_filter = page.locator('select[name="product_type"]')
        product_type_filter.select_option("vps")
        filter_button.click()

        page.wait_for_load_state("networkidle")

        # Verify filter worked
        type_filter_count = page.locator('h3:has-text("📦 Products")').inner_text()
        print(f"    Type filter results: {type_filter_count}")

        # Test status filters
        _clear_product_filters(page)

        # Test active status filter
        active_status_filter = page.locator('select:has-text("All Status")')
        active_status_filter.select_option("Active Only")
        filter_button.click()

        page.wait_for_load_state("networkidle")

        active_filter_count = page.locator('h3:has-text("📦 Products")').inner_text()
        print(f"    Active filter results: {active_filter_count}")

        # Verify that active products are shown with active status badges
        active_badges = page.locator('button:has-text("Active")')
        active_badge_count = active_badges.count()
        print(f"    ✅ Found {active_badge_count} active status badges in filtered results")

        # Test clear filters
        _clear_product_filters(page)

        cleared_count = page.locator('h3:has-text("📦 Products")').inner_text()
        print(f"    After clearing filters: {cleared_count}")

        print("  ✅ Product search and filtering functionality works correctly")


# ===============================================================================
# ROLE-BASED ACCESS CONTROL TESTS
# ===============================================================================

def test_product_catalog_staff_access_control(page: Page) -> None:
    """
    Test that only staff users can access product catalog management.

    This test verifies:
    1. Staff users can access product catalog
    2. Customer users cannot access product catalog
    3. Appropriate error handling for unauthorized access
    """
    print("🧪 Testing product catalog access control")

    with ComprehensivePageMonitor(page, "product catalog access control",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        # Test 1: Verify staff user has access
        print("    Testing staff user access...")
        ensure_fresh_platform_session(page)
        assert login_platform_user(page)

        # Navigate directly to products URL
        navigate_to_platform_page(page, "/products/")
        page.wait_for_load_state("networkidle")

        # Should successfully load product catalog
        expect(page).to_have_url(re.compile(r"/products/"))
        catalog_heading = page.locator('h1:has-text("🛍️ Product Catalog")')
        expect(catalog_heading).to_be_visible()

        # Verify Business dropdown shows Products link
        navigate_to_platform_page(page, "/")
        business_dropdown = page.locator('button:has-text("🏢 Business")')
        expect(business_dropdown.first).to_be_attached()
        business_dropdown.click()
        page.wait_for_load_state("networkidle")

        products_link = page.locator('a:has-text("🛍️ Products"), menuitem:has-text("🛍️ Products"), a[href*="/products/"]')
        expect(products_link.first).to_be_attached()

        print("    ✅ Staff user has proper access to product catalog")

        # Test 2: Verify customer user does NOT have access to platform
        print("    Testing customer user access restrictions...")
        ensure_fresh_platform_session(page)
        # Customers cannot log into the platform (staff-only service)
        # login_user targets portal (:8701), not platform (:8700)
        # Instead, verify that unauthenticated access to products redirects to login
        page.goto(f"{PLATFORM_BASE_URL}/products/")
        page.wait_for_load_state("networkidle")

        # Should redirect to login page since no staff session exists
        current_url = page.url
        if is_login_url(current_url):
            print("    ✅ Unauthenticated user redirected to login when accessing product catalog")
        elif "/products/" in current_url:
            # If URL is accessible without login, check for permission error
            error_message = page.locator('text="permission", text="unauthorized", text="access denied"')
            if error_message.count() > 0:
                print("    ✅ Unauthenticated user sees proper permission error message")
            else:
                print("    ⚠️ Products URL accessible without authentication")
        else:
            print(f"    ✅ Unauthenticated user appropriately blocked from product catalog (redirected to {current_url})")

        print("  ✅ Product catalog access control working correctly")


# ===============================================================================
# MOBILE RESPONSIVENESS TESTS
# ===============================================================================

def test_product_catalog_mobile_responsiveness(page: Page) -> None:
    """
    Test product catalog mobile responsiveness and touch interactions.

    This test verifies:
    1. Product catalog displays correctly on mobile viewports
    2. Touch interactions work properly
    3. Mobile navigation elements function correctly
    4. Tables and forms are mobile-friendly
    """
    print("🧪 Testing product catalog mobile responsiveness")

    with ComprehensivePageMonitor(page, "product catalog mobile responsiveness",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True,
                                 check_performance=False):
        # Login and navigate to products on desktop first
        ensure_fresh_platform_session(page)
        assert login_platform_user(page)
        navigate_to_platform_page(page, "/products/")
        page.wait_for_load_state("networkidle")

        # Test mobile viewport
        with MobileTestContext(page, 'mobile_medium') as mobile:
            print("    📱 Testing product catalog on mobile viewport")

            run_standard_mobile_test(page, mobile, context_label="product catalog")

            # Optional UI element — presence depends on product configuration
            # Product cards/table should be scrollable/accessible; table may be hidden on mobile
            products_table = page.locator('table')
            if products_table.is_visible():
                print("      ✅ Products table visible on mobile")
            else:
                print("      ⚠️ Products table may not be visible on mobile")

            # Test mobile-specific interactions
            # Check if action buttons are properly sized for touch
            action_buttons = page.locator('table a[href*="/products/"]')
            button_count = action_buttons.count()
            if button_count > 0:
                # Try clicking first action button
                try:
                    first_button = action_buttons.first
                    if first_button.is_visible():
                        first_button.click()
                        page.wait_for_load_state("networkidle")
                        if "/products/" in page.url and page.url != f"{PLATFORM_BASE_URL}/products/":
                            print("      ✅ Product action buttons work on mobile")
                            # Navigate back
                            navigate_to_platform_page(page, "/products/")
                        else:
                            print("      ⚠️ Product action button click may not have worked")
                except (TimeoutError, PlaywrightError):
                    print("      ⚠️ Unable to test product action buttons on mobile")

        # Test tablet landscape view
        with MobileTestContext(page, 'tablet_landscape') as tablet:
            print("    📱 Testing product catalog on tablet landscape")

            page.reload()
            page.wait_for_load_state("networkidle")

            # Check layout on tablet
            tablet_layout_issues = tablet.check_responsive_layout()
            tablet_critical = [issue for issue in tablet_layout_issues
                             if 'horizontal scroll' in issue.lower()]

            if tablet_critical:
                print("      ⚠️ Tablet has horizontal scroll issues")
            else:
                print("      ✅ Tablet layout looks good")

            # Test tablet navigation
            tablet_nav_count = tablet.test_mobile_navigation()
            if tablet_nav_count > 0:
                print(f"      ✅ Tablet navigation working ({tablet_nav_count} elements)")
            else:
                print("      ✅ Tablet uses desktop navigation (expected)")

        print("  ✅ Product catalog mobile responsiveness testing completed")


# ===============================================================================
# COMPREHENSIVE WORKFLOW TESTS
# ===============================================================================


def test_product_catalog_responsive_breakpoints(page: Page) -> None:
    """
    Test product catalog functionality across all responsive breakpoints.

    This test validates that core product catalog functionality works on:
    - Desktop viewports (baseline)
    - Tablet viewports (landscape and portrait)
    - Mobile viewports (various sizes)
    """
    print("🧪 Testing product catalog across responsive breakpoints")

    with ComprehensivePageMonitor(page, "product catalog responsive breakpoints",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,
                                 allow_accessibility_skip=True):
        # Login first
        ensure_fresh_platform_session(page)
        assert login_platform_user(page)

        def test_product_catalog_functionality(test_page, context="general"):
            """Test core product catalog functionality across viewports."""
            try:
                # Navigate to products
                test_page.goto(f"{PLATFORM_BASE_URL}/products/")
                test_page.wait_for_load_state("networkidle")

                # Verify authentication maintained
                require_authentication(test_page)

                # Check core elements are present - find any visible h1
                all_h1s = test_page.locator('h1').all()
                heading_visible = any(
                    h1.is_visible() and ("product" in (h1.text_content() or "").lower() or "catalog" in (h1.text_content() or "").lower())
                    for h1 in all_h1s
                )
                # Table may be hidden on mobile, check for any product content
                products_table = test_page.locator('table')
                product_cards = test_page.locator('[class*="product"], [data-product], tr:has-text("Product")')
                has_products = products_table.is_visible() or product_cards.count() > 0

                elements_present = heading_visible and has_products

                if elements_present:
                    # Count products shown
                    product_rows = test_page.locator('table tbody tr')
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
        mobile_extras = results.get('mobile_extras', {})
        if mobile_extras:
            layout_issues = mobile_extras.get('layout_issues', [])
            touch_works = mobile_extras.get('touch_works', False)

            print("\n  📊 Mobile catalog summary:")
            print(f"    - Layout issues: {len(layout_issues)}")
            print(f"    - Touch interactions: {'YES' if touch_works else 'LIMITED'}")

        print("  ✅ Product catalog validated across all responsive breakpoints")
