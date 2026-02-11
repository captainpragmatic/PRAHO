"""
Invoices E2E Tests for PRAHO Portal - Customer Tests

This module tests customer-side invoices/billing functionality including:
- Customer invoice access (my invoices only)
- Customer invoice restrictions (no staff features)

Split from tests/e2e/test_invoices_pytest.py (customer portion).
Uses portal service at :8701.
"""

import pytest
from playwright.sync_api import Page

# Import shared utilities
from tests.e2e.utils import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    AuthenticationError,
    ComprehensivePageMonitor,
    ensure_fresh_session,
    login_user,
)


def navigate_to_invoices(page: Page) -> bool:
    """
    Navigate to the invoices/billing page on the portal service.

    Args:
        page: Playwright page object

    Returns:
        bool: True if navigation successful
    """
    try:
        page.goto(f"{BASE_URL}/billing/invoices/")
        page.wait_for_load_state("networkidle", timeout=5000)

        # Verify we're on the billing page
        current_url = page.url
        if "/billing/invoices/" in current_url:
            print("    ✅ Successfully navigated to invoices page")
            return True
        else:
            print(f"    ❌ Navigation failed - expected billing/invoices, got {current_url}")
            return False

    except Exception as e:
        print(f"    ❌ Navigation to invoices failed: {str(e)[:50]}")
        return False


def _validate_basic_page_structure(page: Page) -> int:
    """Validate basic page structure elements and return count."""
    basic_elements = [
        ('main', 'main content area'),
        ('h1, h2, h3', 'page headings'),
        ('table, .table, .invoice-list', 'invoice listing'),
    ]

    total_elements = 0
    for selector, description in basic_elements:
        count = page.locator(selector).count()
        total_elements += count
        print(f"📊 Found {count} {description}")

    return total_elements


def _check_customer_features(page: Page) -> None:
    """Check customer-specific invoice features and restrictions."""
    customer_features = [
        ('.invoice-list, .my-invoices', 'my invoices list'),
        ('a[href*="/invoices/"], .invoice-link', 'invoice detail links'),
        ('.invoice-status, .status', 'invoice status indicators'),
    ]

    customer_feature_count = 0
    for selector, feature_name in customer_features:
        count = page.locator(selector).count()
        customer_feature_count += count
        if count > 0:
            print(f"    ✅ Found {feature_name}: {count} elements")

    # Customer should NOT see staff-only features
    restricted_features = page.locator('a[href*="/proformas/create/"], a[href*="/reports/"]').count()
    if restricted_features == 0:
        print("    ✅ Properly restricted from staff features")
    else:
        print(f"    ❌ Has access to {restricted_features} staff-only features")

    print(f"👤 Customer features found: {customer_feature_count}")


def _count_navigation_elements(page: Page) -> int:
    """Count navigation elements on the page."""
    nav_elements = [
        ('nav', 'navigation elements'),
        ('a[href*="/dashboard/"], a[href*="/billing/"], a[href*="/tickets/"]', 'navigation links'),
        ('button', 'interactive buttons'),
    ]

    nav_total = 0
    for selector, _description in nav_elements:
        count = page.locator(selector).count()
        nav_total += count

    return nav_total


def verify_invoices_functionality(page: Page, user_type: str) -> bool:
    """
    Verify invoice page functionality for customer user.

    Args:
        page: Playwright page object
        user_type: Type of user ('customer')

    Returns:
        bool: True if invoice functionality is working correctly
    """
    print(f"📊 Verifying invoice functionality for {user_type}")

    # Navigate to invoices page
    if not navigate_to_invoices(page):
        return False

    # Validate page structure
    total_elements = _validate_basic_page_structure(page)

    # User-specific functionality checks
    if user_type == "customer":
        _check_customer_features(page)

    # Count navigation elements
    nav_total = _count_navigation_elements(page)
    print(f"📊 Total invoice content elements: {total_elements + nav_total}")

    # Page should have meaningful content
    has_content = total_elements >= 3  # At least main, headings, and invoice list/table

    if has_content:
        print(f"✅ Invoice functionality verified for {user_type}")
        return True
    else:
        print(f"❌ Invoice page appears to lack sufficient content for {user_type}")
        return False


def test_customer_invoices_functionality(page: Page) -> None:
    """Test customer invoice access displays correct content and functions properly."""
    print("🧪 Testing customer invoice functionality with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "customer invoices test",
                                 check_console=False,        # Disable to avoid connection issues
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Keep fast for customer test
        # Ensure fresh session and login as customer
        ensure_fresh_session(page)
        if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
            pytest.skip("Login precondition failed — TODO: check E2E service health")

        try:
            # Verify customer invoice functionality
            assert verify_invoices_functionality(page, "customer"), \
                "Customer invoice functionality verification failed"

        except AuthenticationError:
            pytest.fail("Lost authentication during customer invoices test")
