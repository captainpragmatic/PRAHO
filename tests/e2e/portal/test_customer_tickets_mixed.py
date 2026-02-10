"""
Tickets E2E Tests for PRAHO Portal - Customer Tests

This module tests customer-side tickets/support functionality including:
- Customer ticket access (my tickets only)
- Customer ticket restrictions (no staff features)

Split from tests/e2e/test_tickets_pytest.py (customer portion).
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


def navigate_to_tickets(page: Page) -> bool:
    """
    Navigate to the tickets/support page on the portal service.

    Args:
        page: Playwright page object

    Returns:
        bool: True if navigation successful
    """
    try:
        page.goto(f"{BASE_URL}/tickets/")
        page.wait_for_load_state("networkidle", timeout=5000)

        # Verify we're on the tickets page
        current_url = page.url
        if "/tickets/" in current_url:
            print("    ✅ Successfully navigated to tickets page")
            return True
        else:
            print(f"    ❌ Navigation failed - expected tickets, got {current_url}")
            return False

    except Exception as e:
        print(f"    ❌ Navigation to tickets failed: {str(e)[:50]}")
        return False


def _validate_tickets_page_structure(page: Page) -> int:
    """Validate basic tickets page structure elements and return count."""
    basic_elements = [
        ('main', 'main content area'),
        ('h1, h2, h3', 'page headings'),
        ('table, .table, .ticket-list', 'ticket listing'),
    ]

    total_elements = 0
    for selector, description in basic_elements:
        count = page.locator(selector).count()
        total_elements += count
        print(f"🎫 Found {count} {description}")

    return total_elements


def _check_customer_ticket_features(page: Page) -> None:
    """Check customer-specific ticket features and restrictions."""
    customer_features = [
        ('.ticket-list, .my-tickets', 'my tickets list'),
        ('a[href*="/tickets/"], .ticket-link', 'ticket detail links'),
        ('.ticket-status, .status', 'ticket status indicators'),
    ]

    customer_feature_count = 0
    for selector, feature_name in customer_features:
        count = page.locator(selector).count()
        customer_feature_count += count
        if count > 0:
            print(f"    ✅ Found {feature_name}: {count} elements")

    # Customer should NOT see admin-only features (internal notes, etc)
    restricted_features = page.locator('input[name="is_internal"], .internal-note').count()
    if restricted_features == 0:
        print("    ✅ Properly restricted from staff features")
    else:
        print(f"    ❌ Has access to {restricted_features} staff-only features")

    print(f"👤 Customer features found: {customer_feature_count}")


def _count_ticket_navigation_elements(page: Page) -> int:
    """Count navigation elements on the tickets page."""
    nav_elements = [
        ('nav', 'navigation elements'),
        ('a[href*="/tickets/"], a[href*="/dashboard/"]', 'navigation links'),
        ('button', 'interactive buttons'),
    ]

    nav_total = 0
    for selector, _description in nav_elements:
        count = page.locator(selector).count()
        nav_total += count

    return nav_total


def verify_tickets_functionality(page: Page, user_type: str) -> bool:
    """
    Verify ticket page functionality for customer user.

    Args:
        page: Playwright page object
        user_type: Type of user ('customer')

    Returns:
        bool: True if ticket functionality is working correctly
    """
    print(f"🎫 Verifying ticket functionality for {user_type}")

    # Navigate to tickets page
    if not navigate_to_tickets(page):
        return False

    # Validate page structure
    total_elements = _validate_tickets_page_structure(page)

    # User-specific functionality checks
    if user_type == "customer":
        _check_customer_ticket_features(page)

    # Count navigation elements
    nav_total = _count_ticket_navigation_elements(page)
    print(f"🎫 Total ticket content elements: {total_elements + nav_total}")

    # Page should have meaningful content
    has_content = total_elements >= 3  # At least main, headings, and ticket list/table

    if has_content:
        print(f"✅ Ticket functionality verified for {user_type}")
        return True
    else:
        print(f"❌ Ticket page appears to lack sufficient content for {user_type}")
        return False


def test_customer_tickets_functionality(page: Page) -> None:
    """Test customer ticket access displays correct content and functions properly."""
    print("🧪 Testing customer ticket functionality with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "customer tickets test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Keep fast for customer test
        # Ensure fresh session and login as customer
        ensure_fresh_session(page)
        if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
            pytest.skip("Cannot login as customer")

        try:
            # Verify customer ticket functionality
            assert verify_tickets_functionality(page, "customer"), \
                "Customer ticket functionality verification failed"

        except AuthenticationError:
            pytest.fail("Lost authentication during customer tickets test")
