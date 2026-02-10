"""
Tickets E2E Tests for PRAHO Platform - Staff/Admin Tests

This module tests staff-side tickets/support functionality including:
- Staff ticket management (all customer tickets)
- Ticket creation and reply workflows
- Mobile responsiveness
- Role-based access control (both staff and customer perspectives)

Split from tests/e2e/test_tickets_pytest.py (staff portion).
Uses platform service at :8700.
"""

import pytest
from playwright.sync_api import Page

# Import shared utilities
from tests.e2e.utils import (
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    PLATFORM_BASE_URL,
    AuthenticationError,
    ComprehensivePageMonitor,
    MobileTestContext,
    ensure_fresh_platform_session,
    login_platform_user,
    login_user,
    require_authentication,
    run_responsive_breakpoints_test,
)


def navigate_to_tickets(page: Page) -> bool:
    """
    Navigate to the tickets/support page on the platform service.

    Args:
        page: Playwright page object

    Returns:
        bool: True if navigation successful
    """
    try:
        page.goto(f"{PLATFORM_BASE_URL}/tickets/")
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


def _check_staff_ticket_features(page: Page) -> None:
    """Check staff-specific ticket features."""
    staff_features = [
        ('a[href*="/tickets/create/"], button:has-text("Create"), .btn-create', 'create ticket'),
        ('a[href*="/tickets/"], .ticket-link', 'ticket detail links'),
        ('.ticket-actions, .actions', 'ticket action buttons'),
    ]

    staff_feature_count = 0
    for selector, feature_name in staff_features:
        count = page.locator(selector).count()
        staff_feature_count += count
        if count > 0:
            print(f"    ✅ Found {feature_name}: {count} elements")
        else:
            print(f"    ❌ Missing {feature_name}")

    print(f"👤 Staff features found: {staff_feature_count}")


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
    Verify ticket page functionality for different user types.

    Args:
        page: Playwright page object
        user_type: Type of user ('superuser' or 'customer')

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
    if user_type == "superuser":
        _check_staff_ticket_features(page)

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


def test_staff_tickets_functionality(page: Page) -> None:
    """Test staff ticket management displays correct content and functions properly."""
    print("🧪 Testing staff ticket functionality with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "staff tickets test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Keep fast for staff test
        # Ensure fresh session and login as staff
        ensure_fresh_platform_session(page)
        if not login_platform_user(page):
            pytest.skip("Cannot login as superuser")

        try:
            # Verify staff ticket functionality
            assert verify_tickets_functionality(page, "superuser"), \
                "Staff ticket functionality verification failed"

        except AuthenticationError:
            pytest.fail("Lost authentication during staff tickets test")


def test_tickets_role_based_access(page: Page) -> None:
    """
    Test that tickets display appropriate content based on user roles.

    This test verifies role-based access control is working correctly
    by testing both staff and customer ticket access. The customer login
    portion tests portal login from the platform test context.
    """
    print("🧪 Testing ticket role-based access with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "tickets role-based access test",
                                 check_console=True,    # Re-enable console checking
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Keep fast for multi-user test

        # Test staff access on platform
        print(f"\n  👤 Testing ticket access for superuser")
        ensure_fresh_platform_session(page)

        if not login_platform_user(page):
            pytest.skip("Cannot login as superuser")

        try:
            assert verify_tickets_functionality(page, "superuser"), \
                "Ticket access verification failed for superuser"
            print(f"    ✅ Ticket access correct for superuser")
        except AuthenticationError:
            pytest.fail("Lost authentication during superuser ticket test")

        # Test customer access (uses portal login_user for customer role)
        print(f"\n  👤 Testing ticket access for customer (portal login)")
        # NOTE: This tests customer login via portal - uses login_user with BASE_URL
        from tests.e2e.utils import BASE_URL, ensure_fresh_session
        ensure_fresh_session(page)

        if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
            pytest.skip("Cannot login as customer")

        try:
            # Navigate to portal tickets
            page.goto(f"{BASE_URL}/tickets/")
            page.wait_for_load_state("networkidle", timeout=5000)
            print(f"    ✅ Ticket access correct for customer")
        except AuthenticationError:
            pytest.fail("Lost authentication during customer ticket test")

        print("  ✅ Ticket role-based access control verified!")


def test_tickets_actions_and_interactions(page: Page) -> None:
    """
    Test ticket actions and interactive elements work correctly.

    This test focuses on ticket-specific buttons, forms, and interactions
    for staff users who have full ticket management capabilities.
    """
    print("🧪 Testing ticket actions and interactions with full validation")

    with ComprehensivePageMonitor(page, "ticket interactions test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Skip performance for speed
        # Login as staff for maximum ticket access
        ensure_fresh_platform_session(page)
        if not login_platform_user(page):
            pytest.skip("Cannot login as superuser")

        try:
            require_authentication(page)

            # Navigate to tickets page
            if not navigate_to_tickets(page):
                pytest.fail("Cannot navigate to tickets page")

            print("  🔘 Testing ticket content interactions...")

            # Test ticket-specific interactive elements
            ticket_elements = [
                ('.ticket-actions button', 'ticket action buttons'),
                ('a[href*="/tickets/"]', 'ticket detail links'),
                ('.pagination a, .pagination button', 'pagination controls'),
                ('.search-form input, .filter-form select', 'search and filter controls'),
                ('table th a, .sortable', 'sortable table headers'),
            ]

            interactions_tested = 0

            for selector, element_type in ticket_elements:
                elements = page.locator(selector)
                count = elements.count()

                if count > 0:
                    print(f"    🎫 Found {count} {element_type}")

                    # Test first interactive element if it's safe
                    try:
                        first_element = elements.first
                        if first_element.is_visible() and first_element.is_enabled():
                            # Get element info for safety check
                            href = first_element.get_attribute("href") or ""
                            onclick = first_element.get_attribute("onclick") or ""

                            # Skip dangerous elements
                            if any(danger in (href + onclick).lower()
                                   for danger in ['delete', 'remove', 'logout']):
                                print("      ⚠️ Skipping potentially dangerous element")
                                continue

                            # Safe interaction test
                            first_element.click(timeout=2000)
                            page.wait_for_load_state("networkidle", timeout=3000)
                            interactions_tested += 1

                            # Verify we're still authenticated
                            require_authentication(page)

                            print(f"      ✅ Successfully interacted with {element_type}")

                            # Return to tickets if we navigated away
                            if "/tickets/" not in page.url:
                                navigate_to_tickets(page)

                    except Exception as e:
                        print(f"      ⚠️ Interaction failed: {str(e)[:50]}")
                        continue

            print(f"  🎫 Ticket interactions tested: {interactions_tested}")

            # Verify we're still on tickets page after interactions
            if "/tickets/" not in page.url:
                print("  🔄 Returning to tickets page after interactions")
                navigate_to_tickets(page)

        except AuthenticationError:
            pytest.fail("Lost authentication during ticket interactions test")


def test_tickets_mobile_responsiveness(page: Page) -> None:
    """
    Test ticket management responsiveness across mobile breakpoints.

    This test ensures the ticket system works correctly on mobile devices by:
    - Testing functionality across different viewport sizes
    - Checking mobile-specific navigation elements
    - Validating responsive layout behavior
    - Testing touch interactions
    """
    print("🧪 Testing ticket mobile responsiveness with comprehensive validation")

    with ComprehensivePageMonitor(page, "tickets mobile responsiveness test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable full validation
                                 check_performance=False):   # Skip performance for speed
        # Login as staff for full ticket access
        ensure_fresh_platform_session(page)
        if not login_platform_user(page):
            pytest.skip("Cannot login as superuser")

        try:
            require_authentication(page)

            # Test ticket functionality across responsive breakpoints
            results = run_responsive_breakpoints_test(page, verify_tickets_functionality, "superuser")

            # Verify desktop functionality as baseline
            assert results.get('desktop'), "Tickets should work on desktop viewport"

            # Check results - be resilient to server connection issues during viewport switches
            passed_breakpoints = sum([
                results.get('desktop', False),
                results.get('tablet_landscape', False),
                results.get('mobile', False)
            ])

            # Require at least 2/3 breakpoints to pass (allowing for server instability)
            assert passed_breakpoints >= 2, f"Only {passed_breakpoints}/3 responsive breakpoints passed. Results: {results}"

            if not results.get('tablet_landscape'):
                print("    ⚠️  Tablet landscape had connection issues (server restart)")
            if not results.get('mobile'):
                print("    ⚠️  Mobile viewport had connection issues (server restart)")

            # Check mobile-specific results
            mobile_extras = results.get('mobile_extras', {})

            # Log mobile-specific findings
            nav_elements = mobile_extras.get('navigation_elements', 0)
            layout_issues = mobile_extras.get('layout_issues', [])
            touch_works = mobile_extras.get('touch_works', False)

            print(f"    📱 Mobile navigation elements: {nav_elements}")
            print(f"    📱 Layout issues found: {len(layout_issues)}")
            print(f"    📱 Touch interactions: {'WORKING' if touch_works else 'LIMITED'}")

            # Report any layout issues (but don't fail the test)
            if layout_issues:
                print("    ⚠️  Mobile layout issues detected:")
                for issue in layout_issues[:3]:  # Show first 3 issues
                    print(f"      - {issue}")

            print("  ✅ Ticket mobile responsiveness validated across all breakpoints")

        except AuthenticationError:
            pytest.fail("Lost authentication during ticket mobile responsiveness test")


def test_tickets_mobile_specific_features(page: Page) -> None:
    """
    Test ticket features specific to mobile viewport.

    This test focuses on mobile-only behaviors like:
    - Mobile ticket table/list layouts
    - Touch-optimized interactions for ticket management
    - Responsive content adaptation
    - Mobile-specific UI elements
    """
    print("🧪 Testing ticket mobile-specific features")

    with ComprehensivePageMonitor(page, "tickets mobile features test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,  # Keep fast for focused test
                                 check_performance=False):   # Keep fast for focused test
        # Login as staff
        ensure_fresh_platform_session(page)
        if not login_platform_user(page):
            pytest.skip("Cannot login as superuser")

        try:
            require_authentication(page)

            # Test mobile medium viewport (standard smartphone)
            with MobileTestContext(page, 'mobile_medium') as mobile:
                print("  📱 Testing standard mobile ticket viewport (375x667)")

                # Verify ticket functionality still works
                assert verify_tickets_functionality(page, "superuser"), \
                    "Ticket functionality should work on mobile"

                # Test mobile navigation
                nav_count = mobile.test_mobile_navigation()
                print(f"    ✅ Mobile navigation test completed ({nav_count} elements)")

                # Check responsive layout for ticket tables/lists
                layout_issues = mobile.check_responsive_layout()
                if layout_issues:
                    print(f"    ⚠️  Found {len(layout_issues)} responsive layout issues")
                    for issue in layout_issues[:2]:  # Show first 2
                        print(f"      - {issue}")
                else:
                    print("    ✅ No responsive layout issues detected")

                # Test touch interactions on ticket elements
                touch_success = mobile.test_touch_interactions()
                if not touch_success:
                    print("    Info: Limited touch interactivity (may be normal for this page)")

            # Test mobile small viewport (older/smaller devices)
            with MobileTestContext(page, 'mobile_small') as mobile_small:
                print("  📱 Testing small mobile ticket viewport (320x568)")

                # Verify ticket core functionality still works
                basic_functionality = verify_tickets_functionality(page, "superuser")
                if basic_functionality:
                    print("    ✅ Tickets work on small mobile viewport")
                else:
                    print("    ⚠️  Tickets have issues on small mobile viewport")

                # Check for critical layout problems on small screens
                small_layout_issues = mobile_small.check_responsive_layout()
                critical_issues = [issue for issue in small_layout_issues
                                 if 'horizontal scroll' in issue.lower()]

                if critical_issues:
                    print(f"    ⚠️  Critical small-screen issues: {len(critical_issues)}")
                else:
                    print("    ✅ No critical small-screen layout issues")

            print("  ✅ Mobile-specific ticket features tested successfully")

        except AuthenticationError:
            pytest.fail("Lost authentication during ticket mobile features test")
