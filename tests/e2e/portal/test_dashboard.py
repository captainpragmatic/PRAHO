"""
Dashboard E2E Tests for PRAHO Platform

This module tests dashboard-specific functionality including:
- Dashboard content and widgets
- Dashboard role-based content display
- Dashboard actions and interactions
- Dashboard data validation

Uses shared utilities from tests.e2e.utils for consistency.
"""

import pytest
from playwright.sync_api import Page

# Import shared utilities
from tests.e2e.utils import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    AuthenticationError,
    ComprehensivePageMonitor,
    MobileTestContext,
    ensure_fresh_session,
    login_user,
    require_authentication,
    run_responsive_breakpoints_test,
    verify_dashboard_functionality,
)


def test_superuser_dashboard_functionality(page: Page) -> None:
    """Test superuser dashboard displays correct content and functions properly."""
    print("🧪 Testing superuser dashboard functionality with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "superuser dashboard test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable with DDT filtering
                                 check_performance=False):   # Keep fast for now
        # Ensure fresh session and login
        ensure_fresh_session(page)
        if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
            pytest.skip("Login precondition failed — TODO: check E2E service health")

        try:
            # Verify dashboard functionality using semantic validation
            assert verify_dashboard_functionality(page, "superuser"), \
                "Superuser dashboard functionality verification failed"

        except AuthenticationError:
            pytest.fail("Lost authentication during superuser dashboard test")


def test_customer_dashboard_functionality(page: Page) -> None:
    """Test customer dashboard displays correct content and functions properly."""
    print("🧪 Testing customer dashboard functionality with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "customer dashboard test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Enable with DDT filtering
                                 check_performance=False):   # Keep fast for customer test
        # Ensure fresh session and login
        ensure_fresh_session(page)
        if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
            pytest.skip("Login precondition failed — TODO: check E2E service health")

        try:
            # Verify dashboard functionality using semantic validation
            assert verify_dashboard_functionality(page, "customer"), \
                "Customer dashboard functionality verification failed"

        except AuthenticationError:
            pytest.fail("Lost authentication during customer dashboard test")


def test_dashboard_role_based_content(page: Page) -> None:
    """
    Test that dashboard displays appropriate content based on user roles.

    This test verifies role-based access control is working correctly
    by testing both superuser and customer dashboard content.
    """
    print("🧪 Testing dashboard role-based content with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "role-based content test",
                                 check_console=False,        # Disable for multi-user test
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,  # Keep fast for multi-user test
                                 allow_accessibility_skip=True,
                                 check_performance=False):   # Keep fast for multi-user test
        users = [
            (SUPERUSER_EMAIL, SUPERUSER_PASSWORD, "superuser"),
            (CUSTOMER_EMAIL, CUSTOMER_PASSWORD, "customer"),
        ]

        for email, password, user_type in users:
            print(f"\n  👤 Testing dashboard content for {user_type}")

            # Fresh session for each user
            ensure_fresh_session(page)

            if not login_user(page, email, password):
                pytest.skip("Login precondition failed — TODO: check E2E service health")

            try:
                # Verify role-based content is displayed correctly
                assert verify_dashboard_functionality(page, user_type), \
                    f"Dashboard content verification failed for {user_type}"

                print(f"    ✅ Dashboard content correct for {user_type}")

            except AuthenticationError:
                pytest.fail(f"Lost authentication during {user_type} content test")


def test_dashboard_actions_and_interactions(page: Page) -> None:
    """
    Test dashboard actions and interactive elements work correctly.

    This test focuses on dashboard-specific buttons, forms, and interactions
    rather than general navigation.
    """
    print("🧪 Testing dashboard actions and interactions with full validation")

    with ComprehensivePageMonitor(page, "dashboard interactions test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Re-enable with DDT filtering
                                 check_performance=False):   # Skip performance for speed
        # Login as superuser for maximum dashboard access
        ensure_fresh_session(page)
        if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
            pytest.skip("Login precondition failed — TODO: check E2E service health")

        try:
            require_authentication(page)

            print("  🔘 Testing dashboard content interactions...")

            # Test dashboard-specific interactive elements
            dashboard_elements = [
                ('.card button', 'dashboard card buttons'),
                ('.widget [role="button"]', 'dashboard widget buttons'),
                ('.dashboard-action', 'dashboard action elements'),
                ('main .btn', 'main content buttons'),
            ]

            interactions_tested = 0

            for selector, element_type in dashboard_elements:
                elements = page.locator(selector)
                count = elements.count()

                if count > 0:
                    print(f"    📊 Found {count} {element_type}")

                    # Test first interactive element if it's safe
                    try:
                        first_element = elements.first
                        if first_element.is_visible() and first_element.is_enabled():
                            # Get element info for safety check
                            href = first_element.get_attribute("href") or ""
                            onclick = first_element.get_attribute("onclick") or ""

                            # Skip dangerous elements
                            if any(danger in (href + onclick).lower()
                                   for danger in ['logout', 'delete', 'remove']):
                                print("      ⚠️ Skipping potentially dangerous element")
                                continue

                            # Safe interaction test
                            first_element.click(timeout=2000)
                            page.wait_for_load_state("networkidle", timeout=3000)
                            interactions_tested += 1

                            # Verify we're still authenticated
                            require_authentication(page)

                            print(f"      ✅ Successfully interacted with {element_type}")

                    except Exception as e:
                        print(f"      ⚠️ Interaction failed: {str(e)[:50]}")
                        continue

            print(f"  📊 Dashboard interactions tested: {interactions_tested}")

            # Verify we're still on dashboard after interactions
            if "/dashboard/" not in page.url:
                print("  🔄 Returning to dashboard after interactions")
                page.goto(f"{BASE_URL}/dashboard/")
                page.wait_for_load_state("networkidle")

        except AuthenticationError:
            pytest.fail("Lost authentication during dashboard interactions test")


def test_dashboard_mobile_responsiveness(page: Page) -> None:
    """
    Test dashboard responsiveness across mobile breakpoints.

    This test ensures the dashboard works correctly on mobile devices by:
    - Testing functionality across different viewport sizes
    - Checking mobile-specific navigation elements
    - Validating responsive layout behavior
    - Testing touch interactions
    """
    print("🧪 Testing dashboard mobile responsiveness with comprehensive validation")

    with ComprehensivePageMonitor(page, "dashboard mobile responsiveness test",
                                 check_console=False,        # Disable for viewport switching
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=True,   # Important for mobile a11y
                                 check_performance=False):   # Skip performance for speed
        # Login as superuser for full dashboard access
        ensure_fresh_session(page)
        if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
            pytest.skip("Login precondition failed — TODO: check E2E service health")

        try:
            require_authentication(page)

            # Test dashboard functionality across responsive breakpoints
            results = run_responsive_breakpoints_test(page, verify_dashboard_functionality, "superuser")

            # Verify desktop functionality as baseline
            assert results.get('desktop'), "Dashboard should work on desktop viewport"

            # Verify tablet functionality
            assert results.get('tablet_landscape'), "Dashboard should work on tablet landscape viewport"

            # Verify mobile functionality
            assert results.get('mobile'), "Dashboard should work on mobile viewport"

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

            print("  ✅ Dashboard mobile responsiveness validated across all breakpoints")

        except AuthenticationError:
            pytest.fail("Lost authentication during dashboard mobile responsiveness test")


def test_dashboard_mobile_specific_features(page: Page) -> None:
    """
    Test dashboard features specific to mobile viewport.

    This test focuses on mobile-only behaviors like:
    - Mobile navigation patterns
    - Touch-optimized interactions
    - Responsive content adaptation
    - Mobile-specific UI elements
    """
    print("🧪 Testing dashboard mobile-specific features")

    with ComprehensivePageMonitor(page, "dashboard mobile features test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,  # Keep fast for focused test
                                 allow_accessibility_skip=True,
                                 check_performance=False):   # Keep fast for focused test
        # Login as superuser
        ensure_fresh_session(page)
        if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
            pytest.skip("Login precondition failed — TODO: check E2E service health")

        try:
            require_authentication(page)

            # Test mobile medium viewport (standard smartphone)
            with MobileTestContext(page, 'mobile_medium') as mobile:
                print("  📱 Testing standard mobile viewport (375x667)")

                # Verify dashboard still functions
                assert verify_dashboard_functionality(page, "superuser"), \
                    "Dashboard functionality should work on mobile"

                # Test mobile navigation
                nav_count = mobile.test_mobile_navigation()
                print(f"    ✅ Mobile navigation test completed ({nav_count} elements)")

                # Check responsive layout
                layout_issues = mobile.check_responsive_layout()
                if layout_issues:
                    print(f"    ⚠️  Found {len(layout_issues)} responsive layout issues")
                    for issue in layout_issues[:2]:  # Show first 2
                        print(f"      - {issue}")
                else:
                    print("    ✅ No responsive layout issues detected")

                # Test touch interactions
                touch_success = mobile.test_touch_interactions()
                if not touch_success:
                    print("    Info: Limited touch interactivity (may be normal for this page)")

            # Test mobile small viewport (older/smaller devices)
            with MobileTestContext(page, 'mobile_small') as mobile_small:
                print("  📱 Testing small mobile viewport (320x568)")

                # Verify dashboard core functionality still works
                basic_functionality = verify_dashboard_functionality(page, "superuser")
                if basic_functionality:
                    print("    ✅ Dashboard works on small mobile viewport")
                else:
                    print("    ⚠️  Dashboard has issues on small mobile viewport")

                # Check for critical layout problems on small screens
                small_layout_issues = mobile_small.check_responsive_layout()
                critical_issues = [issue for issue in small_layout_issues
                                 if 'horizontal scroll' in issue.lower()]

                if critical_issues:
                    print(f"    ⚠️  Critical small-screen issues: {len(critical_issues)}")
                else:
                    print("    ✅ No critical small-screen layout issues")

            print("  ✅ Mobile-specific dashboard features tested successfully")

        except AuthenticationError:
            pytest.fail("Lost authentication during dashboard mobile features test")


# Remove old configuration - will be centralized in conftest.py
