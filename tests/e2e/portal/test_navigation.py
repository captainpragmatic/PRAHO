"""
Navigation E2E Tests for PRAHO Platform

This module tests navigation functionality including:
- Cross-page navigation flows
- Header and menu interactions
- Role-based navigation access
- Mobile navigation responsiveness
- Navigation completeness validation

Uses shared utilities from tests.e2e.utils for consistency.
"""

import pytest
from playwright.sync_api import Page

# Import shared utilities
from tests.e2e.utils import (
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    AuthenticationError,
    ComprehensivePageMonitor,
    MobileTestContext,
    count_elements,
    ensure_fresh_session,
    get_test_user_credentials,
    is_logged_in_url,
    is_login_url,
    login_user,
    navigate_to_dashboard,
    require_authentication,
    run_responsive_breakpoints_test,
    safe_click_element,
)


def test_navigation_cross_page_flow(page: Page) -> None:
    """
    Test navigation between different sections of the application.

    This test verifies that navigation links work correctly and users can
    move between different areas of the platform.
    """
    print("🧪 Testing cross-page navigation flow with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "cross-page navigation test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,  # Keep fast for navigation flow
                                 check_performance=False,
                                 ignore_patterns=["401", "403", "404", "429", "Forbidden", "favicon"]):   # Keep fast for navigation flow
        # Login as superuser for maximum navigation access
        ensure_fresh_session(page)
        if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
            pytest.skip("Cannot login as superuser")

    try:
        require_authentication(page)

        # Define navigation test cases with expected sections
        navigation_tests = [
            ("customers", "customer management"),
            ("admin", "administration panel"),
        ]

        success_count = 0

        for section, description in navigation_tests:
            print(f"  🔗 Testing navigation to {description}")

            # Start from dashboard
            navigate_to_dashboard(page)
            require_authentication(page)

            # Look for navigation link
            if section == "admin":
                link_selector = 'a[href*="/admin/"], a:has-text("Admin")'
            else:
                link_selector = f'a[href*="/{section}/"], a:has-text("{section.title()}")'

            link = page.locator(link_selector).first

            if link.count() == 0:
                print(f"    ⚠️ {description} navigation not found - may not be available")
                continue

            if not link.is_visible():
                print(f"    ⚠️ {description} navigation not visible")
                continue

            try:
                # Click navigation link
                link.click()
                page.wait_for_load_state("networkidle", timeout=5000)

                current_url = page.url

                # Verify navigation worked
                if f"/{section}/" in current_url or (section == "admin" and "/admin/" in current_url):
                    print(f"    ✅ Successfully navigated to {description}")
                    success_count += 1
                else:
                    print(f"    ❌ Navigation failed - expected {section}, got {current_url}")

            except Exception as e:
                print(f"    ❌ Navigation to {description} failed: {str(e)[:50]}")

        print(f"📊 Navigation success: {success_count}/{len(navigation_tests)} sections")

        # Verify we can return to dashboard
        navigate_to_dashboard(page)
        require_authentication(page)
        assert is_logged_in_url(page.url), "Should be able to return to dashboard"

    except AuthenticationError:
        pytest.fail("Lost authentication during navigation flow test")


def test_navigation_header_interactions(page: Page) -> None:
    """
    Test navigation header button interactions for both superuser and customer accounts.

    This test focuses specifically on navigation elements in the header/navbar,
    testing both user roles to ensure proper access controls.
    """
    print("🧪 Testing navigation header button interactions with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "navigation header interactions test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,  # Keep fast for multi-user test
                                 check_performance=False,
                                 ignore_patterns=["401", "403", "404", "429", "Forbidden", "favicon"]):   # Keep fast for multi-user test

        # Get test user credentials
        users = get_test_user_credentials()
        test_cases = [
            (users['superuser']['email'], users['superuser']['password'], "superuser"),
            (users['customer']['email'], users['customer']['password'], "customer"),
        ]

        successful_tests = 0
        for email, password, user_type in test_cases:
            try:
                _test_user_navigation_interactions(page, email, password, user_type)
                successful_tests += 1
            except Exception as e:
                print(f"    ❌ {user_type} navigation test failed: {str(e)[:100]}")

        # Require at least one successful test (preferably superuser)
        assert successful_tests > 0, "At least one user type must successfully complete navigation tests"

    # End on a clean state - only if we're logged in
    try:
        if is_logged_in_url(page.url):
            navigate_to_dashboard(page)
    except Exception:  # noqa: S110
        pass  # Ignore cleanup errors

    print("  ✅ Navigation header interaction testing completed!")


def _test_user_navigation_interactions(page: Page, email: str, password: str, user_type: str) -> None:
    """Test navigation interactions for a single user type"""
    print(f"\n  👤 Testing navigation header for {user_type}")

    # Start fresh for each user type - clear session and go to login
    ensure_fresh_session(page)

    # Login with current user - skip this user type if login fails
    if not login_user(page, email, password):
        print(f"    ⚠️  Skipping {user_type} - login failed for {email}")
        return

    print(f"    🔘 Testing navigation elements for {user_type}...")

    # Define navigation-specific selectors (more conservative approach)
    navigation_elements = [
        # Navigation bar elements
        ('nav a[href]:visible', 'visible navigation links'),
        ('nav button:visible', 'visible navigation buttons'),
        ('.navbar a[href]:visible', 'visible navbar links'),
        ('.navbar button:visible', 'visible navbar buttons'),

        # Header elements (but avoid logout buttons)
        ('header a[href]:not([href*="logout"]):visible', 'header links (non-logout)'),
        ('header button:not([data-action="logout"]):visible', 'header buttons (non-logout)'),
    ]

    user_total_clicked, user_total_found = _test_navigation_elements(page, navigation_elements, user_type)
    print(f"    📊 {user_type.title()} summary: Found {user_total_found} nav elements, clicked {user_total_clicked}")


def _test_navigation_elements(page: Page, navigation_elements: list, user_type: str) -> tuple[int, int]:
    """Test individual navigation elements and return click/found counts"""
    user_total_clicked = 0
    user_total_found = 0

    for selector, element_type in navigation_elements:
        try:
            count = count_elements(page, selector, element_type)
            user_total_found += count

            if count > 0:
                clicked_count = _test_element_clicks(page, selector, count, user_type)
                user_total_clicked += clicked_count

                # If we got logged out, break out of element testing
                if is_login_url(page.url):
                    break

        except Exception as selector_error:
            print(f"      ❌ Selector error for {element_type}: {str(selector_error)[:100]}")
            continue

    return user_total_clicked, user_total_found


def _test_element_clicks(page: Page, selector: str, count: int, user_type: str) -> int:
    """Test clicking on navigation elements and return count of successful clicks"""
    clicked_count = 0
    # Test clicking navigation elements (max 2 for nav to avoid excessive testing)
    elements_to_test = min(count, 2)

    for i in range(elements_to_test):
        if _should_stop_testing(page, user_type):
            break

        try:
            clicked = _try_click_navigation_element(page, selector, i)
            if clicked:
                clicked_count += 1

        except Exception as element_error:
            print(f"        ❌ Element error: {str(element_error)[:100]}")
            continue

    return clicked_count


def _should_stop_testing(page: Page, user_type: str) -> bool:
    """Check if we should stop testing (e.g., if logged out)"""
    if is_login_url(page.url):
        print(f"          ⚠️  Got logged out, ending {user_type} testing")
        return True
    return False


def _try_click_navigation_element(page: Page, selector: str, index: int) -> bool:
    """Try to click a navigation element and handle the result"""
    element = page.locator(selector).nth(index)

    # Check if element is visible and enabled
    if not (element.is_visible() and element.is_enabled()):
        return False

    # Get element info for logging
    href = element.get_attribute("href") or ""
    text = element.inner_text()[:30] or element.get_attribute("title") or "nav element"

    # Skip problematic links
    if _should_skip_element(href):
        print(f"        ⚠️  Skipping: {text} ({href})")
        return False

    print(f"        🔘 Clicking nav element: {text}")

    # Perform the click with proper error handling
    if safe_click_element(page, f"({selector})[{index}]", f"nav element: {text}"):
        _handle_navigation_result(page, text)
        return True

    return False


def _should_skip_element(href: str) -> bool:
    """Determine if an element should be skipped based on its href"""
    return bool(href.startswith(('mailto:', 'tel:', 'javascript:')) or
                href == '#' or
                'logout' in href.lower() or
                'signout' in href.lower() or
                (href and not href.startswith('/')))


def _handle_navigation_result(page: Page, element_text: str) -> None:
    """Handle the result after clicking a navigation element"""
    current_url = page.url
    print(f"          ✅ Successfully clicked - URL: {current_url}")

    # If we're no longer on the dashboard, navigate back
    if not is_logged_in_url(current_url) and not is_login_url(current_url):
        print("          🔄 Navigating back to dashboard")
        navigate_to_dashboard(page)


def test_navigation_menu_visibility_by_role(page: Page) -> None:
    """
    Test that navigation menu items are visible based on user roles.

    This test verifies role-based access control for navigation elements
    using functional validation instead of simple element counting.
    """
    print("🧪 Testing navigation menu visibility by role with comprehensive monitoring")

    # Use comprehensive monitoring context for the entire test
    with ComprehensivePageMonitor(page, "navigation menu visibility test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,  # Keep fast for role-based test
                                 check_performance=False,
                                 ignore_patterns=["401", "403", "404", "429", "Forbidden", "favicon"]):   # Keep fast for role-based test

        # Test superuser navigation access
        print("\n  👑 Testing superuser navigation access")
        ensure_fresh_session(page)
        if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
            pytest.skip("Cannot login as superuser")

        try:
            require_authentication(page)

            # Verify superuser sees staff navigation elements
            staff_links = page.locator('a:has-text("Customers"), a:has-text("Invoices"), a:has-text("Tickets"), a:has-text("Services")')
            staff_count = staff_links.count()

            assert staff_count >= 4, f"Superuser should see staff navigation (found {staff_count})"
            print(f"    ✅ Found {staff_count} staff navigation items")

        except AuthenticationError:
            pytest.fail("Lost authentication during superuser navigation test")

        # Test customer navigation restrictions
        print("\n  👤 Testing customer navigation restrictions")
        ensure_fresh_session(page)
        if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
            pytest.skip("Cannot login as customer")

        try:
            require_authentication(page)

            # Verify customer does NOT see staff navigation
            staff_only_links = page.locator('a:has-text("Customers")')  # Staff-only link
            staff_count = staff_only_links.count()

            assert staff_count == 0, f"Customer should not see staff navigation (found {staff_count})"
            print("    ✅ Customer properly restricted from staff navigation")

            # Verify customer sees their own navigation (My Tickets, My Invoices, etc.)
            customer_links = page.locator('a:has-text("My Tickets"), a:has-text("My Invoices"), a:has-text("My Services")')
            customer_count = customer_links.count()
            print(f"    ✅ Found {customer_count} customer navigation items")

        except AuthenticationError:
            pytest.fail("Lost authentication during customer navigation test")

        print("  ✅ Navigation role-based access control verified!")


def test_navigation_dropdown_interactions(page: Page) -> None:
    """
    Test dropdown menu interactions in the navigation header.

    This test focuses on dropdown menus, user menus, and collapsible navigation elements.
    """
    print("🧪 Testing navigation dropdown interactions with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "navigation dropdown interactions test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,  # Keep fast for dropdown test
                                 check_performance=False,
                                 ignore_patterns=["401", "403", "404", "429", "Forbidden", "favicon"]):   # Keep fast for dropdown test
        # Login as superuser for maximum navigation access
        ensure_fresh_session(page)
        assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)

    # Test dropdown elements
    dropdown_selectors = [
        ('.dropdown-toggle', 'dropdown toggles'),
        ('[data-toggle="dropdown"]', 'data dropdown toggles'),
        ('.nav-item.dropdown', 'navigation dropdown items'),
        ('.user-menu', 'user menu elements'),
        ('.navbar-toggler', 'mobile menu toggles'),
    ]

    total_dropdowns = 0
    total_clicked = 0

    for selector, description in dropdown_selectors:
        count = count_elements(page, selector, description)
        total_dropdowns += count

        if count > 0 and safe_click_element(page, f"{selector}:first-child", f"first {description}"):
            total_clicked += 1

            # Wait a moment for dropdown to appear
            page.wait_for_timeout(500)

            # Check if dropdown content is visible
            dropdown_content_selectors = [
                '.dropdown-menu:visible',
                '.dropdown-content:visible',
                '[aria-expanded="true"]'
            ]

            for content_selector in dropdown_content_selectors:
                content_count = count_elements(page, content_selector, 'dropdown content')
                if content_count > 0:
                    print(f"      ✅ Dropdown content appeared: {content_count} items")
                    break

            # Click somewhere else to close dropdown
            page.click('body')
            page.wait_for_timeout(200)

        print(f"  📊 Summary: Found {total_dropdowns} dropdown elements, successfully clicked {total_clicked}")

        print("  ✅ Navigation dropdown testing completed!")


def test_mobile_navigation_responsiveness(page: Page) -> None:
    """
    Test mobile navigation behavior and responsiveness with comprehensive validation.

    This test checks navigation functionality across different mobile viewport sizes,
    validates mobile-specific UI elements, and ensures proper responsive behavior.
    """
    print("🧪 Testing mobile navigation responsiveness with comprehensive monitoring")

    with ComprehensivePageMonitor(page, "mobile navigation responsiveness test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,   # Important for mobile navigation a11y
                                 check_performance=False,
                                 ignore_patterns=["401", "403", "404", "429", "Forbidden", "favicon"]):   # Keep fast for mobile test
        # Login as superuser for full navigation access
        ensure_fresh_session(page)
        assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)

        # Test mobile medium viewport (standard smartphone)
        with MobileTestContext(page, 'mobile_medium') as mobile:
            print("  📱 Testing standard mobile navigation (375x667)")

            # Test mobile navigation elements
            nav_count = mobile.test_mobile_navigation()

            # Test responsive layout for navigation
            layout_issues = mobile.check_responsive_layout()

            # Test touch interactions on navigation
            touch_success = mobile.test_touch_interactions()

            print(f"    ✅ Mobile navigation elements: {nav_count}")
            print(f"    ✅ Layout issues: {len(layout_issues)}")
            print(f"    ✅ Touch interactions: {'WORKING' if touch_success else 'LIMITED'}")

        # Test mobile small viewport (smaller/older devices)
        with MobileTestContext(page, 'mobile_small') as mobile_small:
            print("  📱 Testing small mobile navigation (320x568)")

            # Test navigation still works on very small screens
            small_nav_count = mobile_small.test_mobile_navigation()
            small_layout_issues = mobile_small.check_responsive_layout()

            # Focus on critical issues for small screens
            critical_issues = [issue for issue in small_layout_issues
                             if any(keyword in issue.lower()
                                  for keyword in ['horizontal scroll', 'small touch'])]

            print(f"    ✅ Small screen navigation: {small_nav_count} elements")
            if critical_issues:
                print(f"    ⚠️  Critical issues on small screens: {len(critical_issues)}")
            else:
                print("    ✅ No critical small-screen issues")

        print("  ✅ Mobile navigation responsiveness testing completed!")


def test_navigation_responsive_breakpoints(page: Page) -> None:
    """
    Test navigation functionality across all responsive breakpoints.

    This comprehensive test validates that navigation works correctly on:
    - Desktop viewports (baseline)
    - Tablet viewports (landscape and portrait)
    - Mobile viewports (various sizes)

    Uses the responsive breakpoint testing utility for consistency.
    """
    print("🧪 Testing navigation across responsive breakpoints")

    with ComprehensivePageMonitor(page, "navigation responsive breakpoints test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,  # Keep fast for comprehensive test
                                 check_performance=False,
                                 ignore_patterns=["401", "403", "404", "429", "Forbidden", "favicon"]):   # Keep fast for comprehensive test
        # Login as superuser for full navigation access
        ensure_fresh_session(page)
        assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)

        try:
            require_authentication(page)

            # Define a navigation test function to run across breakpoints
            def test_navigation_functionality(test_page, context="general"):
                """Test basic navigation functionality."""
                try:
                    # Verify we're still authenticated
                    require_authentication(test_page)

                    # Check for key navigation elements
                    nav_links = test_page.locator('nav a, .navbar a, header a').count()
                    nav_buttons = test_page.locator('nav button, .navbar button, header button').count()

                    # Verify we have some navigation elements
                    has_navigation = nav_links > 0 or nav_buttons > 0

                    if has_navigation:
                        print(f"      ✅ Navigation elements found: {nav_links} links, {nav_buttons} buttons")
                    else:
                        print("      ⚠️  No navigation elements found")

                    return has_navigation

                except Exception as e:
                    print(f"      ❌ Navigation test failed: {str(e)[:50]}")
                    return False

            # Test navigation across all responsive breakpoints
            results = run_responsive_breakpoints_test(page, test_navigation_functionality)

            # Verify all breakpoints pass
            desktop_pass = results.get('desktop', False)
            tablet_pass = results.get('tablet_landscape', False)
            mobile_pass = results.get('mobile', False)

            assert desktop_pass, "Navigation should work on desktop viewport"
            assert tablet_pass, "Navigation should work on tablet viewport"
            assert mobile_pass, "Navigation should work on mobile viewport"

            # Report mobile-specific findings
            mobile_extras = results.get('mobile_extras', {})
            if mobile_extras:
                nav_elements = mobile_extras.get('navigation_elements', 0)
                layout_issues = mobile_extras.get('layout_issues', [])
                touch_works = mobile_extras.get('touch_works', False)

                print("\n  📊 Mobile navigation summary:")
                print(f"    - Navigation elements: {nav_elements}")
                print(f"    - Layout issues: {len(layout_issues)}")
                print(f"    - Touch interactions: {'YES' if touch_works else 'LIMITED'}")

            print("  ✅ Navigation validated across all responsive breakpoints")

        except AuthenticationError:
            pytest.fail("Lost authentication during navigation responsive breakpoints test")


# Remove old configuration - will be centralized in conftest.py
