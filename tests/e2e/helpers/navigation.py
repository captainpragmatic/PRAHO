"""
E2E Navigation & Verification Utilities — dashboard, page nav, role-based checks.

Navigation helpers and semantic validation for admin access, role content, and dashboards.
"""

from playwright.sync_api import Page
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError

from tests.e2e.helpers.constants import BASE_URL, is_logged_in_url
from tests.e2e.helpers.interactions import count_elements

# ===============================================================================
# NAVIGATION UTILITIES
# ===============================================================================

def navigate_to_dashboard(page: Page) -> bool:
    """
    Navigate to the main dashboard.

    Args:
        page: Playwright page object

    Returns:
        bool: True if navigation successful, False otherwise

    Example:
        assert navigate_to_dashboard(page)
    """
    print("🏠 Navigating to dashboard")

    try:
        page.goto(f"{BASE_URL}/dashboard/")
        page.wait_for_load_state("networkidle")

        if is_logged_in_url(page.url):
            print("✅ Successfully navigated to dashboard")
            return True
        else:
            print(f"❌ Dashboard navigation failed, current URL: {page.url}")
            return False

    except Exception as e:
        print(f"❌ Dashboard navigation error: {str(e)[:100]}")
        return False


def navigate_to_page(page: Page, path: str, expected_url_fragment: str | None = None) -> bool:
    """
    Navigate to a specific page and verify the navigation.

    Args:
        page: Playwright page object
        path: URL path to navigate to (relative to BASE_URL)
        expected_url_fragment: Optional URL fragment to verify navigation

    Returns:
        bool: True if navigation successful, False otherwise

    Example:
        assert navigate_to_page(page, "/app/customers/", "customers")
    """
    full_url = f"{BASE_URL}{path}"
    print(f"🔗 Navigating to {full_url}")

    try:
        page.goto(full_url)
        page.wait_for_load_state("networkidle")

        # Check if we're on the expected page
        expected_fragment = expected_url_fragment or path
        if expected_fragment in page.url:
            print(f"✅ Successfully navigated to {path}")
            return True
        else:
            print(f"❌ Navigation failed, expected {expected_fragment}, got {page.url}")
            return False

    except Exception as e:
        print(f"❌ Navigation error: {str(e)[:100]}")
        return False


# ===============================================================================
# SEMANTIC VALIDATION UTILITIES
# ===============================================================================

def verify_admin_access(page: Page, should_have_access: bool) -> bool:
    """
    Test that Django admin is properly removed from PRAHO platform.

    Django admin has been completely removed from PRAHO. Staff users now use
    the custom staff interface at /app/ with role-based access control.
    Admin URLs should return 404 for all users.

    Args:
        page: Playwright page object
        should_have_access: Ignored - admin is removed for all users

    Returns:
        bool: True if admin is properly removed (404 response)
    """
    print("🔐 Verifying admin is removed (admin URLs should return 404)")

    # Django admin removed - all users should get 404 when accessing /admin/
    return _test_admin_access_blocked(page)


# Legacy admin verification functions removed - Django admin disabled
# Staff users now use custom interface at /app/ with role-based access control


def _check_staff_navigation(page: Page) -> bool:
    """Check that staff navigation elements are visible."""
    staff_links = page.locator('a:has-text("Customers"), a:has-text("Invoices"), a:has-text("Tickets"), a:has-text("Services")')
    staff_count = staff_links.count()

    if staff_count == 0:
        print("❌ Admin user should see staff navigation")
        return False

    print(f"✅ Found {staff_count} staff navigation items")
    return True


# _test_django_admin_access function removed - Django admin disabled


def _check_no_staff_navigation(page: Page) -> bool:
    """Check that staff-only navigation is not visible."""
    staff_only_links = page.locator('a:has-text("Customers")')  # Only staff see "Customers", customers see "My Invoices"
    staff_count = staff_only_links.count()

    if staff_count > 0:
        print(f"❌ Non-admin user should not see staff navigation ({staff_count} found)")
        _debug_navigation_links(page)
        return False

    return True


def _test_admin_access_blocked(page: Page) -> bool:
    """Test that admin URLs return 404 (admin completely removed)."""
    try:
        page.goto(f"{BASE_URL}/admin/")
        page.wait_for_load_state("networkidle", timeout=5000)
    except PlaywrightTimeoutError:
        # Timeout is acceptable — 404 pages can stall networkidle; check content anyway
        pass
    except Exception as e:
        print(f"❌ Unexpected error navigating to /admin/: {str(e)[:80]}")
        return False

    page_text = page.locator("body").text_content() or ""
    if "404" in page_text or "not found" in page_text.lower():
        print("✅ Admin URLs properly return 404 (admin removed)")
        return True
    print(f"❌ Admin URL should return 404, got: {page.url}")
    print(f"   Content snippet: {page_text[:200]}...")
    return False


def _debug_navigation_links(page: Page) -> None:
    """Debug helper to show what navigation links are visible."""
    all_links = page.locator('nav a')
    link_count = all_links.count()
    print(f"   Debug: Found {link_count} navigation links total")
    for i in range(min(link_count, 10)):  # Show first 10 links
        link_text = all_links.nth(i).text_content() or ""
        link_href = all_links.nth(i).get_attribute('href') or ""
        print(f"   Link {i+1}: '{link_text}' -> {link_href}")


def verify_navigation_completeness(page: Page, expected_sections: list[str]) -> bool:
    """
    Verify all expected navigation sections are present and functional.

    Args:
        page: Playwright page object
        expected_sections: List of sections that should be accessible

    Returns:
        bool: True if all expected navigation works

    Example:
        verify_navigation_completeness(page, ["customers", "billing", "tickets"])
    """
    print(f"🗺️ Verifying navigation completeness for {len(expected_sections)} sections")

    success_count = 0

    for section in expected_sections:
        print(f"  🔗 Testing {section} navigation")

        # Look for navigation link
        link = page.locator(f'a[href*="/{section}/"], a:has-text("{section.title()}")')

        if link.count() == 0:
            print(f"    ❌ {section} navigation link not found")
            continue

        # Test the link actually works
        try:
            link.first.click()
            page.wait_for_load_state("networkidle", timeout=5000)

            if f"/{section}/" not in page.url:
                print(f"    ❌ {section} navigation failed - expected URL with /{section}/")
                continue

            print(f"    ✅ {section} navigation works")
            success_count += 1

            # Return to known state for next test
            navigate_to_dashboard(page)

        except Exception as e:
            print(f"    ❌ {section} navigation error: {str(e)[:50]}")
            continue

    print(f"📊 Navigation completeness: {success_count}/{len(expected_sections)} working")
    return success_count == len(expected_sections)


def verify_role_based_content(page: Page, user_type: str) -> bool:
    """
    Verify that role-based content is displayed correctly.

    Args:
        page: Playwright page object
        user_type: Type of user ('superuser' or 'customer')

    Returns:
        bool: True if role-based content is correct
    """
    print(f"👤 Verifying role-based content for {user_type}")

    # Portal treats all users identically — no superuser-specific navigation.
    # Both superuser and customer see the same portal navigation links.
    # Platform-specific features (/app/, /customers/) live at :8700 only.
    if user_type in ("superuser", "customer"):
        expected_features = [
            ('a[href*="/tickets/"]', "support tickets"),
            ('a[href*="/billing/"]', "billing access"),
        ]
        forbidden_features = [
            ('a[href*="/admin/"]', "admin panel access"),
        ]
    else:
        print(f"❌ Unknown user type: {user_type}")
        return False

    # Check expected features are present
    for selector, feature_name in expected_features:
        if count_elements(page, selector) == 0:
            print(f"    ❌ Missing expected feature: {feature_name}")
            return False
        print(f"    ✅ Found expected feature: {feature_name}")

    # Check forbidden features are absent
    for selector, feature_name in forbidden_features:
        if count_elements(page, selector) > 0:
            print(f"    ❌ Found forbidden feature: {feature_name}")
            return False
        print(f"    ✅ Correctly hidden feature: {feature_name}")

    print(f"✅ Role-based content correct for {user_type}")
    return True


def verify_dashboard_functionality(page: Page, user_type: str) -> bool:
    """
    Verify dashboard shows appropriate content and functions for user type.

    Args:
        page: Playwright page object
        user_type: Type of user ('superuser' or 'customer')

    Returns:
        bool: True if dashboard functionality is correct
    """
    print(f"📊 Verifying dashboard functionality for {user_type}")

    # Verify we're on the dashboard
    if not is_logged_in_url(page.url):
        print("❌ Not on dashboard page")
        return False

    # Check page title contains PRAHO or reasonable alternatives
    title = page.title()
    title_acceptable = any(word in title.upper() for word in ["PRAHO", "DASHBOARD", "HOST", "ADMIN"])
    if not title_acceptable:
        print(f"⚠️ Dashboard title may be unexpected: {title}")
        # Don't fail on title alone - continue checking

    # Look for dashboard content with broader selectors
    content_selectors = [
        '.card', '.widget', '.dashboard-item', '[data-widget]',
        'main', '.content', '.dashboard', '#dashboard',
        'h1', 'h2', 'h3',  # Any headers indicating content
        'nav', '.navbar', '.navigation',  # Navigation elements
        'table', '.table',  # Data tables
        'form', '.form',   # Forms
        'a[href]',         # Any links
        'button',          # Any buttons
    ]

    total_content = 0
    for selector in content_selectors:
        count = count_elements(page, selector)
        total_content += count
        if count > 0:
            print(f"📊 Found {count} {selector}")

    if total_content == 0:
        print("❌ No dashboard content found at all - major issue")
        return False

    print(f"📊 Total dashboard content elements: {total_content}")

    # Verify role-based content
    role_content_valid = verify_role_based_content(page, user_type)
    if not role_content_valid:
        print("❌ Role-based content validation failed")
        return False

    print(f"✅ Dashboard functionality verified for {user_type} (basic content present)")
    return True
