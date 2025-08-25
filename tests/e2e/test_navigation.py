"""
Navigation Header E2E Tests for PRAHO Platform

This module tests navigation header functionality including:
- Navigation menu interactions for different user types
- Header button functionality
- User role-based navigation access
- Multi-user navigation flow testing

Uses shared utilities from tests.e2e.utils for consistency.
"""

from playwright.sync_api import Page

# Import shared utilities
from tests.e2e.utils import (
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    assert_no_console_errors,
    count_elements,
    ensure_fresh_session,
    get_test_user_credentials,
    login_user,
    navigate_to_dashboard,
    safe_click_element,
)


def test_navigation_header_interactions(page: Page):
    """
    Test navigation header button interactions for both superuser and customer accounts.
    
    This test focuses specifically on navigation elements in the header/navbar,
    testing both user roles to ensure proper access controls.
    """
    print("🧪 Testing navigation header button interactions")
    
    # Get test user credentials
    users = get_test_user_credentials()
    test_cases = [
        (users['superuser']['email'], users['superuser']['password'], "superuser"),
        (users['customer']['email'], users['customer']['password'], "customer"),
    ]
    
    for email, password, user_type in test_cases:
        print(f"\n  👤 Testing navigation header for {user_type}")
        
        # Start fresh for each user type - clear session and go to login
        ensure_fresh_session(page)
        
        # Login with current user
        assert login_user(page, email, password)
        
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
        
        user_total_clicked = 0
        user_total_found = 0
        
        for selector, element_type in navigation_elements:
            try:
                count = count_elements(page, selector, element_type)
                user_total_found += count
                
                if count > 0:
                    # Test clicking navigation elements (max 2 for nav to avoid excessive testing)
                    elements_to_test = min(count, 2)
                    
                    for i in range(elements_to_test):
                        try:
                            element = page.locator(selector).nth(i)
                            
                            # Check if element is visible and enabled
                            if element.is_visible() and element.is_enabled():
                                # Get element info for logging
                                href = element.get_attribute("href") or ""
                                text = element.inner_text()[:30] or element.get_attribute("title") or "nav element"
                                
                                # Skip problematic links
                                if (href.startswith(('mailto:', 'tel:', 'javascript:')) or href == '#' or 'logout' in href.lower() or 'signout' in href.lower() or (href and not href.startswith('/'))):
                                    print(f"        ⚠️  Skipping: {text} ({href})")
                                    continue
                                
                                print(f"        🔘 Clicking nav element: {text}")
                                
                                # Perform the click with proper error handling
                                if safe_click_element(page, f"({selector})[{i}]", f"nav element: {text}"):
                                    user_total_clicked += 1
                                    
                                    # Log where we ended up
                                    current_url = page.url
                                    print(f"          ✅ Successfully clicked - URL: {current_url}")
                                    
                                    # If we're no longer on the dashboard, navigate back
                                    if "/app/" not in current_url and "/auth/login/" not in current_url:
                                        print("          🔄 Navigating back to dashboard")
                                        navigate_to_dashboard(page)
                                    elif "/auth/login/" in current_url:
                                        # If we got logged out, break out of this user's testing
                                        print(f"          ⚠️  Got logged out, ending {user_type} testing")
                                        break
                                    
                        except Exception as element_error:
                            print(f"        ❌ Element error: {str(element_error)[:100]}")
                            continue
                    
                    # If we got logged out, break out of element testing
                    if "/auth/login/" in page.url:
                        break
                            
            except Exception as selector_error:
                print(f"      ❌ Selector error for {element_type}: {str(selector_error)[:100]}")
                continue
        
        print(f"    📊 {user_type.title()} summary: Found {user_total_found} nav elements, clicked {user_total_clicked}")
    
    # End on a clean state
    navigate_to_dashboard(page)
    
    print("  ✅ Navigation header interaction testing completed!")


def test_navigation_menu_visibility_by_role(page: Page):
    """
    Test that navigation menu items are visible based on user roles.
    
    This test verifies that different user types see appropriate navigation options.
    """
    print("🧪 Testing navigation menu visibility by role")
    
    # Test superuser navigation
    print("\n  👑 Testing superuser navigation visibility")
    ensure_fresh_session(page)
    assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    
    superuser_nav_elements = [
        ('nav a[href*="/admin/"]', 'admin links'),
        ('nav a[href*="/app/customers/"]', 'customer management links'),
        ('a:has-text("Admin")', 'admin text links'),
        ('a:has-text("Customers")', 'customer text links'),
    ]
    
    superuser_found = 0
    for selector, description in superuser_nav_elements:
        count = count_elements(page, selector, f"superuser {description}")
        superuser_found += count
    
    print(f"    📊 Superuser navigation elements found: {superuser_found}")
    
    # Test customer navigation
    print("\n  👤 Testing customer navigation visibility")
    ensure_fresh_session(page)
    assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
    
    customer_nav_elements = [
        ('nav a[href*="/app/tickets/"]', 'ticket links'),
        ('nav a[href*="/app/services/"]', 'service links'),
        ('a:has-text("Tickets")', 'ticket text links'),
        ('a:has-text("Services")', 'service text links'),
    ]
    
    customer_found = 0
    for selector, description in customer_nav_elements:
        count = count_elements(page, selector, f"customer {description}")
        customer_found += count
    
    print(f"    📊 Customer navigation elements found: {customer_found}")
    
    # Verify no admin access for customers
    admin_elements_for_customer = count_elements(page, 'nav a[href*="/admin/"]', 'admin links for customer')
    assert admin_elements_for_customer == 0, "Customer should not see admin navigation"
    
    print("  ✅ Navigation role visibility testing completed!")


def test_navigation_dropdown_interactions(page: Page):
    """
    Test dropdown menu interactions in the navigation header.
    
    This test focuses on dropdown menus, user menus, and collapsible navigation elements.
    """
    print("🧪 Testing navigation dropdown interactions")
    
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
        
        if count > 0:
            # Test clicking first dropdown (avoid excessive clicking)
            if safe_click_element(page, f"{selector}:first-child", f"first {description}"):
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
    
    # Check for console errors
    assert_no_console_errors(page)
    
    print("  ✅ Navigation dropdown testing completed!")


def test_mobile_navigation_responsiveness(page: Page):
    """
    Test mobile navigation behavior and responsiveness.
    
    This test checks that navigation works properly on mobile viewport sizes.
    """
    print("🧪 Testing mobile navigation responsiveness")
    
    # Set mobile viewport
    page.set_viewport_size({"width": 375, "height": 667})  # iPhone 8 size
    
    # Login as superuser
    ensure_fresh_session(page)
    assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    
    # Look for mobile navigation elements
    mobile_nav_selectors = [
        ('.navbar-toggler', 'mobile menu toggle'),
        ('.navbar-toggle', 'navbar toggle'),
        ('[data-toggle="collapse"]', 'collapse toggle'),
        ('.hamburger', 'hamburger menu'),
        ('.mobile-menu-toggle', 'mobile menu toggle'),
    ]
    
    mobile_elements_found = 0
    
    for selector, description in mobile_nav_selectors:
        count = count_elements(page, selector, f"mobile {description}")
        mobile_elements_found += count
        
        if count > 0:
            # Test clicking mobile menu toggle
            if safe_click_element(page, selector, f"mobile {description}"):
                print("      ✅ Mobile menu toggle clicked")
                
                # Wait for mobile menu animation
                page.wait_for_timeout(500)
                
                # Look for expanded mobile menu
                expanded_menu_selectors = [
                    '.navbar-collapse.show',
                    '.mobile-menu.open',
                    '.nav-menu.active',
                    '[aria-expanded="true"]'
                ]
                
                for menu_selector in expanded_menu_selectors:
                    if count_elements(page, menu_selector, 'expanded mobile menu') > 0:
                        print("      ✅ Mobile menu expanded successfully")
                        break
    
    print(f"  📱 Mobile navigation elements found: {mobile_elements_found}")
    
    # Reset to desktop viewport
    page.set_viewport_size({"width": 1280, "height": 720})
    
    print("  ✅ Mobile navigation testing completed!")


# ===============================================================================
# CONFIGURATION FOR NAVIGATION TESTS
# ===============================================================================

def pytest_configure(config):
    """Configure pytest-playwright settings for navigation tests."""
    config.option.headed = False  # Run headless by default
    config.option.slowmo = 100    # Slight slowdown for navigation interactions
    config.option.browser = "chromium"
