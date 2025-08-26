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
    AuthenticationError,
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    ComprehensivePageMonitor,
    count_elements,
    ensure_fresh_session,
    get_test_user_credentials,
    login_user,
    navigate_to_dashboard,
    require_authentication,
    safe_click_element,
    verify_admin_access,
    verify_navigation_completeness,
)


def test_navigation_cross_page_flow(page: Page):
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
                                 check_performance=False):   # Keep fast for navigation flow
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
        assert "/app/" in page.url, "Should be able to return to dashboard"
        
    except AuthenticationError:
        pytest.fail("Lost authentication during navigation flow test")


def test_navigation_header_interactions(page: Page):
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
                                 check_performance=False):   # Keep fast for multi-user test
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
                                 check_performance=False):   # Keep fast for role-based test
        
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
            print(f"    ✅ Customer properly restricted from staff navigation")
            
            # Verify customer sees their own navigation (My Tickets, My Invoices, etc.)
            customer_links = page.locator('a:has-text("My Tickets"), a:has-text("My Invoices"), a:has-text("My Services")')
            customer_count = customer_links.count()
            print(f"    ✅ Found {customer_count} customer navigation items")
            
        except AuthenticationError:
            pytest.fail("Lost authentication during customer navigation test")
        
        print("  ✅ Navigation role-based access control verified!")


def test_navigation_dropdown_interactions(page: Page):
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
                                 check_performance=False):   # Keep fast for dropdown test
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
        
        print("  ✅ Navigation dropdown testing completed!")


def test_mobile_navigation_responsiveness(page: Page):
    """
    Test mobile navigation behavior and responsiveness.
    
    This test checks that navigation works properly on mobile viewport sizes.
    """
    print("🧪 Testing mobile navigation responsiveness with comprehensive monitoring")
    
    with ComprehensivePageMonitor(page, "mobile navigation responsiveness test",
                                 check_console=True,
                                 check_network=True,
                                 check_html=True,
                                 check_css=True,
                                 check_accessibility=False,  # Keep fast for mobile test
                                 check_performance=False):   # Keep fast for mobile test
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


# Remove old configuration - will be centralized in conftest.py
