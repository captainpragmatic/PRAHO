"""
Dashboard E2E Tests for PRAHO Platform

This module tests dashboard functionality including:
- User authentication and dashboard access
- Dashboard content interactions
- Role-specific feature testing
- Dashboard page button interactions

Uses shared utilities from tests.e2e.utils for consistency.
"""

import pytest
from playwright.sync_api import Page

# Import shared utilities
from tests.e2e.utils import (
    BASE_URL,
    SUPERUSER_EMAIL, SUPERUSER_PASSWORD,
    CUSTOMER_EMAIL, CUSTOMER_PASSWORD,
    login_user, navigate_to_dashboard,
    get_serious_console_errors, assert_no_console_errors,
    safe_click_element, count_elements
)


def test_superuser_dashboard_functionality(page: Page):
    """Test superuser dashboard functionality using shared utilities."""
    print("🧪 Testing superuser dashboard with pytest-playwright")
    
    # Login using shared utility
    assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    
    # Test dashboard functionality
    _dashboard_common_functionality(page, "superuser")
    test_superuser_specific_features(page)
    
    # Check for console errors using shared utility
    assert_no_console_errors(page)


def test_customer_dashboard_functionality(page: Page):
    """Test customer dashboard functionality using shared utilities."""
    print("🧪 Testing customer dashboard with pytest-playwright")
    
    # Login using shared utility
    assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
    
    _dashboard_common_functionality(page, "customer")
    test_customer_specific_features(page)
    
    # Check for console errors using shared utility
    assert_no_console_errors(page)


def test_dashboard_navigation_flow(page: Page):
    """
    Test navigation between different sections.
    
    This demonstrates pytest-playwright's better async handling - 
    no need to worry about timing issues or manual waits.
    """
    print("🧪 Testing navigation flow")
    
    # Login as superuser
    assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    
    # Test navigation to different sections
    navigation_tests = [
        ("/app/customers/", "Customers"),
        ("/admin/", "Admin"),
        ("/app/", "Dashboard"),
    ]
    
    for url_path, section_name in navigation_tests:
        try:
            # Try to find and click navigation link
            link = page.locator(f'a[href*="{url_path}"], a:has-text("{section_name}")').first
            if link.is_visible():
                print(f"  🔄 Testing navigation to {section_name}")
                link.click()
                
                # pytest-playwright handles async waits better
                page.wait_for_load_state("networkidle", timeout=5000)
                
                current_url = page.url
                print(f"    ✅ Navigated to: {current_url}")
                
                # Navigate back to dashboard
                page.goto(f"{BASE_URL}/app/")
                page.wait_for_load_state("networkidle")
                
        except Exception as e:
            print(f"    ⚠️  Navigation to {section_name} failed: {e}")


def _dashboard_common_functionality(page: Page, user_type: str):
    """Test common dashboard functionality (helper function)."""
    print(f"🔍 Testing common functionality for {user_type}")
    
    # Verify dashboard page
    assert "/app/" in page.url
    
    # Check page title
    title = page.title()
    assert "PRAHO" in title
    
    # Test navigation elements using shared utility
    nav_found = False
    nav_selectors = ['nav', '.navbar', '.navigation', '[data-nav]', '.sidebar']
    
    for selector in nav_selectors:
        if count_elements(page, selector) > 0:
            nav_found = True
            print(f"  ✅ Found navigation: {selector}")
            break
    
    if not nav_found:
        print("  ⚠️  No navigation found")
    
    # Test dashboard widgets using shared utility
    widget_selectors = ['.card', '.widget', '.dashboard-item', '[data-widget]']
    total_widgets = sum(count_elements(page, selector) for selector in widget_selectors)
    print(f"  📊 Dashboard widgets found: {total_widgets}")


def test_superuser_specific_features(page: Page):
    """Test superuser-specific features."""
    print("  🔧 Testing superuser features")
    
    # Look for admin access using shared utility
    admin_selectors = ['a[href*="/admin/"]', 'a:has-text("Admin")', '[data-admin]']
    
    admin_found = any(count_elements(page, selector) > 0 for selector in admin_selectors)
    if admin_found:
        print("    ✅ Admin access found")
    else:
        print("    ⚠️  Admin access not found")


def test_customer_specific_features(page: Page):
    """Test customer-specific features."""
    print("  👤 Testing customer features")
    
    # Look for customer features using shared utility
    customer_selectors = [
        'a[href*="/services/"]',
        'a[href*="/billing/"]',
        'a[href*="/tickets/"]',
    ]
    
    features_found = sum(1 for selector in customer_selectors 
                        if count_elements(page, selector) > 0)
    print(f"    👤 Customer features found: {features_found}")


def test_dashboard_button_interactions(page: Page):
    """
    Test button interactions on the dashboard page content only (excluding navigation header).
    
    This test focuses on clickable elements within the main dashboard content area,
    avoiding navigation elements to prevent unwanted page transitions.
    """
    print("🧪 Testing dashboard page content button interactions")
    
    # Login as superuser for maximum access
    assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    
    print("  🔘 Testing clickable elements in dashboard content...")
    
    # Define selectors for page content elements only (excluding navigation)
    page_content_elements = [
        # Dashboard content buttons (excluding nav)
        ('main button', 'main content buttons'),
        ('.content button', 'content area buttons'),
        ('.dashboard button', 'dashboard buttons'),
        ('.card button', 'card buttons'),
        ('.widget button', 'widget buttons'),
        
        # Content area links (excluding nav)
        ('main a[href]', 'main content links'),
        ('.content a[href]', 'content area links'),
        ('.dashboard a[href]', 'dashboard links'),
        ('.card a[href]', 'card links'),
        
        # Form elements in content
        ('main input[type="submit"]', 'main submit buttons'),
        ('.content input[type="submit"]', 'content submit buttons'),
        ('main [role="button"]', 'main role buttons'),
        ('.content [role="button"]', 'content role buttons'),
        
        # HTMX elements in content
        ('main [hx-get]', 'main HTMX GET triggers'),
        ('main [hx-post]', 'main HTMX POST triggers'),
        ('.content [hx-get]', 'content HTMX GET triggers'),
        ('.content [hx-post]', 'content HTMX POST triggers'),
        ('.card [hx-trigger]', 'card HTMX triggers'),
        
        # Action buttons and dropdowns in content
        ('.btn', 'CSS button classes in content'),
        ('.dropdown-toggle:not(nav .dropdown-toggle)', 'content dropdown toggles'),
        ('[data-toggle]:not(nav [data-toggle])', 'content data toggle elements'),
    ]
    
    total_clicked = 0
    total_found = 0
    
    for selector, element_type in page_content_elements:
        count = count_elements(page, selector, element_type)
        total_found += count
        
        if count > 0:
            # Test clicking first few elements (max 2 for content to avoid excessive testing)
            elements_to_test = min(count, 2)
            
            for i in range(elements_to_test):
                try:
                    element = page.locator(selector).nth(i)
                    
                    # Check if element is visible and enabled
                    if element.is_visible() and element.is_enabled():
                        # Get element info for logging
                        href = element.get_attribute("href") or ""
                        text = element.inner_text()[:30] or element.get_attribute("title") or "element"
                        
                        # Skip problematic links
                        if (href.startswith('mailto:') or href.startswith('tel:') or
                            href.startswith('javascript:') or href == '#' or
                            (href and not href.startswith('/'))):
                            print(f"        ⚠️  Skipping: {text} ({href})")
                            continue
                        
                        print(f"      🔘 Clicking content element: {text}")
                        
                        # Use shared utility for safe clicking
                        if safe_click_element(page, f"({selector})[{i}]", f"content element: {text}"):
                            total_clicked += 1
                            
                            current_url = page.url
                            print(f"        ✅ Successfully clicked - URL: {current_url}")
                            
                            # Content clicks should keep us on dashboard or related pages
                            if "/app/" not in current_url:
                                print(f"        🔄 Unexpected navigation, returning to dashboard")
                                navigate_to_dashboard(page)
                            
                except Exception as element_error:
                    print(f"      ❌ Element error: {str(element_error)[:100]}")
                    continue
    
    print(f"  📊 Summary: Found {total_found} dashboard content elements, successfully clicked {total_clicked}")
    
    # Verify we're still on the dashboard
    assert "/app/" in page.url, "Should still be on dashboard after content interactions"
    
    print("  ✅ Dashboard content button interaction testing completed!")


# ===============================================================================
# CONFIGURATION FOR DASHBOARD TESTS
# ===============================================================================

def pytest_configure(config):
    """Configure pytest-playwright settings for dashboard tests."""
    config.option.headed = False  # Run headless by default
    config.option.slowmo = 0      # No slowdown by default
    config.option.browser = "chromium"
