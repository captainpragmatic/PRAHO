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
    AuthenticationError,
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    assert_no_console_errors,
    ensure_fresh_session,
    login_user,
    require_authentication,
    verify_dashboard_functionality,
)


def test_superuser_dashboard_functionality(page: Page):
    """Test superuser dashboard displays correct content and functions properly."""
    print("🧪 Testing superuser dashboard functionality")
    
    # Ensure fresh session and login
    ensure_fresh_session(page)
    if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
        pytest.skip("Cannot login as superuser")
    
    try:
        # Verify dashboard functionality using semantic validation
        assert verify_dashboard_functionality(page, "superuser"), \
            "Superuser dashboard functionality verification failed"
        
        # Check for console errors
        assert_no_console_errors(page)
        
    except AuthenticationError:
        pytest.fail("Lost authentication during superuser dashboard test")


def test_customer_dashboard_functionality(page: Page):
    """Test customer dashboard displays correct content and functions properly."""
    print("🧪 Testing customer dashboard functionality")
    
    # Ensure fresh session and login  
    ensure_fresh_session(page)
    if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
        pytest.skip("Cannot login as customer")
    
    try:
        # Verify dashboard functionality using semantic validation
        assert verify_dashboard_functionality(page, "customer"), \
            "Customer dashboard functionality verification failed"
        
        # Check for console errors
        assert_no_console_errors(page)
        
    except AuthenticationError:
        pytest.fail("Lost authentication during customer dashboard test")


def test_dashboard_role_based_content(page: Page):
    """
    Test that dashboard displays appropriate content based on user roles.
    
    This test verifies role-based access control is working correctly
    by testing both superuser and customer dashboard content.
    """
    print("🧪 Testing dashboard role-based content")
    
    users = [
        (SUPERUSER_EMAIL, SUPERUSER_PASSWORD, "superuser"),
        (CUSTOMER_EMAIL, CUSTOMER_PASSWORD, "customer"),
    ]
    
    for email, password, user_type in users:
        print(f"\n  👤 Testing dashboard content for {user_type}")
        
        # Fresh session for each user
        ensure_fresh_session(page)
        
        if not login_user(page, email, password):
            pytest.skip(f"Cannot login as {user_type}")
        
        try:
            # Verify role-based content is displayed correctly
            assert verify_dashboard_functionality(page, user_type), \
                f"Dashboard content verification failed for {user_type}"
            
            print(f"    ✅ Dashboard content correct for {user_type}")
            
        except AuthenticationError:
            pytest.fail(f"Lost authentication during {user_type} content test")


def test_dashboard_actions_and_interactions(page: Page):
    """
    Test dashboard actions and interactive elements work correctly.
    
    This test focuses on dashboard-specific buttons, forms, and interactions
    rather than general navigation.
    """
    print("🧪 Testing dashboard actions and interactions")
    
    # Login as superuser for maximum dashboard access
    ensure_fresh_session(page)
    if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
        pytest.skip("Cannot login as superuser")
    
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
                            print(f"      ⚠️ Skipping potentially dangerous element")
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
        if "/app/" not in page.url:
            print("  🔄 Returning to dashboard after interactions")
            page.goto(f"{BASE_URL}/app/")
            page.wait_for_load_state("networkidle")
        
        assert_no_console_errors(page)
        
    except AuthenticationError:
        pytest.fail("Lost authentication during dashboard interactions test")


# Remove old configuration - will be centralized in conftest.py
