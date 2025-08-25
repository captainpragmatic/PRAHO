"""
E2E Testing Utilities for PRAHO Platform

This module contains shared utilities, fixtures, and helper functions
for end-to-end testing with pytest-playwright.

Centralizes common functionality like:
- User authentication (login/logout)
- Page navigation helpers
- Console error monitoring
- Common test configurations
"""

import pytest
from playwright.sync_api import Page, expect
from typing import Optional, List, Dict, Any


# ===============================================================================
# TEST CONFIGURATION
# ===============================================================================

# Base URL for the application
BASE_URL = "http://localhost:8001"

# Test user credentials
SUPERUSER_EMAIL = "admin@pragmatichost.com"
SUPERUSER_PASSWORD = "admin123"
CUSTOMER_EMAIL = "customer@pragmatichost.com"
CUSTOMER_PASSWORD = "admin123"


# ===============================================================================
# SHARED FIXTURES
# ===============================================================================

@pytest.fixture(autouse=True)
def setup_console_monitoring(page: Page):
    """
    Automatically monitor console errors for all E2E tests.
    
    This fixture runs automatically for every test and tracks
    JavaScript console errors, making them available via page.console_errors.
    """
    console_errors = []
    
    def handle_console(msg):
        if msg.type == "error":
            console_errors.append(msg.text)
            print(f"🚨 Console Error: {msg.text}")
    
    page.on("console", handle_console)
    
    # Make console_errors available to tests (dynamic attribute)
    setattr(page, 'console_errors', console_errors)
    yield page


# ===============================================================================
# AUTHENTICATION UTILITIES
# ===============================================================================

def login_user(page: Page, email: str, password: str) -> bool:
    """
    Helper to login user.
    
    Args:
        page: Playwright page object
        email: User email
        password: User password
        
    Returns:
        bool: True if login successful, False otherwise
        
    Example:
        assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    """
    print(f"🔐 Logging in {email}")
    
    # Navigate to login page
    page.goto(f"{BASE_URL}/auth/login/")
    page.wait_for_load_state("networkidle")
    
    # Fill login form
    page.fill('input[name="email"]', email)
    page.fill('input[name="password"]', password)
    page.click('button[type="submit"]')
    
    # Wait for redirect after login - use timeout and better waiting strategy
    try:
        page.wait_for_url(f"{BASE_URL}/app/", timeout=10000)
        print(f"✅ Successfully logged in as {email}")
        return True
    except Exception as e:
        print(f"❌ Login failed for {email}: {e}")
        current_url = page.url
        print(f"    Current URL: {current_url}")
        
        # Check if there's an error message on the page
        error_elements = page.locator('.alert-danger, .error, .invalid-feedback').all()
        if error_elements:
            for error in error_elements:
                if error.is_visible():
                    error_text = error.inner_text()
                    print(f"    Error message: {error_text}")
        
        return False


def logout_user(page: Page) -> bool:
    """
    Helper to logout current user.
    
    Args:
        page: Playwright page object
        
    Returns:
        bool: True if logout successful, False otherwise
        
    Example:
        assert logout_user(page)
    """
    print("🚪 Logging out current user")
    
    try:
        # Navigate to logout endpoint
        page.goto(f"{BASE_URL}/auth/logout/")
        page.wait_for_load_state("networkidle", timeout=3000)
        
        # Check if we're back on login page
        if "/auth/login/" in page.url:
            print("✅ Successfully logged out")
            return True
        else:
            print(f"⚠️  Logout may have failed, current URL: {page.url}")
            return False
            
    except Exception as e:
        print(f"❌ Logout error: {str(e)[:100]}")
        return False


def ensure_fresh_session(page: Page) -> None:
    """
    Ensure a fresh session by logging out and clearing any existing state.
    
    Args:
        page: Playwright page object
        
    Example:
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
    """
    print("🔄 Ensuring fresh session")
    
    # Try to logout first
    logout_user(page)
    
    # Navigate to login page to ensure clean state
    page.goto(f"{BASE_URL}/auth/login/")
    page.wait_for_load_state("networkidle")


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
        page.goto(f"{BASE_URL}/app/")
        page.wait_for_load_state("networkidle")
        
        if "/app/" in page.url:
            print("✅ Successfully navigated to dashboard")
            return True
        else:
            print(f"❌ Dashboard navigation failed, current URL: {page.url}")
            return False
            
    except Exception as e:
        print(f"❌ Dashboard navigation error: {str(e)[:100]}")
        return False


def navigate_to_page(page: Page, path: str, expected_url_fragment: Optional[str] = None) -> bool:
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
# CONSOLE ERROR UTILITIES
# ===============================================================================

def get_serious_console_errors(page: Page) -> list:
    """
    Get console errors excluding benign warnings.
    
    Args:
        page: Playwright page object
        
    Returns:
        list: List of serious console errors (excludes X-Frame-Options warnings)
        
    Example:
        serious_errors = get_serious_console_errors(page)
        assert len(serious_errors) == 0, f"Console errors: {serious_errors}"
    """
    console_errors = getattr(page, 'console_errors', [])
    serious_errors = [
        error for error in console_errors 
        if not error.startswith("X-Frame-Options may only be set via an HTTP header")
    ]
    return serious_errors


def assert_no_console_errors(page: Page) -> None:
    """
    Assert that there are no serious console errors.
    
    Args:
        page: Playwright page object
        
    Raises:
        AssertionError: If serious console errors are found
        
    Example:
        assert_no_console_errors(page)
    """
    serious_errors = get_serious_console_errors(page)
    assert len(serious_errors) == 0, f"Serious console errors found: {serious_errors}"


# ===============================================================================
# ELEMENT INTERACTION UTILITIES
# ===============================================================================

def safe_click_element(page: Page, selector: str, description: Optional[str] = None) -> bool:
    """
    Safely click an element with proper error handling.
    
    Args:
        page: Playwright page object
        selector: CSS selector for the element
        description: Optional description for logging
        
    Returns:
        bool: True if click successful, False otherwise
        
    Example:
        success = safe_click_element(page, 'button[type="submit"]', 'submit button')
    """
    desc = description or selector
    print(f"🔘 Attempting to click: {desc}")
    
    try:
        element = page.locator(selector)
        
        if element.count() == 0:
            print(f"⚠️  Element not found: {desc}")
            return False
            
        if not element.first.is_visible():
            print(f"⚠️  Element not visible: {desc}")
            return False
            
        if not element.first.is_enabled():
            print(f"⚠️  Element not enabled: {desc}")
            return False
            
        # Perform the click
        element.first.click(timeout=2000)
        page.wait_for_load_state("networkidle", timeout=3000)
        
        print(f"✅ Successfully clicked: {desc}")
        return True
        
    except Exception as e:
        print(f"❌ Click failed for {desc}: {str(e)[:100]}")
        return False


def count_elements(page: Page, selector: str, description: Optional[str] = None) -> int:
    """
    Count elements matching a selector with logging.
    
    Args:
        page: Playwright page object
        selector: CSS selector for the elements
        description: Optional description for logging
        
    Returns:
        int: Number of elements found
        
    Example:
        button_count = count_elements(page, 'button', 'buttons')
    """
    desc = description or selector
    
    try:
        count = page.locator(selector).count()
        print(f"📊 Found {count} {desc}")
        return count
        
    except Exception as e:
        print(f"❌ Error counting {desc}: {str(e)[:100]}")
        return 0


# ===============================================================================
# PYTEST CONFIGURATION
# ===============================================================================

def pytest_configure(config):
    """Configure pytest-playwright settings for all E2E tests."""
    # These settings apply to all E2E tests
    config.option.headed = False  # Run headless by default (set to True for debugging)
    config.option.slowmo = 0      # No slowdown by default (increase for debugging)
    config.option.browser = "chromium"  # Default browser


# ===============================================================================
# TEST DATA UTILITIES
# ===============================================================================

def get_test_user_credentials():
    """
    Get test user credentials for different user types.
    
    Returns:
        dict: Dictionary of user types and their credentials
        
    Example:
        users = get_test_user_credentials()
        superuser = users['superuser']
        customer = users['customer']
    """
    return {
        'superuser': {
            'email': SUPERUSER_EMAIL,
            'password': SUPERUSER_PASSWORD,
            'type': 'superuser'
        },
        'customer': {
            'email': CUSTOMER_EMAIL,
            'password': CUSTOMER_PASSWORD,
            'type': 'customer'
        }
    }
