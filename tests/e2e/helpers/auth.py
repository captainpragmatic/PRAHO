"""
E2E Authentication Utilities — login, logout, session management.

Platform (:8700) and Portal (:8701) authentication helpers.
"""

import json
import time
from collections.abc import Generator
from urllib.parse import quote

import pytest
from playwright.sync_api import Page

from tests.e2e.helpers.constants import (
    BASE_URL,
    LOGIN_URL,
    LOGOUT_URL,
    PLATFORM_BASE_URL,
    PLATFORM_LOGIN_URL,
    PLATFORM_LOGOUT_URL,
    STAFF_EMAIL,
    STAFF_PASSWORD,
    is_logged_in_url,
    is_login_url,
)

# ===============================================================================
# COOKIE CONSENT
# ===============================================================================

def _dismiss_cookie_consent(page: Page, base_url: str) -> None:
    """Set cookie_consent cookie to prevent the GDPR banner from blocking interactions."""
    cookie_value = quote('{"essential":true,"functional":true,"analytics":true,"marketing":true}')
    page.context.add_cookies([{
        "name": "cookie_consent",
        "value": cookie_value,
        "url": base_url,
    }])


def dismiss_cookie_consent(page: Page) -> None:
    """
    Dismiss the cookie consent banner by clicking "Accept All".

    Use in Portal E2E tests that need to bypass the banner to interact
    with page content underneath. Sets the cookie_consent client cookie
    """
    try:
        banner = page.locator('#cookie-consent-banner, .cookie-consent, [data-cookie-consent]')
        if banner.is_visible(timeout=2000):
            accept_btn = banner.locator('button', has_text='Accept All')
            accept_btn.click()
            banner.wait_for(state='hidden', timeout=3000)
            print("✅ Cookie consent banner dismissed")
    except Exception:  # noqa: S110
        # Banner not present or already dismissed — that's fine
        pass


# ===============================================================================
# PLATFORM AUTHENTICATION
# ===============================================================================

def login_platform_user(page: Page, email: str | None = None, password: str | None = None) -> bool:
    """
    Login to the platform (staff backend) at :8700.

    Args:
        page: Playwright page object
        email: Staff email (defaults to STAFF_EMAIL)
        password: Staff password (defaults to STAFF_PASSWORD)

    Returns:
        bool: True if login successful, False otherwise
    """
    email = email or STAFF_EMAIL
    password = password or STAFF_PASSWORD
    print(f"🔐 Logging in to platform as {email}")

    # Dismiss cookie consent banner to prevent it from covering the form
    _dismiss_cookie_consent(page, PLATFORM_BASE_URL)

    for attempt in range(3):  # Increased from 2 to 3 attempts
        if attempt > 0:
            print(f"🔄 Platform login retry (attempt {attempt + 1})")
            # Clear cookies and navigate explicitly to ensure fresh state
            page.context.clear_cookies()
            _dismiss_cookie_consent(page, PLATFORM_BASE_URL)

            # Delay between attempts to avoid rate limiting from rapid test execution
            page.wait_for_timeout(1000)

        try:
            page.goto(f"{PLATFORM_BASE_URL}{PLATFORM_LOGIN_URL}", timeout=10000)
            page.wait_for_load_state("networkidle", timeout=8000)
        except Exception as e:
            print(f"❌ Cannot navigate to platform login: {str(e)[:50]}")
            if attempt < 2:
                continue
            return False

        # Already authenticated (redirected away from login page)
        if PLATFORM_LOGIN_URL not in page.url:
            print(f"✅ Already logged in to platform as {email}")
            return True

        try:
            # Wait for email input to be visible before interacting
            email_input = page.locator('input[name="email"], input[name="username"], input[type="email"]').first
            email_input.wait_for(state="visible", timeout=5000)
            print("  ✅ Login form visible")

            # Fill form fields using the detected input element
            email_input.fill(email)
            page.wait_for_timeout(200)  # Give browser time to register input
            page.fill('input[name="password"]', password)
            page.wait_for_timeout(200)  # Give browser time to register input

            # Click submit and wait for navigation with longer timeout
            page.click('button[type="submit"]')
            try:
                page.wait_for_url(lambda url: PLATFORM_LOGIN_URL not in url, timeout=15000)
            except Exception:
                # Fallback: wait for networkidle and check manually
                page.wait_for_load_state("networkidle", timeout=8000)

        except Exception as e:
            print(f"❌ Cannot fill platform login form: {str(e)[:50]}")
            if attempt < 2:
                continue
            return False

        # Check we left the login page
        if PLATFORM_LOGIN_URL not in page.url:
            # Verify we're actually on a dashboard/authenticated page
            page.wait_for_load_state("networkidle", timeout=5000)
            print(f"✅ Successfully logged in to platform as {email}")
            return True

        if attempt < 2:
            print(f"⚠️ Platform login attempt {attempt + 1} failed, retrying...")

    print(f"❌ Platform login failed for {email}, still on {page.url}")
    return False


def logout_platform_user(page: Page) -> bool:
    """Logout from the platform (staff backend)."""
    print("🚪 Logging out from platform")
    try:
        page.goto(f"{PLATFORM_BASE_URL}{PLATFORM_LOGOUT_URL}")
        page.wait_for_load_state("networkidle", timeout=3000)
        if PLATFORM_LOGIN_URL in page.url or "/auth/login/" in page.url:
            print("✅ Successfully logged out from platform")
            return True
        return False
    except Exception as e:
        print(f"❌ Platform logout error: {str(e)[:100]}")
        return False


def ensure_fresh_platform_session(page: Page) -> None:
    """Ensure a fresh session on the platform service."""
    print("🔄 Ensuring fresh platform session")
    # Navigate away first to stop any background JS (HTMX polling, fetch)
    # that would fire 401s after cookies are cleared.
    page.goto("about:blank")
    page.context.clear_cookies()
    _dismiss_cookie_consent(page, PLATFORM_BASE_URL)
    # Small delay to let cookie consent dismissal take effect
    page.wait_for_timeout(300)
    page.goto(f"{PLATFORM_BASE_URL}{PLATFORM_LOGIN_URL}", timeout=10000)
    page.wait_for_load_state("networkidle", timeout=5000)
    print("  ✅ Navigated to platform login page")


def navigate_to_platform_page(page: Page, path: str, expected_url_fragment: str | None = None) -> bool:
    """
    Navigate to a page on the platform service.

    Args:
        page: Playwright page object
        path: URL path relative to PLATFORM_BASE_URL
        expected_url_fragment: Optional fragment to verify navigation

    Returns:
        bool: True if navigation successful
    """
    full_url = f"{PLATFORM_BASE_URL}{path}"
    print(f"🔗 Navigating to platform {full_url}")
    try:
        page.goto(full_url)
        page.wait_for_load_state("networkidle")
        expected_fragment = expected_url_fragment or path
        if expected_fragment in page.url:
            print(f"✅ Successfully navigated to platform {path}")
            return True
        print(f"❌ Platform navigation failed, expected {expected_fragment}, got {page.url}")
        return False
    except Exception as e:
        print(f"❌ Platform navigation error: {str(e)[:100]}")
        return False


# ===============================================================================
# SHARED FIXTURES
# ===============================================================================

@pytest.fixture(autouse=True)
def setup_console_monitoring(page: Page) -> Generator[Page, None, None]:
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
    page.console_errors = console_errors
    yield page


# ===============================================================================
# PORTAL AUTHENTICATION
# ===============================================================================

def login_user_with_retry(page: Page, email: str, password: str, max_attempts: int = 3) -> bool:  # noqa: C901, PLR0911, PLR0912, PLR0915
    """
    Enhanced login function with retry logic and better debugging.

    Args:
        page: Playwright page object
        email: User email
        password: User password
        max_attempts: Maximum number of login attempts

    Returns:
        bool: True if login successful, False otherwise
    """
    print(f"🔐 Logging in {email} (with retry logic)")

    for attempt in range(max_attempts):
        if attempt > 0:
            print(f"🔄 Login attempt {attempt + 1}/{max_attempts}")
            # Clear cookies between attempts for fresh state
            page.context.clear_cookies()
            page.wait_for_timeout(300)

        # Dismiss cookie consent banner to prevent it from covering the form
        _dismiss_cookie_consent(page, BASE_URL)
        page.wait_for_timeout(300)

        # Navigate to login page fresh
        try:
            page.goto(f"{BASE_URL}{LOGIN_URL}", timeout=10000)
            page.wait_for_load_state("networkidle", timeout=5000)
        except Exception as e:
            print(f"❌ Cannot navigate to login page: {str(e)[:50]}")
            if attempt == max_attempts - 1:
                return False
            continue

        # Wait for email input to be visible before interacting
        try:
            email_input = page.locator('input[name="email"], input[name="username"], input[type="email"]').first
            email_input.wait_for(state="visible", timeout=8000)
            page.wait_for_selector('input[name="password"]', timeout=8000)
            page.wait_for_selector('button[type="submit"], input[type="submit"]', timeout=8000)
            print("  ✅ Login form visible")
        except Exception as e:
            print(f"❌ Login form not ready: {str(e)[:50]}")
            if attempt == max_attempts - 1:
                return False
            continue

        # Clear and fill form fields
        try:
            password_field = page.locator('input[name="password"]')

            # Clear fields first
            email_input.clear()
            password_field.clear()

            # Fill with explicit wait between actions
            email_input.fill(email)
            page.wait_for_timeout(500)  # Small delay
            password_field.fill(password)
            page.wait_for_timeout(500)  # Small delay

            print("  ✅ Form fields filled")
        except Exception as e:
            print(f"❌ Cannot fill login form: {str(e)[:50]}")
            if attempt == max_attempts - 1:
                return False
            continue

        # Submit form with enhanced waiting
        try:
            submit_button = page.locator('button[type="submit"], input[type="submit"]').first
            submit_button.click()
            print("  ✅ Form submitted")

            # Wait for response with multiple strategies and longer timeout
            page.wait_for_load_state("networkidle", timeout=12000)  # Increased from 10s to 12s

            # Check for successful redirect
            page.wait_for_timeout(2000)  # Give time for redirect
            current_url = page.url

            if is_logged_in_url(current_url):
                print(f"✅ Successfully logged in as {email}")
                return True
            elif is_login_url(current_url):
                # Still on login page - check for error messages
                error_elements = page.locator('.alert, .error, [role="alert"]')
                if error_elements.count() > 0:
                    error_text = error_elements.first.text_content() or "Unknown error"
                    print(f"  ⚠️ Login error message: {error_text[:100]}")
                else:
                    print("  ⚠️ Still on login page, no error message visible")

                if attempt == max_attempts - 1:
                    return False
                continue
            else:
                print(f"  i️  Redirected to unexpected page: {current_url}")
                if is_logged_in_url(current_url):
                    print(f"✅ Login successful (alternate redirect): {email}")
                    return True

        except Exception as e:
            print(f"❌ Form submission failed: {str(e)[:50]}")
            if attempt == max_attempts - 1:
                return False
            continue

    print(f"❌ Login failed after {max_attempts} attempts for {email}")
    return False


def login_user(page: Page, email: str, password: str) -> bool:
    """
    Helper to login user on the portal with improved error handling.

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

    # Dismiss cookie consent banner to prevent it from covering the form
    _dismiss_cookie_consent(page, BASE_URL)

    # Small delay to let cookie consent dismissal take effect
    page.wait_for_timeout(300)

    # Navigate to login page if not already there
    current_url = page.url
    if not is_login_url(current_url) and not wait_for_server_ready(page):
        print("❌ Server is not ready for login")
        return False

    # Wait for email input to be visible before interacting
    try:
        email_input = page.locator('input[name="email"], input[name="username"], input[type="email"]').first
        email_input.wait_for(state="visible", timeout=5000)
        page.wait_for_selector('input[name="password"]', timeout=5000)
        page.wait_for_selector('button[type="submit"]', timeout=5000)
        print("  ✅ Login form visible")
    except Exception as e:
        print(f"❌ Login form not ready: {str(e)[:50]}")
        return False

    # Fill login form
    try:
        email_input.fill(email)
        page.fill('input[name="password"]', password)
        page.click('button[type="submit"]')
    except Exception as e:
        print(f"❌ Cannot fill login form: {str(e)[:50]}")
        return False

    # Wait for redirect after login - use multiple strategies with longer timeout
    try:
        # First try: wait for dashboard URL with longer timeout
        page.wait_for_url(f"{BASE_URL}/dashboard/", timeout=12000)  # Increased from 8s to 12s
        print(f"✅ Successfully logged in as {email}")
        return True
    except Exception:
        # Second try: check if we're on dashboard by URL pattern
        try:
            page.wait_for_load_state("networkidle", timeout=3000)
            current_url = page.url
            if is_logged_in_url(current_url):
                print(f"✅ Successfully logged in as {email} (alternate check)")
                return True
        except Exception:  # noqa: S110
            pass

        # Login failed - gather debug info
        print(f"❌ Login failed for {email}")
        current_url = page.url
        print(f"    Current URL: {current_url}")

        # Check if there's an error message on the page
        try:
            error_elements = page.locator('.alert-danger, .error, .invalid-feedback').all()
            for error in error_elements:
                if error.is_visible():
                    error_text = error.inner_text()
                    print(f"    Error message: {error_text}")
        except Exception:  # noqa: S110
            pass

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
        page.goto(f"{BASE_URL}{LOGOUT_URL}")
        page.wait_for_load_state("networkidle", timeout=3000)

        # Check if we're back on login page
        if is_login_url(page.url):
            print("✅ Successfully logged out")
            return True
        else:
            print(f"⚠️  Logout may have failed, current URL: {page.url}")
            return False

    except Exception as e:
        print(f"❌ Logout error: {str(e)[:100]}")
        return False


def wait_for_server_ready(page: Page, max_attempts: int = 10) -> bool:
    """
    Wait for the Django server to be ready and responsive.

    Args:
        page: Playwright page object
        max_attempts: Maximum number of attempts to check server

    Returns:
        bool: True if server is ready, False otherwise
    """
    for attempt in range(max_attempts):
        try:
            page.goto(f"{BASE_URL}{LOGIN_URL}", timeout=3000)
            page.wait_for_load_state("domcontentloaded", timeout=3000)
            return True
        except Exception:
            if attempt < max_attempts - 1:
                print(f"  ⏳ Server not ready, waiting... (attempt {attempt + 1}/{max_attempts})")
                time.sleep(2)
            else:
                print(f"  ❌ Server failed to become ready after {max_attempts} attempts")
                return False

    return False


def ensure_fresh_session(page: Page) -> None:
    """
    Ensure a fresh session by safely clearing any existing state.

    Args:
        page: Playwright page object

    Example:
        ensure_fresh_session(page)
        assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
    """
    print("🔄 Ensuring fresh session")

    # Navigate away first to stop any background JS (HTMX polling, fetch)
    # that would fire 401s after cookies are cleared.
    page.goto("about:blank")
    page.context.clear_cookies()
    _dismiss_cookie_consent(page, BASE_URL)

    # Wait for server to be ready and navigate to login page
    if not wait_for_server_ready(page):
        raise Exception("Server is not responding after multiple attempts")

    print("  ✅ Navigated to login page")


# ===============================================================================
# AUTHENTICATION ERROR
# ===============================================================================

def apply_storage_state(
    page: Page,
    storage_state_path: str | None,
    validation_url: str,
    login_url_fragment: str,
) -> bool:
    """
    Apply saved auth cookies and validate they work.

    Returns True if auth state was applied successfully, False if fallback needed.
    """
    if not storage_state_path:
        return False

    with open(storage_state_path) as f:
        state = json.load(f)

    cookies = state.get("cookies", [])
    if not cookies:
        return False

    page.context.add_cookies(cookies)
    page.goto(validation_url, timeout=10000)
    page.wait_for_load_state("networkidle", timeout=5000)

    if login_url_fragment in page.url:
        page.context.clear_cookies()
        return False

    return True


class AuthenticationError(Exception):
    """Raised when authentication is lost during testing."""


def require_authentication(page: Page) -> None:
    """
    Verify user is authenticated, raise AuthenticationError if not.

    Args:
        page: Playwright page object

    Raises:
        AuthenticationError: If user is not authenticated
    """
    if is_login_url(page.url):
        raise AuthenticationError("User authentication lost during test")


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
    from tests.e2e.helpers.constants import (  # noqa: PLC0415
        CUSTOMER_EMAIL,
        CUSTOMER_PASSWORD,
        SUPERUSER_EMAIL,
        SUPERUSER_PASSWORD,
    )

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
