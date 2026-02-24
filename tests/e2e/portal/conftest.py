"""
Portal E2E Test Configuration

Fixtures and configuration for portal (customer frontend :8701) E2E tests.
"""

import pytest
from playwright.sync_api import Page

from tests.e2e.utils import (
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    ComprehensivePageMonitor,
    _dismiss_cookie_consent,
    apply_storage_state,
    ensure_fresh_session,
    login_user,
)


@pytest.fixture
def portal_url():
    """Base URL for the portal service."""
    return BASE_URL


@pytest.fixture(autouse=True)
def auto_dismiss_cookie_consent(request, page):
    """
    Automatically dismiss the cookie consent banner for all portal E2E tests.

    The cookie consent banner is a fixed-position overlay that blocks Playwright
    click interactions on page elements underneath. This fixture pre-sets the
    cookie_consent cookie so the banner never appears.

    Tests in test_cookie_consent.py opt out via the 'no_auto_dismiss' marker
    since they need the banner visible to test its behavior.
    """
    if 'no_auto_dismiss' in [m.name for m in request.node.iter_markers()]:
        return
    _dismiss_cookie_consent(page, BASE_URL)


@pytest.fixture
def customer_page(page: Page, _customer_storage_state: str | None):
    """
    Authenticated customer page on the portal service.

    Uses session-scoped auth cookies when available, with fallback to
    full login if auth state is missing or expired.
    """
    if apply_storage_state(page, _customer_storage_state,
                           f"{BASE_URL}/dashboard/",
                           "/login/"):
        return page
    ensure_fresh_session(page)
    if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
        pytest.fail("Customer login failed — is the E2E service running? (make dev-e2e)")
    return page


@pytest.fixture
def superuser_page(page: Page, _superuser_storage_state: str | None):
    """
    Authenticated superuser page on the portal service.

    Uses session-scoped auth cookies when available, with fallback to
    full login if auth state is missing or expired.
    """
    if apply_storage_state(page, _superuser_storage_state,
                           f"{BASE_URL}/dashboard/",
                           "/login/"):
        return page
    ensure_fresh_session(page)
    if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
        pytest.fail("Superuser login failed — is the E2E service running? (make dev-e2e)")
    return page


@pytest.fixture
def monitored_customer_page(page: Page, request: pytest.FixtureRequest, _customer_storage_state: str | None):
    """
    Authenticated customer page wrapped in ComprehensivePageMonitor.

    Combines login + monitoring in one fixture. Monitor context name
    is derived from the test function name.

    Usage: ``def test_something(monitored_customer_page): ...``
    """
    test_name = request.node.name.removeprefix("test_")
    with ComprehensivePageMonitor(page, test_name,
                                  check_console=True,
                                  check_network=True,
                                  check_html=True,
                                  check_css=True,
                                  check_accessibility=True,
                                  check_performance=False):
        if not apply_storage_state(page, _customer_storage_state,
                                   f"{BASE_URL}/dashboard/",
                                   "/login/"):
            ensure_fresh_session(page)
            if not login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD):
                pytest.fail("Customer login failed — is the E2E service running? (make dev-e2e)")
        yield page


@pytest.fixture
def monitored_superuser_page(page: Page, request: pytest.FixtureRequest, _superuser_storage_state: str | None):
    """
    Authenticated superuser page wrapped in ComprehensivePageMonitor.

    Combines login + monitoring in one fixture. Monitor context name
    is derived from the test function name.

    Usage: ``def test_something(monitored_superuser_page): ...``
    """
    test_name = request.node.name.removeprefix("test_")
    with ComprehensivePageMonitor(page, test_name,
                                  check_console=True,
                                  check_network=True,
                                  check_html=True,
                                  check_css=True,
                                  check_accessibility=True,
                                  check_performance=False):
        if not apply_storage_state(page, _superuser_storage_state,
                                   f"{BASE_URL}/dashboard/",
                                   "/login/"):
            ensure_fresh_session(page)
            if not login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD):
                pytest.fail("Superuser login failed — is the E2E service running? (make dev-e2e)")
        yield page
