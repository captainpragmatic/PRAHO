"""
Platform E2E Test Configuration

Fixtures and configuration for platform (staff backend :8700) E2E tests.
"""

import pytest
from playwright.sync_api import Page

from tests.e2e.utils import (
    PLATFORM_BASE_URL,
    ComprehensivePageMonitor,
    apply_storage_state,
    ensure_fresh_platform_session,
    login_platform_user,
)


@pytest.fixture
def platform_url():
    """Base URL for the platform service."""
    return PLATFORM_BASE_URL


@pytest.fixture
def staff_page(page: Page, _staff_storage_state: str | None):
    """
    Authenticated staff page on the platform service.

    Uses session-scoped auth cookies when available, with fallback to
    full login if auth state is missing or expired.
    """
    if apply_storage_state(page, _staff_storage_state,
                           f"{PLATFORM_BASE_URL}/app/dashboard/",
                           "/auth/login/"):
        return page
    # Fallback: full login
    ensure_fresh_platform_session(page)
    if not login_platform_user(page):
        pytest.fail("Staff login failed — is the E2E service running? (make dev-e2e)")
    return page


@pytest.fixture
def monitored_staff_page(page: Page, request: pytest.FixtureRequest, _staff_storage_state: str | None):
    """
    Authenticated staff page wrapped in ComprehensivePageMonitor.

    Uses session-scoped auth cookies when available, with fallback to
    full login if auth state is missing or expired.
    """
    test_name = request.node.name.removeprefix("test_")
    with ComprehensivePageMonitor(page, test_name,
                                  check_console=True,
                                  check_network=True,
                                  check_html=True,
                                  check_css=True,
                                  check_accessibility=False,
                                  allow_accessibility_skip=True):
        if not apply_storage_state(page, _staff_storage_state,
                                   f"{PLATFORM_BASE_URL}/app/dashboard/",
                                   "/auth/login/"):
            ensure_fresh_platform_session(page)
            if not login_platform_user(page):
                pytest.fail("Staff login failed — is the E2E service running? (make dev-e2e)")
        yield page
