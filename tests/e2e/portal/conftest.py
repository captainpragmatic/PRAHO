"""
Portal E2E Test Configuration

Fixtures and configuration for portal (customer frontend :8701) E2E tests.
"""

import pytest

from tests.e2e.utils import BASE_URL, _dismiss_cookie_consent


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
