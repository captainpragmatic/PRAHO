"""
Portal E2E Test Configuration

Fixtures and configuration for portal (customer frontend :8701) E2E tests.
"""

import pytest

from tests.e2e.utils import BASE_URL


@pytest.fixture
def portal_url():
    """Base URL for the portal service."""
    return BASE_URL
