"""
Platform E2E Test Configuration

Fixtures and configuration for platform (staff backend :8700) E2E tests.
"""

import pytest

from tests.e2e.utils import PLATFORM_BASE_URL


@pytest.fixture
def platform_url():
    """Base URL for the platform service."""
    return PLATFORM_BASE_URL
