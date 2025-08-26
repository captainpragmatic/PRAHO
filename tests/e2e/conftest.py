"""
E2E Test Configuration for PRAHO Platform

Centralized configuration for all end-to-end tests using pytest-playwright.
This file provides shared fixtures and browser settings.
"""

import pytest


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """
    Configure browser settings for all E2E tests.
    
    This fixture provides consistent browser configuration across all E2E tests
    including viewport size, security settings, and performance optimizations.
    """
    return {
        **browser_context_args,
        "viewport": {"width": 1280, "height": 720},
        "ignore_https_errors": True,
        "bypass_csp": True,  # Allow our test interactions
    }


def pytest_configure(config):
    """
    Configure pytest-playwright settings for all E2E tests.
    
    This centralized configuration ensures consistent test execution
    across all E2E test files.
    """
    # Only set options if they don't already exist
    if not hasattr(config.option, 'headed'):
        config.option.headed = False  # Run headless by default
    if not hasattr(config.option, 'slowmo'):
        config.option.slowmo = 0      # No slowdown by default
    if not hasattr(config.option, 'browser_name'):
        config.option.browser_name = "chromium"  # Default browser
