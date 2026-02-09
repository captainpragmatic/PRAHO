"""
E2E Test Configuration for PRAHO Platform

Centralized configuration for all end-to-end tests using pytest-playwright.
This file provides shared fixtures and browser settings.
"""

import pytest
from playwright.sync_api import Playwright, Browser, BrowserContext, Page


# Browser launch arguments for containerized environments
# These args are required for running Chromium in sandboxed/container environments
# where /tmp may have restricted permissions and shared memory is limited.
CHROMIUM_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--single-process",
    "--no-zygote",
    "--disable-software-rasterizer",
]


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args):
    """
    Configure browser launch arguments for containerized environments.
    """
    return {
        **browser_type_launch_args,
        "args": CHROMIUM_ARGS,
    }


@pytest.fixture(scope="session")
def browser(playwright: Playwright) -> Browser:
    """
    Custom browser fixture that launches chromium with container-safe arguments.

    This overrides the default playwright browser fixture to ensure
    our CHROMIUM_ARGS are applied in containerized environments.
    """
    browser = playwright.chromium.launch(
        headless=True,
        args=CHROMIUM_ARGS,
    )
    yield browser
    browser.close()


@pytest.fixture(scope="function")
def context(browser: Browser) -> BrowserContext:
    """
    Create a new browser context for each test with proper settings.
    """
    context = browser.new_context(
        viewport={"width": 1280, "height": 720},
        ignore_https_errors=True,
        bypass_csp=True,
    )
    yield context
    context.close()


@pytest.fixture(scope="function")
def page(context: BrowserContext) -> Page:
    """
    Create a new page for each test.
    """
    page = context.new_page()
    yield page
    page.close()


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
