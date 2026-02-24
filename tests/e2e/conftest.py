"""
E2E Test Configuration for PRAHO Platform

Centralized configuration for all end-to-end tests using pytest-playwright.
This file customizes browser launch args based on the runtime environment.
"""

import os
import sys

# Prevent stale .pyc bytecode cache — critical for Docker bind mounts where
# filesystem timestamps can desync, causing Python to use outdated cached bytecode.
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

import pytest  # noqa: E402
from playwright.sync_api import Browser  # noqa: E402

from tests.e2e.helpers.constants import (  # noqa: E402
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    LOGIN_URL,
    PLATFORM_BASE_URL,
    PLATFORM_LOGIN_URL,
    STAFF_EMAIL,
    STAFF_PASSWORD,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
)


def _get_chromium_args() -> list[str]:
    """
    Build Chromium launch arguments based on the runtime environment.

    On CI/Linux containers: aggressive flags for headless stability.
    On macOS dev: minimal flags to avoid browser crashes.
    """
    # Common safe args for all environments
    args = [
        "--disable-dev-shm-usage",
        "--disable-gpu",
    ]

    # Container/CI-only args (Linux) - these crash Chromium on macOS
    # NOTE: --single-process and --no-zygote are omitted because they prevent
    # browser context reuse across tests (browser dies after first context close).
    if os.environ.get("CI") or sys.platform == "linux":
        args.extend([
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-software-rasterizer",
        ])

    return args


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args):
    """
    Configure browser launch arguments based on the runtime environment.
    """
    return {
        **browser_type_launch_args,
        "args": _get_chromium_args(),
    }


def pytest_configure(config):
    """Register custom markers for E2E tests."""
    config.addinivalue_line("markers", "e2e: end-to-end test")
    config.addinivalue_line("markers", "no_auto_dismiss: skip automatic cookie consent dismissal")


# ===============================================================================
# SESSION-SCOPED AUTH STATE FIXTURES
# ===============================================================================


@pytest.fixture(scope="session")
def _staff_storage_state(browser: Browser, tmp_path_factory) -> str | None:
    """Login to platform once per session and save auth cookies."""
    context = browser.new_context()
    page = context.new_page()
    try:
        page.goto(f"{PLATFORM_BASE_URL}{PLATFORM_LOGIN_URL}", timeout=15000)
        page.wait_for_load_state("networkidle", timeout=10000)

        email_input = page.locator(
            'input[name="email"], input[name="username"], input[type="email"]'
        ).first
        email_input.wait_for(state="visible", timeout=8000)
        email_input.fill(STAFF_EMAIL)
        page.fill('input[name="password"]', STAFF_PASSWORD)
        page.click('button[type="submit"]')
        page.wait_for_url(lambda url: PLATFORM_LOGIN_URL not in url, timeout=15000)
        page.wait_for_load_state("networkidle", timeout=5000)

        if PLATFORM_LOGIN_URL in page.url:
            return None

        state_path = str(tmp_path_factory.mktemp("auth") / "staff-auth-state.json")
        context.storage_state(path=state_path)
        return state_path
    except Exception:
        return None
    finally:
        context.close()


@pytest.fixture(scope="session")
def _customer_storage_state(browser: Browser, tmp_path_factory) -> str | None:
    """Login to portal once per session as customer and save auth cookies."""
    context = browser.new_context()
    page = context.new_page()
    try:
        page.goto(f"{BASE_URL}{LOGIN_URL}", timeout=15000)
        page.wait_for_load_state("networkidle", timeout=10000)

        email_input = page.locator(
            'input[name="email"], input[name="username"], input[type="email"]'
        ).first
        email_input.wait_for(state="visible", timeout=8000)
        email_input.fill(CUSTOMER_EMAIL)
        page.fill('input[name="password"]', CUSTOMER_PASSWORD)
        page.click('button[type="submit"]')
        page.wait_for_url(lambda url: LOGIN_URL not in url, timeout=15000)
        page.wait_for_load_state("networkidle", timeout=5000)

        if LOGIN_URL in page.url:
            return None

        state_path = str(tmp_path_factory.mktemp("auth") / "customer-auth-state.json")
        context.storage_state(path=state_path)
        return state_path
    except Exception:
        return None
    finally:
        context.close()


@pytest.fixture(scope="session")
def _superuser_storage_state(browser: Browser, tmp_path_factory) -> str | None:
    """Login to portal once per session as superuser and save auth cookies."""
    context = browser.new_context()
    page = context.new_page()
    try:
        page.goto(f"{BASE_URL}{LOGIN_URL}", timeout=15000)
        page.wait_for_load_state("networkidle", timeout=10000)

        email_input = page.locator(
            'input[name="email"], input[name="username"], input[type="email"]'
        ).first
        email_input.wait_for(state="visible", timeout=8000)
        email_input.fill(SUPERUSER_EMAIL)
        page.fill('input[name="password"]', SUPERUSER_PASSWORD)
        page.click('button[type="submit"]')
        page.wait_for_url(lambda url: LOGIN_URL not in url, timeout=15000)
        page.wait_for_load_state("networkidle", timeout=5000)

        if LOGIN_URL in page.url:
            return None

        state_path = str(tmp_path_factory.mktemp("auth") / "superuser-auth-state.json")
        context.storage_state(path=state_path)
        return state_path
    except Exception:
        return None
    finally:
        context.close()
