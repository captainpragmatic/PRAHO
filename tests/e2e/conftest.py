"""
E2E Test Configuration for PRAHO Platform

Centralized configuration for all end-to-end tests using pytest-playwright.
This file customizes browser launch args based on the runtime environment.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

# Prevent stale .pyc bytecode cache — critical for Docker bind mounts where
# filesystem timestamps can desync, causing Python to use outdated cached bytecode.
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True

import pytest  # noqa: E402
from playwright.sync_api import Browser  # noqa: E402

from scripts.e2e_stack import environment  # noqa: E402
from tests.e2e.helpers import ComprehensivePageMonitor, ensure_fresh_session, login_user  # noqa: E402
from tests.e2e.helpers.constants import (  # noqa: E402
    BASE_URL,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    LOGIN_URL,
    PLATFORM_BASE_URL,
    PLATFORM_LOGIN_URL,
    PROJECT_ROOT,
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
        args.extend(
            [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-software-rasterizer",
            ]
        )

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


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    """Pin locale and timezone so tests are deterministic regardless of system language."""
    return {
        **browser_context_args,
        "locale": "en-US",
        "timezone_id": "Europe/Bucharest",
    }


def pytest_configure(config):
    """Register custom markers for E2E tests."""
    _unexpected_skips.clear()
    config.addinivalue_line("markers", "e2e: end-to-end test")
    config.addinivalue_line("markers", "no_auto_dismiss: skip automatic cookie consent dismissal")
    config.addinivalue_line(
        "markers",
        "expect_server_errors(pattern): Mark test as expecting specific server error patterns",
    )


_unexpected_skips: list[str] = []


def pytest_runtest_logreport(report):
    if os.environ.get("E2E_STRICT") == "1" and (report.skipped or getattr(report, "wasxfail", None)):
        _unexpected_skips.append(report.nodeid)


def pytest_sessionfinish(session, exitstatus):
    if _unexpected_skips:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter:
            reporter.write_sep("=", "Strict E2E: skipped/xfail tests leave required coverage unverified")
            for nodeid in sorted(set(_unexpected_skips)):
                reporter.write_line(nodeid)


@pytest.fixture(scope="session")
def e2e_baseline():
    path = PROJECT_ROOT / "logs/e2e-fixtures.json"
    assert path.is_file(), "Run make dev-e2e and make check-e2e to validate the live prerequisites"
    return json.loads(path.read_text())


@pytest.fixture
def e2e_scenario():
    """Create owned live-server input; never write via pytest's isolated database."""
    root = Path(__file__).resolve().parents[2]

    def create(name):
        result = subprocess.run(  # noqa: S603 -- fixed local management command and owned scenario inputs
            [sys.executable, "manage.py", "seed_e2e", "--scenario", name, "--key", uuid4().hex[:12]],
            cwd=root / "services/platform",
            env=environment(),
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"E2E scenario {name} failed: {result.stderr}"
        return json.loads(result.stdout)

    return create


@pytest.fixture
def account_page(page, e2e_scenario, request):
    """A private account for password, MFA, contact and address mutations."""
    account = e2e_scenario("account")
    ensure_fresh_session(page)
    assert login_user(page, account["email"], account["password"]), "Owned account login failed"
    with ComprehensivePageMonitor(page, request.node.name) as monitor:
        for marker in request.node.iter_markers("expect_server_errors"):
            monitor.add_expected_error_patterns(list(marker.args))
        yield page, account


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

        email_input = page.locator('input[name="email"], input[name="username"], input[type="email"]').first
        email_input.wait_for(state="visible", timeout=8000)
        email_input.fill(STAFF_EMAIL)
        page.fill('input[name="password"]', STAFF_PASSWORD)
        page.locator('button[type="submit"]:visible').first.click()
        page.wait_for_url(lambda url: PLATFORM_LOGIN_URL not in url, timeout=15000)
        page.wait_for_load_state("networkidle", timeout=5000)

        assert PLATFORM_LOGIN_URL not in page.url, "E2E staff could not authenticate"

        state_path = str(tmp_path_factory.mktemp("auth") / "staff-auth-state.json")
        context.storage_state(path=state_path)
        return state_path
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

        email_input = page.locator('input[name="email"], input[name="username"], input[type="email"]').first
        email_input.wait_for(state="visible", timeout=8000)
        email_input.fill(CUSTOMER_EMAIL)
        page.fill('input[name="password"]', CUSTOMER_PASSWORD)
        page.locator('button[type="submit"]:visible').first.click()
        page.wait_for_url(lambda url: LOGIN_URL not in url, timeout=15000)
        page.wait_for_load_state("networkidle", timeout=5000)

        assert LOGIN_URL not in page.url, "E2E customer could not authenticate"

        state_path = str(tmp_path_factory.mktemp("auth") / "customer-auth-state.json")
        context.storage_state(path=state_path)
        return state_path
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

        email_input = page.locator('input[name="email"], input[name="username"], input[type="email"]').first
        email_input.wait_for(state="visible", timeout=8000)
        email_input.fill(SUPERUSER_EMAIL)
        page.fill('input[name="password"]', SUPERUSER_PASSWORD)
        page.locator('button[type="submit"]:visible').first.click()
        page.wait_for_url(lambda url: LOGIN_URL not in url, timeout=15000)
        page.wait_for_load_state("networkidle", timeout=5000)

        assert LOGIN_URL not in page.url, "E2E admin could not authenticate to the portal"

        state_path = str(tmp_path_factory.mktemp("auth") / "superuser-auth-state.json")
        context.storage_state(path=state_path)
        return state_path
    finally:
        context.close()
