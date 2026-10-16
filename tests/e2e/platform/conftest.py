"""
Platform E2E Test Configuration

Fixtures and configuration for platform (staff backend :8700) E2E tests.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import TYPE_CHECKING

import pytest
from playwright.sync_api import Page

from tests.e2e.helpers import (
    PLATFORM_BASE_URL,
    ComprehensivePageMonitor,
    apply_storage_state,
    apply_test_markers,
    ensure_fresh_platform_session,
    login_platform_user,
)

if TYPE_CHECKING:
    from tests.virtualmin_lab.workflows.harness import Bench


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
                           f"{PLATFORM_BASE_URL}/dashboard/",
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
                                  allow_accessibility_skip=True) as monitor:
        apply_test_markers(monitor, request)
        if not apply_storage_state(page, _staff_storage_state,
                                   f"{PLATFORM_BASE_URL}/dashboard/",
                                   "/auth/login/"):
            ensure_fresh_platform_session(page)
            if not login_platform_user(page):
                pytest.fail("Staff login failed — is the E2E service running? (make dev-e2e)")
        yield page


# ===============================================================================
# VIRTUALMIN LAB SMOKE TESTS (make test-virtualmin-e2e)
# ===============================================================================
# These tests need the Docker Virtualmin lab, its settings module and a server started by
# tests/virtualmin_lab/run_e2e.sh. That runner is the only thing that sets VIRTUALMIN_E2E; scripts/e2e_stack.py
# passes pytest an allow-listed environment without it, so the default `make test-e2e` never imports them.
if os.environ.get("VIRTUALMIN_E2E") == "1":
    import django

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.lab")
    django.setup()
else:
    collect_ignore_glob = ["test_virtualmin_lab_*.py"]


@pytest.fixture(scope="session")
def lab_bench() -> Iterator[Bench]:
    """Both lab nodes and the way back to a clean lab, through the production gateway.

    The bench belongs to the test process; the server has its own transport and its own queue worker. Tests
    therefore never drain the queue themselves (`Bench.run_queue` would race the server's worker): they wait
    for the server to finish, and read the node.
    """
    from apps.provisioning.management.commands._virtualmin_lab import (  # noqa: PLC0415
        lab_transport,
        load_state,
        refuse_unless_lab_settings,
    )
    from apps.provisioning.virtualmin_backup_service import REMOTE_ARCHIVE_DIR  # noqa: PLC0415
    from tests.virtualmin_lab.workflows.harness import build_bench  # noqa: PLC0415

    refuse_unless_lab_settings()
    state = load_state()
    with lab_transport(state):
        bench = build_bench(state)
        bench.reset_meters()
        bench.refresh_health()  # placement and migration only accept servers that read healthy
        bench.remove_leftovers()
        # Archives an interrupted or refused run left in the nodes' staging directory: the tests assert that a
        # backup or restore leaves nothing behind, so they start from an empty one.
        for node_lab in bench.labs.values():
            node_lab.exec("sh", "-c", 'rm -f "$1"/virtualmin_backup_* "$1"/migration_*', "sh", REMOTE_ARCHIVE_DIR)
        try:
            yield bench
        finally:
            bench.remove_leftovers()
            bench.put_back()


@pytest.fixture
def lab_staff_page(page: Page) -> Page:
    """A browser signed in to the lab server as the lab's staff user."""
    from tests.e2e.helpers.virtualmin_lab import staff_credentials  # noqa: PLC0415

    email, password = staff_credentials()
    ensure_fresh_platform_session(page)
    if not login_platform_user(page, email, password):
        pytest.fail("Lab staff login failed: is the lab server running? (make test-virtualmin-e2e)")
    return page
