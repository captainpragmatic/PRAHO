# ===============================================================================
# PORTAL SERVICE TEST CONFIGURATION - DATABASE ACCESS BLOCKER ⚠️
# ===============================================================================
# Ensures portal service cannot access platform database during tests
# This enforces the security boundary between services

from collections.abc import Callable
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
def block_database_access() -> None:
    """
    Automatically prevent all database access in portal tests.
    
    This fixture runs for every test in the portal service and ensures
    that any attempt to access the database results in a clear error,
    enforcing the service boundary.
    """
    
    # Block database operations to enforce service boundaries
    
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
    
    # Block database operations
    with patch.object(connections[DEFAULT_DB_ALIAS], 'ensure_connection', blocked_ensure_connection), \
         patch.object(connections[DEFAULT_DB_ALIAS], 'cursor', blocked_cursor):
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
    api_mock.get_customer.return_value = {
        'id': 1,
        'email': 'test@example.com',
        'name': 'Test Customer'
    }
    
    api_mock.get_orders.return_value = [
        {'id': 1, 'status': 'active', 'product': 'Shared Hosting'}
    ]
    
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
        with patch('django.db.connection.cursor') as mock_cursor:
            mock_cursor.side_effect = ImproperlyConfigured(
                "Database access detected in portal test!"
            )
            return test_func(*args, **kwargs)
    return wrapper


# ===============================================================================
# PLATFORM API MOCK RESPONSES 📡
# ===============================================================================

# Common API response templates for testing
MOCK_CUSTOMER_RESPONSE = {
    'id': 1,
    'email': 'test@pragmatichost.com',
    'name': 'Test Customer',
    'status': 'active',
    'created_at': '2025-01-01T00:00:00Z'
}

MOCK_ORDER_RESPONSE = {
    'id': 1, 
    'customer_id': 1,
    'product_name': 'Shared Hosting',
    'status': 'active',
    'monthly_price': '29.99',
    'created_at': '2025-01-01T00:00:00Z'
}

MOCK_INVOICE_RESPONSE = {
    'id': 1,
    'order_id': 1,
    'amount': '29.99',
    'status': 'paid',
    'due_date': '2025-02-01T00:00:00Z'
}
