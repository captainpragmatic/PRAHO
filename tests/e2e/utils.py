"""
E2E Testing Utilities for PRAHO Platform — Re-export Shim

This module re-exports all symbols from the tests.e2e.helpers package
for backward compatibility. All functionality has been split into focused modules:

    tests/e2e/helpers/
    ├── __init__.py          # Re-exports everything (this shim delegates here)
    ├── constants.py         # URLs, credentials, configuration
    ├── auth.py              # Login, logout, session management
    ├── interactions.py      # safe_click_element, count_elements
    ├── monitoring.py        # ComprehensivePageMonitor, quality checks
    ├── navigation.py        # Dashboard nav, admin/role verification
    ├── user_manager.py      # E2EUserManager, test_users context manager
    └── mobile.py            # MobileTestContext, responsive breakpoint testing

New code should import from specific modules:
    from tests.e2e.helpers.auth import login_user
    from tests.e2e.helpers.monitoring import ComprehensivePageMonitor

Existing imports continue to work:
    from tests.e2e.utils import login_user, ComprehensivePageMonitor
"""

from tests.e2e.helpers import *  # noqa: F403
