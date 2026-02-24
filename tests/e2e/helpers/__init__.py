"""
E2E Test Helpers Package — split from utils.py for ADR-0012 compliance.

Re-exports all public symbols for backward compatibility.
Import from here or from individual modules:

    from tests.e2e.helpers import login_user, ComprehensivePageMonitor
    from tests.e2e.helpers.auth import login_user
    from tests.e2e.helpers.monitoring import ComprehensivePageMonitor
"""

# Constants
# Authentication
from tests.e2e.helpers.auth import (
    AuthenticationError,
    _dismiss_cookie_consent,
    apply_storage_state,
    dismiss_cookie_consent,
    ensure_fresh_platform_session,
    ensure_fresh_session,
    get_test_user_credentials,
    login_platform_user,
    login_user,
    login_user_with_retry,
    logout_platform_user,
    logout_user,
    navigate_to_platform_page,
    require_authentication,
    setup_console_monitoring,
    wait_for_server_ready,
)
from tests.e2e.helpers.constants import (
    BASE_URL,
    CUSTOMER2_EMAIL,
    CUSTOMER2_PASSWORD,
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    LEGACY_CUSTOMER_EMAIL,
    LEGACY_CUSTOMER_PASSWORD,
    LEGACY_SUPERUSER_EMAIL,
    LEGACY_SUPERUSER_PASSWORD,
    LOGIN_URL,
    LOGOUT_URL,
    PLATFORM_BASE_URL,
    PLATFORM_LOGIN_URL,
    PLATFORM_LOGOUT_URL,
    REGISTER_URL,
    STAFF_EMAIL,
    STAFF_PASSWORD,
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD,
    is_logged_in_url,
    is_login_url,
)

# Element Interactions
from tests.e2e.helpers.interactions import (
    count_elements,
    safe_click_element,
)

# Mobile Testing
from tests.e2e.helpers.mobile import (
    DESKTOP_VIEWPORT,
    MOBILE_VIEWPORTS,
    MobileTestContext,
    assert_responsive_results,
    run_responsive_breakpoints_test,
    run_standard_mobile_test,
)

# Page Quality Monitoring
from tests.e2e.helpers.monitoring import (
    ComprehensivePageMonitor,
    ConsoleMonitor,
    PageQualityConfig,
    assert_no_console_errors,
    check_accessibility_basics,
    check_css_issues,
    check_html_validation,
    check_network_errors,
    check_performance_issues,
    setup_console_monitoring_standalone,
)

# Navigation & Verification
from tests.e2e.helpers.navigation import (
    _check_no_staff_navigation,
    _check_staff_navigation,
    _debug_navigation_links,
    _test_admin_access_blocked,
    navigate_to_dashboard,
    navigate_to_page,
    verify_admin_access,
    verify_dashboard_functionality,
    verify_navigation_completeness,
    verify_role_based_content,
)

# User Management
from tests.e2e.helpers.user_manager import (
    E2EUserManager,
    TestUserManager,
    create_and_login_admin,
    create_and_login_customer,
    login_test_user,
    test_users,
)

__all__ = [
    # Constants
    "BASE_URL",
    "CUSTOMER2_EMAIL",
    "CUSTOMER2_PASSWORD",
    "CUSTOMER_EMAIL",
    "CUSTOMER_PASSWORD",
    "DESKTOP_VIEWPORT",
    "LEGACY_CUSTOMER_EMAIL",
    "LEGACY_CUSTOMER_PASSWORD",
    "LEGACY_SUPERUSER_EMAIL",
    "LEGACY_SUPERUSER_PASSWORD",
    "LOGIN_URL",
    "LOGOUT_URL",
    "MOBILE_VIEWPORTS",
    "PLATFORM_BASE_URL",
    "PLATFORM_LOGIN_URL",
    "PLATFORM_LOGOUT_URL",
    "REGISTER_URL",
    "STAFF_EMAIL",
    "STAFF_PASSWORD",
    "SUPERUSER_EMAIL",
    "SUPERUSER_PASSWORD",
    # Auth
    "AuthenticationError",
    # Monitoring
    "ComprehensivePageMonitor",
    "ConsoleMonitor",
    # User Management
    "E2EUserManager",
    # Mobile
    "MobileTestContext",
    "PageQualityConfig",
    "TestUserManager",
    # Navigation
    "_check_no_staff_navigation",
    "_check_staff_navigation",
    "_debug_navigation_links",
    "_dismiss_cookie_consent",
    "_test_admin_access_blocked",
    "apply_storage_state",
    "assert_no_console_errors",
    "assert_responsive_results",
    "check_accessibility_basics",
    "check_css_issues",
    "check_html_validation",
    "check_network_errors",
    "check_performance_issues",
    # Interactions
    "count_elements",
    "create_and_login_admin",
    "create_and_login_customer",
    "dismiss_cookie_consent",
    "ensure_fresh_platform_session",
    "ensure_fresh_session",
    "get_test_user_credentials",
    "is_logged_in_url",
    "is_login_url",
    "login_platform_user",
    "login_test_user",
    "login_user",
    "login_user_with_retry",
    "logout_platform_user",
    "logout_user",
    "navigate_to_dashboard",
    "navigate_to_page",
    "navigate_to_platform_page",
    "require_authentication",
    "run_responsive_breakpoints_test",
    "run_standard_mobile_test",
    "safe_click_element",
    "setup_console_monitoring",
    "setup_console_monitoring_standalone",
    "test_users",
    "verify_admin_access",
    "verify_dashboard_functionality",
    "verify_navigation_completeness",
    "verify_role_based_content",
    "wait_for_server_ready",
]
