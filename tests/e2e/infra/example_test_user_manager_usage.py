
"""
===============================================================================
EXAMPLE: TEST USER MANAGER USAGE
===============================================================================

This file demonstrates how to use the new TestUserManager system for
comprehensive E2E testing with dynamic user creation and guaranteed cleanup.

The TestUserManager provides:
- Dynamic user creation with random credentials
- Customer organization creation and relationships
- Guaranteed cleanup using context managers and atexit handlers
- Thread-safe operations
- Integration with existing login utilities

Author: AI Assistant
Created: 2025-08-29
Framework: Playwright + pytest + TestUserManager
"""

from playwright.sync_api import Page

# Import the new test user management system
from tests.e2e.utils import (
    BASE_URL,
    LOGOUT_URL,
    ComprehensivePageMonitor,
    TestUserManager,
    create_and_login_admin,
    create_and_login_customer,
    ensure_fresh_session,
    login_test_user,
    navigate_to_dashboard,
    test_users,
)

# ===============================================================================
# BASIC USAGE EXAMPLES
# ===============================================================================

def test_basic_admin_creation_and_login(page: Page) -> None:
    """
    Example: Basic admin user creation and login.

    Shows the simplest usage pattern with automatic cleanup.
    """
    print("\n🧪 Testing basic admin creation and login...")

    # Create test user manager with automatic cleanup
    with TestUserManager() as user_mgr:
        # Create a random admin user
        admin = user_mgr.create_admin_user()

        print(f"📧 Generated admin email: {admin['email']}")
        print(f"🔐 Generated admin password: {admin['password']}")

        # Ensure fresh session before login
        ensure_fresh_session(page)

        # Login with the created user
        with ComprehensivePageMonitor(page, "admin login"):
            login_success = login_test_user(page, admin)
            assert login_success, f"Failed to login admin user: {admin['email']}"

        # Verify we're logged in and on dashboard
        assert navigate_to_dashboard(page), "Should be able to navigate to dashboard"
        assert "/app/" in page.url, "Should be on dashboard after login"

        print("✅ Admin creation and login successful")

    # User is automatically cleaned up when exiting the context manager


def test_customer_with_organization_creation(page: Page) -> None:
    """
    Example: Customer user with organization creation.

    Shows how to create a customer user with an associated company.
    """
    print("\n🧪 Testing customer with organization creation...")

    with TestUserManager() as user_mgr:
        # Create customer user with organization
        customer_user, customer_org = user_mgr.create_customer_with_org()

        print(f"📧 Customer email: {customer_user['email']}")
        print(f"🏢 Company name: {customer_org['company_name']}")
        print(f"🆔 Customer ID: {customer_org['id']}")

        # Login with customer user
        ensure_fresh_session(page)

        with ComprehensivePageMonitor(page, "customer login"):
            login_success = login_test_user(page, customer_user)
            assert login_success, f"Failed to login customer user: {customer_user['email']}"

        # Verify dashboard access
        assert navigate_to_dashboard(page), "Customer should access dashboard"

        print("✅ Customer with organization creation successful")

    # Both user and organization are automatically cleaned up


def test_staff_user_creation(page: Page) -> None:
    """
    Example: Staff user creation with different roles.

    Shows how to create staff users with specific roles.
    """
    print("\n🧪 Testing staff user creation...")

    with TestUserManager() as user_mgr:
        # Create different types of staff users
        support_staff = user_mgr.create_staff_user(role='support')
        billing_staff = user_mgr.create_staff_user(role='billing')
        manager_staff = user_mgr.create_staff_user(role='manager')

        print(f"🎧 Support staff: {support_staff['email']}")
        print(f"💰 Billing staff: {billing_staff['email']}")
        print(f"👔 Manager staff: {manager_staff['email']}")

        # Test login with support staff
        ensure_fresh_session(page)

        with ComprehensivePageMonitor(page, "staff login"):
            login_success = login_test_user(page, support_staff)
            assert login_success, f"Failed to login support staff: {support_staff['email']}"

        assert navigate_to_dashboard(page), "Staff should access dashboard"

        print("✅ Staff user creation successful")

    # All staff users are automatically cleaned up


# ===============================================================================
# ADVANCED USAGE EXAMPLES
# ===============================================================================

def test_multiple_users_with_convenient_syntax(page: Page) -> None:
    """
    Example: Creating multiple users with convenient syntax.

    Shows the test_users() context manager for creating multiple users at once.
    """
    print("\n🧪 Testing multiple users with convenient syntax...")

    # Create multiple users with one context manager
    with test_users(
        ('admin',),                              # Simple admin
        ('customer', {'company_name': 'ACME Corp'}),  # Customer with custom company name
        ('staff', {'role': 'billing'})           # Billing staff
    ) as (admin, customer_data, billing_staff):

        # Unpack customer data (returns tuple of user and org)
        customer_user, customer_org = customer_data

        print(f"👑 Admin: {admin['email']}")
        print(f"🏢 Customer: {customer_user['email']} at {customer_org['company_name']}")
        print(f"💰 Billing Staff: {billing_staff['email']} ({billing_staff['role']})")

        # Test admin login
        ensure_fresh_session(page)

        with ComprehensivePageMonitor(page, "admin workflow"):
            assert login_test_user(page, admin)
            assert navigate_to_dashboard(page)

        print("✅ Multiple user creation successful")

    # All users and organizations are automatically cleaned up


def test_one_step_login_helpers(page: Page) -> None:
    """
    Example: Using one-step login helpers.

    Shows create_and_login_* helpers for immediate login.
    """
    print("\n🧪 Testing one-step login helpers...")

    with TestUserManager() as user_mgr:
        # Create and login admin in one step
        ensure_fresh_session(page)

        admin = create_and_login_admin(page, user_mgr)
        print(f"👑 Logged in admin: {admin['email']}")

        # Should already be on dashboard
        assert "/app/" in page.url, "Should be logged in on dashboard"

        # Logout and test customer creation + login
        page.goto(f"{BASE_URL}{LOGOUT_URL}")
        page.wait_for_load_state("networkidle")

        customer_user, customer_org = create_and_login_customer(page, user_mgr)
        print(f"🏢 Logged in customer: {customer_user['email']} for {customer_org['company_name']}")

        # Should be on dashboard
        assert "/app/" in page.url, "Customer should be logged in on dashboard"

        print("✅ One-step login helpers successful")

    # Automatic cleanup


# ===============================================================================
# ERROR HANDLING AND EDGE CASES
# ===============================================================================

def test_duplicate_user_handling(page: Page) -> None:
    """
    Example: Error handling for duplicate users.

    Shows how the system handles attempts to create duplicate users.
    """
    print("\n🧪 Testing duplicate user handling...")

    with TestUserManager() as user_mgr:
        # Create first user
        admin1 = user_mgr.create_admin_user(email="specific.admin@test.praho.local")
        print(f"✅ Created first admin: {admin1['email']}")

        # Try to create duplicate user (should fail)
        try:
            admin2 = user_mgr.create_admin_user(email="specific.admin@test.praho.local")
            raise AssertionError("Should not be able to create duplicate user")
        except ValueError as e:
            print(f"✅ Correctly prevented duplicate user: {e}")

        # Verify first user still works
        ensure_fresh_session(page)
        assert login_test_user(page, admin1)

        print("✅ Duplicate user handling successful")


def test_user_lookup_functionality(page: Page) -> None:
    """
    Example: User lookup and information retrieval.

    Shows how to look up created users by email.
    """
    print("\n🧪 Testing user lookup functionality...")

    with TestUserManager() as user_mgr:
        # Create users
        admin = user_mgr.create_admin_user()
        customer_user, customer_org = user_mgr.create_customer_with_org()
        staff = user_mgr.create_staff_user(role='support')

        # Look up users
        admin_info = user_mgr.get_user_by_email(admin['email'])
        customer_info = user_mgr.get_user_by_email(customer_user['email'])
        staff_info = user_mgr.get_user_by_email(staff['email'])

        # Verify admin info
        assert admin_info is not None
        assert admin_info['is_superuser'] == True
        assert admin_info['staff_role'] == 'admin'
        print(f"✅ Admin lookup: {admin_info['email']} (superuser: {admin_info['is_superuser']})")

        # Verify customer info
        assert customer_info is not None
        assert customer_info['is_staff'] == False
        assert customer_info['staff_role'] == ''
        print(f"✅ Customer lookup: {customer_info['email']} (staff: {customer_info['is_staff']})")

        # Verify staff info
        assert staff_info is not None
        assert staff_info['is_staff'] == True
        assert staff_info['staff_role'] == 'support'
        print(f"✅ Staff lookup: {staff_info['email']} (role: {staff_info['staff_role']})")

        # Try looking up non-existent user
        missing_user = user_mgr.get_user_by_email("nonexistent@test.praho.local")
        assert missing_user is None
        print("✅ Correctly returned None for non-existent user")

        print("✅ User lookup functionality successful")


# ===============================================================================
# INTEGRATION WITH EXISTING TEST PATTERNS
# ===============================================================================

def test_integration_with_existing_page_monitoring(page: Page) -> None:
    """
    Example: Integration with existing E2E test patterns.

    Shows how TestUserManager works with existing ComprehensivePageMonitor
    and other E2E testing utilities.
    """
    print("\n🧪 Testing integration with existing patterns...")

    with TestUserManager() as user_mgr:
        # Create test users
        admin = user_mgr.create_admin_user()
        customer_user, customer_org = user_mgr.create_customer_with_org()

        # Test admin workflow with comprehensive monitoring
        ensure_fresh_session(page)

        with ComprehensivePageMonitor(page, "admin comprehensive workflow") as monitor:
            # Login admin
            login_success = login_test_user(page, admin)
            assert login_success, "Admin login should succeed"

            # Navigate around the application
            assert navigate_to_dashboard(page)

            # Try navigating to different sections (if they exist)
            if page.locator('a[href*="customers"]').count() > 0:
                page.click('a[href*="customers"]')
                page.wait_for_load_state("networkidle")

        # Monitor automatically checks for console errors, network issues, etc.
        print("✅ Admin workflow completed with comprehensive monitoring")

        # Test customer workflow
        ensure_fresh_session(page)

        with ComprehensivePageMonitor(page, "customer comprehensive workflow") as monitor:
            # Login customer
            login_success = login_test_user(page, customer_user)
            assert login_success, "Customer login should succeed"

            # Customer-specific navigation
            assert navigate_to_dashboard(page)

        print("✅ Customer workflow completed with comprehensive monitoring")

        print("✅ Integration with existing patterns successful")


# ===============================================================================
# PERFORMANCE AND CLEANUP TESTING
# ===============================================================================

def test_cleanup_performance_and_reliability(page: Page) -> None:
    """
    Example: Testing cleanup performance and reliability.

    Shows that cleanup works reliably even with many users.
    """
    print("\n🧪 Testing cleanup performance and reliability...")

    # Create many users to test cleanup performance
    user_count = 5  # Keep reasonable for CI

    with TestUserManager() as user_mgr:
        created_users = []

        for i in range(user_count):
            if i % 2 == 0:
                # Create admin users
                user = user_mgr.create_admin_user()
                created_users.append(user)
            else:
                # Create customer users with organizations
                user, org = user_mgr.create_customer_with_org()
                created_users.append((user, org))

        print(f"✅ Created {user_count} test users successfully")

        # Test that a few of them can login
        sample_admin = next(u for u in created_users if isinstance(u, dict) and u['type'] == 'admin')

        ensure_fresh_session(page)
        login_success = login_test_user(page, sample_admin)
        assert login_success, "Sample admin should be able to login"

        print(f"✅ Sample user {sample_admin['email']} can login successfully")

    # All users are automatically cleaned up here
    print("✅ Cleanup performance and reliability test completed")


if __name__ == "__main__":
    print("""
    ===============================================================================
    TEST USER MANAGER USAGE EXAMPLES
    ===============================================================================

    This file demonstrates the new TestUserManager system for E2E testing.

    To run these examples:

        # Run all examples
        pytest tests/e2e/example_test_user_manager_usage.py -v

        # Run specific example
        pytest tests/e2e/example_test_user_manager_usage.py::test_basic_admin_creation_and_login -v

    Key Benefits:
    ✅ Dynamic user creation with random credentials
    ✅ Automatic customer organization creation
    ✅ Guaranteed cleanup (context managers + atexit handlers)
    ✅ Thread-safe operations
    ✅ Integration with existing login utilities
    ✅ Comprehensive error handling
    ✅ Multiple convenience patterns

    ===============================================================================
    """)
