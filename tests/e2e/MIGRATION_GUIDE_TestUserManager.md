# TestUserManager Migration Guide

This guide shows how to migrate existing E2E tests to use the new `TestUserManager` system for dynamic user creation and guaranteed cleanup.

## 🔄 Migration Overview

The new `TestUserManager` replaces hardcoded test users with dynamic user creation, providing:

- **Random credentials** for each test run
- **Guaranteed cleanup** using context managers and atexit handlers  
- **Customer organization creation** with proper relationships
- **Thread-safe operations** for parallel testing
- **Integration with existing utilities** like `login_user()` and `ComprehensivePageMonitor`

## 📋 Before and After Examples

### Basic User Login

**❌ OLD APPROACH (Hardcoded Users):**
```python
from tests.e2e.utils import (
    SUPERUSER_EMAIL, 
    SUPERUSER_PASSWORD,
    login_user,
    navigate_to_dashboard
)

def test_admin_functionality(page: Page) -> None:
    # Uses hardcoded admin credentials
    ensure_fresh_session(page)
    assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    assert navigate_to_dashboard(page)
    # Test admin functionality...
    # No cleanup needed (users persist)
```

**✅ NEW APPROACH (Dynamic Users):**
```python
from tests.e2e.utils import (
    TestUserManager,
    login_test_user,
    navigate_to_dashboard,
    create_and_login_admin  # Convenience helper
)

def test_admin_functionality(page: Page) -> None:
    # Creates fresh admin user with random credentials
    with TestUserManager() as user_mgr:
        admin = user_mgr.create_admin_user()
        
        ensure_fresh_session(page)
        assert login_test_user(page, admin)
        assert navigate_to_dashboard(page)
        # Test admin functionality...
        # Automatic cleanup when context exits

# OR use the one-step helper:
def test_admin_functionality_onestep(page: Page) -> None:
    with TestUserManager() as user_mgr:
        ensure_fresh_session(page)
        admin = create_and_login_admin(page, user_mgr)
        # Already logged in and on dashboard
        # Test admin functionality...
        # Automatic cleanup
```

### Customer User Testing

**❌ OLD APPROACH:**
```python
from tests.e2e.utils import (
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
    login_user
)

def test_customer_functionality(page: Page) -> None:
    # Uses hardcoded customer - may not have proper organization setup
    ensure_fresh_session(page)
    assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
    # Test customer functionality...
    # May interfere with other tests using same customer
```

**✅ NEW APPROACH:**
```python
from tests.e2e.utils import (
    TestUserManager,
    login_test_user,
    create_and_login_customer  # One-step helper
)

def test_customer_functionality(page: Page) -> None:
    with TestUserManager() as user_mgr:
        # Creates customer user AND associated organization
        customer_user, customer_org = user_mgr.create_customer_with_org()
        
        print(f"Testing with customer: {customer_user['email']}")
        print(f"Organization: {customer_org['company_name']}")
        
        ensure_fresh_session(page)
        assert login_test_user(page, customer_user)
        # Test customer functionality...
        # Both user and organization cleaned up automatically

# OR use the one-step helper:
def test_customer_functionality_onestep(page: Page) -> None:
    with TestUserManager() as user_mgr:
        ensure_fresh_session(page)
        customer_user, customer_org = create_and_login_customer(page, user_mgr)
        # Already logged in, test functionality...
        # Automatic cleanup
```

### Staff User Testing

**❌ OLD APPROACH:**
```python
# Had to use admin user for all staff testing
def test_staff_functionality(page: Page) -> None:
    ensure_fresh_session(page)
    assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    # Not testing actual staff roles, just admin
```

**✅ NEW APPROACH:**
```python
def test_support_staff_functionality(page: Page) -> None:
    with TestUserManager() as user_mgr:
        # Create specific staff role
        support_staff = user_mgr.create_staff_user(role='support')
        
        ensure_fresh_session(page)
        assert login_test_user(page, support_staff)
        # Test support-specific functionality...
        # Automatic cleanup

def test_billing_staff_functionality(page: Page) -> None:
    with TestUserManager() as user_mgr:
        billing_staff = user_mgr.create_staff_user(role='billing')
        
        ensure_fresh_session(page)
        assert login_test_user(page, billing_staff)
        # Test billing-specific functionality...
        # Automatic cleanup
```

### Multiple User Testing

**❌ OLD APPROACH:**
```python
def test_multi_user_workflow(page: Page) -> None:
    # Limited to predefined users, potential conflicts
    ensure_fresh_session(page)
    assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    # Do admin stuff...
    
    page.goto(f"{BASE_URL}/auth/logout/")
    assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)  
    # Do customer stuff...
    # No proper cleanup, users may have leftover state
```

**✅ NEW APPROACH:**
```python
def test_multi_user_workflow(page: Page) -> None:
    # Create multiple fresh users with clean state
    with test_users(
        ('admin',),
        ('customer', {'company_name': 'Test Corp'}),
        ('staff', {'role': 'billing'})
    ) as (admin, customer_data, billing_staff):
        
        customer_user, customer_org = customer_data
        
        # Test admin workflow
        ensure_fresh_session(page)
        assert login_test_user(page, admin)
        # Do admin stuff...
        
        # Test customer workflow
        ensure_fresh_session(page) 
        assert login_test_user(page, customer_user)
        # Do customer stuff with proper organization...
        
        # Test staff workflow
        ensure_fresh_session(page)
        assert login_test_user(page, billing_staff)
        # Do billing staff stuff...
        
        # All users and organizations cleaned up automatically
```

## 🔧 Step-by-Step Migration Process

### 1. Update Imports

**Remove old imports:**
```python
# Remove these
from tests.e2e.utils import (
    SUPERUSER_EMAIL,
    SUPERUSER_PASSWORD, 
    CUSTOMER_EMAIL,
    CUSTOMER_PASSWORD,
)
```

**Add new imports:**
```python
# Add these
from tests.e2e.utils import (
    TestUserManager,
    test_users,
    login_test_user,
    create_and_login_admin,
    create_and_login_customer,
)
```

### 2. Replace Hardcoded Credentials

**Find patterns like:**
```python
assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
```

**Replace with:**
```python
with TestUserManager() as user_mgr:
    admin = user_mgr.create_admin_user()
    assert login_test_user(page, admin)
    
    # OR for customers:
    customer_user, customer_org = user_mgr.create_customer_with_org()
    assert login_test_user(page, customer_user)
```

### 3. Add Context Managers

Wrap test logic in `TestUserManager` context:

```python
def test_example(page: Page) -> None:
    with TestUserManager() as user_mgr:
        # User creation and test logic here
        admin = user_mgr.create_admin_user()
        # ... rest of test
        # Automatic cleanup when context exits
```

### 4. Update Test Structure

For tests that need multiple users or complex setup, consider using the convenient `test_users()` helper:

```python
def test_complex_workflow(page: Page) -> None:
    with test_users(
        ('admin',), 
        ('customer',),
        ('staff', {'role': 'support'})
    ) as (admin, customer_data, support):
        customer_user, customer_org = customer_data
        # Test logic with all three user types
```

## 📝 Common Migration Patterns

### Pattern 1: Simple User Replacement

**Before:**
```python
def test_something(page: Page) -> None:
    ensure_fresh_session(page)
    assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    # test logic
```

**After:**
```python
def test_something(page: Page) -> None:
    with TestUserManager() as user_mgr:
        ensure_fresh_session(page)
        admin = create_and_login_admin(page, user_mgr)
        # test logic (admin already logged in)
```

### Pattern 2: Customer Organization Testing

**Before:**
```python
def test_customer_billing(page: Page) -> None:
    ensure_fresh_session(page)
    assert login_user(page, CUSTOMER_EMAIL, CUSTOMER_PASSWORD)
    # Hope customer has proper organization setup
```

**After:**
```python
def test_customer_billing(page: Page) -> None:
    with TestUserManager() as user_mgr:
        ensure_fresh_session(page)
        customer_user, customer_org = create_and_login_customer(page, user_mgr)
        
        # Guaranteed to have proper organization with known data
        print(f"Testing billing for: {customer_org['company_name']}")
        print(f"Customer ID: {customer_org['id']}")
```

### Pattern 3: Role-Specific Testing

**Before:**
```python
# Could only test with admin, not specific staff roles
def test_support_features(page: Page) -> None:
    assert login_user(page, SUPERUSER_EMAIL, SUPERUSER_PASSWORD)
    # Actually testing admin, not support staff
```

**After:**
```python
def test_support_features(page: Page) -> None:
    with TestUserManager() as user_mgr:
        support_staff = user_mgr.create_staff_user(role='support')
        
        ensure_fresh_session(page)
        assert login_test_user(page, support_staff)
        # Actually testing support staff role
```

## ⚠️ Migration Considerations

### 1. Test Isolation
- **Before:** Tests could interfere with each other using shared users
- **After:** Each test gets fresh users, eliminating interference

### 2. Database State
- **Before:** Users accumulated data over multiple test runs
- **After:** Clean database state for each test run

### 3. Parallel Testing
- **Before:** Race conditions with shared users
- **After:** Thread-safe user creation, safe for parallel execution

### 4. CI/CD Integration
- **Before:** Required pre-created test users in CI environments
- **After:** Users created dynamically, no setup required

## 🔍 Debugging and Troubleshooting

### Enable Verbose Logging
The TestUserManager provides detailed logging. Look for:
```
✅ Created admin user: admin_abc123@test.praho.local
✅ Created customer user: customer_xyz789@test.praho.local with organization: Tech Solutions 42 SRL
🧹 Cleaning up 2 session users and 1 organizations...
  🗑️ Deleted customer: 15
  🗑️ Deleted user: admin_abc123@test.praho.local
  🗑️ Deleted user: customer_xyz789@test.praho.local
✅ Session cleanup completed
```

### Common Issues

**Issue:** Django not initialized
```
❌ Failed to initialize Django: Apps aren't loaded yet.
```
**Solution:** Make sure Django settings are properly configured. The TestUserManager handles this automatically.

**Issue:** User creation fails
```
❌ Failed to create admin user: User with email admin@example.com already exists
```
**Solution:** Don't specify hardcoded emails. Let the system generate random ones.

**Issue:** Database connection issues
```
❌ Session cleanup failed: no such table: users
```
**Solution:** Ensure test database is properly migrated before running tests.

## 📚 Quick Reference

### Essential Methods

```python
# Context manager (recommended)
with TestUserManager() as user_mgr:
    admin = user_mgr.create_admin_user()
    customer_user, customer_org = user_mgr.create_customer_with_org()
    staff = user_mgr.create_staff_user(role='support')

# Convenient multi-user creation
with test_users(('admin',), ('customer',)) as (admin, customer_data):
    customer_user, customer_org = customer_data

# One-step login helpers
with TestUserManager() as user_mgr:
    admin = create_and_login_admin(page, user_mgr)
    customer_user, customer_org = create_and_login_customer(page, user_mgr)
```

### Integration with Existing Utils

```python
# Still use existing utilities
ensure_fresh_session(page)
login_test_user(page, user_credentials)  # Instead of login_user()
navigate_to_dashboard(page)

# Works with ComprehensivePageMonitor
with TestUserManager() as user_mgr:
    admin = user_mgr.create_admin_user()
    
    with ComprehensivePageMonitor(page, "admin workflow"):
        assert login_test_user(page, admin)
        # Test logic with full monitoring
```

## ✅ Migration Checklist

- [ ] Update imports (remove hardcoded credentials, add TestUserManager)
- [ ] Wrap test logic in `TestUserManager()` context manager
- [ ] Replace `login_user(page, EMAIL, PASSWORD)` with `login_test_user(page, user_creds)`
- [ ] Use `create_customer_with_org()` for customer tests needing organizations
- [ ] Consider `create_and_login_*()` helpers for simpler code
- [ ] Test migration with `pytest tests/e2e/example_test_user_manager_usage.py`
- [ ] Verify cleanup works (check logs for cleanup messages)
- [ ] Update any hardcoded user references in assertions or test data

The new system provides better isolation, reliability, and flexibility while maintaining compatibility with existing E2E testing patterns.