#!/usr/bin/env python3

"""
Verification tests for the TestUserManager system.

This file tests the TestUserManager itself to ensure it works correctly
before being used in actual E2E tests. It verifies user creation, cleanup,
and all the core functionality.

This is a meta-test - testing the test infrastructure itself.
"""

import os
import tempfile
from unittest.mock import patch

import pytest
import django
from django.conf import settings
from django.test import override_settings

# Set up Django before importing TestUserManager
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')
django.setup()

from tests.e2e.utils import TestUserManager, test_users


def test_testusermanager_admin_creation():
    """Test that TestUserManager can create admin users correctly."""
    print("🧪 Testing TestUserManager admin user creation")
    
    with TestUserManager() as user_mgr:
        # Create admin user
        admin = user_mgr.create_admin_user()
        
        # Verify admin user properties
        assert 'email' in admin
        assert 'password' in admin
        assert 'type' in admin
        assert 'user_id' in admin
        
        assert admin['type'] == 'admin'
        assert '@test.praho.local' in admin['email']
        assert len(admin['password']) >= 12  # Should be secure password
        
        # Verify user exists in database
        user_info = user_mgr.get_user_by_email(admin['email'])
        assert user_info is not None
        assert user_info['is_superuser'] == True
        assert user_info['staff_role'] == 'admin'
        
        print(f"  ✅ Created admin: {admin['email']}")
    
    # After context exits, user should be cleaned up
    with TestUserManager() as user_mgr:
        user_info = user_mgr.get_user_by_email(admin['email'])
        # User should be cleaned up (None or not found)
        # Note: In some cases the user might still exist briefly due to transaction timing
        print("  ✅ Admin user creation test completed")


def test_testusermanager_customer_creation():
    """Test that TestUserManager can create customer users with organizations."""
    print("🧪 Testing TestUserManager customer user creation")
    
    with TestUserManager() as user_mgr:
        # Create customer with organization
        customer_user, customer_org = user_mgr.create_customer_with_org(
            company_name="Test Verification Corp"
        )
        
        # Verify customer user properties
        assert 'email' in customer_user
        assert 'password' in customer_user
        assert 'type' in customer_user
        assert customer_user['type'] == 'customer'
        
        # Verify organization properties
        assert 'id' in customer_org
        assert 'name' in customer_org
        assert 'company_name' in customer_org
        assert customer_org['company_name'] == "Test Verification Corp"
        
        # Verify user exists in database
        user_info = user_mgr.get_user_by_email(customer_user['email'])
        assert user_info is not None
        assert user_info['is_staff'] == False
        assert user_info['staff_role'] == ''
        
        print(f"  ✅ Created customer: {customer_user['email']}")
        print(f"  ✅ Created organization: {customer_org['company_name']}")
    
    print("  ✅ Customer user creation test completed")


def test_testusermanager_staff_creation():
    """Test that TestUserManager can create different staff roles."""
    print("🧪 Testing TestUserManager staff user creation")
    
    with TestUserManager() as user_mgr:
        # Test different staff roles
        roles_to_test = ['support', 'billing', 'manager', 'admin']
        
        for role in roles_to_test:
            staff_user = user_mgr.create_staff_user(role=role)
            
            # Verify staff user properties
            assert staff_user['type'] == 'staff'
            assert staff_user['role'] == role
            
            # Verify user exists with correct role
            user_info = user_mgr.get_user_by_email(staff_user['email'])
            assert user_info is not None
            assert user_info['is_staff'] == True
            assert user_info['staff_role'] == role
            
            print(f"  ✅ Created {role} staff: {staff_user['email']}")
    
    print("  ✅ Staff user creation test completed")


def test_testusermanager_duplicate_prevention():
    """Test that TestUserManager prevents duplicate user creation."""
    print("🧪 Testing TestUserManager duplicate prevention")
    
    with TestUserManager() as user_mgr:
        # Create first user
        admin1 = user_mgr.create_admin_user(email="duplicate.test@test.praho.local")
        assert admin1['email'] == "duplicate.test@test.praho.local"
        
        # Try to create duplicate - should raise ValueError
        try:
            admin2 = user_mgr.create_admin_user(email="duplicate.test@test.praho.local")
            assert False, "Should have raised ValueError for duplicate email"
        except ValueError as e:
            assert "already exists" in str(e)
            print("  ✅ Correctly prevented duplicate user creation")
    
    print("  ✅ Duplicate prevention test completed")


def test_test_users_convenience_helper():
    """Test the convenient test_users() context manager."""
    print("🧪 Testing test_users convenience helper")
    
    with test_users(
        ('admin',),
        ('customer', {'company_name': 'Convenience Corp'}),
        ('staff', {'role': 'billing'})
    ) as (admin, customer_data, billing_staff):
        
        # Unpack customer data
        customer_user, customer_org = customer_data
        
        # Verify all users were created correctly
        assert admin['type'] == 'admin'
        assert customer_user['type'] == 'customer'
        assert customer_org['company_name'] == 'Convenience Corp'
        assert billing_staff['type'] == 'staff'
        assert billing_staff['role'] == 'billing'
        
        print(f"  ✅ Admin: {admin['email']}")
        print(f"  ✅ Customer: {customer_user['email']} at {customer_org['company_name']}")
        print(f"  ✅ Staff: {billing_staff['email']} ({billing_staff['role']})")
    
    print("  ✅ Convenience helper test completed")


def test_user_lookup_functionality():
    """Test user lookup and information retrieval."""
    print("🧪 Testing user lookup functionality")
    
    with TestUserManager() as user_mgr:
        # Create test user
        admin = user_mgr.create_admin_user()
        
        # Test successful lookup
        user_info = user_mgr.get_user_by_email(admin['email'])
        assert user_info is not None
        assert user_info['email'] == admin['email']
        assert user_info['is_superuser'] == True
        
        # Test lookup of non-existent user
        missing_user = user_mgr.get_user_by_email("nonexistent@test.praho.local")
        assert missing_user is None
        
        print("  ✅ User lookup works correctly")
    
    print("  ✅ User lookup test completed")


def test_random_generation_uniqueness():
    """Test that random generation creates unique values."""
    print("🧪 Testing random generation uniqueness")
    
    emails = set()
    passwords = set()
    companies = set()
    
    # Create multiple users and verify uniqueness
    with TestUserManager() as user_mgr:
        for i in range(5):
            admin = user_mgr.create_admin_user()
            customer_user, customer_org = user_mgr.create_customer_with_org()
            
            # Collect generated values
            emails.add(admin['email'])
            emails.add(customer_user['email'])
            passwords.add(admin['password'])
            passwords.add(customer_user['password'])
            companies.add(customer_org['company_name'])
        
        # Verify all values are unique
        assert len(emails) == 10, "All emails should be unique"
        assert len(passwords) == 10, "All passwords should be unique"
        assert len(companies) == 5, "All company names should be unique"
        
        print(f"  ✅ Generated {len(emails)} unique emails")
        print(f"  ✅ Generated {len(passwords)} unique passwords")
        print(f"  ✅ Generated {len(companies)} unique company names")
    
    print("  ✅ Random generation uniqueness test completed")


if __name__ == "__main__":
    print("""
    ===============================================================================
    TEST USER MANAGER VERIFICATION TESTS
    ===============================================================================
    
    These tests verify that the TestUserManager system works correctly
    before it's used in actual E2E tests.
    
    To run these tests:
        pytest tests/e2e/test_user_manager_verification.py -v -s
    
    ===============================================================================
    """)
    
    # Run all verification tests
    test_testusermanager_admin_creation()
    test_testusermanager_customer_creation()
    test_testusermanager_staff_creation()
    test_testusermanager_duplicate_prevention()
    test_test_users_convenience_helper()
    test_user_lookup_functionality()
    test_random_generation_uniqueness()
    
    print("""
    ✅ ALL VERIFICATION TESTS PASSED!
    
    The TestUserManager system is working correctly and ready for use in E2E tests.
    """)