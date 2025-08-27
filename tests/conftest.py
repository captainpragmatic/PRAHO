# ===============================================================================
# PYTEST CONFIGURATION FOR PRAHO PLATFORM
# ===============================================================================
"""
Global test configuration for PRAHO Platform.

Test Structure:
- tests/ mirrors apps/ structure for app-specific tests
- tests/integration-tests/ for cross-app integration tests  
- Naming convention: test_{app}_{feature}.py

Test Discovery:
- pytest automatically discovers tests in tests/{app}/ directories
- Run specific app tests: pytest tests/billing/
- Run integration tests: pytest tests/integration-tests/
- Run all tests: pytest tests/
"""

import os

import django


def pytest_configure():
    """Configure Django settings for pytest"""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.test')

    # Configure Django
    django.setup()

# ===============================================================================
# PYTEST FIXTURES - UPDATED FOR NORMALIZED CUSTOMER MODEL
# ===============================================================================

from decimal import Decimal  # noqa: E402

import pytest  # noqa: E402
from django.contrib.auth import get_user_model  # noqa: E402

from apps.customers.models import (  # noqa: E402
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerTaxProfile,
)

User = get_user_model()

@pytest.fixture
def user():
    """Create test user"""
    return User.objects.create_user(
        username='testuser',
        email='test@pragmatichost.com',
        password='testpass123'
    )

@pytest.fixture
def admin_user():
    """Create admin user for tests"""
    return User.objects.create_user(
        username='admin_test',
        email='admin@test.ro',
        password='testpass123',
        first_name='Admin',
        last_name='User',
        is_staff=True,
        is_superuser=True,
        staff_role='admin'
    )

@pytest.fixture
def romanian_customer(admin_user):
    """Create test Romanian customer with normalized structure"""
    # Create core customer
    customer = Customer.objects.create(
        name='SC Test SRL',
        customer_type='company',
        company_name='SC Test SRL',
        primary_email='contact@test.ro',
        primary_phone='+40721234567',
        data_processing_consent=True,
        created_by=admin_user
    )

    # Create tax profile
    CustomerTaxProfile.objects.create(
        customer=customer,
        cui='RO12345678',
        vat_number='RO12345678',
        registration_number='J40/1234/2023',
        is_vat_payer=True,
        vat_rate=Decimal('19.00')
    )

    # Create billing profile
    CustomerBillingProfile.objects.create(
        customer=customer,
        payment_terms=30,
        credit_limit=Decimal('5000.00'),
        preferred_currency='RON'
    )

    # Create legal address
    CustomerAddress.objects.create(
        customer=customer,
        address_type='legal',
        address_line1='Str. Test Nr. 1',
        city='București',
        county='Sector 1',
        postal_code='010101',
        country='România',
        is_current=True
    )

    return customer

@pytest.fixture
def authenticated_client(client, user):
    """Client logged in with test user"""
    client.force_login(user)
    return client

# ===============================================================================
# TEST MARKS - DEFINED IN PYPROJECT.TOML
# ===============================================================================
"""
Test marks are configured in pyproject.toml [tool.pytest.ini_options] markers.
Use with: @pytest.mark.slow, @pytest.mark.integration, etc.
"""
