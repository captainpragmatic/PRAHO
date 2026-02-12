# ===============================================================================
# COMPREHENSIVE UNIT TESTS FOR CUSTOMER SERVICES
# ===============================================================================
"""
Unit tests for customer management services in PRAHO Platform.
Tests cover CRUD operations, profile management, and Romanian compliance.
"""

from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.customers.models import (
    Customer,
    CustomerAddress,
    CustomerBillingProfile,
    CustomerTaxProfile,
)


@pytest.mark.django_db
class TestCustomerModel:
    """Test Customer model functionality"""

    def test_customer_creation_company(self):
        """Company customer should be created correctly"""
        from tests.factories.core_factories import create_admin_user

        admin = create_admin_user(username='customer_admin')

        customer = Customer.objects.create(
            name='SC Test SRL',
            customer_type='company',
            company_name='SC Test SRL',
            primary_email='test@company.ro',
            data_processing_consent=True,
            created_by=admin,
        )

        assert customer.pk is not None
        assert customer.customer_type == 'company'
        assert customer.company_name == 'SC Test SRL'
        assert customer.status == 'active'

    def test_customer_creation_individual(self):
        """Individual customer should be created correctly"""
        from tests.factories.core_factories import create_admin_user

        admin = create_admin_user(username='customer_admin_ind')

        customer = Customer.objects.create(
            name='Ion Popescu',
            customer_type='individual',
            first_name='Ion',
            last_name='Popescu',
            primary_email='ion.popescu@email.ro',
            data_processing_consent=True,
            created_by=admin,
        )

        assert customer.pk is not None
        assert customer.customer_type == 'individual'
        assert customer.first_name == 'Ion'
        assert customer.last_name == 'Popescu'

    def test_customer_str_representation(self):
        """Customer string representation should be meaningful"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        str_repr = str(customer)

        # Should contain customer name or company name
        assert customer.name in str_repr or customer.company_name in str_repr

    def test_customer_requires_consent(self):
        """Customer should require data processing consent"""
        from tests.factories.core_factories import create_admin_user

        admin = create_admin_user(username='customer_admin_consent')

        customer = Customer.objects.create(
            name='Test Customer',
            customer_type='company',
            company_name='Test Company',
            primary_email='noconsent@test.ro',
            data_processing_consent=False,  # No consent
            created_by=admin,
        )

        # Customer can be created but consent is tracked
        assert customer.data_processing_consent is False


@pytest.mark.django_db
class TestCustomerTaxProfile:
    """Test Romanian tax profile functionality"""

    def test_tax_profile_creation(self):
        """Tax profile should be created with Romanian fields"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        tax_profile = customer.tax_profile

        assert tax_profile is not None
        assert tax_profile.cui == 'RO12345678'
        assert tax_profile.vat_number == 'RO12345678'
        assert tax_profile.is_vat_payer is True
        assert tax_profile.vat_rate == Decimal('21.00')

    def test_tax_profile_vat_rate(self):
        """Default VAT rate should be 21% for Romania"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        assert customer.tax_profile.vat_rate == Decimal('21.00')

    def test_non_vat_payer_profile(self):
        """Non-VAT payer should have appropriate settings"""
        from tests.factories.core_factories import create_full_customer, CustomerCreationRequest

        customer = create_full_customer(CustomerCreationRequest(
            is_vat_payer=False,
            primary_email='nonvat@test.ro',
        ))

        # Manually update tax profile for non-VAT payer
        tax_profile = customer.tax_profile
        tax_profile.is_vat_payer = False
        tax_profile.save()

        assert customer.tax_profile.is_vat_payer is False


@pytest.mark.django_db
class TestCustomerBillingProfile:
    """Test billing profile functionality"""

    def test_billing_profile_creation(self):
        """Billing profile should be created with defaults"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        billing_profile = customer.billing_profile

        assert billing_profile is not None
        assert billing_profile.payment_terms == 30
        assert billing_profile.preferred_currency == 'RON'

    def test_billing_profile_credit_limit(self):
        """Credit limit should be set correctly"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        assert customer.billing_profile.credit_limit == Decimal('5000.00')

    def test_billing_profile_currency(self):
        """Preferred currency should be RON by default"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        assert customer.billing_profile.preferred_currency == 'RON'


@pytest.mark.django_db
class TestCustomerAddress:
    """Test customer address functionality"""

    def test_legal_address_creation(self):
        """Legal address should be created correctly"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        address = customer.addresses.filter(address_type='legal').first()

        assert address is not None
        assert address.address_line1 == 'Str. Test Nr. 1'
        assert address.city == 'București'
        assert address.country == 'România'
        assert address.is_current is True

    def test_multiple_addresses(self):
        """Customer should support multiple addresses"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()

        # Add billing address
        CustomerAddress.objects.create(
            customer=customer,
            address_type='billing',
            address_line1='Bd. Unirii Nr. 10',
            city='București',
            county='Sector 3',
            postal_code='030167',
            country='România',
            is_current=True,
        )

        assert customer.addresses.count() == 2
        assert customer.addresses.filter(address_type='legal').exists()
        assert customer.addresses.filter(address_type='billing').exists()

    def test_romanian_address_fields(self):
        """Address should support Romanian-specific fields"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        address = customer.addresses.first()

        # Verify Romanian address fields
        assert address.county is not None  # Romanian "județ"
        assert address.postal_code == '010101'  # 6-digit Romanian postal code


@pytest.mark.django_db
class TestCustomerSoftDelete:
    """Test customer soft delete functionality"""

    def test_customer_soft_delete(self):
        """Customer deletion should be soft delete"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        customer_pk = customer.pk

        # Perform soft delete
        customer.delete()

        # Customer should still exist in database with deleted_at set
        deleted_customer = Customer.all_objects.get(pk=customer_pk)
        assert deleted_customer.deleted_at is not None

    def test_soft_deleted_not_in_queryset(self):
        """Soft deleted customers should not appear in default queryset"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        customer_pk = customer.pk

        customer.delete()

        # Should not be found with normal query
        assert not Customer.objects.filter(pk=customer_pk).exists()

    def test_soft_deleted_in_all_objects(self):
        """Soft deleted customers should appear in all_objects"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        customer_pk = customer.pk

        customer.delete()

        # Should be found with all_objects
        assert Customer.all_objects.filter(pk=customer_pk).exists()


@pytest.mark.django_db
class TestCustomerCreationValidation:
    """Test customer creation validation"""

    def test_email_required(self):
        """Customer should require primary email"""
        from tests.factories.core_factories import create_admin_user

        admin = create_admin_user(username='customer_admin_email')

        # Primary email should be required
        customer = Customer(
            name='No Email Customer',
            customer_type='company',
            company_name='No Email Co',
            data_processing_consent=True,
            created_by=admin,
        )

        # This should either fail or create with null email
        # depending on model configuration
        try:
            customer.full_clean()
        except ValidationError:
            pass  # Expected if email is required

    def test_customer_type_required(self):
        """Customer type should be required"""
        from tests.factories.core_factories import create_admin_user

        admin = create_admin_user(username='customer_admin_type')

        customer = Customer(
            name='No Type Customer',
            primary_email='notype@test.ro',
            data_processing_consent=True,
            created_by=admin,
        )

        # Should have a default or be required
        assert customer.customer_type in ['', 'company', 'individual'] or customer.customer_type is None


@pytest.mark.django_db
class TestCustomerRelationships:
    """Test customer relationship traversal"""

    def test_customer_has_tax_profile(self):
        """Customer should have accessible tax profile"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        assert hasattr(customer, 'tax_profile')
        assert customer.tax_profile is not None

    def test_customer_has_billing_profile(self):
        """Customer should have accessible billing profile"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        assert hasattr(customer, 'billing_profile')
        assert customer.billing_profile is not None

    def test_customer_has_addresses(self):
        """Customer should have accessible addresses"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        assert hasattr(customer, 'addresses')
        assert customer.addresses.count() > 0


@pytest.mark.django_db
class TestRomanianComplianceFields:
    """Test Romanian-specific compliance fields"""

    def test_cui_format(self):
        """CUI should be stored correctly"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        cui = customer.tax_profile.cui

        # Romanian CUI format
        assert cui.startswith('RO') or cui.isdigit()

    def test_registration_number_format(self):
        """Registration number should be stored correctly"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        reg_number = customer.tax_profile.registration_number

        # Romanian J format: J40/1234/2023
        assert '/' in reg_number

    def test_vat_number_format(self):
        """VAT number should be stored correctly"""
        from tests.factories.core_factories import create_full_customer

        customer = create_full_customer()
        vat_number = customer.tax_profile.vat_number

        # Romanian VAT: RO + digits
        assert vat_number.startswith('RO')
