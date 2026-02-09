# ===============================================================================
# TEST FACTORIES - CENTRALIZED TEST DATA GENERATION
# ===============================================================================
"""
Factory module for generating test data across PRAHO Platform.

Usage:
    from tests.factories import UserFactory, CustomerFactory, OrderFactory

    user = UserFactory()
    customer = CustomerFactory(created_by=user)
    order = OrderFactory(customer=customer)
"""

from tests.factories.billing_factories import (
    PaymentCreationRequest,
    create_currency,
    create_customer,
    create_invoice,
    create_payment,
    create_payment_legacy,
)

__all__ = [
    # Billing factories
    'PaymentCreationRequest',
    'create_currency',
    'create_customer',
    'create_invoice',
    'create_payment',
    'create_payment_legacy',
]
