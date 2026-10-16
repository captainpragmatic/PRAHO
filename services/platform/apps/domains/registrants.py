"""One registrar identity rule for availability, checkout and order creation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils.translation import gettext as _

from apps.common.localisation import normalize_country_code
from apps.common.operator import operator_country

from .gateways import RegistrarGatewayFactory

if TYPE_CHECKING:
    from apps.customers.models import Customer

    from .models import Registrar


def registrant_requirements(registrar: Registrar, customer: Customer, action: str = "register") -> frozenset[str]:
    """Transfers carry an authorization key; only registration needs a registrant's identity."""
    if action != "register":
        return frozenset()
    address = customer.get_billing_address()
    country = (normalize_country_code(address.country) if address else "") or operator_country()
    return RegistrarGatewayFactory.create_gateway(registrar).registrant_requirements(customer.customer_type, country)


def missing_registrant_fields(registrar: Registrar, customer: Customer, action: str = "register") -> frozenset[str]:
    required = registrant_requirements(registrar, customer, action)
    if not required:
        return frozenset()
    profile = customer.get_tax_profile()
    return frozenset(
        field for field in required if profile is None or not str(getattr(profile, field, "") or "").strip()
    )


def registrant_identity_error() -> str:
    return _("Complete the registrant identity fields required by this domain registrar.")
