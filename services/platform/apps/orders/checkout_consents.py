"""What a customer accepts when placing an order (ADR-0061).

Every order names the Terms of Service release its customer accepted: the one the checkout page
showed, refused once another is in force. An EU consumer (an individual, not a business) must also
ask for the services to start within the 14-day withdrawal period: without that request a trader may
not begin performing (Directive 2011/83/EU, arts. 7(3), 8(8) and 16), and hosting starts at once.
Preflight tells the portal both, so the checkout page shows exactly what is checked here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from django.utils.translation import gettext_lazy as _

from apps.common.legal import (
    LegalDocument,
    any_legal_document_in_force,
    current_legal_document,
    legal_document_in_force,
)
from apps.common.localisation import LANGUAGES
from apps.common.operator import operator_in_eu
from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from uuid import UUID

    from apps.customers.models import Customer

CheckoutRefusalCode = Literal["terms_required", "terms_changed", "terms_unavailable", "early_start_required"]

# Why ordering waits while no Terms of Service are in force.
ORDERING_UNAVAILABLE = _("Ordering opens once the Terms of Service are published.")


@dataclass(frozen=True)
class CheckoutConsents:
    terms: LegalDocument
    early_start_requested: bool


def early_start_required(customer: Customer) -> bool:
    """Whether this customer must ask for the services to start within the withdrawal period.

    A consumer is a customer that is not a business, as the VAT rules decide (Customer.is_business).
    """
    return operator_in_eu() and not customer.is_business


def checkout_requirements(customer: Customer, language: object) -> tuple[dict[str, Any], list[str]]:
    """What the checkout page shows and sends back, and why no order can be placed yet, if so.

    The page shows the terms release in force in the visitor's language and, for an EU consumer,
    asks for an early start. While no Terms of Service are in force, ordering waits.
    """
    terms = current_legal_document(
        LegalDocument.Kind.TERMS, language if isinstance(language, str) and language in LANGUAGES else ""
    )
    requirements = {
        "terms_document": terms.reference() if terms else None,
        "early_start_required": early_start_required(customer),
    }
    return requirements, [] if terms else [str(ORDERING_UNAVAILABLE)]


def accepted_checkout_consents(
    customer: Customer, terms_document_id: UUID | None, early_start_requested: bool
) -> Result[CheckoutConsents, CheckoutRefusalCode]:
    """The consents an order request carries, or why the order cannot be placed with them."""
    if terms_document_id is None:
        return Err("terms_required")
    terms = legal_document_in_force(terms_document_id, LegalDocument.Kind.TERMS)
    if terms is None:
        return Err("terms_changed" if any_legal_document_in_force(LegalDocument.Kind.TERMS) else "terms_unavailable")
    if early_start_required(customer) and not early_start_requested:
        return Err("early_start_required")
    return Ok(CheckoutConsents(terms=terms, early_start_requested=early_start_requested))
