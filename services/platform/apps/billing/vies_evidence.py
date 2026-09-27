"""Evidence required for a reverse-charge decision."""

from __future__ import annotations

import logging
import re
import unicodedata
from datetime import timedelta
from typing import TYPE_CHECKING

from django.db.models import Exists, OuterRef, Q, QuerySet, Value
from django.db.models.functions import Replace, Upper
from django.utils import timezone
from django.utils.translation import gettext as _

logger = logging.getLogger(__name__)

_NAME_STOPWORDS = frozenset(
    [
        "srl",
        "sa",
        "gmbh",
        "ag",
        "ltd",
        "limited",
        "llc",
        "bv",
        "nv",
        "sarl",
        "sas",
        "spa",
        "sp",
        "zoo",
        "oy",
        "ab",
        "kft",
        "sl",
        "lda",
        "ug",
        "kg",
        "ohg",
        "plc",
        "inc",
        "co",
        "company",
        "europe",
        "international",
        "trading",
        "group",
        "holding",
        "services",
        "solutions",
        "consulting",
        "enterprises",
    ]
)

if TYPE_CHECKING:
    from apps.customers.models import CustomerTaxProfile


def normalize_vat_number(raw: object) -> str:
    """Uppercase and remove spaces, dots and hyphens, or return empty for a falsy value."""
    # Keep these separators aligned with the revalidation sweep's SQL.
    return re.sub(r"[ .-]", "", str(raw).upper()) if raw else ""


def profile_vat_identity(tax_profile: CustomerTaxProfile) -> tuple[str, str]:
    """Issuing country and body of the profile's number, resolved against the billing country.

    An unprefixed number belongs to the customer's billing country, not to the supplier's,
    and Greece is EL for VIES whatever the address says.
    """
    from apps.billing.tax_evidence import vat_identity  # noqa: PLC0415

    billing_address = tax_profile.customer.get_billing_address()
    country = (billing_address.country if billing_address else "") or "RO"
    return vat_identity(str(tax_profile.vat_number or ""), country)


def vat_number_matches_country(vat_number: object, country_code: str) -> bool:
    """Bind the issuing country to the billing country; GR and EL are equivalent."""
    from apps.common.eu_vat_validator import parse_vat_number  # noqa: PLC0415

    if not vat_number or not country_code.strip():
        return False
    country = country_code.strip().upper()
    country = "EL" if country == "GR" else country
    issuing_country, digits = parse_vat_number(str(vat_number), default_country=country)
    issuing_country = "EL" if issuing_country == "GR" else issuing_country
    return bool(digits) and issuing_country == country


def _name_tokens(name: str) -> set[str]:
    decomposed = unicodedata.normalize("NFKD", name.casefold())
    unaccented = "".join(character for character in decomposed if not unicodedata.combining(character))
    # Joining dotted abbreviations makes G.m.b.H. and GmbH equivalent.
    words = re.sub(r"[^\w\s]", " ", unaccented.replace(".", ""), flags=re.UNICODE).replace("_", " ").split()
    return set(words) - _NAME_STOPWORDS


def vies_name_matches(vies_name: str, billing_name: str) -> bool:
    """Require every distinctive invoiced token in the available VIES name."""
    if vies_name.strip().casefold() in {"", "---", "-", "n/a"}:
        return True
    verified = _name_tokens(vies_name)
    invoiced = _name_tokens(billing_name)
    return not verified or not invoiced or invoiced <= verified


def vies_refusal_reason(  # noqa: PLR0911  # one return per refusal reason, in policy order
    tax_profile: CustomerTaxProfile | None, vat_number: object, *, billing_name: str | None = None
) -> str:
    """Explain the evidence decision without recording a refusal."""
    from apps.billing.config import (  # noqa: PLC0415
        get_vies_evidence_max_age_days,
        reverse_charge_requires_consultation_reference,
        reverse_charge_requires_name_match,
    )

    if tax_profile is None:
        return "missing_profile"
    if tax_profile.vies_verification_status != tax_profile.VIESVerificationStatus.VALID:
        return "status_not_valid"
    if normalize_vat_number(tax_profile.vat_number) != normalize_vat_number(vat_number) or not normalize_vat_number(
        vat_number
    ):
        return "number_mismatch"
    if tax_profile.vies_verified_at is None:
        return "missing_timestamp"
    if tax_profile.vies_verified_at < timezone.now() - timedelta(days=get_vies_evidence_max_age_days()):
        return "stale_evidence"
    if reverse_charge_requires_consultation_reference() and not tax_profile.vies_consultation_reference.strip():
        return "missing_consultation_reference"
    if reverse_charge_requires_name_match():
        name = billing_name if billing_name is not None else tax_profile.customer.get_billing_name()
        if not vies_name_matches(tax_profile.vies_verified_name, name):
            return "name_mismatch"
    return ""


def vies_verified_for(
    tax_profile: CustomerTaxProfile | None, vat_number: object, *, billing_name: str | None = None
) -> bool:
    """Decide entitlement and retain each refusal as an audit row, independently of any invoice.

    Cart previews recalculate on every view, so an identical refusal within the last hour is
    not recorded twice; the first one of each hour is what the staff tax page lists.
    """
    from apps.audit.models import AuditEvent  # noqa: PLC0415
    from apps.audit.services import AuditService  # noqa: PLC0415

    reason = vies_refusal_reason(tax_profile, vat_number, billing_name=billing_name)
    if not reason:
        return True
    customer_id = str(tax_profile.customer_id) if tax_profile and tax_profile.customer_id else None
    number = str(vat_number or "")
    logger.warning("🚨 [VAT] VIES evidence refused: %s (customer=%s, VAT=%s)", reason, customer_id, number)
    recently_recorded = AuditEvent.objects.filter(
        action="vies_evidence_refused",
        timestamp__gte=timezone.now() - timedelta(hours=1),
        metadata__customer_id=customer_id,
        metadata__reason=reason,
        metadata__vat_number=number,
    ).exists()
    if not recently_recorded:
        AuditService.log_simple_event(
            event_type="vies_evidence_refused",
            content_object=tax_profile if tax_profile is not None and tax_profile.pk else None,
            actor_type="system",
            description=_("VIES evidence refused: %(reason)s") % {"reason": reason},
            metadata={"reason": reason, "customer_id": customer_id, "vat_number": number},
        )
    return False


def profiles_needing_vies_evidence() -> QuerySet[CustomerTaxProfile]:
    """Select incomplete valid profiles in SQL, including profiles without a cache row."""
    from apps.billing.config import get_vies_evidence_max_age_days  # noqa: PLC0415
    from apps.billing.tax_models import VATValidation  # noqa: PLC0415
    from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

    validations = VATValidation.objects.filter(
        Q(full_vat_number=OuterRef("normalized_vat_number")) | Q(vat_number=OuterRef("normalized_vat_number"))
    )
    return (
        CustomerTaxProfile.objects.exclude(vat_number="")
        .annotate(
            normalized_vat_number=Upper(
                Replace(
                    Replace(Replace("vat_number", Value(" "), Value("")), Value("-"), Value("")),
                    Value("."),
                    Value(""),
                )
            ),
            has_vat_validation=Exists(validations),
        )
        .filter(
            vies_verification_status=CustomerTaxProfile.VIESVerificationStatus.VALID,
        )
        .filter(
            Q(vies_verified_at__isnull=True)
            | Q(vies_verified_at__lt=timezone.now() - timedelta(days=get_vies_evidence_max_age_days()))
            | Q(vies_consultation_reference="")
            | Q(has_vat_validation=False)
        )
    )
