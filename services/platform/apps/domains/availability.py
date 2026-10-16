"""Availability and TLD prices shared by the staff and signed portal endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from django.utils.translation import gettext as _

from apps.billing.currency_policy import get_selling_currency_policy
from apps.common.types import Err, Ok, Result

from .domain_names import canonicalize_domain_name
from .models import Domain
from .registrants import registrant_requirements
from .services import DomainRegistrarGateway, DomainValidationService, RegistrarService, TLDService

if TYPE_CHECKING:
    from apps.customers.models import Customer


class DomainAvailabilityService:
    @staticmethod
    def check(
        domain_name: str, *, customer: Customer | None = None, action: str = "register"
    ) -> Result[dict[str, object], str]:
        if action not in ("register", "transfer"):
            return Err(_("Choose to register or transfer the domain."))
        valid, error = DomainValidationService.validate_domain_name(domain_name)
        if not valid:
            return Err(str(error))
        name = canonicalize_domain_name(domain_name)
        extension = DomainValidationService.extract_tld_from_domain(name)
        tld = TLDService.get_tld_pricing(extension)
        if tld is None:
            return Err(_("This domain extension is not offered."))
        registrar = RegistrarService.select_best_registrar_for_tld(tld)
        currency = get_selling_currency_policy().currency_code
        periods: list[dict[str, int | str]] = []
        pricing: dict[str, object] = {}
        try:
            for years in range(tld.min_registration_period, tld.max_registration_period + 1):
                cost = TLDService.calculate_domain_cost(tld, years, False, currency_code=currency)
                privacy = TLDService.calculate_domain_cost(tld, years, True, currency_code=currency)
                periods.append(
                    {
                        "years": years,
                        "total_cost_cents": cost["total_cost_cents"],
                        "currency": currency,
                        "whois_cost_cents": privacy["whois_cost_cents"],
                    }
                )
                pricing[f"{years}_year" if years == 1 else f"{years}_years"] = cost
            transfer = TLDService.calculate_domain_cost(tld, 1, False, action="transfer", currency_code=currency)
        except ValueError:
            return Err(_("Current prices are unavailable. Please try again later."))
        available = False
        confirmed = True
        local = Domain.objects.filter(name=name).exists()
        if registrar is not None and not local:
            confirmed, available = DomainRegistrarGateway.check_domain_availability(registrar, name)
        required = (
            registrant_requirements(registrar, customer, action)
            if registrar is not None and customer is not None
            else frozenset()
        )
        data: dict[str, object] = {
            "success": True,
            "domain_name": name,
            "tld_extension": extension,
            "orderable": registrar is not None,
            "available": available,
            "message": _("Domain is available") if available else _("Domain is not available"),
            "register_price_cents": periods[0]["total_cost_cents"],
            "transfer_price_cents": transfer["total_cost_cents"],
            "currency": currency,
            "requires": sorted(required),
            "pricing": pricing,
            "registration_periods": periods,
            "whois_privacy_available": tld.whois_privacy_available,
            "registrar": registrar.display_name if registrar else "",
        }
        if not confirmed:
            error_message = _("Could not verify domain availability. Please try again.")
            data.update({"success": False, "available": False, "error": error_message, "message": error_message})
        return Ok(data)
