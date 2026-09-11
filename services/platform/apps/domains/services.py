# ===============================================================================
# DOMAIN MANAGEMENT SERVICES - BUSINESS LOGIC LAYER
# ===============================================================================
"""
PRAHO Platform - Domain Management Services

Provides business logic for domain operations including:
- Domain registration, renewal, and transfer
- DNS zone management and nameserver updates
- Registrar integration and failover
- Domain expiration monitoring and auto-renewal
- WHOIS privacy and domain locking
- Cost tracking and profit margin analysis
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal, TypedDict, cast
from uuid import UUID

from django.db import transaction
from django.db.models import Min, Q, QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django_fsm import ConcurrentTransition, TransitionNotAllowed

from apps.common.types import Err, Ok, Result, Retriability, retriability_of
from apps.settings.services import SettingsService

from .domain_names import canonicalize_domain_name, longest_matching_tld_suffix
from .models import TLD, Domain, DomainOperation, DomainOrderItem, Registrar

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.orders.models import Order

    from .gateways import BaseRegistrarGateway, DomainInfoResult, RegistrarAPIError

logger = logging.getLogger(__name__)

# Module-level default for WHOIS privacy price
_DEFAULT_WHOIS_PRIVACY_PRICE_CENTS = 500

# Domain name validation constants
MIN_DOMAIN_NAME_LENGTH = 3  # Minimum length for domain names
MAX_DOMAIN_NAME_LENGTH = 253  # Maximum length per RFC 1035

# The accepted-but-unconfirmed registration outcome travels through the Err channel
# (the Ok contract means "active"), but callers must be able to distinguish it from
# a real rejection — shared constant so views compare against the SAME lazy string.
REGISTRATION_PENDING_MESSAGE = _("Registration accepted by the registrar and awaiting confirmation — do not resubmit.")


@dataclass
class DomainRegistrationConfig:
    """Configuration for domain registration"""

    customer: Any
    domain_name: str
    tld: Any
    registrar: Any
    registrant_data: dict[str, Any]
    years: int = 1
    whois_privacy: bool = False
    auto_renew: bool = True


# Minimal country-name → ISO 3166-1 alpha-2 mapping for the registrant address.
# The platform is Romania-first; unrecognized already-2-letter codes pass through.
_COUNTRY_NAME_TO_CODE = {
    "românia": "RO",
    "romania": "RO",
    "moldova": "MD",
    "republica moldova": "MD",
}


def _country_to_iso_code(country: str) -> str:
    """Best-effort ISO alpha-2 code from a free-text country field."""
    normalized = country.strip().lower()
    if normalized in _COUNTRY_NAME_TO_CODE:
        return _COUNTRY_NAME_TO_CODE[normalized]
    if len(country.strip()) == 2:  # noqa: PLR2004  # already an alpha-2 code
        return country.strip().upper()
    return ""


# ===============================================================================
# DOMAIN REPOSITORY PATTERN
# ===============================================================================


class DomainRepository:
    """
    🏷️ Data access layer for domain operations

    Provides optimized queries and data filtering for domain management.
    """

    @staticmethod
    def get_customer_domains(customer: Customer) -> QuerySet[Domain]:
        """📋 Get all domains for a customer with optimized queries"""

        return (
            Domain.objects.filter(customer=customer)
            .select_related("tld", "registrar", "customer")
            .order_by("-created_at")
        )

    @staticmethod
    def get_expiring_domains(days: int = 30) -> QuerySet[Domain]:
        """⚠️ Get domains expiring within specified days"""

        cutoff_date = timezone.now() + timedelta(days=days)
        return Domain.objects.filter(
            status="active", expires_at__lte=cutoff_date, expires_at__gt=timezone.now()
        ).select_related("customer", "tld", "registrar")

    @staticmethod
    def get_auto_renewal_candidates() -> QuerySet[Domain]:
        """🔄 Get domains eligible for auto-renewal"""

        # Domains expiring in 7 days or less, with auto_renew enabled
        renewal_cutoff = timezone.now() + timedelta(days=7)
        return Domain.objects.filter(
            status="active", auto_renew=True, expires_at__lte=renewal_cutoff, expires_at__gt=timezone.now()
        ).select_related("customer", "tld", "registrar")

    @staticmethod
    def search_domains(query: str, customer: Customer | None = None) -> QuerySet[Domain]:
        """🔍 Search domains by name with optional customer filter"""

        queryset = Domain.objects.filter(name__icontains=query).select_related("customer", "tld", "registrar")

        if customer:
            queryset = queryset.filter(customer=customer)

        return queryset

    @staticmethod
    def get_registrar_domains(registrar: Registrar, status: str | None = None) -> QuerySet[Domain]:
        """🏢 Get domains managed by specific registrar"""

        queryset = Domain.objects.filter(registrar=registrar).select_related("customer", "tld")

        if status:
            queryset = queryset.filter(status=status)

        return queryset.order_by("-expires_at")


# ===============================================================================
# DOMAIN VALIDATION SERVICE
# ===============================================================================


class DomainValidationService:
    """
    ✅ Domain validation and availability checking service

    Provides validation for domain names and checks availability.
    """

    @staticmethod
    def validate_domain_name(  # Complexity: multi-step workflow  # noqa: PLR0911  # Complexity: multi-step business logic
        domain_name: str,
    ) -> tuple[bool, str]:
        """🔍 Validate domain name format and characters"""
        if not domain_name:
            return False, cast(str, _("Domain name is required"))

        # Remove leading/trailing whitespace
        domain_name = domain_name.strip().lower()

        # Reject non-ASCII before any other check. str.isalnum() is True for Unicode
        # letters, so a Cyrillic/Greek homograph would otherwise pass the character
        # check below and be forwarded verbatim to the registrar. IDNs must be
        # punycode-encoded (ASCII) by the caller.
        if not domain_name.isascii():
            return False, cast(str, _("Domain name must be ASCII (punycode-encode internationalized domains)"))

        # Check length
        if len(domain_name) < MIN_DOMAIN_NAME_LENGTH:
            return False, cast(str, _("Domain name too short (minimum 3 characters)"))
        if len(domain_name) > MAX_DOMAIN_NAME_LENGTH:
            return False, cast(str, _("Domain name too long (maximum 253 characters)"))

        # Check for valid characters (letters, numbers, dots, hyphens)
        if not all(c.isalnum() or c in ".-" for c in domain_name):
            return False, cast(str, _("Domain name contains invalid characters"))

        # Check for proper structure
        if ".." in domain_name:
            return False, cast(str, _("Domain name cannot contain consecutive dots"))
        if domain_name.startswith("-") or domain_name.endswith("-"):
            return False, cast(str, _("Domain name cannot start or end with hyphen"))
        if domain_name.startswith(".") or domain_name.endswith("."):
            return False, cast(str, _("Domain name cannot start or end with dot"))

        # Must contain at least one dot (TLD)
        if "." not in domain_name:
            return False, cast(str, _("Domain name must include TLD (e.g., .com, .ro)"))

        return True, ""

    @staticmethod
    def extract_tld_from_domain(domain_name: str) -> str:
        """🌐 Resolve the longest configured TLD suffix for a domain name."""
        if "." not in domain_name:
            return ""
        configured_extensions = TLD.objects.values_list("extension", flat=True)
        resolved = longest_matching_tld_suffix(domain_name, configured_extensions)
        return resolved or domain_name.rsplit(".", maxsplit=1)[-1].lower()

    @staticmethod
    def is_romanian_domain(domain_name: str) -> bool:
        """🇷🇴 Check if domain is Romanian (.ro, .com.ro, etc.)"""
        romanian_tlds = ["ro", "com.ro", "org.ro", "info.ro", "arts.ro", "firm.ro"]
        domain_lower = domain_name.lower()
        return any(domain_lower.endswith(f".{tld}") for tld in romanian_tlds)


# ===============================================================================
# TLD MANAGEMENT SERVICE
# ===============================================================================


class TLDService:
    """
    🌐 TLD management and pricing service

    Handles TLD configuration, pricing, and registrar assignments.
    """

    @staticmethod
    def get_available_tlds() -> QuerySet[TLD]:
        """📋 Get all active TLDs with pricing"""

        return (
            TLD.objects.filter(is_active=True)
            .prefetch_related("registrar_assignments__registrar")
            .order_by("extension")
        )

    @staticmethod
    def get_featured_tlds() -> QuerySet[TLD]:
        """⭐ Get featured TLDs for homepage"""

        return TLD.objects.filter(is_active=True, is_featured=True).order_by("registration_price_cents")

    @staticmethod
    def get_tld_pricing(tld_extension: str) -> TLD | None:
        """💰 Get TLD pricing and configuration"""

        try:
            return TLD.objects.get(extension=tld_extension.lower(), is_active=True)
        except TLD.DoesNotExist:
            return None

    @staticmethod
    def validate_registration_period(tld: TLD, years: int) -> str | None:
        """Return a customer-safe error when ``years`` violates TLD policy."""
        if tld.min_registration_period <= years <= tld.max_registration_period:
            return None
        return str(
            _("Registration period for .{tld} must be between {min} and {max} years").format(
                tld=tld.extension,
                min=tld.min_registration_period,
                max=tld.max_registration_period,
            )
        )

    @staticmethod
    def validate_renewal_period(tld: TLD, years: int) -> str | None:
        """Return a customer-safe error when a renewal violates TLD policy."""
        if tld.min_registration_period <= years <= tld.max_registration_period:
            return None
        return str(
            _("Renewal period for .{tld} must be between {min} and {max} years").format(
                tld=tld.extension,
                min=tld.min_registration_period,
                max=tld.max_registration_period,
            )
        )

    @staticmethod
    def calculate_domain_cost(
        tld: TLD,
        years: int,
        include_whois_privacy: bool = False,
        *,
        action: Literal["register", "renew"] = "register",
    ) -> dict[str, Any]:
        """💰 Calculate total domain cost with options"""
        unit_price_cents = tld.registration_price_cents if action == "register" else tld.renewal_price_cents
        base_cost_cents = unit_price_cents * years
        whois_cost_cents = 0

        # Add WHOIS privacy cost if requested and available
        if include_whois_privacy and tld.whois_privacy_available:
            whois_privacy_price = SettingsService.get_integer_setting(
                "domains.whois_privacy_price_cents", _DEFAULT_WHOIS_PRIVACY_PRICE_CENTS
            )
            whois_cost_cents = whois_privacy_price * years

        total_cost_cents = base_cost_cents + whois_cost_cents

        return {
            "base_cost_cents": base_cost_cents,
            "base_cost": base_cost_cents / 100,
            "whois_cost_cents": whois_cost_cents,
            "whois_cost": whois_cost_cents / 100,
            "total_cost_cents": total_cost_cents,
            "total_cost": total_cost_cents / 100,
            "years": years,
            "tld_extension": tld.extension,
        }


# ===============================================================================
# REGISTRAR SERVICE
# ===============================================================================


class RegistrarService:
    """
    🏢 Registrar management and API integration service

    Handles registrar selection, failover, and API communication.
    """

    @staticmethod
    def get_primary_registrar_for_tld(tld: TLD) -> Registrar | None:
        """🥇 Get primary registrar for TLD"""
        assignment = (
            tld.registrar_assignments.filter(is_primary=True, is_active=True, registrar__status="active")
            .select_related("registrar")
            .first()
        )

        return assignment.registrar if assignment else None

    @staticmethod
    def get_fallback_registrars_for_tld(tld: TLD) -> QuerySet[Registrar]:
        """🔄 Get fallback registrars for TLD in priority order"""

        return Registrar.objects.filter(
            tld_assignments__tld=tld,
            tld_assignments__is_active=True,
            tld_assignments__is_primary=False,
            status="active",
        ).order_by("tld_assignments__priority")

    @staticmethod
    def select_best_registrar_for_tld(tld: TLD) -> Registrar | None:
        """🎯 Select best available registrar for TLD"""
        # Try primary first
        primary = RegistrarService.get_primary_registrar_for_tld(tld)
        if primary:
            return primary

        # Fall back to highest priority backup
        fallbacks = RegistrarService.get_fallback_registrars_for_tld(tld)
        return fallbacks.first()

    @staticmethod
    def sync_all_registrars() -> int:
        """🔄 Sync all registrars' stats (placeholder).

        - Updates `total_domains` by counting related domains
        - Sets `last_sync_at` to current time
        - Clears `last_error`

        Returns number of registrars updated.
        """
        updated = 0
        for registrar in Registrar.objects.all():
            try:
                total = registrar.domains.count()
                registrar.total_domains = total
                registrar.last_sync_at = timezone.now()
                registrar.last_error = ""
                registrar.save(update_fields=["total_domains", "last_sync_at", "last_error", "updated_at"])
                updated += 1
            except Exception as e:
                logger.error(f"🔥 [Registrar] Sync failed for {registrar.name}: {e}")
                registrar.last_error = str(e)
                registrar.last_sync_at = timezone.now()
                registrar.save(update_fields=["last_error", "last_sync_at", "updated_at"])

        logger.info(f"✅ [Registrar] Synced {updated} registrars")
        return updated


# ===============================================================================
# DOMAIN LIFECYCLE SERVICE
# ===============================================================================


class DomainLifecycleService:
    """
    🔄 Domain lifecycle management service

    Handles domain registration, renewal, transfer, and expiration workflows.
    """

    @staticmethod
    def create_domain_registration(
        customer: Customer, domain_name: str, years: int = 1, whois_privacy: bool = False, auto_renew: bool = True
    ) -> Result[Domain, str]:
        """Create new domain registration.

        Returns Ok(Domain) on success, Err(message) on failure.
        """
        # Run all validation checks
        validation_result = DomainLifecycleService._validate_registration_preconditions(domain_name)
        if validation_result is not None:
            return Err(validation_result)

        # Get validated components
        components = DomainLifecycleService._get_registration_components(domain_name)
        if components.is_err():
            return Err(components.unwrap_err())

        tld, registrar = components.unwrap()

        period_error = TLDService.validate_registration_period(tld, years)
        if period_error is not None:
            return Err(period_error)

        # Build + validate registrant data BEFORE creating any row, so a customer
        # missing required contact/tax data is rejected without leaving an orphan
        # pending domain and without a blank-data call to the registrar.
        registrant_result = DomainLifecycleService._build_registrant_data(customer)
        if registrant_result.is_err():
            return Err(registrant_result.unwrap_err())

        config = DomainRegistrationConfig(
            customer=customer,
            domain_name=domain_name,
            tld=tld,
            registrar=registrar,
            registrant_data=registrant_result.unwrap(),
            years=years,
            whois_privacy=whois_privacy,
            auto_renew=auto_renew,
        )
        return DomainLifecycleService._execute_domain_registration(config)

    @staticmethod
    def _validate_registration_preconditions(domain_name: str) -> str | None:
        """Validate all preconditions for domain registration."""
        is_valid, error_msg = DomainValidationService.validate_domain_name(domain_name)
        if not is_valid:
            return error_msg

        if Domain.objects.filter(name=canonicalize_domain_name(domain_name)).exists():
            return cast(str, _("Domain is already registered in the system"))

        return None

    @staticmethod
    def _get_registration_components(domain_name: str) -> Result[tuple[Any, Any], str]:
        """Get TLD and registrar for domain registration."""
        tld_extension = DomainValidationService.extract_tld_from_domain(domain_name)
        tld = TLDService.get_tld_pricing(tld_extension)
        if not tld:
            return Err(cast(str, _(f"TLD '.{tld_extension}' is not supported")))

        registrar = RegistrarService.select_best_registrar_for_tld(tld)
        if not registrar:
            return Err(cast(str, _("No available registrar for this TLD")))

        return Ok((tld, registrar))

    @staticmethod
    def _execute_domain_registration(config: DomainRegistrationConfig) -> Result[Domain, str]:
        from .operation_services import DomainOperationService  # noqa: PLC0415

        try:
            return DomainOperationService.register(config)
        except Exception:
            logger.exception("Registration bookkeeping failed for %s", config.domain_name)
            return Err("Could not record registration; review its status before retrying.")

    @staticmethod
    def _build_registrant_data(customer: Customer) -> Result[dict[str, Any], str]:
        """Assemble registrar-ready registrant data from the customer, address, and tax profile.

        Produces exactly the keys the Gandi/ROTLD mappers read (first_name, last_name,
        email, phone, address, city, postal_code, country_code, entity_type,
        company_name, cui, cnp) and validates that every registrar-required field is
        present. Returns Err(message) listing any missing fields so registration is
        rejected in PRAHO instead of sending blank contact data to the registrar.
        """
        entity_type = "company" if customer.customer_type == "company" else "individual"
        address = customer.get_billing_address()
        tax = customer.get_tax_profile()

        name_parts = (customer.name or "").strip().split(None, 1)
        first_name = name_parts[0] if name_parts else ""
        last_name = name_parts[1] if len(name_parts) > 1 else ""

        data: dict[str, Any] = {
            "first_name": first_name,
            "last_name": last_name,
            "email": customer.primary_email or "",
            "phone": customer.primary_phone or "",
            "address": address.address_line1 if address else "",
            "city": address.city if address else "",
            "postal_code": address.postal_code if address else "",
            "country_code": _country_to_iso_code(address.country) if address else "",
            "entity_type": entity_type,
            "company_name": customer.company_name or "",
            "cui": tax.cui if tax else "",
            "cnp": tax.cnp if tax else "",
            "registration_number": tax.registration_number if tax else "",
        }

        # Required for every registrant, plus entity-specific identity fields.
        required = ["first_name", "email", "phone", "address", "city", "postal_code", "country_code"]
        required.append("company_name" if entity_type == "company" else "last_name")

        missing = [field for field in required if not data[field]]
        if missing:
            return Err(
                cast(str, _("Cannot register: customer is missing required registrant data: {fields}")).format(
                    fields=", ".join(missing)
                )
            )
        return Ok(data)

    @staticmethod
    def _validate_renewal_preconditions(domain: Domain) -> str | None:
        """Return an error message if the domain cannot be renewed, else None."""
        if domain.status != "active":
            return cast(str, _("Domain must be active to renew"))
        if not domain.expires_at:
            return cast(str, _("Domain expiration date is not set"))
        if not domain.registrar_domain_id:
            # No registrar record to renew against — a local-only extension would be
            # a lie about the registrar's expiry.
            return cast(str, _("Domain has no registrar record; cannot renew"))
        return None

    @staticmethod
    def process_domain_renewal(
        domain: Domain, years: int = 1, idempotency_token: str | None = None
    ) -> Result[str, str]:
        from .operation_services import DomainOperationService  # noqa: PLC0415

        try:
            return DomainOperationService.renew(domain, years, idempotency_token)
        except Exception:
            logger.exception("Renewal bookkeeping failed for %s", domain.name)
            return Err("Could not record renewal; review its status before retrying.")

    @staticmethod
    def update_domain_expiration(domain: Domain, new_expiration: datetime) -> Result[bool, str]:
        """Update domain expiration date (from registrar sync)."""
        try:
            domain.expires_at = new_expiration
            domain.save(update_fields=["expires_at", "updated_at"])

            logger.info("Updated expiration for %s: %s", domain.name, new_expiration)
            return Ok(True)

        except Exception as e:
            logger.error("Failed to update expiration for %s: %s", domain.name, e)
            return Err(cast(str, _("Failed to update domain expiration")))

    # -- Phase 2: Transfer, nameservers, lock --------------------------------

    @staticmethod
    def initiate_transfer(  # noqa: PLR0911  # multi-outcome lifecycle: gateway/registrant/TLD/retriability exits
        domain_name: str, epp_code: str, customer: Customer, registrar: Registrar
    ) -> Result[DomainOperation, str]:
        """Initiate inbound domain transfer (two-phase: DB record + registrar submit)."""
        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415
        from .operation_services import DomainOperationService  # noqa: PLC0415

        try:
            gateway = RegistrarGatewayFactory.create_gateway(registrar)
        except ValueError:
            return Err(f"No gateway for registrar {registrar.name}")

        # Gandi requires an owner contact on transfer-in; validate registrant data
        # BEFORE creating any row so incomplete customer data fails with an
        # actionable message instead of a registrar rejection.
        registrant_result = DomainLifecycleService._build_registrant_data(customer)
        if registrant_result.is_err():
            return Err(registrant_result.unwrap_err())
        registrant_data = registrant_result.unwrap()

        # Phase 1: create Domain + DomainOperation records
        try:
            with transaction.atomic():
                tld_ext = DomainValidationService.extract_tld_from_domain(domain_name)
                tld = TLDService.get_tld_pricing(tld_ext)
                if not tld:
                    return Err(cast(str, _(f"TLD '.{tld_ext}' is not supported")))

                domain = Domain.objects.create(
                    name=canonicalize_domain_name(domain_name),
                    tld=tld,
                    registrar=registrar,
                    customer=customer,
                    status="pending",
                )
                domain.start_transfer_in()
                domain.save()

                op = DomainOperation.objects.create(
                    domain=domain,
                    registrar=registrar,
                    operation_type="transfer_in",
                    parameters={"epp_code": "***"},  # never store plaintext EPP
                )
        except Exception as e:
            logger.error("Failed to create transfer records for %s: %s", domain_name, e)
            return Err(cast(str, _("Failed to initiate transfer")))

        # Phase 2: submit to registrar (outside the transaction above). Use the stored
        # (lowercased) domain.name so the gateway idempotency key matches on any retry —
        # passing the raw domain_name would key "Example.com" separately from "example.com".
        DomainOperationService.dispatch(op)
        result = gateway.initiate_transfer(
            domain.name,
            epp_code,
            registrant_data=registrant_data,
        )
        if result.is_ok():
            transfer = result.unwrap()
            op.registrar_operation_id = transfer.transfer_id
            op.accepted_at = timezone.now()
            op.save(update_fields=["registrar_operation_id", "accepted_at", "updated_at"])
            logger.info("Transfer initiated for %s: %s", domain_name, transfer.transfer_id)
            return Ok(op)

        # Failure: partition by retriability, mirroring _submit_registration_to_registrar.
        # Keep the pending Domain row ONLY on UNKNOWN (the transfer may have started at the
        # registrar); on a definite rejection OR a breaker-open RETRIABLE, delete the row so
        # the unique domain name isn't permanently stranded (the #260 deadlock class).
        error = result.unwrap_err()
        if retriability_of(result) == Retriability.UNKNOWN:
            op.error_message = error.code.value
            op.save(update_fields=["state", "error_message", "updated_at"])
            logger.warning(
                "Transfer outcome UNKNOWN for %s (kept pending, do not resubmit): %s", domain_name, error.code.value
            )
            return Err(cast(str, _("Transfer was submitted but the registrar did not confirm it — do not resubmit.")))
        logger.warning("Transfer rejected for %s (records removed for clean retry): %s", domain_name, error.code.value)
        domain.delete()  # cascades to the DomainOperation row
        return Err(cast(str, _("Registrar rejected the transfer: {error}")).format(error=error.code.value))

    @staticmethod
    def update_nameservers(domain: Domain, nameservers: list[str]) -> Result[DomainOperation, str]:
        """Update nameservers at the registrar (two-phase)."""
        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415
        from .operation_services import DomainOperationService  # noqa: PLC0415

        try:
            gateway = RegistrarGatewayFactory.create_gateway(domain.registrar)
        except ValueError:
            return Err(f"No gateway for registrar {domain.registrar.name}")

        op = DomainOperation.objects.create(
            domain=domain,
            registrar=domain.registrar,
            operation_type="nameserver_update",
            parameters={"nameservers": nameservers},
        )

        DomainOperationService.dispatch(op)
        result = gateway.update_nameservers(domain.name, nameservers)
        if result.is_ok():
            update = result.unwrap()
            if update.pending:
                # Accepted, not completed (#257): leave domain.nameservers untouched
                # until the reconciler confirms the registrar applied the change.
                op.registrar_operation_id = update.operation_handle
                op.accepted_at = timezone.now()
                op.save(
                    update_fields=[
                        "state",
                        "registrar_operation_id",
                        "submitted_at",
                        "accepted_at",
                        "updated_at",
                    ]
                )
                return Ok(op)

            domain.nameservers = nameservers
            domain.save(update_fields=["nameservers", "updated_at"])
            op.mark_completed()
            op.save(update_fields=["state", "completed_at", "updated_at"])
            return Ok(op)

        error = result.unwrap_err()
        if retriability_of(result) != Retriability.UNKNOWN:
            op.mark_failed(error.code.value)
        else:
            op.error_message = error.code.value
        op.save(update_fields=["state", "error_message", "updated_at"])
        return Err(cast(str, _("Nameserver update failed: {error}")).format(error=error.code.value))

    @staticmethod
    def set_domain_lock(domain: Domain, locked: bool) -> Result[DomainOperation, str]:
        """Lock or unlock a domain at the registrar."""
        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415
        from .operation_services import DomainOperationService  # noqa: PLC0415

        try:
            gateway = RegistrarGatewayFactory.create_gateway(domain.registrar)
        except ValueError:
            return Err(f"No gateway for registrar {domain.registrar.name}")

        op = DomainOperation.objects.create(
            domain=domain,
            registrar=domain.registrar,
            operation_type="lock_update",
            parameters={"locked": locked},
        )

        DomainOperationService.dispatch(op)
        result = gateway.set_lock(domain.name, locked)
        if result.is_ok():
            lock_result = result.unwrap()
            if lock_result.pending:
                # Accepted, not completed (#257): local lock state waits for confirmation.
                op.registrar_operation_id = lock_result.operation_handle
                op.accepted_at = timezone.now()
                op.save(
                    update_fields=[
                        "state",
                        "registrar_operation_id",
                        "submitted_at",
                        "accepted_at",
                        "updated_at",
                    ]
                )
                return Ok(op)

            domain.locked = locked
            domain.save(update_fields=["locked", "updated_at"])
            op.mark_completed()
            op.save(update_fields=["state", "completed_at", "updated_at"])
            return Ok(op)

        error = result.unwrap_err()
        if retriability_of(result) != Retriability.UNKNOWN:
            op.mark_failed(error.code.value)
        else:
            op.error_message = error.code.value
        op.save(update_fields=["state", "error_message", "updated_at"])
        return Err(cast(str, _("Lock update failed: {error}")).format(error=error.code.value))

    @staticmethod
    def sync_domain_info(domain: Domain, persist: bool = True) -> Result[DomainOperation, str]:
        """Pull current domain state from the registrar and reconcile the local record.

        Returns Ok(op) with op.result['changed_fields'] describing the drift (empty when
        the local record already matches the registrar). Ok is returned ONLY when the
        registrar responded; a registrar failure returns Err. When persist is False
        (dry-run) nothing is written: the returned DomainOperation is unsaved and no
        Domain fields change.
        """
        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415

        try:
            gateway = RegistrarGatewayFactory.create_gateway(domain.registrar)
        except ValueError:
            return Err(f"No gateway for registrar {domain.registrar.name}")

        result = gateway.get_domain_info(domain.name)
        if result.is_err():
            error = result.unwrap_err()
            if persist:
                op = DomainOperation.objects.create(
                    domain=domain, registrar=domain.registrar, operation_type="domain_info"
                )
                op.mark_failed(error.code.value)
                op.save(update_fields=["state", "error_message", "updated_at"])
            return Err(cast(str, _("Failed to sync {name}: {error}")).format(name=domain.name, error=error.code.value))

        info = result.unwrap()

        # Real drift detection: compare the registrar's values against the LOCAL record
        # BEFORE applying any change (the old truthiness check reported drift every run).
        changed: dict[str, Any] = {}
        if list(domain.nameservers or []) != list(info.nameservers or []):
            changed["nameservers"] = {"from": list(domain.nameservers or []), "to": list(info.nameservers or [])}
        if domain.locked != info.locked:
            changed["locked"] = {"from": domain.locked, "to": info.locked}
        if info.expires_at and domain.expires_at != info.expires_at:
            changed["expires_at"] = {"from": str(domain.expires_at), "to": str(info.expires_at)}
        if info.registrar_domain_id and domain.registrar_domain_id != info.registrar_domain_id:
            changed["registrar_domain_id"] = {"from": domain.registrar_domain_id, "to": info.registrar_domain_id}
        result_data = {"changed_fields": changed, "drift_detected": bool(changed)}

        if not persist:
            # Dry-run: report drift without touching the DB (unsaved op, no domain.save).
            op = DomainOperation(domain=domain, registrar=domain.registrar, operation_type="domain_info")
            op.result = result_data
            return Ok(op)

        domain.nameservers = info.nameservers
        domain.locked = info.locked
        domain.whois_privacy = info.whois_privacy
        if info.expires_at:
            domain.expires_at = info.expires_at
        if info.registrar_domain_id:
            domain.registrar_domain_id = info.registrar_domain_id
        domain.save(
            update_fields=["nameservers", "locked", "whois_privacy", "expires_at", "registrar_domain_id", "updated_at"]
        )
        op = DomainOperation.objects.create(domain=domain, registrar=domain.registrar, operation_type="domain_info")
        op.mark_completed(result_data=result_data)
        op.save(update_fields=["state", "completed_at", "result", "updated_at"])
        return Ok(op)


# ===============================================================================
# DOMAIN RECONCILIATION SERVICE
# ===============================================================================

RECONCILE_GRACE_MINUTES = 15
RECONCILE_BATCH_LIMIT = 50
RECONCILE_OP_MAX_AGE_HOURS = 72


class DomainReconciliationSummary(TypedDict):
    """Counts reported by one reconciliation run."""

    success: bool
    activated: int
    removed: int
    awaiting: int
    unconfirmed: int
    completed: int
    failed: int
    expired: int
    skipped: int
    errors: int
    message: str


class DomainReconciliationService:
    """Converge registrar-accepted domain work without resubmitting it (#258).

    The registrar answers chargeable mutations asynchronously (Gandi 202) or a
    network failure leaves the outcome UNKNOWN — either way a pending Domain or a
    submitted DomainOperation is a promise the platform must later verify.
    ``get_domain_info`` is the single read used to converge (it is not gated by
    REGISTRAR_ADAPTERS_VERIFIED); webhooks remain the event-driven twin of this
    worker and win any race safely via the FSM re-checks below.
    """

    @staticmethod
    def _get_domain_info(
        domain: Domain,
        info_cache: dict[str, Result[DomainInfoResult, RegistrarAPIError]],
    ) -> Result[DomainInfoResult, RegistrarAPIError]:
        """Read registrar state once per domain name during a reconciliation run."""
        cached = info_cache.get(domain.name)
        if cached is not None:
            return cached

        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415

        gateway: BaseRegistrarGateway = RegistrarGatewayFactory.create_gateway(domain.registrar)
        result = gateway.get_domain_info(domain.name)
        info_cache[domain.name] = result
        return result

    @staticmethod
    def _complete_lifecycle_operations(domain_id: UUID, operation_type: str) -> None:
        """Complete submitted lifecycle operations after domain convergence commits."""
        operation_ids = list(
            DomainOperation.objects.filter(
                domain_id=domain_id,
                operation_type=operation_type,
                state="submitted",
            ).values_list("pk", flat=True)
        )
        for operation_id in operation_ids:
            with transaction.atomic():
                Domain.objects.select_for_update().get(pk=domain_id)
                operation = DomainOperation.objects.select_for_update().get(pk=operation_id)
                if operation.state != "submitted":
                    continue
                operation.mark_completed(result_data={"reconciled": True})
                operation.save(update_fields=["state", "completed_at", "result", "updated_at"])

    @classmethod
    def _converge_lifecycle_domain(
        cls,
        domain_id: UUID,
        expected_status: str,
        operation_type: str,
        info: DomainInfoResult,
    ) -> bool:
        """Apply confirmed registrar fields and activate a pending lifecycle row."""
        activated = False
        confirmed_active = False

        with transaction.atomic():
            domain = Domain.objects.select_for_update().get(pk=domain_id)
            if domain.status == expected_status:
                if info.registrar_domain_id:
                    domain.registrar_domain_id = info.registrar_domain_id
                domain.expires_at = info.expires_at
                if info.nameservers:
                    domain.nameservers = info.nameservers
                if info.epp_code:
                    domain.set_encrypted_epp_code(info.epp_code)
                if domain.registered_at is None:
                    domain.registered_at = timezone.now()
                domain.activate()
                domain.save()
                activated = True
                confirmed_active = True
            elif domain.status == "active":
                # A webhook or inline completion won the race. Do not overwrite its
                # fields, but the registrar read still confirms the submitted op.
                confirmed_active = True

        if confirmed_active:
            cls._complete_lifecycle_operations(domain_id, operation_type)
        return activated

    @classmethod
    def _apply_confirmed_operation(cls, operation_id: UUID, info: DomainInfoResult | None) -> bool:  # noqa: PLR0911  # per-op-type confirm/decline exits
        """Atomically apply registrar-confirmed operation state.

        ``info`` is None for lifecycle types (register/transfer_in): their proof is
        the Domain row itself being active — phase A or a webhook activated it and
        this phase only harvests the race/crash gap that would otherwise strand the
        operation in ``submitted`` forever.
        """
        candidate = DomainOperation.objects.get(pk=operation_id)
        with transaction.atomic():
            domain = Domain.objects.select_for_update().get(pk=candidate.domain_id)
            operation = DomainOperation.objects.select_for_update().get(pk=operation_id)
            if operation.state != "submitted":
                return False

            parameters = operation.parameters

            if operation.operation_type in ("register", "transfer_in"):
                if domain.status != "active":
                    return False
                operation.mark_completed(result_data={"reconciled": True})
                operation.save(update_fields=["state", "completed_at", "result", "updated_at"])
                return True

            if info is None:
                return False

            if operation.operation_type == "renew":
                from .operation_services import DomainOperationService  # noqa: PLC0415

                if info.status != "active" or info.expires_at is None:
                    return False
                return DomainOperationService.confirm_renewal(operation, info.expires_at)

            if operation.operation_type == "nameserver_update":
                requested_nameservers = parameters.get("nameservers")
                if not isinstance(requested_nameservers, list) or not all(
                    isinstance(nameserver, str) for nameserver in requested_nameservers
                ):
                    return False
                if set(info.nameservers) != set(requested_nameservers):
                    return False

                domain.nameservers = requested_nameservers
                domain.save(update_fields=["nameservers", "updated_at"])
                operation.mark_completed()
                operation.save(update_fields=["state", "completed_at", "updated_at"])
                return True

            if operation.operation_type == "lock_update":
                requested_lock = parameters.get("locked")
                if not isinstance(requested_lock, bool) or info.locked != requested_lock:
                    return False

                domain.locked = requested_lock
                domain.save(update_fields=["locked", "updated_at"])
                operation.mark_completed()
                operation.save(update_fields=["state", "completed_at", "updated_at"])
                return True

        return False

    @staticmethod
    def _schedule_next_check(operation_id: UUID) -> None:
        """Timeout means review, never failure or permission to resend a mutation."""
        from .operation_services import DomainOperationService  # noqa: PLC0415

        now = timezone.now()
        with transaction.atomic():
            operation = DomainOperation.objects.select_for_update().get(pk=operation_id)
            if operation.state not in ("pending", "submitted"):
                return
            if (operation.submitted_at or operation.created_at) < now - timedelta(hours=RECONCILE_OP_MAX_AGE_HOURS):
                operation.review_required_at = operation.review_required_at or now
            if operation.review_required_at:
                DomainOperationService.request_review(operation, "Unconfirmed after 72h; registrar review required.")
            interval = timedelta(days=1) if operation.review_required_at else timedelta(hours=1)
            operation.next_retry_at = now + interval
            operation.save(update_fields=["review_required_at", "error_message", "next_retry_at", "updated_at"])

    @staticmethod
    def _expire_post_grace_domains(now: datetime) -> tuple[int, int]:
        """Expire active domains strictly after their TLD renewal grace window.

        A domain past expires_at but still INSIDE its TLD grace window must stay
        active: process_domain_renewal requires status "active" and registrars
        allow renewal during grace — expiring early would block legitimate grace
        renewals. Only webhook-less registrars need this local sweep at all.
        """
        minimum_grace = TLD.objects.aggregate(value=Min("grace_period_days"))["value"]
        if minimum_grace is None:
            return 0, 0

        coarse_cutoff = now - timedelta(days=minimum_grace)
        candidates = (
            Domain.objects.filter(
                status="active",
                expires_at__isnull=False,
                expires_at__lt=coarse_cutoff,
            )
            .select_related("tld")
            .order_by("expires_at")
        )

        expired = 0
        errors = 0
        eligible_seen = 0
        for candidate in candidates.iterator():
            if candidate.expires_at is None:
                continue
            if candidate.expires_at + timedelta(days=candidate.tld.grace_period_days) >= now:
                continue
            if eligible_seen >= RECONCILE_BATCH_LIMIT:
                break
            eligible_seen += 1

            try:
                with transaction.atomic():
                    domain = Domain.objects.select_for_update().select_related("tld").get(pk=candidate.pk)
                    if (
                        domain.status != "active"
                        or domain.expires_at is None
                        or domain.expires_at + timedelta(days=domain.tld.grace_period_days) >= now
                    ):
                        continue
                    domain.expire()
                    domain.save()

                expired += 1
                logger.warning(
                    "⚠️ [Domains] Expired %s after its %d-day TLD grace period",
                    candidate.name,
                    candidate.tld.grace_period_days,
                )
            except (ConcurrentTransition, TransitionNotAllowed):
                errors += 1
                logger.error(
                    "🔥 [Domains] Expiry reconciliation raced for %s",
                    candidate.name,
                    exc_info=True,
                )
            except Exception:
                errors += 1
                logger.error(
                    "🔥 [Domains] Expiry reconciliation crashed for %s",
                    candidate.name,
                    exc_info=True,
                )

        return expired, errors

    @staticmethod
    def _adopt_legacy_domains(grace_cutoff: datetime) -> None:
        """Give old pending rows a durable review schedule without inventing success."""
        candidates = (
            Domain.objects.filter(
                status__in=("pending", "transfer_in"),
                created_at__lt=grace_cutoff,
            )
            .exclude(operations__operation_type__in=("register", "transfer_in"))
            .order_by("created_at")
        )
        for candidate in candidates[:RECONCILE_BATCH_LIMIT]:
            with transaction.atomic():
                domain = Domain.objects.select_for_update().get(pk=candidate.pk)
                kind = "register" if domain.status == "pending" else "transfer_in"
                if (
                    domain.status not in ("pending", "transfer_in")
                    or domain.operations.filter(operation_type=kind).exists()
                ):
                    continue
                operation = DomainOperation(domain=domain, registrar=domain.registrar, operation_type=kind)
                operation.mark_submitted()
                operation.submitted_at = domain.created_at
                operation.review_required_at = timezone.now()
                operation.parameters = {"legacy_submission": True}
                operation.save()

    @classmethod
    def _reconcile_operation(
        cls,
        operation: DomainOperation,
        info_cache: dict[str, Result[DomainInfoResult, RegistrarAPIError]],
    ) -> str:
        from .gateways import RegistrarErrorCode  # noqa: PLC0415
        from .operation_services import DomainOperationService  # noqa: PLC0415

        if operation.state == "pending":
            if operation.parameters.get("after_registration"):
                DomainOperationService.resume_registration_nameservers(operation.domain)
            return "unconfirmed"
        if operation.operation_type in ("register", "transfer_in") and operation.domain.status == "active":
            return "completed" if cls._apply_confirmed_operation(operation.pk, None) else "unconfirmed"
        result = cls._get_domain_info(operation.domain, info_cache)
        if result.is_err():
            # Absence cannot disprove a delayed or response-lost mutation.
            return "awaiting" if result.unwrap_err().code == RegistrarErrorCode.DOMAIN_NOT_FOUND else "errors"
        info = result.unwrap()
        if operation.operation_type in ("register", "transfer_in"):
            if info.status != "active" or info.expires_at is None:
                return "unconfirmed"
            expected = "pending" if operation.operation_type == "register" else "transfer_in"
            if cls._converge_lifecycle_domain(operation.domain_id, expected, operation.operation_type, info):
                DomainOperationService.resume_registration_nameservers(operation.domain)
                return "activated"
        return "completed" if cls._apply_confirmed_operation(operation.pk, info) else "unconfirmed"

    @classmethod
    def reconcile(cls) -> DomainReconciliationSummary:
        """Check due work fairly; retain uncertain submissions for read-only review."""
        now = timezone.now()
        cutoff = now - timedelta(minutes=RECONCILE_GRACE_MINUTES)
        cls._adopt_legacy_domains(cutoff)
        summary: DomainReconciliationSummary = {
            "success": True,
            "activated": 0,
            "removed": 0,
            "awaiting": 0,
            "unconfirmed": 0,
            "completed": 0,
            "failed": 0,
            "expired": 0,
            "skipped": 0,
            "errors": 0,
            "message": "",
        }
        info_cache: dict[str, Result[DomainInfoResult, RegistrarAPIError]] = {}
        operations = (
            DomainOperation.objects.filter(
                Q(state="submitted", submitted_at__lt=cutoff) | Q(state="pending", created_at__lt=cutoff),
            )
            .filter(Q(next_retry_at__isnull=True) | Q(next_retry_at__lte=now))
            .select_related(
                "domain__registrar",
                "registrar",
            )
            .order_by("next_retry_at", "created_at")
        )
        eligible = 0
        for operation in operations.iterator():
            if eligible >= RECONCILE_BATCH_LIMIT:
                break
            try:
                outcome = cls._reconcile_operation(operation, info_cache)
                eligible += 1
                if outcome == "activated":
                    summary["activated"] += 1
                elif outcome == "completed":
                    summary["completed"] += 1
                elif outcome == "awaiting":
                    summary["awaiting"] += 1
                elif outcome == "errors":
                    summary["errors"] += 1
                else:
                    summary["unconfirmed"] += 1
            except ValueError:
                summary["skipped"] += 1
            except Exception:
                summary["errors"] += 1
                logger.exception("Domain reconciliation failed for operation %s", operation.pk)
            finally:
                cls._schedule_next_check(operation.pk)
        summary["expired"], expiry_errors = cls._expire_post_grace_domains(now)
        summary["errors"] += expiry_errors
        summary["success"] = summary["errors"] == 0
        summary["message"] = ", ".join(f"{key}={value}" for key, value in summary.items() if key != "message")
        logger.info("Reconciled domains: %s", summary["message"])
        return summary


class DomainNotificationService:
    """
    📧 Domain notification and alerting service

    Handles expiration notices, renewal reminders, and domain alerts.
    """

    DEFAULT_RENEWAL_NOTICE_SCHEDULE: tuple[int, ...] = (30, 14, 7, 3, 1)

    @classmethod
    def _renewal_notice_schedule(cls) -> list[int]:
        """Return a safe canonical schedule even if a row bypassed service validation."""
        raw_schedule = SettingsService.get_list_setting(
            "domains.renewal_notice_schedule_days",
            list(cls.DEFAULT_RENEWAL_NOTICE_SCHEDULE),
        )
        valid_items = bool(raw_schedule) and all(
            isinstance(days, int) and not isinstance(days, bool) and days > 0 for days in raw_schedule
        )
        if (
            not valid_items
            or len(set(raw_schedule)) != len(raw_schedule)
            or raw_schedule != sorted(raw_schedule, reverse=True)
        ):
            logger.error("Invalid domains.renewal_notice_schedule_days; using the safe default")
            return list(cls.DEFAULT_RENEWAL_NOTICE_SCHEDULE)
        return raw_schedule

    @classmethod
    def get_domains_needing_renewal_notice(cls) -> QuerySet[Domain]:
        """📧 Get domains that need renewal notices"""
        notice_periods = cls._renewal_notice_schedule()
        # localdate() so the cutoff matches the local-time semantics of the
        # `expires_at__date` lookup (Django applies TIME_ZONE), and so the
        # day-pairing in due_renewal_notices lands on the same calendar day.
        today = timezone.localdate()

        conditions = Q()
        for days in notice_periods:
            conditions |= (
                Q(expires_at__date=today + timedelta(days=days))
                & ~Q(renewal_notices_sent=days)  # The current threshold has not been sent yet.
            )

        return Domain.objects.filter(conditions, status="active").select_related("customer", "tld")

    @classmethod
    def due_renewal_notices(cls) -> list[tuple[Domain, int]]:
        """📧 Pair each due domain with the schedule threshold it matched."""
        schedule_days = cls._renewal_notice_schedule()
        # Compare in Django's configured timezone: the DB `expires_at__date`
        # lookup that selected these rows evaluates in local time, so a
        # late-evening UTC expiry must be matched on the same local calendar day.
        today = timezone.localdate()
        pairs: list[tuple[Domain, int]] = []
        for domain in cls.get_domains_needing_renewal_notice():
            if domain.expires_at is None:
                continue
            expiry_local_date = timezone.localdate(domain.expires_at)
            for days in schedule_days:
                if expiry_local_date == today + timedelta(days=days):
                    pairs.append((domain, days))
                    break
        return pairs

    @staticmethod
    def mark_renewal_notice_sent(domain: Domain, notice_period: int) -> None:
        """📧 Mark renewal notice as sent"""
        domain.renewal_notices_sent = notice_period
        domain.last_renewal_notice = timezone.now()
        domain.save(update_fields=["renewal_notices_sent", "last_renewal_notice", "updated_at"])


# ===============================================================================
# DOMAIN ORDER PROCESSING SERVICE
# ===============================================================================


class DomainOrderService:
    """
    🛒 Domain order processing service

    Handles domain orders from the e-commerce system.
    """

    @staticmethod
    def create_domain_order_item(  # Domain order requires multiple configuration parameters  # domain registration fields  # noqa: PLR0913  # Business logic parameters
        order: Order,
        domain_name: str,
        action: str,
        years: int = 1,
        whois_privacy: bool = False,
        auto_renew: bool = True,
        epp_code: str = "",
    ) -> tuple[bool, DomainOrderItem | str]:
        """🛒 Create domain order item"""

        # Validate domain name
        is_valid, error_msg = DomainValidationService.validate_domain_name(domain_name)
        if not is_valid:
            return False, error_msg

        # Canonicalize ONCE, right after validation (#442): validate_domain_name strips
        # and lowercases only its local copy, so a padded input like "  Example.RO  "
        # validates fine and then misses the stored canonical row at the .lower()-only
        # renew-link filter below — an unlinked item and a silently skipped renewal.
        domain_name = canonicalize_domain_name(domain_name)

        # Get TLD and pricing
        tld_extension = DomainValidationService.extract_tld_from_domain(domain_name)
        tld = TLDService.get_tld_pricing(tld_extension)
        if not tld:
            return False, cast(str, _(f"TLD '.{tld_extension}' is not supported"))

        if action in {"register", "renew"}:
            period_error = (
                TLDService.validate_registration_period(tld, years)
                if action == "register"
                else TLDService.validate_renewal_period(tld, years)
            )
            if period_error is not None:
                return False, period_error

        # Calculate pricing based on action
        if action == "register":
            unit_price_cents = tld.registration_price_cents
        elif action == "renew":
            unit_price_cents = tld.renewal_price_cents
        elif action == "transfer":
            unit_price_cents = tld.transfer_price_cents
        else:
            return False, cast(str, _("Invalid domain action"))

        # Add WHOIS privacy cost
        if whois_privacy and tld.whois_privacy_available:
            unit_price_cents += SettingsService.get_integer_setting(
                "domains.whois_privacy_price_cents", _DEFAULT_WHOIS_PRIVACY_PRICE_CENTS
            )

        # #430: a renew acts on an EXISTING domain the customer owns. Link it here so
        # process_domain_order_items can reach the renew branch — its guard was
        # `item.action == "renew" and item.domain`, never true because .domain was never set, so
        # every renew item was silently skipped.
        #
        # The `customer=` filter means an unlinked renew is the EXPECTED shape when this customer
        # does not own the domain — the item is still created, and processing logs it rather than
        # renewing anything. This filter is not the security boundary on its own (rows can be
        # created outside this method); process_domain_order_items re-checks ownership on the
        # linked domain before renewing.
        #
        # domain_name was canonicalized (strip+lower) after validation above, matching
        # Domain.name's stored form: #442 made canonicalization structural — save() and the
        # bulk-path queryset canonicalize every write, migration 0006 fixed legacy rows.
        existing_domain: Domain | None = None
        if action == "renew":
            existing_domain = Domain.objects.filter(name=domain_name, customer=order.customer).first()

        try:
            order_item = DomainOrderItem.objects.create(
                order=order,
                domain_name=domain_name,
                tld=tld,
                action=action,
                years=years,
                unit_price_cents=unit_price_cents,
                total_price_cents=unit_price_cents * years,
                whois_privacy=whois_privacy,
                auto_renew=auto_renew,
                epp_code="",
                domain=existing_domain,
            )

            # Encrypt EPP code via model setter (single encryption boundary)
            if action == "transfer" and epp_code:
                order_item.set_encrypted_epp_code(epp_code)
                order_item.save(update_fields=["epp_code"])

            logger.info(f"🛒 [Domain] Created order item: {action} {domain_name} for {years} years")
            return True, order_item

        except Exception as e:
            logger.error(f"🔥 [Domain] Failed to create order item: {e}")
            return False, cast(str, _("Failed to create domain order item"))

    @staticmethod
    def process_domain_order_items(order: Order) -> list[Domain]:  # noqa: PLR0912  # per-action dispatch with per-outcome handling
        """⚡ Process all domain order items for paid order"""

        processed_domains = []

        # select_related the renew path's dereferences too: item.domain (+ its tld/registrar)
        # is read per item below, which would otherwise be a query per renewal.
        domain_items = DomainOrderItem.objects.filter(order=order).select_related(
            "tld", "domain", "domain__tld", "domain__registrar"
        )

        for item in domain_items:
            # #465/#259: lifecycle methods normally return Result, but registrar/cache
            # infrastructure can still raise. One boundary per item prevents any action
            # type from aborting the order's remaining valid items.
            try:
                if item.action == "register":
                    result = DomainLifecycleService.create_domain_registration(
                        customer=order.customer,
                        domain_name=item.domain_name,
                        years=item.years,
                        whois_privacy=item.whois_privacy,
                        auto_renew=item.auto_renew,
                    )

                    if result.is_ok():
                        domain = result.unwrap()
                        item.domain = domain
                        item.save(update_fields=["domain"])
                        processed_domains.append(domain)
                        logger.info("✅ [Domain] Processed registration: %s", item.domain_name)
                    else:
                        logger.error(
                            "🔥 [Domain] Failed to process registration %s: %s",
                            item.domain_name,
                            result.unwrap_err(),
                        )
                        # A pending-accepted/pending-unknown outcome leaves a pending
                        # Domain row (definite rejections delete it) — link it so the
                        # purchased item keeps its provenance once the reconciliation
                        # worker activates the domain.
                        pending_domain = Domain.objects.filter(
                            name=canonicalize_domain_name(item.domain_name),
                            customer=order.customer,
                        ).first()
                        if pending_domain is not None and item.domain_id is None:
                            item.domain = pending_domain
                            item.save(update_fields=["domain"])

                elif item.action == "renew":
                    # #430: create_domain_order_item links the Domain only when the ordering customer
                    # already owns it, so an unlinked renew is the expected shape for a domain this
                    # customer does not own (or that did not exist at order time) — not necessarily a
                    # data defect. Either way it cannot be renewed here, so log it rather than
                    # silently skipping.
                    if item.domain is None:
                        logger.error(
                            "🔥 [Domain] Renew item %s has no linked domain (not owned by this customer "
                            "at order time, or created outside create_domain_order_item) — skipping",
                            item.domain_name,
                        )
                        continue

                    # Ownership is re-checked HERE, not just at link time: DomainOrderItem rows can be
                    # created outside create_domain_order_item (admin, imports, direct ORM), so the
                    # link-step `customer=` filter is not a boundary this path can rely on. Without
                    # this, a row pointing at another customer's domain would renew it on their behalf.

                    if item.domain.customer_id != order.customer_id:
                        logger.error(
                            "🔥 [Domain] Renew item %s links domain owned by customer %s but the order "
                            "belongs to customer %s — refusing to renew",
                            item.domain_name,
                            item.domain.customer_id,
                            order.customer_id,
                        )
                        continue

                    # #259: the order item pk IS the renewal intent — durable, and exactly one
                    # per item, so a retried batch replays rather than re-charging, while two
                    # separate order items for the same domain+years stay distinct.
                    renewal_result = DomainLifecycleService.process_domain_renewal(
                        domain=item.domain, years=item.years, idempotency_token=f"order_item:{item.pk}"
                    )

                    if renewal_result.is_ok():
                        processed_domains.append(item.domain)
                        logger.info("✅ [Domain] Processed renewal: %s", item.domain_name)
                    else:
                        logger.error(
                            "🔥 [Domain] Failed to process renewal %s: %s",
                            item.domain_name,
                            renewal_result.unwrap_err(),
                        )

                elif item.action == "transfer":
                    # #430: inbound transfer creates a new Domain via initiate_transfer, which needs a
                    # resolved registrar — there is no registrar on the order item yet, so this path is
                    # intentionally NOT auto-processed here. Log explicitly instead of dropping it
                    # silently; wiring registrar selection for transfers is tracked separately.
                    logger.warning(
                        "⚠️ [Domain] Transfer item %s is not auto-processed (registrar selection for "
                        "order-driven transfers is not wired yet) — handle via initiate_transfer",
                        item.domain_name,
                    )

                else:
                    # #430: any unhandled action must be VISIBLE, not silently dropped. This logs and
                    # continues rather than raising: one malformed item must not abort processing of
                    # the order's remaining (valid) items. Per-item outcomes are not yet returned to
                    # the caller — tracked as a before-wiring follow-up.
                    logger.error(
                        "🔥 [Domain] Unhandled domain order item action %r for %s — item not processed",
                        item.action,
                        item.domain_name,
                    )

            except Exception:
                logger.error(
                    "🔥 [Domain] Processing %s item %s crashed unexpectedly — continuing with remaining items",
                    item.action,
                    item.domain_name,
                    exc_info=True,
                )
                continue

        return processed_domains


# ===============================================================================
# DOMAIN GATEWAY - EXTERNAL INTEGRATIONS
# ===============================================================================


class DomainRegistrarGateway:
    """Backward-compatible facade that delegates to the gateway layer.

    The real implementations live in apps.domains.gateways (Gandi, ROTLD, etc.).
    This class preserves the existing tuple-based return types so callers
    (webhooks.py, DomainOrderService) don't need to change yet.
    """

    @staticmethod
    def register_domain(
        registrar: Registrar, domain_name: str, years: int, customer_data: dict[str, Any]
    ) -> tuple[bool, dict[str, Any]]:
        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415

        try:
            gateway = RegistrarGatewayFactory.create_gateway(registrar)
        except ValueError:
            logger.error("No gateway registered for %s — cannot register %s", registrar.name, domain_name)
            return False, {"error": f"No gateway for registrar {registrar.name}"}

        result = gateway.register_domain(
            domain_name, years, customer_data, nameservers=registrar.default_nameservers or None
        )
        if result.is_ok():
            reg = result.unwrap()
            return True, {
                "registrar_domain_id": reg.registrar_domain_id,
                "expires_at": reg.expires_at,
                "nameservers": reg.nameservers,
                "epp_code": reg.epp_code,
                "pending": reg.pending,
                "operation_handle": reg.operation_handle,
            }
        # Carry the retriability so the lifecycle can tell a definite rejection
        # (safe to delete the pending row) from an UNKNOWN outcome (may have
        # registered server-side — must keep the row, never resubmit blindly).
        return False, {"error": str(result.unwrap_err()), "retriability": retriability_of(result).value}

    @staticmethod
    def renew_domain(
        registrar: Registrar, domain: Domain, years: int, idempotency_token: str | None = None
    ) -> tuple[bool, dict[str, Any]]:
        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415

        try:
            gateway = RegistrarGatewayFactory.create_gateway(registrar)
        except ValueError:
            logger.error("No gateway registered for %s — cannot renew %s", registrar.name, domain.name)
            return False, {"error": f"No gateway for registrar {registrar.name}"}

        result = gateway.renew_domain(
            domain.registrar_domain_id, domain.name, years, idempotency_token=idempotency_token
        )
        if result.is_ok():
            renewal = result.unwrap()
            return True, {
                "new_expires_at": renewal.new_expires_at,
                "pending": renewal.pending,
                "operation_handle": renewal.operation_handle,
            }
        # Carry retriability like the registration facade: an UNKNOWN outcome means
        # the chargeable renewal MAY have applied and needs durable reconciliation.
        return False, {"error": str(result.unwrap_err()), "retriability": retriability_of(result).value}

    @staticmethod
    def get_domain_info(registrar: Registrar, domain_name: str) -> Result[DomainInfoResult, RegistrarAPIError]:
        from .gateways import RegistrarAPIError, RegistrarGatewayFactory  # noqa: PLC0415

        try:
            return RegistrarGatewayFactory.create_gateway(registrar).get_domain_info(domain_name)
        except ValueError:
            return Err(RegistrarAPIError("No gateway configured"), retriability=Retriability.NOT_RETRIABLE)

    @staticmethod
    def check_domain_availability(registrar: Registrar, domain_name: str) -> tuple[bool, bool]:
        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415

        try:
            gateway = RegistrarGatewayFactory.create_gateway(registrar)
        except ValueError:
            logger.error("No gateway registered for %s — cannot check %s", registrar.name, domain_name)
            return False, False

        result = gateway.check_availability(domain_name)
        if result.is_ok():
            return True, result.unwrap().available
        return False, False

    @staticmethod
    def verify_webhook_signature(registrar: Registrar, payload: str, signature: str) -> bool:
        from .gateways import BaseRegistrarGateway, RegistrarGatewayFactory  # noqa: PLC0415

        # Only the "no gateway registered" case should fall through to the fallback;
        # don't swallow errors from the gateway's own verification.
        try:
            gateway = RegistrarGatewayFactory.create_gateway(registrar)
        except ValueError:
            gateway = None
        if gateway is not None:
            return gateway.verify_webhook_signature(payload, signature)

        # Fallback: shared HMAC-SHA256 for registrars without a dedicated gateway.
        if not registrar.webhook_secret or not signature:
            return False
        try:
            secret = registrar.get_decrypted_webhook_secret()
        except Exception:
            # Previously swallowed silently — log so a decryption/key-rotation outage
            # is visible instead of every webhook quietly failing verification.
            logger.error("Webhook secret decryption failed for %s (encryption key may have rotated)", registrar.name)
            return False
        if not secret or not secret.strip():
            return False
        return BaseRegistrarGateway._verify_hmac_sha256(payload, signature, secret.strip())
