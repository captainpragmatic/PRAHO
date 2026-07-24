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
from typing import TYPE_CHECKING, Any, cast

from django.db import transaction
from django.db.models import Q, QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from apps.common.types import Err, Ok, Result, Retriability, retriability_of
from apps.settings.services import SettingsService

from .models import TLD, Domain, DomainOperation, DomainOrderItem, Registrar

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.orders.models import Order

logger = logging.getLogger(__name__)

# Module-level default for WHOIS privacy price
_DEFAULT_WHOIS_PRIVACY_PRICE_CENTS = 500

# Domain name validation constants
MIN_DOMAIN_NAME_LENGTH = 3  # Minimum length for domain names
MAX_DOMAIN_NAME_LENGTH = 253  # Maximum length per RFC 1035

# Domain registration constants
MIN_REGISTRATION_YEARS = 1  # Minimum registration period
MAX_REGISTRATION_YEARS = 10  # Maximum registration period


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
        """🌐 Extract the TLD from a domain name.

        Multi-label TLDs (``.com.ro``, ``.org.ro``) must not be truncated to their
        last label: ``rsplit('.', 1)`` turned ``shop.com.ro`` into ``ro``, which then
        mislinked/mispriced the Domain or falsely rejected it as unsupported (#237).

        Resolve by longest-suffix match against the configured ``TLD.extension`` values
        so ``shop.com.ro`` → ``com.ro`` while ``example.ro`` → ``ro``. Falls back to the
        last label when the domain matches no configured TLD, so the caller's own
        "unsupported TLD" handling still fires instead of crashing.
        """
        if "." not in domain_name:
            return ""

        domain_lower = domain_name.lower()
        # Longest configured extension that the domain ends with wins (".com.ro" over ".ro").
        matches = [
            ext for ext in TLD.objects.values_list("extension", flat=True) if domain_lower.endswith(f".{ext.lower()}")
        ]
        if matches:
            return max(matches, key=len).lower()

        return domain_lower.rsplit(".", maxsplit=1)[-1]

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
    def calculate_domain_cost(tld: TLD, years: int, include_whois_privacy: bool = False) -> dict[str, Any]:
        """💰 Calculate total domain cost with options"""
        base_cost_cents = tld.registration_price_cents * years
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
        validation_result = DomainLifecycleService._validate_registration_preconditions(domain_name, years)
        if validation_result is not None:
            return Err(validation_result)

        # Get validated components
        components = DomainLifecycleService._get_registration_components(domain_name)
        if components.is_err():
            return Err(components.unwrap_err())

        tld, registrar = components.unwrap()

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
    def _validate_registration_preconditions(domain_name: str, years: int) -> str | None:
        """Validate all preconditions for domain registration."""
        is_valid, error_msg = DomainValidationService.validate_domain_name(domain_name)
        if not is_valid:
            return error_msg

        if years < MIN_REGISTRATION_YEARS or years > MAX_REGISTRATION_YEARS:
            return str(
                _("Registration period must be between {min} and {max} years").format(
                    min=MIN_REGISTRATION_YEARS, max=MAX_REGISTRATION_YEARS
                )
            )

        if Domain.objects.filter(name=domain_name.lower()).exists():
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
        """Execute the actual domain registration.

        Two-step so the external registrar call never runs inside a DB transaction:
        1. Create the local Domain row in ``pending`` state (records intent).
        2. Submit to the registrar via the gateway. On success, persist the
           registrar-returned fields and FSM-transition the domain to ``active``.
           On failure, the domain stays ``pending`` (no failed state exists) so a
           later retry/worker can re-submit — the gateway is idempotent per domain.

        Returns Ok(domain) ONLY when the registrar confirms and the domain is
        active. On a definite rejection the pending row is removed and Err is
        returned so the caller can cleanly retry. On an UNKNOWN outcome (network
        error / 5xx — the registrar may already hold the registration) the row is
        kept pending and Err is returned so the caller never reports success and
        never orphans a possibly-real registration. Durable reconciliation of
        pending rows is tracked separately (issue #237).
        """
        try:
            with transaction.atomic():
                domain = Domain.objects.create(
                    name=config.domain_name.lower(),
                    tld=config.tld,
                    registrar=config.registrar,
                    customer=config.customer,
                    whois_privacy=config.whois_privacy,
                    auto_renew=config.auto_renew,
                )
                logger.info("Created domain registration: %s for customer %s", config.domain_name, config.customer.id)
        except Exception as e:
            logger.error("Failed to create domain registration: %s", e)
            return Err(cast(str, _("Failed to create domain registration")))

        # Submit to the registrar OUTSIDE the transaction above — never hold a DB
        # transaction open across network I/O.
        outcome, message = DomainLifecycleService._submit_registration_to_registrar(domain, config)

        if outcome == "confirmed":
            domain.refresh_from_db()
            return Ok(domain)
        if outcome == "pending_unknown":
            return Err(
                cast(
                    str,
                    _(
                        "Registration was submitted but the registrar did not confirm it. "
                        "It is pending verification — do not resubmit."
                    ),
                )
            )
        # Definite rejection: the pending row has been removed, retry is safe.
        return Err(cast(str, _("Registrar rejected the registration: {error}")).format(error=message))

    @staticmethod
    def _submit_registration_to_registrar(domain: Domain, config: DomainRegistrationConfig) -> tuple[str, str]:
        """Submit a pending domain to its registrar and resolve its final state.

        Returns one of:
        - ("confirmed", "")      registrar confirmed; the domain is now active.
        - ("rejected", message)  definite failure (conflict/auth/validation); the
                                 pending row is DELETED so a retry isn't deadlocked
                                 by the uniqueness precondition.
        - ("pending_unknown", message)  network/5xx (UNKNOWN) or a post-confirm
                                 persistence failure; the row is KEPT pending
                                 because the registrar may hold the registration.
        Never raises.
        """
        success, payload = DomainRegistrarGateway.register_domain(
            config.registrar, domain.name, config.years, config.registrant_data
        )

        if not success:
            error = str(payload.get("error", "unknown error"))
            if payload.get("retriability") == Retriability.UNKNOWN.value:
                logger.warning(
                    "Registrar outcome UNKNOWN for %s (kept pending, do not resubmit): %s", domain.name, error
                )
                return "pending_unknown", error
            # Definite rejection — remove the row so the customer can re-register.
            logger.warning("Registrar rejected %s (row removed for clean retry): %s", domain.name, error)
            domain.delete()
            return "rejected", error

        try:
            with transaction.atomic():
                locked = Domain.objects.select_for_update().get(pk=domain.pk)
                # Another worker may have already completed this domain.
                if locked.status != "pending":
                    return ("confirmed", "") if locked.status == "active" else ("pending_unknown", "")

                locked.registrar_domain_id = payload.get("registrar_domain_id", "")
                if payload.get("expires_at"):
                    locked.expires_at = payload["expires_at"]
                if payload.get("nameservers"):
                    locked.nameservers = payload["nameservers"]
                if payload.get("epp_code"):
                    locked.set_encrypted_epp_code(payload["epp_code"])
                locked.registered_at = timezone.now()
                locked.activate()  # FSM transition: pending -> active
                locked.save()

            logger.info("Registrar confirmed %s — domain active", domain.name)
            return "confirmed", ""
        except Exception as e:
            # The registrar confirmed but we failed to record it — the domain IS
            # registered, so keep the row pending (never delete/orphan) for reconciliation.
            logger.error("Failed to persist registrar result for %s (kept pending): %s", domain.name, e)
            return "pending_unknown", str(e)

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
        }

        # Required for every registrant, plus entity-specific identity fields.
        required = ["first_name", "email", "phone", "address", "city", "postal_code", "country_code"]
        required.append("company_name" if entity_type == "company" else "last_name")
        required.append("cui" if entity_type == "company" else "cnp")  # ROTLD regulatory requirement

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
    def process_domain_renewal(domain: Domain, years: int = 1) -> Result[str, str]:
        """Process domain renewal by renewing at the registrar first.

        The registrar is the source of truth for the new expiry — the local row is
        updated ONLY after the registrar confirms, using the registrar-returned
        date (never local ``365 * years`` math). On any registrar failure the local
        expiry is left untouched (failing toward "not renewed" is the safe
        direction; a later registrar-sync can correct it upward).

        Returns Ok(success_message) on confirmed renewal, Err(error_message) otherwise.
        """
        precondition_error = DomainLifecycleService._validate_renewal_preconditions(domain)
        if precondition_error is not None:
            return Err(precondition_error)

        success, payload = DomainRegistrarGateway.renew_domain(domain.registrar, domain, years)
        if not success:
            logger.warning("Registrar did not confirm renewal of %s: %s", domain.name, payload.get("error"))
            return Err(
                cast(str, _("Registrar did not confirm the renewal: {error}")).format(
                    error=payload.get("error", "unknown error")
                )
            )

        new_expiration = payload.get("new_expires_at")
        if not new_expiration:
            return Err(cast(str, _("Registrar renewal succeeded but returned no new expiry date")))

        try:
            with transaction.atomic():
                domain.expires_at = new_expiration
                domain.renewal_notices_sent = 0
                domain.save(update_fields=["expires_at", "renewal_notices_sent", "updated_at"])

            logger.info("Renewed domain %s for %d years at registrar, expires: %s", domain.name, years, new_expiration)
            return Ok(cast(str, _("Domain renewed successfully")))

        except Exception as e:
            logger.error("Failed to persist renewal for %s: %s", domain.name, e)
            return Err(cast(str, _("Failed to record the renewal")))

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
    def initiate_transfer(
        domain_name: str, epp_code: str, customer: Customer, registrar: Registrar
    ) -> Result[DomainOperation, str]:
        """Initiate inbound domain transfer (two-phase: DB record + registrar submit)."""
        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415

        try:
            gateway = RegistrarGatewayFactory.create_gateway(registrar)
        except ValueError:
            return Err(f"No gateway for registrar {registrar.name}")

        # Phase 1: create Domain + DomainOperation records
        try:
            with transaction.atomic():
                tld_ext = DomainValidationService.extract_tld_from_domain(domain_name)
                tld = TLDService.get_tld_pricing(tld_ext)
                if not tld:
                    return Err(cast(str, _(f"TLD '.{tld_ext}' is not supported")))

                domain = Domain.objects.create(
                    name=domain_name.lower(),
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
        result = gateway.initiate_transfer(domain.name, epp_code)
        if result.is_ok():
            transfer = result.unwrap()
            op.mark_submitted(registrar_operation_id=transfer.transfer_id)
            op.save(update_fields=["state", "registrar_operation_id", "submitted_at", "updated_at"])
            logger.info("Transfer initiated for %s: %s", domain_name, transfer.transfer_id)
            return Ok(op)

        # Failure: partition by retriability, mirroring _submit_registration_to_registrar.
        # Keep the pending Domain row ONLY on UNKNOWN (the transfer may have started at the
        # registrar); on a definite rejection OR a breaker-open RETRIABLE, delete the row so
        # the unique domain name isn't permanently stranded (the #260 deadlock class).
        error = result.unwrap_err()
        if retriability_of(result) == Retriability.UNKNOWN:
            op.mark_failed(error.code.value)
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

        result = gateway.update_nameservers(domain.name, nameservers)
        if result.is_ok():
            domain.nameservers = nameservers
            domain.save(update_fields=["nameservers", "updated_at"])
            op.mark_completed()
            op.save(update_fields=["state", "completed_at", "updated_at"])
            return Ok(op)

        error = result.unwrap_err()
        op.mark_failed(error.code.value)
        op.save(update_fields=["state", "error_message", "updated_at"])
        return Err(cast(str, _("Nameserver update failed: {error}")).format(error=error.code.value))

    @staticmethod
    def set_domain_lock(domain: Domain, locked: bool) -> Result[DomainOperation, str]:
        """Lock or unlock a domain at the registrar."""
        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415

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

        result = gateway.set_lock(domain.name, locked)
        if result.is_ok():
            domain.locked = locked
            domain.save(update_fields=["locked", "updated_at"])
            op.mark_completed()
            op.save(update_fields=["state", "completed_at", "updated_at"])
            return Ok(op)

        error = result.unwrap_err()
        op.mark_failed(error.code.value)
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
# DOMAIN NOTIFICATION SERVICE
# ===============================================================================


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
        now = timezone.now()

        conditions = Q()
        for days in notice_periods:
            cutoff_date = now + timedelta(days=days)
            conditions |= (
                Q(expires_at__date=cutoff_date.date())
                & ~Q(renewal_notices_sent=days)  # The current threshold has not been sent yet.
            )

        return Domain.objects.filter(conditions, status="active").select_related("customer", "tld")

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

        # Get TLD and pricing
        tld_extension = DomainValidationService.extract_tld_from_domain(domain_name)
        tld = TLDService.get_tld_pricing(tld_extension)
        if not tld:
            return False, cast(str, _(f"TLD '.{tld_extension}' is not supported"))

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

        try:
            order_item = DomainOrderItem.objects.create(
                order=order,
                domain_name=domain_name.lower(),
                tld=tld,
                action=action,
                years=years,
                unit_price_cents=unit_price_cents,
                total_price_cents=unit_price_cents * years,
                whois_privacy=whois_privacy,
                auto_renew=auto_renew,
                epp_code="",
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
    def process_domain_order_items(order: Order) -> list[Domain]:
        """⚡ Process all domain order items for paid order"""

        processed_domains = []

        domain_items = DomainOrderItem.objects.filter(order=order).select_related("tld")

        for item in domain_items:
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
                    logger.info("Processed registration: %s", item.domain_name)
                else:
                    logger.error("Failed to process registration %s: %s", item.domain_name, result.unwrap_err())

            elif item.action == "renew" and item.domain:
                renewal_result = DomainLifecycleService.process_domain_renewal(domain=item.domain, years=item.years)

                if renewal_result.is_ok():
                    processed_domains.append(item.domain)
                    logger.info("Processed renewal: %s", item.domain_name)
                else:
                    logger.error("Failed to process renewal %s: %s", item.domain_name, renewal_result.unwrap_err())

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

        result = gateway.register_domain(domain_name, years, customer_data)
        if result.is_ok():
            reg = result.unwrap()
            return True, {
                "registrar_domain_id": reg.registrar_domain_id,
                "expires_at": reg.expires_at,
                "nameservers": reg.nameservers,
                "epp_code": reg.epp_code,
            }
        # Carry the retriability so the lifecycle can tell a definite rejection
        # (safe to delete the pending row) from an UNKNOWN outcome (may have
        # registered server-side — must keep the row, never resubmit blindly).
        return False, {"error": str(result.unwrap_err()), "retriability": retriability_of(result).value}

    @staticmethod
    def renew_domain(registrar: Registrar, domain: Domain, years: int) -> tuple[bool, dict[str, Any]]:
        from .gateways import RegistrarGatewayFactory  # noqa: PLC0415

        try:
            gateway = RegistrarGatewayFactory.create_gateway(registrar)
        except ValueError:
            logger.error("No gateway registered for %s — cannot renew %s", registrar.name, domain.name)
            return False, {"error": f"No gateway for registrar {registrar.name}"}

        result = gateway.renew_domain(domain.registrar_domain_id, domain.name, years)
        if result.is_ok():
            renewal = result.unwrap()
            return True, {"new_expires_at": renewal.new_expires_at}
        return False, {"error": str(result.unwrap_err())}

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
