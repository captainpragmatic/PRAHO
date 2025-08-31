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
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, cast

from django.db import transaction
from django.db.models import Q, QuerySet
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from .models import TLD, Domain, DomainOrderItem, Registrar

if TYPE_CHECKING:
    from apps.customers.models import Customer
    from apps.orders.models import Order

logger = logging.getLogger(__name__)

# Domain name validation constants
MIN_DOMAIN_NAME_LENGTH = 3  # Minimum length for domain names
MAX_DOMAIN_NAME_LENGTH = 253  # Maximum length per RFC 1035


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
        
        return Domain.objects.filter(
            customer=customer
        ).select_related(
            'tld', 'registrar', 'customer'
        ).order_by('-created_at')

    @staticmethod
    def get_expiring_domains(days: int = 30) -> QuerySet[Domain]:
        """⚠️ Get domains expiring within specified days"""
        
        cutoff_date = timezone.now() + timedelta(days=days)
        return Domain.objects.filter(
            status='active',
            expires_at__lte=cutoff_date,
            expires_at__gt=timezone.now()
        ).select_related('customer', 'tld', 'registrar')

    @staticmethod
    def get_auto_renewal_candidates() -> QuerySet[Domain]:
        """🔄 Get domains eligible for auto-renewal"""
        
        # Domains expiring in 7 days or less, with auto_renew enabled
        renewal_cutoff = timezone.now() + timedelta(days=7)
        return Domain.objects.filter(
            status='active',
            auto_renew=True,
            expires_at__lte=renewal_cutoff,
            expires_at__gt=timezone.now()
        ).select_related('customer', 'tld', 'registrar')

    @staticmethod
    def search_domains(query: str, customer: Customer | None = None) -> QuerySet[Domain]:
        """🔍 Search domains by name with optional customer filter"""
        
        queryset = Domain.objects.filter(
            name__icontains=query
        ).select_related('customer', 'tld', 'registrar')
        
        if customer:
            queryset = queryset.filter(customer=customer)
        
        return queryset

    @staticmethod
    def get_registrar_domains(registrar: Registrar, status: str | None = None) -> QuerySet[Domain]:
        """🏢 Get domains managed by specific registrar"""
        
        queryset = Domain.objects.filter(
            registrar=registrar
        ).select_related('customer', 'tld')
        
        if status:
            queryset = queryset.filter(status=status)
        
        return queryset.order_by('-expires_at')


# ===============================================================================
# DOMAIN VALIDATION SERVICE
# ===============================================================================

class DomainValidationService:
    """
    ✅ Domain validation and availability checking service
    
    Provides validation for domain names and checks availability.
    """

    @staticmethod
    def validate_domain_name(domain_name: str) -> tuple[bool, str]:  # noqa: PLR0911 # Domain validation requires multiple early returns
        """🔍 Validate domain name format and characters"""
        if not domain_name:
            return False, cast(str, _("Domain name is required"))
        
        # Remove leading/trailing whitespace
        domain_name = domain_name.strip().lower()
        
        # Check length
        if len(domain_name) < MIN_DOMAIN_NAME_LENGTH:
            return False, cast(str, _("Domain name too short (minimum 3 characters)"))
        if len(domain_name) > MAX_DOMAIN_NAME_LENGTH:
            return False, cast(str, _("Domain name too long (maximum 253 characters)"))
        
        # Check for valid characters (letters, numbers, dots, hyphens)
        if not all(c.isalnum() or c in '.-' for c in domain_name):
            return False, cast(str, _("Domain name contains invalid characters"))
        
        # Check for proper structure
        if '..' in domain_name:
            return False, cast(str, _("Domain name cannot contain consecutive dots"))
        if domain_name.startswith('-') or domain_name.endswith('-'):
            return False, cast(str, _("Domain name cannot start or end with hyphen"))
        if domain_name.startswith('.') or domain_name.endswith('.'):
            return False, cast(str, _("Domain name cannot start or end with dot"))
        
        # Must contain at least one dot (TLD)
        if '.' not in domain_name:
            return False, cast(str, _("Domain name must include TLD (e.g., .com, .ro)"))
        
        return True, ""

    @staticmethod
    def extract_tld_from_domain(domain_name: str) -> str:
        """🌐 Extract TLD from domain name"""
        if '.' not in domain_name:
            return ""
        return domain_name.split('.')[-1].lower()

    @staticmethod
    def is_romanian_domain(domain_name: str) -> bool:
        """🇷🇴 Check if domain is Romanian (.ro, .com.ro, etc.)"""
        romanian_tlds = ['ro', 'com.ro', 'org.ro', 'info.ro', 'arts.ro', 'firm.ro']
        domain_lower = domain_name.lower()
        return any(domain_lower.endswith(f'.{tld}') for tld in romanian_tlds)


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
        
        return TLD.objects.filter(
            is_active=True
        ).prefetch_related(
            'registrar_assignments__registrar'
        ).order_by('extension')

    @staticmethod
    def get_featured_tlds() -> QuerySet[TLD]:
        """⭐ Get featured TLDs for homepage"""
        
        return TLD.objects.filter(
            is_active=True,
            is_featured=True
        ).order_by('registration_price_cents')

    @staticmethod
    def get_tld_pricing(tld_extension: str) -> TLD | None:
        """💰 Get TLD pricing and configuration"""
        
        try:
            return TLD.objects.get(
                extension=tld_extension.lower(),
                is_active=True
            )
        except TLD.DoesNotExist:
            return None

    @staticmethod
    def calculate_domain_cost(tld: TLD, years: int, include_whois_privacy: bool = False) -> dict[str, Any]:
        """💰 Calculate total domain cost with options"""
        base_cost_cents = tld.registration_price_cents * years
        whois_cost_cents = 0
        
        # Add WHOIS privacy cost if requested and available
        if include_whois_privacy and tld.whois_privacy_available:
            # WHOIS privacy typically costs 500 cents (5 RON) per year
            whois_cost_cents = 500 * years
        
        total_cost_cents = base_cost_cents + whois_cost_cents
        
        return {
            'base_cost_cents': base_cost_cents,
            'base_cost': base_cost_cents / 100,
            'whois_cost_cents': whois_cost_cents,
            'whois_cost': whois_cost_cents / 100,
            'total_cost_cents': total_cost_cents,
            'total_cost': total_cost_cents / 100,
            'years': years,
            'tld_extension': tld.extension,
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
        assignment = tld.registrar_assignments.filter(
            is_primary=True,
            is_active=True,
            registrar__status='active'
        ).select_related('registrar').first()
        
        return assignment.registrar if assignment else None

    @staticmethod
    def get_fallback_registrars_for_tld(tld: TLD) -> QuerySet[Registrar]:
        """🔄 Get fallback registrars for TLD in priority order"""
        
        return Registrar.objects.filter(
            tld_assignments__tld=tld,
            tld_assignments__is_active=True,
            tld_assignments__is_primary=False,
            status='active'
        ).order_by('tld_assignments__priority')

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
                registrar.save(update_fields=[
                    'total_domains', 'last_sync_at', 'last_error', 'updated_at'
                ])
                updated += 1
            except Exception as e:
                logger.error(f"🔥 [Registrar] Sync failed for {registrar.name}: {e}")
                registrar.last_error = str(e)
                registrar.last_sync_at = timezone.now()
                registrar.save(update_fields=['last_error', 'last_sync_at', 'updated_at'])

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
        customer: Customer,
        domain_name: str,
        years: int = 1,
        whois_privacy: bool = False,
        auto_renew: bool = True
    ) -> tuple[bool, Domain | str]:
        """🆕 Create new domain registration"""
        
        # Validate domain name
        is_valid, error_msg = DomainValidationService.validate_domain_name(domain_name)
        if not is_valid:
            return False, error_msg
        
        # Extract and validate TLD
        tld_extension = DomainValidationService.extract_tld_from_domain(domain_name)
        tld = TLDService.get_tld_pricing(tld_extension)
        if not tld:
            return False, cast(str, _(f"TLD '.{tld_extension}' is not supported"))
        
        # Select registrar
        registrar = RegistrarService.select_best_registrar_for_tld(tld)
        if not registrar:
            return False, cast(str, _("No available registrar for this TLD"))
        
        # Check if domain already exists
        if Domain.objects.filter(name=domain_name.lower()).exists():
            return False, cast(str, _("Domain is already registered in the system"))
        
        try:
            with transaction.atomic():
                # Create domain record
                domain = Domain.objects.create(
                    name=domain_name.lower(),
                    tld=tld,
                    registrar=registrar,
                    customer=customer,
                    status='pending',  # Will be updated when actually registered
                    whois_privacy=whois_privacy,
                    auto_renew=auto_renew,
                    # Expiration will be set when registration completes
                )
                
                logger.info(
                    f"🆕 [Domain] Created domain registration record: {domain_name} for customer {customer.id}"
                )
                
                return True, domain
                
        except Exception as e:
            logger.error(f"🔥 [Domain] Failed to create domain registration: {e}")
            return False, cast(str, _("Failed to create domain registration"))

    @staticmethod
    def process_domain_renewal(domain: Domain, years: int = 1) -> tuple[bool, str]:
        """🔄 Process domain renewal"""
        if domain.status != 'active':
            return False, cast(str, _("Domain must be active to renew"))
        
        if not domain.expires_at:
            return False, cast(str, _("Domain expiration date is not set"))
        
        try:
            with transaction.atomic():
                # Calculate new expiration date
                new_expiration = domain.expires_at + timedelta(days=365 * years)
                
                # Update domain
                domain.expires_at = new_expiration
                domain.renewal_notices_sent = 0  # Reset renewal notices
                domain.save(update_fields=['expires_at', 'renewal_notices_sent', 'updated_at'])
                
                logger.info(
                    f"🔄 [Domain] Renewed domain {domain.name} for {years} years, expires: {new_expiration}"
                )
                
                return True, cast(str, _("Domain renewed successfully"))
                
        except Exception as e:
            logger.error(f"🔥 [Domain] Failed to renew domain {domain.name}: {e}")
            return False, cast(str, _("Failed to renew domain"))

    @staticmethod
    def update_domain_expiration(domain: Domain, new_expiration: datetime) -> bool:
        """📅 Update domain expiration date (from registrar sync)"""
        try:
            domain.expires_at = new_expiration
            domain.save(update_fields=['expires_at', 'updated_at'])
            
            logger.info(f"📅 [Domain] Updated expiration for {domain.name}: {new_expiration}")
            return True
            
        except Exception as e:
            logger.error(f"🔥 [Domain] Failed to update expiration for {domain.name}: {e}")
            return False


# ===============================================================================
# DOMAIN NOTIFICATION SERVICE
# ===============================================================================

class DomainNotificationService:
    """
    📧 Domain notification and alerting service
    
    Handles expiration notices, renewal reminders, and domain alerts.
    """

    @staticmethod
    def get_domains_needing_renewal_notice() -> QuerySet[Domain]:
        """📧 Get domains that need renewal notices"""
        
        # Domains expiring in 30, 14, 7, 3, 1 days
        notice_periods = [30, 14, 7, 3, 1]
        
        conditions = Q()
        for days in notice_periods:
            cutoff_date = timezone.now() + timedelta(days=days)
            conditions |= Q(
                expires_at__date=cutoff_date.date(),
                renewal_notices_sent__lt=days  # Haven't sent notice for this period yet
            )
        
        return Domain.objects.filter(
            conditions,
            status='active'
        ).select_related('customer', 'tld')

    @staticmethod
    def mark_renewal_notice_sent(domain: Domain, notice_period: int) -> None:
        """📧 Mark renewal notice as sent"""
        domain.renewal_notices_sent = max(domain.renewal_notices_sent, notice_period)
        domain.last_renewal_notice = timezone.now()
        domain.save(update_fields=['renewal_notices_sent', 'last_renewal_notice', 'updated_at'])


# ===============================================================================
# DOMAIN ORDER PROCESSING SERVICE
# ===============================================================================

class DomainOrderService:
    """
    🛒 Domain order processing service
    
    Handles domain orders from the e-commerce system.
    """

    @staticmethod
    def create_domain_order_item(  # noqa: PLR0913 # Domain order requires multiple configuration parameters
        order: Order,
        domain_name: str,
        action: str,
        years: int = 1,
        whois_privacy: bool = False,
        auto_renew: bool = True,
        epp_code: str = ""
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
        if action == 'register':
            unit_price_cents = tld.registration_price_cents
        elif action == 'renew':
            unit_price_cents = tld.renewal_price_cents
        elif action == 'transfer':
            unit_price_cents = tld.transfer_price_cents
        else:
            return False, cast(str, _("Invalid domain action"))
        
        # Add WHOIS privacy cost
        if whois_privacy and tld.whois_privacy_available:
            unit_price_cents += 500  # 5 RON per year
        
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
                epp_code=epp_code if action == 'transfer' else ""
            )
            
            logger.info(f"🛒 [Domain] Created order item: {action} {domain_name} for {years} years")
            return True, order_item
            
        except Exception as e:
            logger.error(f"🔥 [Domain] Failed to create order item: {e}")
            return False, cast(str, _("Failed to create domain order item"))

    @staticmethod
    def process_domain_order_items(order: Order) -> list[Domain]:
        """⚡ Process all domain order items for paid order"""
        
        processed_domains = []
        
        domain_items = DomainOrderItem.objects.filter(
            order=order
        ).select_related('tld')
        
        for item in domain_items:
            if item.action == 'register':
                success, result = DomainLifecycleService.create_domain_registration(
                    customer=order.customer,
                    domain_name=item.domain_name,
                    years=item.years,
                    whois_privacy=item.whois_privacy,
                    auto_renew=item.auto_renew
                )
                
                if success and isinstance(result, Domain):
                    item.domain = result
                    item.save(update_fields=['domain'])
                    processed_domains.append(result)
                    
                    logger.info(f"✅ [Domain] Processed registration: {item.domain_name}")
                else:
                    logger.error(f"🔥 [Domain] Failed to process registration: {item.domain_name}")
            
            elif item.action == 'renew' and item.domain:
                success, msg = DomainLifecycleService.process_domain_renewal(
                    domain=item.domain,
                    years=item.years
                )
                
                if success:
                    processed_domains.append(item.domain)
                    logger.info(f"✅ [Domain] Processed renewal: {item.domain_name}")
                else:
                    logger.error(f"🔥 [Domain] Failed to process renewal: {item.domain_name}")
        
        return processed_domains


# ===============================================================================
# DOMAIN GATEWAY - EXTERNAL INTEGRATIONS
# ===============================================================================

class DomainRegistrarGateway:
    """
    🌐 External registrar API integration gateway
    
    Provides abstraction layer for different registrar APIs (Namecheap, GoDaddy, ROTLD).
    This is a placeholder implementation for future registrar integrations.
    """

    @staticmethod
    def register_domain(
        registrar: Registrar,
        domain_name: str,
        years: int,
        customer_data: dict[str, Any]
    ) -> tuple[bool, dict[str, Any]]:
        """🆕 Register domain with external registrar"""
        logger.info(f"🌐 [Gateway] Would register {domain_name} via {registrar.name}")
        
        # TODO: Implement actual registrar API calls
        # This is a placeholder implementation
        return True, {
            'registrar_domain_id': f'DOM_{domain_name}_{timezone.now().timestamp()}',
            'expires_at': timezone.now() + timedelta(days=365 * years),
            'nameservers': registrar.default_nameservers or [],
            'epp_code': f'EPP_{domain_name[:10].upper()}',
        }

    @staticmethod
    def renew_domain(
        registrar: Registrar,
        domain: Domain,
        years: int
    ) -> tuple[bool, dict[str, Any]]:
        """🔄 Renew domain with external registrar"""
        logger.info(f"🌐 [Gateway] Would renew {domain.name} via {registrar.name}")
        
        # TODO: Implement actual registrar API calls
        return True, {
            'new_expires_at': (domain.expires_at or timezone.now()) + timedelta(days=365 * years),
        }

    @staticmethod
    def check_domain_availability(
        registrar: Registrar,
        domain_name: str
    ) -> tuple[bool, bool]:  # (success, available)
        """🔍 Check domain availability with registrar"""
        logger.info(f"🌐 [Gateway] Would check availability for {domain_name} via {registrar.name}")
        
        # TODO: Implement actual availability check
        # For now, assume domain is available if not in our database
        is_available = not Domain.objects.filter(name=domain_name.lower()).exists()
        
        return True, is_available
