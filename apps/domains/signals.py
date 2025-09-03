"""
Comprehensive domain signals for PRAHO Platform
Event-driven domain management with audit logging and cross-app integration.

Includes:
- Core domain lifecycle events (registration, renewal, transfer, expiration)
- TLD configuration and pricing change monitoring
- Registrar management and API credential security
- Domain security events (EPP codes, lock status, WHOIS privacy)
- Domain order processing and integration
- Business analytics and reporting
- Cross-app integration (billing, customers, orders)
"""

import logging
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db.models.signals import post_delete, post_save, pre_save
from django.dispatch import receiver
from django.utils import timezone

from apps.audit.services import (
    AuditContext,
    AuditEventData,
    AuditService,
    DomainsAuditService,
)
from apps.common.validators import log_security_event

from .models import TLD, Domain, DomainOrderItem, Registrar, TLDRegistrarAssignment

logger = logging.getLogger(__name__)

# ===============================================================================
# DOMAIN LIFECYCLE SIGNALS
# ===============================================================================


@receiver(post_save, sender=Domain)
def handle_domain_created_or_updated(sender: type[Domain], instance: Domain, created: bool, **kwargs: Any) -> None:
    """
    Handle domain creation and updates.

    Triggers:
    - Audit logging for all domain changes
    - Email notifications for status changes
    - Cross-app integration (billing, orders)
    - Security logging for sensitive operations
    - Business analytics updates
    """
    try:
        # Enhanced audit logging using DomainsAuditService
        event_type = "domain_registered" if created else "domain_updated"

        old_values = getattr(instance, "_original_domain_values", {}) if not created else {}
        new_values = {
            "name": instance.name,
            "status": instance.status,
            "registrar": instance.registrar.name if instance.registrar else None,
            "tld": instance.tld.extension if instance.tld else None,
            "expires_at": instance.expires_at.isoformat() if instance.expires_at else None,
            "auto_renew": instance.auto_renew,
            "whois_privacy": instance.whois_privacy,
            "is_locked": instance.is_locked,
            "customer_id": str(instance.customer.id) if instance.customer else None,
        }

        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            # Use specialized domains audit service for richer metadata
            DomainsAuditService.log_domain_event(
                event_type=event_type,
                domain=instance,
                user=None,  # System event
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Domain {instance.name} {'registered' if created else 'updated'}",
            )

        if created:
            # New domain registered
            _handle_new_domain_registration(instance)
            logger.info(f"🌐 [Domain] Registered {instance.name} with {instance.registrar}")

        else:
            # Domain updated - check for status changes
            old_status = old_values.get("status")
            if old_status and old_status != instance.status:
                _handle_domain_status_change_with_virtualmin_sync(instance, old_status, instance.status)

            # Check for expiration changes
            old_expires_at = old_values.get("expires_at")
            if old_expires_at != new_values.get("expires_at"):
                _handle_domain_expiration_change(instance, old_expires_at)

            # Check for registrar changes (transfers)
            old_registrar = old_values.get("registrar")
            if old_registrar and old_registrar != new_values.get("registrar"):
                _handle_domain_transfer(instance, old_registrar, new_values.get("registrar"))

            # Check for security-related changes
            _check_domain_security_changes(instance, old_values, new_values)

        # Update domain analytics
        _update_domain_analytics(instance, created)

    except Exception as e:
        logger.exception(f"🔥 [Domain Signal] Failed to handle domain save: {e}")


@receiver(pre_save, sender=Domain)
def store_original_domain_values(sender: type[Domain], instance: Domain, **kwargs: Any) -> None:
    """Store original values before saving for audit trail"""
    try:
        if instance.pk:
            try:
                original = Domain.objects.get(pk=instance.pk)
                instance._original_domain_values = {
                    "name": original.name,
                    "status": original.status,
                    "registrar": original.registrar.name if original.registrar else None,
                    "tld": original.tld.extension if original.tld else None,
                    "expires_at": original.expires_at.isoformat() if original.expires_at else None,
                    "auto_renew": original.auto_renew,
                    "whois_privacy": original.whois_privacy,
                    "is_locked": original.is_locked,
                }
            except Domain.DoesNotExist:
                instance._original_domain_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Domain Signal] Failed to store original values: {e}")


@receiver(post_delete, sender=Domain)
def handle_domain_cleanup(sender: type[Domain], instance: Domain, **kwargs: Any) -> None:
    """
    Clean up related data when domains are deleted.
    Security consideration: log domain deletion for audit purposes.
    """
    try:
        # Log domain deletion for security audit
        log_security_event(
            "domain_deleted",
            {
                "domain_id": str(instance.id),
                "domain_name": instance.name,
                "registrar": instance.registrar.name if instance.registrar else None,
                "customer_id": str(instance.customer.id) if instance.customer else None,
                "status": instance.status,
                "expires_at": instance.expires_at.isoformat() if instance.expires_at else None,
            },
        )

        # Clean up domain-related caches
        _invalidate_domain_caches(instance)

        # Cancel any pending domain renewal tasks
        _cancel_domain_renewal_tasks(instance)

        logger.warning(f"🗑️ [Domain] Cleaned up deleted domain {instance.name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain Signal] Cleanup failed: {e}")


# ===============================================================================
# TLD CONFIGURATION SIGNALS
# ===============================================================================


@receiver(post_save, sender=TLD)
def handle_tld_created_or_updated(sender: type[TLD], instance: TLD, created: bool, **kwargs: Any) -> None:
    """
    Handle TLD creation and updates.

    Triggers:
    - Audit logging for TLD configuration changes
    - Cache invalidation for pricing calculations
    - Business analytics updates
    - Cross-app notification for pricing changes
    """
    try:
        event_type = "tld_created" if created else "tld_updated"

        old_values = getattr(instance, "_original_tld_values", {}) if not created else {}
        new_values = {
            "extension": instance.extension,
            "registration_price_cents": instance.registration_price_cents,
            "renewal_price_cents": instance.renewal_price_cents,
            "transfer_price_cents": instance.transfer_price_cents,
            "status": instance.status,
        }

        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            DomainsAuditService.log_tld_event(
                event_type=event_type,
                tld=instance,
                user=None,  # System event
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"TLD .{instance.extension} {'created' if created else 'updated'}",
            )

        if not created:
            # Check for pricing changes
            pricing_fields = ["registration_price_cents", "renewal_price_cents", "transfer_price_cents"]
            pricing_changed = any(old_values.get(field) != new_values.get(field) for field in pricing_fields)

            if pricing_changed:
                _handle_tld_pricing_change(instance, old_values, new_values)

        # Invalidate TLD-related caches
        _invalidate_tld_caches(instance)

        logger.info(f"🌐 [TLD] {'Created' if created else 'Updated'} .{instance.extension}")

    except Exception as e:
        logger.exception(f"🔥 [TLD Signal] Failed to handle TLD save: {e}")


@receiver(pre_save, sender=TLD)
def store_original_tld_values(sender: type[TLD], instance: TLD, **kwargs: Any) -> None:
    """Store original TLD values for comparison"""
    try:
        if instance.pk:
            try:
                original = TLD.objects.get(pk=instance.pk)
                instance._original_tld_values = {
                    "extension": original.extension,
                    "registration_price_cents": original.registration_price_cents,
                    "renewal_price_cents": original.renewal_price_cents,
                    "transfer_price_cents": original.transfer_price_cents,
                    "status": original.status,
                }
            except TLD.DoesNotExist:
                instance._original_tld_values = {}
    except Exception as e:
        logger.exception(f"🔥 [TLD Signal] Failed to store original values: {e}")


# ===============================================================================
# REGISTRAR MANAGEMENT SIGNALS
# ===============================================================================


@receiver(post_save, sender=Registrar)
def handle_registrar_created_or_updated(
    sender: type[Registrar], instance: Registrar, created: bool, **kwargs: Any
) -> None:
    """
    Handle registrar creation and updates.

    Triggers:
    - Audit logging for registrar configuration changes
    - Security logging for API credential changes
    - Cache invalidation for registrar listings
    - Business analytics updates
    """
    try:
        event_type = "registrar_created" if created else "registrar_updated"

        old_values = getattr(instance, "_original_registrar_values", {}) if not created else {}
        new_values = {
            "name": instance.name,
            "api_url": "[REDACTED]",  # Never log API URLs
            "status": instance.status,
        }

        # Check if this is a security-sensitive update
        security_sensitive = not created and (
            old_values.get("api_url") != "[REDACTED]"  # API URL changed
            or "api_key" in str(kwargs.get("update_fields", []))  # API credentials updated
        )

        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            DomainsAuditService.log_registrar_event(
                event_type=event_type,
                registrar=instance,
                user=None,  # System event
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Registrar {instance.name} {'created' if created else 'updated'}",
                security_sensitive=security_sensitive,
            )

        if security_sensitive:
            # Log security event for API credential changes
            log_security_event(
                "registrar_api_credentials_updated",
                {
                    "registrar_id": str(instance.id),
                    "registrar_name": instance.name,
                    "timestamp": timezone.now().isoformat(),
                },
            )

        # Invalidate registrar-related caches
        _invalidate_registrar_caches(instance)

        logger.info(f"🔧 [Registrar] {'Created' if created else 'Updated'} {instance.name}")

    except Exception as e:
        logger.exception(f"🔥 [Registrar Signal] Failed to handle registrar save: {e}")


@receiver(pre_save, sender=Registrar)
def store_original_registrar_values(sender: type[Registrar], instance: Registrar, **kwargs: Any) -> None:
    """Store original registrar values for comparison"""
    try:
        if instance.pk:
            try:
                original = Registrar.objects.get(pk=instance.pk)
                instance._original_registrar_values = {
                    "name": original.name,
                    "api_url": "[REDACTED]",  # Never log API URLs
                    "status": original.status,
                }
            except Registrar.DoesNotExist:
                instance._original_registrar_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Registrar Signal] Failed to store original values: {e}")


# ===============================================================================
# TLD-REGISTRAR ASSIGNMENT SIGNALS
# ===============================================================================


@receiver(post_save, sender=TLDRegistrarAssignment)
def handle_tld_registrar_assignment(
    sender: type[TLDRegistrarAssignment], instance: TLDRegistrarAssignment, created: bool, **kwargs: Any
) -> None:
    """
    Handle TLD-Registrar assignment changes.

    This tracks which registrars can handle which TLDs, important for:
    - Business continuity planning
    - Failover scenarios
    - Pricing optimization
    """
    try:
        event_type = "tld_registrar_assignment_created" if created else "tld_registrar_assignment_updated"

        # Audit the assignment change
        event_data = AuditEventData(
            event_type=event_type,
            content_object=instance,
            description=f"TLD .{instance.tld.extension} {'assigned to' if created else 'updated for'} registrar {instance.registrar.name}",
        )

        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            AuditService.log_event(event_data)

        # Invalidate related caches
        _invalidate_tld_registrar_caches(instance.tld, instance.registrar)

        logger.info(f"🔗 [TLD Assignment] .{instance.tld.extension} ↔ {instance.registrar.name}")

    except Exception as e:
        logger.exception(f"🔥 [TLD Assignment Signal] Failed to handle assignment: {e}")


# ===============================================================================
# DOMAIN ORDER ITEM SIGNALS
# ===============================================================================


@receiver(post_save, sender=DomainOrderItem)
def handle_domain_order_item_processing(
    sender: type[DomainOrderItem], instance: DomainOrderItem, created: bool, **kwargs: Any
) -> None:
    """
    Handle domain order item creation and processing.

    Triggers:
    - Audit logging for order processing
    - Cross-app integration with billing and orders
    - Domain provisioning workflows
    """
    try:
        event_type = "domain_order_created" if created else "domain_order_updated"

        old_values = getattr(instance, "_original_order_item_values", {}) if not created else {}
        new_values = {
            "domain_name": instance.domain_name,
            "operation_type": instance.operation_type,
            "registrar": instance.registrar.name if instance.registrar else None,
            "tld": instance.tld.extension if instance.tld else None,
            "price_cents": instance.price_cents,
        }

        if not getattr(settings, "DISABLE_AUDIT_SIGNALS", False):
            DomainsAuditService.log_domain_order_event(
                event_type=event_type,
                domain_order_item=instance,
                user=None,  # System event
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Domain order {instance.operation_type}: {instance.domain_name}",
            )

        if created:
            # New domain order created
            _handle_new_domain_order(instance)
        else:
            # Check for processing status changes
            # This would typically involve checking order item status fields
            _handle_domain_order_processing(instance, old_values, new_values)

        logger.info(f"📋 [Domain Order] {instance.operation_type} for {instance.domain_name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain Order Signal] Failed to handle order item: {e}")


@receiver(pre_save, sender=DomainOrderItem)
def store_original_order_item_values(sender: type[DomainOrderItem], instance: DomainOrderItem, **kwargs: Any) -> None:
    """Store original order item values for comparison"""
    try:
        if instance.pk:
            try:
                original = DomainOrderItem.objects.get(pk=instance.pk)
                instance._original_order_item_values = {
                    "domain_name": original.domain_name,
                    "operation_type": original.operation_type,
                    "registrar": original.registrar.name if original.registrar else None,
                    "tld": original.tld.extension if original.tld else None,
                    "price_cents": original.price_cents,
                }
            except DomainOrderItem.DoesNotExist:
                instance._original_order_item_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Domain Order Signal] Failed to store original values: {e}")


# ===============================================================================
# BUSINESS LOGIC FUNCTIONS
# ===============================================================================


def _handle_new_domain_registration(domain: Domain) -> None:
    """Handle new domain registration tasks"""
    try:
        # Send domain registration confirmation
        _send_domain_registration_email(domain)

        # Schedule domain renewal reminders
        if domain.expires_at:
            _schedule_domain_renewal_reminders(domain)

        # Update customer domain statistics
        _update_customer_domain_stats(domain.customer)

        # Cross-app integration: update billing if needed
        _sync_domain_billing(domain, "registered")

    except Exception as e:
        logger.exception(f"🔥 [Domain Signal] New registration handling failed: {e}")


def _handle_domain_status_change(domain: Domain, old_status: str, new_status: str) -> None:
    """Handle domain status changes with various triggers"""
    try:
        logger.info(f"🔄 [Domain] Status change {domain.name}: {old_status} → {new_status}")

        # Security logging for important status changes
        log_security_event(
            "domain_status_changed",
            {
                "domain_id": str(domain.id),
                "domain_name": domain.name,
                "customer_id": str(domain.customer.id) if domain.customer else None,
                "old_status": old_status,
                "new_status": new_status,
                "registrar": domain.registrar.name if domain.registrar else None,
            },
        )

        # Handle specific status transitions
        if new_status == "active" and old_status in ["pending", "suspended"]:
            _handle_domain_activation(domain)
        elif new_status == "expired" and old_status == "active":
            _handle_domain_expiration(domain)
        elif new_status == "suspended" and old_status == "active":
            _handle_domain_suspension(domain)
        elif new_status == "transferred" and old_status in ["active", "pending_transfer"]:
            _handle_domain_transfer_completion(domain)

    except Exception as e:
        logger.exception(f"🔥 [Domain Signal] Status change handling failed: {e}")


def _handle_domain_expiration_change(domain: Domain, old_expires_at: str | None) -> None:
    """Handle domain expiration date changes"""
    try:
        # Cancel old renewal reminders
        if old_expires_at:
            _cancel_domain_renewal_tasks(domain)

        # Schedule new renewal reminders
        if domain.expires_at:
            _schedule_domain_renewal_reminders(domain)

        # Log expiration change for business analytics
        logger.info(f"📅 [Domain] Expiration updated for {domain.name}: {old_expires_at} → {domain.expires_at}")

    except Exception as e:
        logger.exception(f"🔥 [Domain Signal] Expiration change handling failed: {e}")


def _handle_domain_transfer(domain: Domain, old_registrar: str | None, new_registrar: str | None) -> None:
    """Handle domain transfer between registrars"""
    try:
        # Log security event for domain transfer
        DomainsAuditService.log_domain_security_event(
            event_type="domain_transfer_completed",
            domain=domain,
            security_action="registrar_transfer",
            security_metadata={
                "old_registrar": old_registrar,
                "new_registrar": new_registrar,
                "transfer_date": timezone.now().isoformat(),
            },
            description=f"Domain {domain.name} transferred from {old_registrar} to {new_registrar}",
        )

        # Send transfer confirmation email
        _send_domain_transfer_email(domain, old_registrar, new_registrar)

        # Update domain analytics
        _update_domain_transfer_analytics(domain, old_registrar, new_registrar)

        logger.info(f"🔄 [Domain] Transfer completed: {domain.name} ({old_registrar} → {new_registrar})")

    except Exception as e:
        logger.exception(f"🔥 [Domain Signal] Transfer handling failed: {e}")


def _check_domain_security_changes(domain: Domain, old_values: dict[str, Any], new_values: dict[str, Any]) -> None:
    """Check for security-related domain changes"""
    try:
        # Check for lock status changes
        if old_values.get("is_locked") != new_values.get("is_locked"):
            DomainsAuditService.log_domain_security_event(
                event_type="domain_lock_changed",
                domain=domain,
                security_action="lock_status_changed",
                security_metadata={
                    "old_locked": old_values.get("is_locked"),
                    "new_locked": new_values.get("is_locked"),
                },
            )

        # Check for WHOIS privacy changes
        if old_values.get("whois_privacy") != new_values.get("whois_privacy"):
            DomainsAuditService.log_domain_security_event(
                event_type="whois_privacy_changed",
                domain=domain,
                security_action="whois_privacy_changed",
                security_metadata={
                    "old_privacy": old_values.get("whois_privacy"),
                    "new_privacy": new_values.get("whois_privacy"),
                },
            )

    except Exception as e:
        logger.exception(f"🔥 [Domain Signal] Security check failed: {e}")


def _handle_tld_pricing_change(tld: TLD, old_values: dict[str, Any], new_values: dict[str, Any]) -> None:
    """Handle TLD pricing changes with notifications"""
    try:
        # Calculate pricing changes
        pricing_changes = {}
        pricing_fields = ["registration_price_cents", "renewal_price_cents", "transfer_price_cents"]

        for field in pricing_fields:
            old_price = old_values.get(field, 0)
            new_price = new_values.get(field, 0)
            if old_price != new_price:
                pricing_changes[field] = {
                    "old_price_cents": old_price,
                    "new_price_cents": new_price,
                    "change_cents": new_price - old_price,
                    "change_percent": ((new_price - old_price) / old_price * 100) if old_price > 0 else 0,
                }

        if pricing_changes:
            # Log pricing change for business analytics
            logger.info(f"💰 [TLD] Pricing changed for .{tld.extension}: {pricing_changes}")

            # Notify relevant stakeholders
            _send_tld_pricing_change_notification(tld, pricing_changes)

            # Update billing system caches
            _invalidate_billing_tld_caches(tld)

    except Exception as e:
        logger.exception(f"🔥 [TLD Signal] Pricing change handling failed: {e}")


# ===============================================================================
# CROSS-APP INTEGRATION FUNCTIONS
# ===============================================================================


def _sync_domain_billing(domain: Domain, event_type: str) -> None:
    """Sync domain events with billing system"""
    try:
        # This would integrate with the billing system
        # For example, creating invoice line items for domain registrations
        logger.info(f"💰 [Domain] Synced billing for {domain.name}: {event_type}")

    except Exception as e:
        logger.exception(f"🔥 [Domain] Billing sync failed: {e}")


def _handle_new_domain_order(domain_order_item: DomainOrderItem) -> None:
    """Handle new domain order creation"""
    try:
        # Send order confirmation
        _send_domain_order_confirmation(domain_order_item)

        # Schedule order processing
        _schedule_domain_order_processing(domain_order_item)

        # Update order analytics
        _update_domain_order_analytics(domain_order_item, "created")

    except Exception as e:
        logger.exception(f"🔥 [Domain Order] New order handling failed: {e}")


def _handle_domain_order_processing(
    domain_order_item: DomainOrderItem, old_values: dict[str, Any], new_values: dict[str, Any]
) -> None:
    """Handle domain order processing updates"""
    try:
        # Check for processing status changes and handle accordingly
        logger.info(f"📋 [Domain Order] Processing update for {domain_order_item.domain_name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain Order] Processing handling failed: {e}")


# ===============================================================================
# ANALYTICS & REPORTING FUNCTIONS
# ===============================================================================


def _update_domain_analytics(domain: Domain, created: bool) -> None:
    """Update domain analytics and KPIs"""
    try:
        # Update domain metrics
        logger.info(f"📊 [Analytics] Updated domain metrics for {domain.name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain Analytics] Update failed: {e}")


def _update_customer_domain_stats(customer: Any) -> None:
    """Update customer domain statistics"""
    try:
        logger.info(f"📊 [Customer] Updated domain stats for {customer}")

    except Exception as e:
        logger.exception(f"🔥 [Customer] Domain stats update failed: {e}")


def _update_domain_transfer_analytics(domain: Domain, old_registrar: str | None, new_registrar: str | None) -> None:
    """Update analytics for domain transfers"""
    try:
        logger.info(f"📊 [Analytics] Domain transfer recorded: {domain.name}")

    except Exception as e:
        logger.exception(f"🔥 [Transfer Analytics] Update failed: {e}")


def _update_domain_order_analytics(domain_order_item: DomainOrderItem, event_type: str) -> None:
    """Update domain order analytics"""
    try:
        logger.info(f"📊 [Order Analytics] Updated for {domain_order_item.domain_name}: {event_type}")

    except Exception as e:
        logger.exception(f"🔥 [Order Analytics] Update failed: {e}")


# ===============================================================================
# EMAIL NOTIFICATION FUNCTIONS
# ===============================================================================


def _send_domain_registration_email(domain: Domain) -> None:
    """Send domain registration confirmation email"""
    try:
        logger.info(f"📧 [Domain] Would send registration email for {domain.name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain Email] Registration email failed: {e}")


def _send_domain_transfer_email(domain: Domain, old_registrar: str | None, new_registrar: str | None) -> None:
    """Send domain transfer confirmation email"""
    try:
        logger.info(f"📧 [Domain] Would send transfer email for {domain.name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain Email] Transfer email failed: {e}")


def _send_tld_pricing_change_notification(tld: TLD, pricing_changes: dict[str, Any]) -> None:
    """Send TLD pricing change notification to stakeholders"""
    try:
        logger.info(f"📧 [TLD] Would send pricing change notification for .{tld.extension}")

    except Exception as e:
        logger.exception(f"🔥 [TLD Email] Pricing notification failed: {e}")


def _send_domain_order_confirmation(domain_order_item: DomainOrderItem) -> None:
    """Send domain order confirmation email"""
    try:
        logger.info(f"📧 [Order] Would send order confirmation for {domain_order_item.domain_name}")

    except Exception as e:
        logger.exception(f"🔥 [Order Email] Confirmation email failed: {e}")


# ===============================================================================
# BUSINESS LOGIC HELPER FUNCTIONS
# ===============================================================================


def _handle_domain_activation(domain: Domain) -> None:
    """Handle domain activation"""
    try:
        logger.info(f"✅ [Domain] Activated {domain.name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain] Activation handling failed: {e}")


def _handle_domain_expiration(domain: Domain) -> None:
    """Handle domain expiration"""
    try:
        logger.warning(f"⚠️ [Domain] Expired {domain.name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain] Expiration handling failed: {e}")


def _handle_domain_suspension(domain: Domain) -> None:
    """Handle domain suspension"""
    try:
        logger.warning(f"⏸️ [Domain] Suspended {domain.name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain] Suspension handling failed: {e}")


def _handle_domain_transfer_completion(domain: Domain) -> None:
    """Handle domain transfer completion"""
    try:
        logger.info(f"🔄 [Domain] Transfer completed for {domain.name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain] Transfer completion failed: {e}")


# ===============================================================================
# SCHEDULING AND TASK FUNCTIONS
# ===============================================================================


def _schedule_domain_renewal_reminders(domain: Domain) -> None:
    """Schedule domain renewal reminder tasks"""
    try:
        logger.info(f"📅 [Domain] Would schedule renewal reminders for {domain.name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain] Renewal scheduling failed: {e}")


def _cancel_domain_renewal_tasks(domain: Domain) -> None:
    """Cancel domain renewal reminder tasks"""
    try:
        logger.info(f"🚫 [Domain] Would cancel renewal tasks for {domain.name}")

    except Exception as e:
        logger.exception(f"🔥 [Domain] Task cancellation failed: {e}")


def _schedule_domain_order_processing(domain_order_item: DomainOrderItem) -> None:
    """Schedule domain order processing tasks"""
    try:
        logger.info(f"📅 [Order] Would schedule processing for {domain_order_item.domain_name}")

    except Exception as e:
        logger.exception(f"🔥 [Order] Processing scheduling failed: {e}")


# ===============================================================================
# CACHE INVALIDATION FUNCTIONS
# ===============================================================================


def _invalidate_domain_caches(domain: Domain) -> None:
    """Invalidate caches related to the domain"""
    try:
        cache_keys = [
            f"domain:{domain.id}",
            f"domain_name:{domain.name}",
            f"customer_domains:{domain.customer.id}",
            "active_domains",
            "expiring_domains",
        ]

        cache.delete_many(cache_keys)

    except Exception as e:
        logger.exception(f"🔥 [Cache] Domain cache cleanup failed: {e}")


def _invalidate_tld_caches(tld: TLD) -> None:
    """Invalidate TLD-related caches"""
    try:
        cache_keys = [f"tld:{tld.id}", f"tld_extension:{tld.extension}", "active_tlds", "tld_pricing"]

        cache.delete_many(cache_keys)

    except Exception as e:
        logger.exception(f"🔥 [Cache] TLD cache cleanup failed: {e}")


def _invalidate_registrar_caches(registrar: Registrar) -> None:
    """Invalidate registrar-related caches"""
    try:
        cache_keys = [f"registrar:{registrar.id}", "active_registrars", "registrar_tlds"]

        cache.delete_many(cache_keys)

    except Exception as e:
        logger.exception(f"🔥 [Cache] Registrar cache cleanup failed: {e}")


def _invalidate_tld_registrar_caches(tld: TLD, registrar: Registrar) -> None:
    """Invalidate TLD-registrar assignment caches"""
    try:
        cache_keys = [f"tld_registrars:{tld.id}", f"registrar_tlds:{registrar.id}", "tld_registrar_assignments"]

        cache.delete_many(cache_keys)

    except Exception as e:
        logger.exception(f"🔥 [Cache] TLD-registrar cache cleanup failed: {e}")


def _invalidate_billing_tld_caches(tld: TLD) -> None:
    """Invalidate billing-related TLD caches"""
    try:
        cache_keys = [f"tld_pricing:{tld.extension}", "domain_pricing", "billing_tld_rates"]

        cache.delete_many(cache_keys)

    except Exception as e:
        logger.exception(f"🔥 [Cache] Billing TLD cache cleanup failed: {e}")


# ===============================================================================
# CROSS-APP INTEGRATION: VIRTUALMIN DOMAIN SYNCHRONIZATION
# ===============================================================================


def sync_domain_to_virtualmin(domain: Domain) -> None:
    """
    Sync domain creation/updates to Virtualmin control panel.
    
    Cross-app integration point: domains → provisioning
    """
    try:
        # Import here to avoid circular imports
        from apps.provisioning.models import Service  # noqa: PLC0415
        from apps.provisioning.virtualmin_models import VirtualminAccount  # noqa: PLC0415
        from apps.provisioning.virtualmin_service import VirtualminProvisioningService  # noqa: PLC0415
        
        # Find hosting services associated with this domain
        hosting_services = Service.objects.filter(
            domains__domain__name=domain.name,
            status__in=['active', 'provisioning']
        ).distinct()
        
        if hosting_services:
            logger.info(f"🔄 [CrossApp] Syncing domain {domain.name} to Virtualmin for {len(hosting_services)} services")
            
            for service in hosting_services:
                try:
                    # Check if Virtualmin account already exists
                    virtualmin_account = VirtualminAccount.objects.filter(
                        domain=domain.name,
                        service=service
                    ).first()
                    
                    if virtualmin_account:
                        # Update existing account if needed
                        if domain.status != 'active' and virtualmin_account.status == 'active':
                            # Domain became inactive - suspend Virtualmin account
                            provisioning_service = VirtualminProvisioningService()
                            result = provisioning_service.suspend_account(
                                virtualmin_account, 
                                reason=f"Domain status changed to {domain.status}"
                            )
                            
                            if result.is_ok():
                                logger.info(f"🚫 [CrossApp] Suspended Virtualmin account for {domain.name}")
                            else:
                                logger.error(f"🔥 [CrossApp] Failed to suspend Virtualmin account for {domain.name}: {result.unwrap_err()}")
                                
                        elif domain.status == 'active' and virtualmin_account.status == 'suspended':
                            # Domain became active - unsuspend Virtualmin account
                            provisioning_service = VirtualminProvisioningService()
                            result = provisioning_service.unsuspend_account(virtualmin_account)
                            
                            if result.is_ok():
                                logger.info(f"✅ [CrossApp] Unsuspended Virtualmin account for {domain.name}")
                            else:
                                logger.error(f"🔥 [CrossApp] Failed to unsuspend Virtualmin account for {domain.name}: {result.unwrap_err()}")
                    else:
                        # No existing account - this might need provisioning
                        logger.debug(f"📋 [CrossApp] No Virtualmin account found for domain {domain.name}, may need provisioning")
                        
                except Exception as e:
                    logger.error(f"🔥 [CrossApp] Failed to sync domain {domain.name} to service {service.id}: {e}")
                    
        else:
            logger.debug(f"📋 [CrossApp] No hosting services found for domain {domain.name}, skipping Virtualmin sync")
            
    except Exception as e:
        logger.error(f"🔥 [CrossApp] Failed to sync domain {domain.name} to Virtualmin: {e}")


# Enhanced domain creation handler to include Virtualmin sync
def _handle_new_domain_registration_with_virtualmin_sync(domain: Domain) -> None:
    """
    Handle new domain registration with Virtualmin synchronization.
    
    Extends the existing domain registration handler to include control panel sync.
    """
    try:
        # Call existing domain registration logic
        _handle_new_domain_registration(domain)
        
        # Add Virtualmin synchronization
        if domain.status == 'active':
            sync_domain_to_virtualmin(domain)
            
    except Exception as e:
        logger.error(f"🔥 [CrossApp] Enhanced domain registration handling failed for {domain.name}: {e}")


def _handle_domain_status_change_with_virtualmin_sync(domain: Domain, old_status: str, new_status: str) -> None:
    """
    Handle domain status changes with Virtualmin synchronization.
    
    Extends the existing status change handler to include control panel sync.
    """
    try:
        # Call existing status change logic
        _handle_domain_status_change(domain, old_status, new_status)
        
        # Add Virtualmin synchronization for status changes
        if old_status != new_status:
            sync_domain_to_virtualmin(domain)
            
    except Exception as e:
        logger.error(f"🔥 [CrossApp] Enhanced domain status change handling failed for {domain.name}: {e}")
