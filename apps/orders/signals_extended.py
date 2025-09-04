"""
Extended order signals for cross-app integration and data maintenance.
These complement the existing signals in signals.py with additional functionality.
"""

import logging
from typing import Any

from django.core.cache import cache
from django.core.files.storage import default_storage
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.common.validators import log_security_event

from .models import Order, OrderItem

# Optional service imports - these may not exist yet
try:
    from apps.domains.services import DomainRegistrationService  # type: ignore[attr-defined]
except ImportError:
    DomainRegistrationService = None

try:
    from apps.tickets.services import TicketCreateData, TicketService  # type: ignore[attr-defined]
except ImportError:
    TicketCreateData = None
    TicketService = None

logger = logging.getLogger(__name__)

# ===============================================================================
# CROSS-APP INTEGRATION SIGNALS
# ===============================================================================


@receiver(post_save, sender=Order)
def handle_order_domain_provisioning(sender: type[Order], instance: Order, created: bool, **kwargs: Any) -> None:
    """
    Trigger domain registration/management for orders containing domain products.

    This signal bridges orders → domains app for automatic domain provisioning.
    """
    try:
        if not created:
            return

        # Check if order contains domain products
        domain_items = instance.items.filter(product_type="domain", domain_name__isnull=False)

        if domain_items.exists():
            for item in domain_items:
                try:
                    if DomainRegistrationService is None:
                        logger.warning("🌐 [Domain] DomainRegistrationService not available, skipping registration")
                        continue

                    # Queue domain registration
                    result = DomainRegistrationService.queue_domain_registration(
                        domain_name=item.domain_name,
                        order_item=item,
                        registrar_preference=getattr(item, "meta", {}).get("registrar", "default"),
                    )

                    if hasattr(result, "is_ok") and result.is_ok():
                        logger.info(f"🌐 [Domain] Registration queued for {item.domain_name}")
                    else:
                        logger.error(
                            f"🔥 [Domain] Failed to queue registration: {getattr(result, 'error', 'Unknown error')}"
                        )

                except Exception as e:
                    logger.exception(f"🔥 [Domain] Domain registration signal failed: {e}")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Domain provisioning failed: {e}")


@receiver(post_save, sender=Order)
def handle_customer_credit_limit_update(sender: type[Order], instance: Order, created: bool, **kwargs: Any) -> None:
    """
    Update customer credit limits and payment history based on order patterns.

    This bridges orders → customers app for credit management.
    """
    try:
        if not created:
            old_status = getattr(instance, "_original_values", {}).get("status")

            # Update customer stats on order completion or payment
            if instance.status == "completed" and old_status != "completed":
                _update_customer_order_history(instance, "completed")

            elif instance.status in ["cancelled", "failed"] and old_status not in ["cancelled", "failed"]:
                _update_customer_order_history(instance, "negative")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Customer credit update failed: {e}")


@receiver(post_save, sender=OrderItem)
def handle_service_group_management(sender: type[OrderItem], instance: OrderItem, created: bool, **kwargs: Any) -> None:
    """
    Automatically create and manage service groups for order bundles.

    This bridges orders → provisioning for complex service relationships.
    """
    try:
        if not created:
            return

        # Check if this item is part of a service bundle
        order = instance.order
        bundle_items = order.items.filter(product_type="hosting", config__bundle_group__isnull=False).exclude(
            id=instance.id
        )

        if bundle_items.exists() and instance.config.get("bundle_group"):
            bundle_group = instance.config["bundle_group"]

            try:
                from apps.provisioning.services import ServiceGroupService  # noqa: PLC0415

                # Create or update service group for this bundle
                result = ServiceGroupService.create_or_update_bundle_group(  # type: ignore[attr-defined]
                    group_name=f"Order {order.order_number} - {bundle_group}",
                    order_items=[*list(bundle_items), instance],
                    primary_service=instance.service,
                )

                if hasattr(result, "is_ok") and result.is_ok():
                    service_group = result.unwrap() if hasattr(result, "unwrap") else None
                    if service_group:
                        logger.info(f"🔗 [Service Group] Created/updated {service_group.name}")

            except Exception as e:
                logger.exception(f"🔥 [Service Group] Bundle management failed: {e}")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Service group management failed: {e}")


# ===============================================================================
# TICKET INTEGRATION SIGNALS
# ===============================================================================


@receiver(post_save, sender=OrderItem)
def handle_failed_provisioning_ticket_creation(
    sender: type[OrderItem], instance: OrderItem, created: bool, **kwargs: Any
) -> None:
    """
    Automatically create support tickets for failed provisioning.

    This bridges orders → tickets for automated issue tracking.
    """
    try:
        if created:
            return

        old_status = getattr(instance, "_original_item_values", {}).get("provisioning_status")

        # Create ticket when provisioning fails
        if instance.provisioning_status == "failed" and old_status != "failed" and instance.service is not None:
            if TicketCreateData is None or TicketService is None:
                logger.warning("🎫 [Ticket] Ticket services not available, skipping ticket creation")
                return

            try:
                ticket_data = TicketCreateData(
                    customer=instance.order.customer,
                    subject=f"Service Provisioning Failed - Order {instance.order.order_number}",
                    description=f"""
                    Service provisioning failed for order item:
                    
                    Order: {instance.order.order_number}
                    Product: {instance.product_name}
                    Service ID: {instance.service.id}
                    Error: {instance.provisioning_notes or "No details provided"}
                    
                    Please investigate and resolve this issue.
                    """,
                    priority="high",
                    department="technical",
                    auto_created=True,
                    related_order=instance.order,
                    related_service=instance.service,
                )

                result = TicketService.create_ticket(ticket_data)
                if hasattr(result, "is_ok") and result.is_ok():
                    ticket = result.unwrap() if hasattr(result, "unwrap") else None
                    if ticket:
                        logger.info(f"🎫 [Ticket] Created #{ticket.id} for failed provisioning")
            except Exception as e:
                logger.exception(f"🔥 [Ticket] Failed provisioning ticket creation failed: {e}")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Ticket creation signal failed: {e}")


# ===============================================================================
# DATA CLEANUP & MAINTENANCE SIGNALS
# ===============================================================================


@receiver(post_delete, sender=Order)
def handle_order_cleanup(sender: type[Order], instance: Order, **kwargs: Any) -> None:
    """
    Clean up related data when orders are deleted.

    This handles file cleanup, cache invalidation, and audit compliance.
    """
    try:
        # Clear related caches
        cache_keys = [
            f"order:{instance.id}",
            f"customer_orders:{instance.customer.id}",
            f"order_items:{instance.id}",
            f"order_totals:{instance.id}",
        ]

        cache.delete_many(cache_keys)
        logger.info(f"🗑️ [Cache] Cleared order caches for {instance.order_number}")

        # Clean up any uploaded files
        _cleanup_order_files(instance)

        # Cancel any pending webhook deliveries
        _cancel_order_webhooks(instance)

        # Log the deletion for audit
        log_security_event(
            "order_deleted",
            {
                "order_id": str(instance.id),
                "order_number": instance.order_number,
                "customer_id": str(instance.customer.id),
                "total_cents": instance.total_cents,
                "status": instance.status,
            },
        )

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Order cleanup failed: {e}")


@receiver(post_delete, sender=OrderItem)
def handle_order_item_service_cleanup(sender: type[OrderItem], instance: OrderItem, **kwargs: Any) -> None:
    """
    Handle service cleanup when order items are deleted.

    This ensures services are properly handled when their order items are removed.
    """
    try:
        if instance.service:
            try:
                from apps.provisioning.services import ServiceManagementService  # noqa: PLC0415

                # Mark service for review if order item is deleted
                result = ServiceManagementService.mark_service_for_review(  # type: ignore[call-arg]
                    service=instance.service, reason=f"Order item {instance.id} deleted", priority="high"
                )

                if result.is_ok():  # type: ignore[attr-defined]
                    logger.info(f"⚠️ [Service] Marked service {instance.service.id} for review")

            except Exception as e:
                logger.exception(f"🔥 [Service] Service cleanup failed: {e}")

        # Clear item-specific caches
        cache.delete(f"order_item:{instance.id}")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Item cleanup failed: {e}")


# ===============================================================================
# INTEGRATION STATUS TRACKING SIGNALS
# ===============================================================================


@receiver(post_save, sender=Order)
def handle_external_system_sync(sender: type[Order], instance: Order, created: bool, **kwargs: Any) -> None:
    """
    Sync order data with external systems (accounting, CRM, etc.).

    This enables integration with Romanian accounting systems and ERP platforms.
    """
    try:
        if not created:
            return

        # Check if customer has external integrations enabled
        if hasattr(instance.customer, "integrations") and instance.customer.integrations.exists():
            active_integrations = instance.customer.integrations.filter(is_active=True)

            for integration in active_integrations:
                try:
                    from apps.integrations.services import ExternalSyncService  # noqa: PLC0415

                    # Queue sync job for each active integration
                    ExternalSyncService.queue_order_sync(  # type: ignore[attr-defined]
                        order=instance, integration=integration, sync_type="order_created"
                    )

                    logger.info(f"🔄 [Integration] Queued {integration.name} sync for order {instance.order_number}")

                except Exception as e:
                    logger.exception(f"🔥 [Integration] Sync queueing failed for {integration.name}: {e}")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] External system sync failed: {e}")


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================


def _update_customer_order_history(order: Order, event_type: str) -> None:
    """Update customer order statistics and payment history"""
    try:
        from apps.customers.services import CustomerStatsService  # noqa: PLC0415

        CustomerStatsService.update_order_stats(  # type: ignore[attr-defined]
            customer=order.customer, event_type=event_type, order_total=order.total_cents, order_date=order.created_at
        )

        logger.info(f"📊 [Customer] Updated order history for {order.customer.id}")

    except Exception as e:
        logger.exception(f"🔥 [Customer] Order history update failed: {e}")


def _cleanup_order_files(order: Order) -> None:
    """Clean up any files associated with the order"""
    try:
        # Check for uploaded files in order meta
        if order.meta.get("uploaded_files"):
            for file_path in order.meta["uploaded_files"]:
                try:
                    if default_storage.exists(file_path):
                        default_storage.delete(file_path)
                        logger.info(f"🗑️ [File] Deleted {file_path}")
                except Exception as e:
                    logger.exception(f"🔥 [File] Failed to delete {file_path}: {e}")

        # Clean up any generated PDFs or documents
        _cleanup_generated_documents(order)

    except Exception as e:
        logger.exception(f"🔥 [Order] File cleanup failed: {e}")


def _cleanup_generated_documents(order: Order) -> None:
    """Clean up generated PDFs and documents for the order"""
    try:
        # This would clean up any order confirmations, contracts, etc.
        # Implementation depends on where these files are stored
        pass
    except Exception as e:
        logger.exception(f"🔥 [Order] Document cleanup failed: {e}")


def _cancel_order_webhooks(order: Order) -> None:
    """Cancel any pending webhook deliveries for the order"""
    try:
        from apps.integrations.models import WebhookDelivery  # noqa: PLC0415

        # Cancel pending webhooks related to this order
        # Use customer and event type since WebhookDelivery doesn't use GenericForeignKey
        pending_webhooks = WebhookDelivery.objects.filter(
            customer=order.customer,
            event_type__startswith="order.",  # order.created, order.cancelled, etc.
            status="pending",
        )

        cancelled_count = pending_webhooks.update(status="cancelled")

        if cancelled_count > 0:
            logger.info(f"🚫 [Webhook] Cancelled {cancelled_count} pending deliveries for order {order.order_number}")

    except Exception as e:
        logger.exception(f"🔥 [Webhook] Webhook cancellation failed: {e}")
