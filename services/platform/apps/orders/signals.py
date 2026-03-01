"""
Order signals for PRAHO Platform
Event-driven order lifecycle management with Romanian compliance.
"""

import contextlib
import logging
from typing import Any

from django.db.models.signals import post_delete, post_save, pre_save
from django.dispatch import receiver

from apps.audit.services import AuditContext, AuditEventData, AuditService, BusinessEventData, OrdersAuditService
from apps.common.validators import log_security_event

from .models import Order, OrderItem

logger = logging.getLogger(__name__)

# ===============================================================================
# ORDER LIFECYCLE SIGNALS
# ===============================================================================


@receiver(post_save, sender=Order)
def handle_order_created_or_updated(sender: type[Order], instance: Order, created: bool, **kwargs: Any) -> None:
    """
    Handle order creation and updates.

    Triggers:
    - Audit logging for all order changes
    - Invoice generation when order is paid
    - Notification sending for status changes
    - Service provisioning queue updates
    """
    try:
        # Audit logging for all order changes
        event_type = "order_created" if created else "order_updated"

        # Get the previous values for audit (if available)
        old_values = getattr(instance, "_original_values", {}) if not created else {}
        new_values = {
            "order_number": instance.order_number,
            "status": instance.status,
            "total_cents": instance.total_cents,
            "customer_id": str(instance.customer.id),
        }

        # Enhanced order audit logging using OrdersAuditService
        event_data = BusinessEventData(
            event_type=event_type,
            business_object=instance,
            user=None,  # System event
            context=AuditContext(actor_type="system"),
            old_values=old_values,
            new_values=new_values,
            description=f"Order {instance.order_number} {'created' if created else 'updated'}",
        )
        OrdersAuditService.log_order_event(event_data)

        if created:
            # Order created - send welcome email
            _send_order_confirmation_email(instance)
            logger.info(f"✅ [Order] Created {instance.order_number} for {instance.customer}")

        else:
            # Order updated - check for status changes
            old_status = old_values.get("status")
            if old_status and old_status != instance.status:
                _handle_order_status_change(instance, old_status, instance.status)

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Failed to handle order save: {e}")


@receiver(pre_save, sender=Order)
def store_original_order_values(sender: type[Order], instance: Order, **kwargs: Any) -> None:
    """Store original values before saving for audit trail.

    Note on Race Conditions:
    This signal reads original values without locking. In theory, two concurrent updates
    could both read the same "original" values. However:
    1. Using select_for_update in signals can cause deadlocks
    2. The worst case is slightly inaccurate audit trails (A->C instead of A->B->C)
    3. Primary data integrity is maintained by Django's normal save() mechanism
    4. For critical operations, use dedicated service methods with proper locking instead

    The trade-off of occasional audit imprecision is acceptable vs. deadlock risk.
    """
    try:
        if instance.pk:  # Only for existing orders
            try:
                # Read current database state for comparison
                # Note: No select_for_update to avoid deadlocks in signal handlers
                original = Order.objects.get(pk=instance.pk)
                instance._original_values = {
                    "status": original.status,
                    "total_cents": original.total_cents,
                    "notes": original.notes,
                }
            except Order.DoesNotExist:
                instance._original_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Failed to store original values: {e}")


def _handle_order_status_change(order: Order, old_status: str, new_status: str) -> None:
    """Handle order status changes with various triggers"""
    try:
        logger.info(f"🔄 [Order] Status change {order.order_number}: {old_status} → {new_status}")

        # Security event for important status changes
        log_security_event(
            "order_status_changed",
            {
                "order_id": str(order.id),
                "order_number": order.order_number,
                "customer_id": str(order.customer.id),
                "old_status": old_status,
                "new_status": new_status,
            },
        )

        # Trigger different actions based on status transitions
        if new_status == "pending" and old_status == "draft":
            # Order becomes payable - create pending services (industry standard)
            _create_pending_services_for_order(order)

        elif new_status == "processing" and old_status == "pending":
            # Payment received - generate invoice and update services to provisioning
            _trigger_invoice_generation(order)
            _update_services_to_provisioning(order)

        elif new_status == "completed" and old_status == "processing":
            # Order completed - start provisioning
            _trigger_service_provisioning(order)
            _send_order_completed_email(order)

        elif new_status == "cancelled":
            # Order cancelled - cleanup and notifications
            _handle_order_cancellation(order, old_status)

        elif new_status in ["refunded", "partially_refunded"]:
            # Refund processed - update related services
            _handle_order_refund(order, new_status)

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Failed to handle status change: {e}")


def _create_pending_services_for_order(order: Order) -> None:
    """Create pending Service records when order becomes payable (industry standard)"""
    try:
        from .services import OrderServiceCreationService  # noqa: PLC0415

        result = OrderServiceCreationService.create_pending_services(order)
        if result.is_ok():
            services_created = result.unwrap()
            if services_created:
                logger.info(
                    f"✅ [Order Signal] Created {len(services_created)} pending services for order {order.order_number}"
                )
            else:
                logger.info(f"💡 [Order Signal] No new services created for order {order.order_number}")
        else:
            logger.error(f"🔥 [Order Signal] Service creation failed: {result.error}")  # type: ignore[union-attr]

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Service creation failed: {e}")


def _update_services_to_provisioning(order: Order) -> None:
    """Update service status from pending to provisioning when payment confirmed"""
    try:
        from .services import OrderServiceCreationService  # noqa: PLC0415

        result = OrderServiceCreationService.update_service_status_on_payment(order)
        if result.is_ok():
            updated_services = result.unwrap()
            logger.info(f"🔄 [Order Signal] Updated {len(updated_services)} services to provisioning status")
        else:
            logger.error(f"🔥 [Order Signal] Service status update failed: {result.error}")  # type: ignore[union-attr]

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Service status update failed: {e}")


def _trigger_invoice_generation(order: Order) -> None:
    """Trigger automatic invoice generation for processing orders"""
    try:
        # Try to import invoice generation service
        try:
            from apps.billing.services import InvoiceService  # noqa: PLC0415
        except ImportError:
            logger.warning("📋 [Order] InvoiceGenerationService not available, skipping invoice generation")
            return

        # Generate invoice asynchronously if Django-Q2 is available
        try:
            from django_q.tasks import async_task  # noqa: PLC0415

            async_task("apps.orders.tasks.generate_invoice_for_order", str(order.id))
            logger.info(f"📋 [Order] Invoice generation queued for {order.order_number}")
        except ImportError:
            # Fallback to synchronous generation
            result = InvoiceService.generate_from_order(order)
            if hasattr(result, "is_ok") and result.is_ok():
                invoice = result.unwrap() if hasattr(result, "unwrap") else None
                if invoice:
                    logger.info(f"📋 [Order] Invoice {invoice.number} generated for {order.order_number}")
            else:
                logger.error(f"🔥 [Order] Invoice generation failed: {getattr(result, 'error', 'Unknown error')}")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Invoice generation failed: {e}")


def _trigger_service_provisioning(order: Order) -> None:
    """Trigger service provisioning for completed orders"""
    try:
        from apps.provisioning.services import ProvisioningService  # noqa: PLC0415

        # Queue provisioning tasks for all order items
        for item in order.items.all():
            if item.provisioning_status == "pending":
                try:
                    from django_q.tasks import async_task  # noqa: PLC0415

                    async_task("apps.orders.tasks.provision_order_item", str(item.id))
                    logger.info(f"⚡ [Order] Provisioning queued for item {item.id}")
                except ImportError:
                    # Fallback to synchronous provisioning
                    result = ProvisioningService.provision_order_item(item)
                    if result.is_ok():
                        logger.info(f"⚡ [Order] Item {item.id} provisioned successfully")
                    else:
                        logger.error(f"🔥 [Order] Provisioning failed: {result.error}")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Provisioning trigger failed: {e}")


def _handle_order_cancellation(order: Order, old_status: str) -> None:
    """Handle order cancellation cleanup"""
    try:
        # Cancel any pending provisioning
        order.items.filter(provisioning_status="pending").update(provisioning_status="cancelled")

        # Send cancellation email
        _send_order_cancelled_email(order)

        # If order was processing, may need to handle refunds
        if old_status == "processing":
            logger.warning(f"⚠️ [Order] Processing order {order.order_number} cancelled - manual refund review needed")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Cancellation handling failed: {e}")


def _handle_order_refund(order: Order, refund_status: str) -> None:
    """Handle order refund completion"""
    try:
        # Suspend related services if full refund
        if refund_status == "refunded":
            from apps.provisioning.services import ServiceManagementService  # noqa: PLC0415

            services = [item.service for item in order.items.filter(service__isnull=False) if item.service]

            for service in services:
                result = ServiceManagementService.suspend_service(
                    service, reason="Order fully refunded", suspend_immediately=True
                )
                if result.is_ok():
                    logger.info(f"🔄 [Order] Service {service.id} suspended due to refund")

        # Send refund notification
        _send_order_refund_email(order, refund_status)

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Refund handling failed: {e}")


# ===============================================================================
# ORDER ITEM SIGNALS
# ===============================================================================


@receiver(post_save, sender=OrderItem)
def handle_order_item_changes(sender: type[OrderItem], instance: OrderItem, created: bool, **kwargs: Any) -> None:
    """
    Handle order item creation and updates.

    Triggers:
    - Order total recalculation
    - Provisioning queue updates
    - Service relationship management
    """
    try:
        if created:
            # New item added - recalculate order totals
            instance.order.calculate_totals()
            logger.info(f"📦 [Order] Item added to {instance.order.order_number}: {instance.product_name}")

        else:
            # Item updated - check for provisioning status changes
            old_values = getattr(instance, "_original_item_values", {})
            old_provisioning_status = old_values.get("provisioning_status")

            if old_provisioning_status != instance.provisioning_status:
                _handle_item_provisioning_status_change(instance, old_provisioning_status)

        # Enhanced order item audit logging
        event_type = "order_item_added" if created else "order_item_updated"
        old_values = getattr(instance, "_original_item_values", {}) if not created else {}
        new_values = {
            "product_name": instance.product_name,
            "quantity": instance.quantity,
            "provisioning_status": instance.provisioning_status,
            "unit_price_cents": instance.unit_price_cents,
        }

        OrdersAuditService.log_order_item_event(
            BusinessEventData(
                event_type=event_type,
                business_object=instance,
                user=None,
                context=AuditContext(actor_type="system"),
                old_values=old_values,
                new_values=new_values,
                description=f"Order item {'added to' if created else 'updated in'} {instance.order.order_number}",
            )
        )

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Failed to handle order item change: {e}")


@receiver(pre_save, sender=OrderItem)
def store_original_item_values(sender: type[OrderItem], instance: OrderItem, **kwargs: Any) -> None:
    """Store original order item values for comparison"""
    try:
        if instance.pk:
            try:
                original = OrderItem.objects.get(pk=instance.pk)
                instance._original_item_values = {
                    "provisioning_status": original.provisioning_status,
                    "quantity": original.quantity,
                }
            except OrderItem.DoesNotExist:
                instance._original_item_values = {}
    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Failed to store original item values: {e}")


@receiver(post_delete, sender=OrderItem)
def handle_order_item_deletion(sender: type[OrderItem], instance: OrderItem, **kwargs: Any) -> None:
    """Handle order item deletion"""
    try:
        # Recalculate order totals
        if instance.order_id:  # Order might be deleted too
            with contextlib.suppress(Order.DoesNotExist):
                instance.order.calculate_totals()

        # Audit log the deletion
        event_data = AuditEventData(
            event_type="order_item_deleted",
            content_object=instance.order if hasattr(instance, "order") else None,
            description=f"Order item deleted: {instance.product_name}",
        )
        AuditService.log_event(event_data)

        logger.info(f"🗑️ [Order] Item deleted from order: {instance.product_name}")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Failed to handle item deletion: {e}")


def _handle_item_provisioning_status_change(item: OrderItem, old_status: str | None) -> None:
    """Handle order item provisioning status changes"""
    try:
        new_status = item.provisioning_status
        logger.info(f"⚡ [Order] Item {item.id} provisioning: {old_status} → {new_status}")

        # Log specific provisioning events with OrdersAuditService
        provisioning_events = {
            "in_progress": "provisioning_started",
            "completed": "provisioning_completed",
            "failed": "provisioning_failed",
            "cancelled": "provisioning_cancelled",
        }

        if new_status in provisioning_events:
            OrdersAuditService.log_provisioning_event(  # type: ignore[call-arg]
                event_type=provisioning_events[new_status],
                order_item=item,
                service=item.service,
                user=None,  # System event
                context=AuditContext(actor_type="system"),
                description=f"Order item provisioning {new_status}: {item.product_name}",
            )

        if new_status == "completed" and item.service:
            # Item successfully provisioned - send notification
            _send_service_ready_email(item)

            # Check if all items in order are provisioned
            order = item.order
            all_completed = all(oi.provisioning_status == "completed" for oi in order.items.all())

            if all_completed and order.status == "processing":
                # Mark order as completed
                from apps.orders.services import OrderService, StatusChangeData  # noqa: PLC0415

                status_change = StatusChangeData(new_status="completed", notes="All items successfully provisioned")
                OrderService.update_order_status(order, status_change)

        elif new_status == "failed":
            # Provisioning failed - may need manual intervention
            logger.error(f"🔥 [Order] Item {item.id} provisioning failed: {item.provisioning_notes}")
            _send_provisioning_failed_email(item)

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Item provisioning status change failed: {e}")


# ===============================================================================
# EMAIL NOTIFICATION HELPERS
# ===============================================================================


def _send_order_confirmation_email(order: Order) -> None:
    """Send order confirmation email"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="order_confirmation",
            recipient=order.customer_email,
            context={"order": order, "customer": order.customer, "order_items": order.items.all()},
            priority="high",
        )
    except Exception as e:
        logger.exception(f"🔥 [Order] Failed to send confirmation email: {e}")


def _send_order_completed_email(order: Order) -> None:
    """Send order completion email"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="order_completed",
            recipient=order.customer_email,
            context={"order": order, "customer": order.customer},
            priority="normal",
        )
    except Exception as e:
        logger.exception(f"🔥 [Order] Failed to send completion email: {e}")


def _send_order_cancelled_email(order: Order) -> None:
    """Send order cancellation email"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="order_cancelled",
            recipient=order.customer_email,
            context={"order": order, "customer": order.customer},
        )
    except Exception as e:
        logger.exception(f"🔥 [Order] Failed to send cancellation email: {e}")


def _send_order_refund_email(order: Order, refund_status: str) -> None:
    """Send order refund notification email"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        template_key = "order_refunded" if refund_status == "refunded" else "order_partially_refunded"

        EmailService.send_template_email(
            template_key=template_key,
            recipient=order.customer_email,
            context={"order": order, "customer": order.customer, "refund_status": refund_status},
        )
    except Exception as e:
        logger.exception(f"🔥 [Order] Failed to send refund email: {e}")


def _send_service_ready_email(item: OrderItem) -> None:
    """Send service ready notification"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="service_ready",
            recipient=item.order.customer_email,
            context={"order_item": item, "service": item.service, "order": item.order, "customer": item.order.customer},
        )
    except Exception as e:
        logger.exception(f"🔥 [Order] Failed to send service ready email: {e}")


def _send_provisioning_failed_email(item: OrderItem) -> None:
    """Send provisioning failure notification"""
    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415

        EmailService.send_template_email(
            template_key="provisioning_failed",
            recipient=item.order.customer_email,
            context={
                "order_item": item,
                "order": item.order,
                "customer": item.order.customer,
                "error_message": item.provisioning_notes,
            },
            priority="high",
        )
    except Exception as e:
        logger.exception(f"🔥 [Order] Failed to send provisioning failed email: {e}")
