"""
Order signals for PRAHO Platform
Event-driven order lifecycle management with Romanian compliance.
"""

import contextlib
import logging
from typing import Any

from django.core.cache import cache
from django.core.files.storage import default_storage
from django.db import transaction
from django.db.models.signals import post_delete, post_save, pre_save
from django.dispatch import receiver
from django_fsm import ConcurrentTransition, TransitionNotAllowed

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

        # M1 review fix: Audit logging in its own try/except so failure doesn't
        # prevent on_commit callbacks from being registered (emails, status handling).
        try:
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
        except Exception as e:
            logger.warning("⚠️ [Order Signal] Audit logging failed for %s: %s", instance.order_number, e)

        if created:
            # Wrap in on_commit so email is not sent if the enclosing transaction
            # rolls back (e.g. atomic block that saves the Order then fails later).
            # L4 fix: Use default arg capture for consistency with billing signals pattern
            transaction.on_commit(lambda order=instance: _send_order_confirmation_email(order))
            logger.info(f"✅ [Order] Created {instance.order_number} for {instance.customer}")

        else:
            # Order updated - check for status changes
            old_status = old_values.get("status")
            if old_status and old_status != instance.status:
                # Capture loop variables to avoid late-binding closure issues.
                _old = old_status
                _new = instance.status
                transaction.on_commit(
                    lambda order=instance, old=_old, new=_new: _handle_order_status_change(order, old, new)
                )

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
        if new_status == "awaiting_payment" and old_status == "draft":
            # Order becomes payable — create pending services (industry standard)
            _create_pending_services_for_order(order)

            # C1: Smart email timing based on payment method
            # Bank transfer: send proforma email immediately (customer needs payment details)
            # Card: defer email (Stripe handles the flow; send proforma only on failure)
            # TODO: Dispatch to background task queue when django-q integration is available.
            # Currently synchronous by design for alpha phase (PDF ~20ms; SMTP is the bottleneck).
            # Nested on_commit() is not an option here — this already runs inside on_commit.
            if order.payment_method == "bank_transfer" and order.total_cents > 0:
                _send_proforma_email_for_order(order)

        elif new_status == "provisioning":
            # Provisioning started — can come from paid (auto) or in_review (admin approved)
            # Per F12: check new_status regardless of old_status
            _update_services_to_provisioning(order)

        elif new_status == "completed" and old_status == "provisioning":
            # Order completed — all items provisioned
            _trigger_service_provisioning(order)
            _send_order_completed_email(order)

        elif new_status == "cancelled":
            # Order cancelled — cleanup and notifications
            _handle_order_cancellation(order, old_status)

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Failed to handle status change: {e}")


def _create_pending_services_for_order(order: Order) -> None:
    """Create pending Service records when order becomes payable (industry standard)"""
    try:
        from .services import (  # noqa: PLC0415  # Deferred: avoids circular import
            OrderServiceCreationService,  # Circular: same-app signal  # Deferred: avoids circular import
        )

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
        from .services import (  # noqa: PLC0415  # Deferred: avoids circular import
            OrderServiceCreationService,  # Circular: same-app signal  # Deferred: avoids circular import
        )

        result = OrderServiceCreationService.update_service_status_on_payment(order)
        if result.is_ok():
            updated_services = result.unwrap()
            logger.info(f"🔄 [Order Signal] Updated {len(updated_services)} services to provisioning status")
        else:
            logger.error(f"🔥 [Order Signal] Service status update failed: {result.error}")  # type: ignore[union-attr]

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Service status update failed: {e}")


def _trigger_service_provisioning(order: Order) -> None:
    """Trigger service provisioning for completed orders"""
    try:
        from apps.provisioning.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            ProvisioningService,  # Circular: cross-app signal  # Deferred: avoids circular import
        )

        # Queue provisioning tasks for all order items
        for item in order.items.all():
            if item.provisioning_status == "pending":
                try:
                    from django_q.tasks import (  # noqa: PLC0415  # Deferred: avoids circular import
                        async_task,  # Deferred: django-q task  # Deferred: avoids circular import
                    )

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


def _handle_order_cancellation(order: Order, old_status: str) -> None:  # noqa: PLR0912, PLR0915, C901
    """Handle order cancellation cleanup.

    D3: Hard-delete services on cancellation to free unique resources (domains, usernames).
    Per F6: pending services can be hard-deleted directly (never provisioned).
    Services in provisioning/active state: fail/suspend instead of deleting real infrastructure.
    """
    try:
        with transaction.atomic():
            # D3: Handle services linked to cancelled order items.
            # H6 fix: Only hard-delete services in "pending" status (never provisioned).
            # Services in "provisioning" or "active" state represent real infrastructure
            # — fail/suspend them instead of deleting to avoid data loss.
            service_details = []
            suspended_service_details = []
            for item in (
                order.items.select_for_update(of=("self",)).select_related("service").filter(service__isnull=False)
            ):
                service = item.service
                if service is None:
                    continue  # Narrowing: filter guarantees non-null but type annotation is Service | None
                service_id = str(service.id)
                service_name = service.service_name

                # Cancel provisioning FSM on the item
                if item.provisioning_status in ("pending", "in_progress"):
                    try:
                        item.cancel_provisioning()
                        item.save(update_fields=["provisioning_status"])
                    except TransitionNotAllowed:
                        logger.debug(
                            "⏭️ [Order] Item %s already in terminal state %s, skip cancel",
                            item.id,
                            item.provisioning_status,
                        )

                if service.status == "pending":
                    # Safe to hard-delete — never provisioned, no external resources allocated
                    item.service = None
                    item.save(update_fields=["service"])
                    service.delete()
                    service_details.append({"id": service_id, "name": service_name})
                    logger.info("🗑️ [Order] Deleted pending service %s on order cancellation", service_id)
                elif service.status in ("provisioning", "active"):
                    # Real infrastructure exists — fail/suspend instead of deleting
                    try:
                        if service.status == "provisioning":
                            service.fail_provisioning()
                        else:
                            service.suspend(reason=f"Order {order.order_number} cancelled")
                        service.save(update_fields=["status", "updated_at"])
                        suspended_service_details.append(
                            {"id": service_id, "name": service_name, "action": "suspended"}
                        )
                        logger.warning(
                            "⚠️ [Order] Service %s (%s) suspended/failed due to cancellation of order %s",
                            service_id,
                            service.status,
                            order.order_number,
                        )
                    except (TransitionNotAllowed, ConcurrentTransition):
                        logger.warning(
                            "⚠️ [Order] Cannot suspend/fail service %s (status=%s) — manual review required",
                            service_id,
                            service.status,
                        )
                else:
                    # Already in terminal state (failed, terminated, expired) — clear FK only
                    item.service = None
                    item.save(update_fields=["service"])

            # Also cancel items without services (pending provisioning)
            for item in order.items.filter(service__isnull=True, provisioning_status__in=["pending", "in_progress"]):
                try:
                    item.cancel_provisioning()
                    item.save(update_fields=["provisioning_status"])
                except TransitionNotAllowed:
                    logger.debug(
                        "⏭️ [Order] Item %s already in terminal state %s, skip cancel",
                        item.id,
                        item.provisioning_status,
                    )

            # Audit: services_deleted_on_cancellation  # noqa: ERA001  # Label comment, not commented-out code
            if service_details:
                log_security_event(
                    "services_deleted_on_cancellation",
                    {
                        "order_id": str(order.id),
                        "order_number": order.order_number,
                        "services_deleted": service_details,
                        "count": len(service_details),
                    },
                )
            if suspended_service_details:
                log_security_event(
                    "services_suspended_on_cancellation",
                    {
                        "order_id": str(order.id),
                        "order_number": order.order_number,
                        "services_suspended": suspended_service_details,
                        "count": len(suspended_service_details),
                    },
                )

            # M4 fix: Void proforma if it exists and is in a voidable state.
            # Orders cancelled from awaiting_payment have a draft/sent proforma that should
            # be voided. Orders cancelled after payment have invoices that need manual review.
            # C4 review fix: Moved inside atomic block so proforma cleanup is atomic with
            # service cleanup — prevents inconsistent state if proforma voiding fails.
            if order.proforma_id:
                proforma = order.proforma
                assert proforma is not None  # narrowing: proforma_id check guarantees non-None
                if proforma.status == "sent":
                    try:
                        proforma.expire()
                        proforma.save(update_fields=["status"])
                        logger.info(
                            "📋 [Order] Expired proforma %s on cancellation of order %s",
                            proforma.number,
                            order.order_number,
                        )
                    except Exception as e:
                        logger.error(
                            "🔥 [Order] Could not expire proforma %s for order %s — manual review needed: %s",
                            proforma.number,
                            order.order_number,
                            e,
                            exc_info=True,
                        )
                elif proforma.status == "draft":
                    # Draft proformas were never sent to the customer — delete them.
                    # expire() only accepts source="sent", so deletion is the correct action.
                    proforma_number = proforma.number
                    order.proforma = None
                    order.save(update_fields=["proforma"])
                    proforma.delete()
                    logger.info(
                        "🗑️ [Order] Deleted draft proforma %s on cancellation of order %s",
                        proforma_number,
                        order.order_number,
                    )
                elif proforma.status in ("accepted", "converted"):
                    logger.warning(
                        "⚠️ [Order] Order %s cancelled but proforma %s is %s — manual financial review needed",
                        order.order_number,
                        proforma.number,
                        proforma.status,
                    )
                elif proforma.status == "expired":
                    logger.info(
                        "📋 [Order] Proforma %s already expired when order %s cancelled — no action needed",
                        proforma.number,
                        order.order_number,
                    )
                elif proforma.status == "void":
                    logger.info(
                        "📋 [Order] Proforma %s already void when order %s cancelled — no action needed",
                        proforma.number,
                        order.order_number,
                    )
                else:
                    logger.warning(
                        "⚠️ [Order] Unhandled proforma status %s for proforma %s on cancelled order %s",
                        proforma.status,
                        proforma.number,
                        order.order_number,
                    )

        # Send cancellation email after transaction commits to avoid ghost emails on rollback (#130/M6)
        transaction.on_commit(lambda: _send_order_cancelled_email(order))

        # If order was provisioning or paid, may need to handle refunds
        if old_status in ("provisioning", "paid", "in_review"):
            logger.warning(
                f"⚠️ [Order] Order {order.order_number} cancelled from {old_status} — manual refund review needed"
            )

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Cancellation handling failed: {e}")


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
            OrdersAuditService.log_provisioning_event(
                BusinessEventData(
                    event_type=provisioning_events[new_status],
                    business_object=item,
                    context=AuditContext(actor_type="system"),
                    description=f"Order item provisioning {new_status}: {item.product_name}",
                )
            )

        if new_status == "completed" and item.service:
            # Item successfully provisioned - send notification
            _send_service_ready_email(item)

            # Check if all items in order are provisioned
            order = item.order
            all_completed = all(oi.provisioning_status == "completed" for oi in order.items.all())

            if all_completed and order.status == "provisioning":
                # Mark order as completed
                from apps.orders.services import (  # Circular: same-app signal  # noqa: PLC0415  # Deferred: avoids circular import
                    OrderService,
                    StatusChangeData,
                )

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


def _send_proforma_email_for_order(order: Order) -> None:
    """Send proforma email for bank transfer orders (C1: smart email timing)."""
    try:
        if not order.proforma:
            logger.warning("⚠️ [Order] No proforma to send for order %s", order.order_number)
            return
        from apps.billing.proforma_service import send_proforma_email  # noqa: PLC0415

        sent = send_proforma_email(order.proforma, recipient_email=order.customer_email)
        if sent:
            # Transition proforma draft → sent (FSM) only on successful email delivery.
            proforma = order.proforma
            if proforma.status == "draft":
                try:
                    proforma.send_proforma()
                    proforma.save(update_fields=["status"])
                except TransitionNotAllowed:
                    logger.warning(
                        "⚠️ [Order] Email sent for proforma %s but FSM transition to 'sent' failed (status: %s)",
                        proforma.number,
                        proforma.status,
                    )
            logger.info("📧 [Order] Sent proforma email for order %s", order.order_number)
    except Exception as e:
        logger.exception("🔥 [Order] Failed to send proforma email for %s: %s", order.order_number, e)


def _send_order_confirmation_email(order: Order) -> None:
    """Send order confirmation email"""
    try:
        from apps.notifications.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            EmailService,  # Circular: cross-app signal  # Deferred: avoids circular import
        )

        EmailService.send_template_email(
            template_key="order_placed",
            recipient=order.customer_email,
            context={"order": order, "customer": order.customer, "order_items": order.items.all()},
            priority="high",
        )
    except Exception as e:
        logger.exception(f"🔥 [Order] Failed to send confirmation email: {e}")


def _send_order_completed_email(order: Order) -> None:
    """Send order completion email"""
    try:
        from apps.notifications.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            EmailService,  # Circular: cross-app signal  # Deferred: avoids circular import
        )

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
        from apps.notifications.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            EmailService,  # Circular: cross-app signal  # Deferred: avoids circular import
        )

        EmailService.send_template_email(
            template_key="order_cancelled",
            recipient=order.customer_email,
            context={"order": order, "customer": order.customer},
        )
    except Exception as e:
        logger.exception(f"🔥 [Order] Failed to send cancellation email: {e}")


def _send_service_ready_email(item: OrderItem) -> None:
    """Send service ready notification"""
    try:
        from apps.notifications.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            EmailService,  # Circular: cross-app signal  # Deferred: avoids circular import
        )

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
        from apps.notifications.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            EmailService,  # Circular: cross-app signal  # Deferred: avoids circular import
        )

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


# ===============================================================================
# CROSS-APP SIGNAL RECEIVERS (Phase B)
# ===============================================================================


def _handle_proforma_payment_received(sender: Any, proforma: Any, invoice: Any, payment: Any, **kwargs: Any) -> None:
    """Handle proforma_payment_received signal from Billing.

    Billing emits this signal after payment is recorded and proforma is converted to invoice.
    Orders listens to confirm the order and start provisioning.
    Dependency direction: Orders → Billing (imports signal). Billing → nothing.
    """
    try:
        from .services import OrderPaymentConfirmationService  # noqa: PLC0415

        for order in proforma.orders.filter(status="awaiting_payment"):
            result = OrderPaymentConfirmationService.confirm_order(order, invoice=invoice)
            if result.is_ok():
                logger.info("✅ [Order Signal] Confirmed order %s after proforma payment", order.order_number)
            else:
                logger.error(
                    "🔥 [Order Signal] Failed to confirm order %s: %s",
                    order.order_number,
                    result.unwrap_err() if result.is_err() else "unknown",
                )
    except Exception as e:
        # M10 fix: Use logger.critical for Sentry-level alerting on payment signal failure.
        # If this handler fails, the customer paid but the order is not confirmed — requires
        # immediate intervention. The background task provides a safety net but may take 5 min.
        logger.critical("🔥 [Order Signal] proforma_payment_received handler failed: %s", e, exc_info=True)


def _connect_billing_signals() -> None:
    """Connect cross-app billing signals. Called from apps.py ready()."""
    from apps.billing.custom_signals import invoice_refunded, proforma_payment_received  # noqa: PLC0415

    proforma_payment_received.connect(_handle_proforma_payment_received, dispatch_uid="orders_proforma_paid")
    invoice_refunded.connect(_handle_invoice_refunded, dispatch_uid="orders_invoice_refunded")


# ===============================================================================
# CROSS-APP INTEGRATION SIGNALS
# (merged from signals_extended.py — two valid receivers registered here)
# ===============================================================================


@receiver(post_delete, sender=Order)
def handle_order_cleanup(sender: type[Order], instance: Order, **kwargs: Any) -> None:
    """Clean up related data when orders are deleted.

    Handles file cleanup, cache invalidation, and audit compliance.
    """
    # M5 review fix: Independent try/except for each cleanup step so one failure
    # doesn't prevent the others (e.g., cache down shouldn't block audit logging).
    try:
        cache_keys = [
            f"order:{instance.id}",
            f"customer_orders:{instance.customer.id}",
            f"order_items:{instance.id}",
            f"order_totals:{instance.id}",
        ]
        cache.delete_many(cache_keys)
        logger.info(f"🗑️ [Cache] Cleared order caches for {instance.order_number}")
    except Exception as e:
        logger.warning("⚠️ [Order Signal] Cache cleanup failed for %s: %s", instance.order_number, e)

    try:
        _cleanup_order_files(instance)
    except Exception as e:
        logger.warning("⚠️ [Order Signal] File cleanup failed for %s: %s", instance.order_number, e)

    try:
        _cancel_order_webhooks(instance)
    except Exception as e:
        logger.warning("⚠️ [Order Signal] Webhook cleanup failed for %s: %s", instance.order_number, e)

    try:
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
        logger.warning("⚠️ [Order Signal] Audit logging failed for deleted order %s: %s", instance.order_number, e)


@receiver(post_delete, sender=OrderItem)
def handle_order_item_service_cleanup(sender: type[OrderItem], instance: OrderItem, **kwargs: Any) -> None:
    """Handle service cleanup when order items are deleted.

    Marks the linked service for manual review instead of deleting it,
    so staff can decide whether to terminate or reassign the service.
    """
    try:
        if instance.service:
            try:
                from apps.provisioning.services import (  # noqa: PLC0415
                    ServiceManagementService,  # Circular: cross-app signal
                )

                # H5 (signal fix): pass service_id as str, not the ORM instance
                result = ServiceManagementService.mark_service_for_review(
                    service_id=str(instance.service.id),
                    reason=f"Order item {instance.id} deleted",
                )

                if result.is_ok():
                    logger.info(f"⚠️ [Service] Marked service {instance.service.id} for review")

            except Exception as e:
                logger.exception(f"🔥 [Service] Service cleanup failed: {e}")

        cache.delete(f"order_item:{instance.id}")

    except Exception as e:
        logger.exception(f"🔥 [Order Signal] Item cleanup failed: {e}")


# ===============================================================================
# INVOICE REFUND SIGNAL HANDLER
# ===============================================================================


def _handle_invoice_refunded(sender: Any, invoice: Any, refund_type: str, **kwargs: Any) -> None:
    """Handle invoice refund — suspend linked services.

    Full refund: suspend all active services linked to the invoice's order.
    Partial refund: log for manual review (partial service suspension is business-specific).
    """
    try:
        orders = Order.objects.filter(invoice=invoice)

        for order in orders:
            # H2 fix: Wrap per-order service suspension in an atomic block with
            # select_for_update(of=("self",)) to prevent TOCTOU race conditions.
            # of=("self",) prevents locking FK tables (service, product) which
            # could cause deadlocks.
            with transaction.atomic():
                items_with_services = (
                    order.items.select_for_update(of=("self",)).filter(service__isnull=False).select_related("service")
                )

                for item in items_with_services:
                    service = item.service
                    if service is None:
                        continue

                    # C3 fix: Capture the action taken BEFORE mutation so the audit log
                    # reflects reality. Previously, service.status was checked AFTER
                    # suspend() mutated it, so "suspended" was never logged.
                    action_taken = "flagged_for_review"

                    if refund_type == "full":
                        if service.status == "active":
                            try:
                                service.suspend(reason=f"Full refund on invoice {invoice.number}")
                                service.save(update_fields=["status", "updated_at"])
                                action_taken = "suspended"
                                logger.info(
                                    "⚠️ [Refund] Suspended service %s for refunded invoice %s",
                                    service.id,
                                    invoice.number,
                                )
                            except Exception as e:
                                action_taken = "suspension_failed"
                                logger.exception(
                                    "🔥 [Refund] Failed to suspend service %s: %s",
                                    service.id,
                                    e,
                                )
                    else:
                        logger.info(
                            "📋 [Refund] Partial refund on invoice %s — service %s needs manual review",
                            invoice.number,
                            service.id,
                        )

                    log_security_event(
                        "invoice_refund_service_action",
                        {
                            "invoice_id": str(invoice.id),
                            "invoice_number": invoice.number,
                            "service_id": str(service.id),
                            "refund_type": refund_type,
                            "action": action_taken,
                        },
                    )
    except Exception as e:
        logger.critical(
            "🔥 [Order Signal] invoice_refunded handler failed — refund issued but services may still be active: %s",
            e,
            exc_info=True,
        )


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================


_ALLOWED_UPLOAD_PREFIX = "orders/"


def _cleanup_order_files(order: Order) -> None:
    """Clean up any files associated with the order.

    H5 fix: Validates each path before deletion to prevent path traversal attacks.
    Paths must:
    - Not contain ".." after normalization
    - Start with the allowed "orders/" prefix
    """
    import posixpath  # noqa: PLC0415

    try:
        if order.meta.get("uploaded_files"):
            for file_path in order.meta["uploaded_files"]:
                try:
                    normalized = posixpath.normpath(file_path)
                    if ".." in normalized or not normalized.startswith(_ALLOWED_UPLOAD_PREFIX):
                        logger.warning("⚠️ [File] Suspicious path in order meta, skipping: %s", file_path)
                        continue
                    if default_storage.exists(normalized):
                        default_storage.delete(normalized)
                        logger.info(f"🗑️ [File] Deleted {normalized}")
                except Exception as e:
                    logger.exception(f"🔥 [File] Failed to delete {file_path}: {e}")

    except Exception as e:
        logger.exception(f"🔥 [Order] File cleanup failed: {e}")


def _cancel_order_webhooks(order: Order) -> None:
    """Cancel any pending webhook deliveries for the order."""
    try:
        from apps.integrations.models import (  # noqa: PLC0415
            WebhookDelivery,  # Circular: cross-app signal
        )

        pending_webhooks = WebhookDelivery.objects.filter(
            customer=order.customer,
            event_type__startswith="order.",
            status="pending",
            payload__order_id=str(order.id),
        )

        cancelled_count = pending_webhooks.update(  # fsm-bypass: WebhookDelivery is not FSM-protected
            status="cancelled"
        )

        if cancelled_count > 0:
            logger.info(f"🚫 [Webhook] Cancelled {cancelled_count} pending deliveries for order {order.order_number}")

    except Exception as e:
        logger.exception(f"🔥 [Webhook] Webhook cancellation failed: {e}")
