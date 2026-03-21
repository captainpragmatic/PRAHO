"""
Order processing background tasks.

This module contains Django-Q2 tasks for order processing, fulfillment,
payment synchronization, and recurring order management.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any, TypedDict

from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone
from django_fsm import ConcurrentTransition, TransitionNotAllowed
from django_q.models import Schedule
from django_q.tasks import async_task, schedule

from apps.audit.services import AuditService
from apps.billing.models import Payment
from apps.billing.services import InvoiceService
from apps.orders.models import Order
from apps.orders.services import OrderService

# Constants
_DEFAULT_MAX_PAYMENT_FAILURES_BEFORE_ORDER_FAIL = 3
MAX_PAYMENT_FAILURES_BEFORE_ORDER_FAIL = _DEFAULT_MAX_PAYMENT_FAILURES_BEFORE_ORDER_FAIL

# Import at module level to avoid PLC0415
try:
    from apps.provisioning.models import Service
except ImportError:
    Service = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


class OrderProcessingResults(TypedDict):
    """Results of order processing batch"""

    processed_orders: list[dict[str, Any]]
    confirmed_orders: int
    timed_out_orders: int
    failed_orders: int
    provisioning_triggered: int
    errors: list[str]


# Task configuration
TASK_RETRY_DELAY = 300  # 5 minutes
TASK_MAX_RETRIES = 2
_DEFAULT_TASK_SOFT_TIME_LIMIT = 300  # 5 minutes
TASK_SOFT_TIME_LIMIT = _DEFAULT_TASK_SOFT_TIME_LIMIT
_DEFAULT_TASK_TIME_LIMIT = 600  # 10 minutes
TASK_TIME_LIMIT = _DEFAULT_TASK_TIME_LIMIT


def get_max_payment_failures_before_order_fail() -> int:
    """Get max payment failures before order fail from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting(
        "orders.max_payment_failures_before_fail", _DEFAULT_MAX_PAYMENT_FAILURES_BEFORE_ORDER_FAIL
    )


def get_task_soft_time_limit() -> int:
    """Get task soft time limit from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("orders.task_soft_time_limit", _DEFAULT_TASK_SOFT_TIME_LIMIT)


def get_task_time_limit() -> int:
    """Get task time limit from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("orders.task_time_limit", _DEFAULT_TASK_TIME_LIMIT)


def process_pending_orders() -> dict[str, Any]:  # noqa: C901, PLR0912  # Complexity: dispatch + lock + per-order branching; helpers already extracted
    """
    Process orders stuck in "awaiting_payment" status.

    This task handles:
    - Trigger provisioning for paid orders
    - Handle order timeouts and cancellations
    - Update order status based on payment status
    - Process orders that should move to paid/provisioning

    Runs every 5 minutes to ensure timely order processing.

    Returns:
        Dictionary with processing results
    """
    logger.info("🔄 [OrderProcessor] Starting pending order processing")

    results: dict[str, Any] = {
        "processed_orders": [],
        "confirmed_orders": 0,
        "timed_out_orders": 0,
        "failed_orders": 0,
        "provisioning_triggered": 0,
        "errors": [],
    }

    try:
        # Prevent concurrent processing (atomic lock acquisition)
        lock_key = "process_pending_orders_lock"
        if not cache.add(lock_key, True, 300):
            logger.info("⏭️ [OrderProcessor] Pending order processing already running, skipping")
            return {"success": True, "message": "Already running"}

        try:
            # Get all awaiting_payment orders (B12: include proforma for fallback)
            pending_orders = (
                Order.objects.filter(status="awaiting_payment")
                .select_related("customer", "currency", "invoice", "proforma")
                .prefetch_related("items")
            )

            now = timezone.now()

            for order in pending_orders:
                order_result = {
                    "order_id": str(order.id),
                    "order_number": order.order_number,
                    "action": None,
                    "status": None,
                }

                try:
                    # B12: Create proforma if missing (edge case — signal failed or race)
                    if order.total_cents > 0 and not order.proforma:
                        try:
                            from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

                            proforma_result = ProformaService.create_from_order(order)
                            if proforma_result.is_ok():
                                logger.info(
                                    "📄 [OrderProcessor] Created missing proforma for %s",
                                    order.order_number,
                                )
                                order.refresh_from_db()
                        except Exception as e:
                            logger.error("🔥 [OrderProcessor] Failed to create proforma fallback: %s", e)

                    # Check if order has timed out
                    if _handle_order_timeout(order, now, order_result, results):
                        continue

                    # Check payment status if order has invoice
                    if order.invoice:
                        invoice = order.invoice

                        if invoice.status == "paid":
                            _process_paid_order(order, invoice, order_result, results)
                        elif invoice.status == "void":
                            _process_cancelled_invoice(order, now, order_result, results)

                    # Order without invoice - check if it needs one
                    elif order.total_cents > 0:
                        _create_order_invoice(order, order_result, results)

                    else:
                        # Free order - move directly to confirmed
                        _process_free_order(order, order_result, results)

                    results["processed_orders"].append(order_result)

                except Exception as e:
                    logger.error(f"🔥 [OrderProcessor] Error processing order {order.order_number}: {e}")
                    results["errors"].append(f"Order {order.order_number}: {e}")
                    results["failed_orders"] += 1

            logger.info(
                f"✅ [OrderProcessor] Pending order processing completed: "
                f"{results['confirmed_orders']} confirmed, "
                f"{results['timed_out_orders']} timed out, "
                f"{results['provisioning_triggered']} provisioning triggered"
            )

            return {"success": True, "results": results}

        finally:
            # Always release lock
            cache.delete(lock_key)

    except Exception as e:
        logger.exception(f"💥 [OrderProcessor] Critical error in pending order processing: {e}")
        results["errors"].append(str(e))
        return {"success": False, "error": str(e), "results": results}


def _process_payment_confirmation(order: Order, invoice: Any, total_paid_cents: int, results: dict[str, Any]) -> bool:
    """Process payment confirmation for an order."""
    if total_paid_cents >= invoice.total_cents and order.status == "awaiting_payment":
        old_status = order.status
        try:
            order.mark_paid()
            order.save(update_fields=["status", "updated_at"])
        except (TransitionNotAllowed, ConcurrentTransition):
            logger.warning(
                "⚠️ [PaymentSync] Cannot mark order %s as paid from status %s", order.order_number, old_status
            )
            return False
        results["payment_confirmations"] += 1

        # Log payment confirmation
        AuditService.log_simple_event(
            event_type="order_payment_confirmed",
            user=None,
            content_object=order,
            description=f"Order payment confirmed: {order.order_number}",
            old_values={"status": old_status},
            new_values={"status": "paid"},
            actor_type="system",
            metadata={
                "order_id": str(order.id),
                "order_number": order.order_number,
                "invoice_id": str(invoice.id),
                "amount_paid_cents": total_paid_cents,
                "invoice_total_cents": invoice.total_cents,
                "source_app": "orders",
            },
        )
        return True
    return False


def _process_payment_failures(order: Order, payments: list[Any], results: dict[str, Any]) -> bool:
    """Process payment failures for an order."""
    failed_payments = [p for p in payments if p.status == "failed"]
    if not failed_payments or order.status != "awaiting_payment":
        return False

    # Check if all payment attempts have failed
    recent_failures = [p for p in failed_payments if p.created_at >= timezone.now() - timedelta(hours=24)]

    if len(recent_failures) >= MAX_PAYMENT_FAILURES_BEFORE_ORDER_FAIL:
        old_status = order.status
        try:
            order.fail()
        except (TransitionNotAllowed, ConcurrentTransition):
            logger.warning("⚠️ [PaymentSync] Cannot fail order %s from status %s", order.order_number, old_status)
            return False
        order.notes = (
            f"{order.notes}\n[AUTO] Order marked as failed due to repeated payment failures at {timezone.now()}"
        )
        order.save(update_fields=["status", "notes", "updated_at"])
        results["payment_failures"] += 1

        # Log payment failure
        AuditService.log_simple_event(
            event_type="order_payment_failed",
            user=None,
            content_object=order,
            description=f"Order payment failed: {order.order_number}",
            old_values={"status": old_status},
            new_values={"status": "failed"},
            actor_type="system",
            metadata={
                "order_id": str(order.id),
                "order_number": order.order_number,
                "failed_attempts": len(recent_failures),
                "source_app": "orders",
            },
        )
        return True
    return False


def _process_refunds(order: Order, payments: list[Any], total_paid_cents: int, results: dict[str, Any]) -> bool:
    """Process refunds for an order.

    Phase A: Refunds are now handled at Invoice/Payment level, not Order FSM.
    This function only logs refund activity for monitoring — no order state changes.
    """
    total_refunded_cents = sum(p.amount_cents for p in payments if p.status in ["refunded", "partially_refunded"])

    if total_refunded_cents <= 0:
        return False

    # Log for visibility but don't change order status — refunds are billing concern
    logger.info(
        "💰 [PaymentSync] Refund detected for order %s: %d/%d cents refunded (order stays %s)",
        order.order_number,
        total_refunded_cents,
        total_paid_cents,
        order.status,
    )
    results["refunds_processed"] += 1
    return False


def _add_updated_order_result(
    order: Order, old_status: str, total_paid_cents: int, total_refunded_cents: int, results: dict[str, Any]
) -> None:
    """Add order update information to results."""
    results["updated_orders"].append(
        {
            "order_id": str(order.id),
            "order_number": order.order_number,
            "old_status": old_status,
            "new_status": order.status,
            "total_paid_cents": total_paid_cents,
            "total_refunded_cents": total_refunded_cents,
        }
    )


def _handle_order_timeout(order: Order, now: Any, order_result: dict[str, Any], results: dict[str, Any]) -> bool:
    """Handle order timeout logic."""
    timeout_threshold = order.created_at + timedelta(hours=24)

    if now <= timeout_threshold:
        return False

    # Cancel timed out orders
    try:
        order.cancel()
    except (TransitionNotAllowed, ConcurrentTransition):
        logger.warning(
            "⚠️ [OrderProcessor] Cannot cancel timed-out order %s from status %s", order.order_number, order.status
        )
        return False
    order.notes = f"{order.notes}\n[AUTO] Order cancelled due to timeout at {now}"
    order.save(update_fields=["status", "notes", "updated_at"])

    order_result["action"] = "timeout_cancelled"
    order_result["status"] = "cancelled"
    results["timed_out_orders"] += 1

    # Log timeout cancellation
    AuditService.log_simple_event(
        event_type="order_timeout_cancelled",
        user=None,
        content_object=order,
        description=f"Order {order.order_number} cancelled due to timeout",
        actor_type="system",
        metadata={
            "order_id": str(order.id),
            "order_number": order.order_number,
            "customer_id": str(order.customer.id),
            "timeout_hours": 24,
            "created_at": order.created_at.isoformat(),
            "cancelled_at": now.isoformat(),
            "source_app": "orders",
        },
    )
    return True


def _trigger_item_provisioning(order: Order, results: dict[str, Any]) -> int:
    """Trigger provisioning for order items."""
    provisioned_items = 0
    for item in order.items.filter(provisioning_status="pending"):
        try:
            async_task("apps.provisioning.tasks.provision_order_item", item.id, timeout=TASK_TIME_LIMIT)
            provisioned_items += 1
        except Exception as e:
            logger.error(f"🔥 [OrderProcessor] Failed to trigger provisioning for item {item.id}: {e}")
            results["errors"].append(f"Provisioning trigger failed for item {item.id}: {e}")
    return provisioned_items


def _process_paid_order(order: Order, invoice: Any, order_result: dict[str, Any], results: dict[str, Any]) -> None:
    """Process orders with paid invoices (fallback task).

    C2 fix: Routes through OrderPaymentConfirmationService.confirm_order() instead of
    calling mark_paid()+start_provisioning() directly. This ensures the review gate
    threshold check is applied consistently for both signal-based and task-based paths.
    """
    from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

    result = OrderPaymentConfirmationService.confirm_order(order, invoice=invoice)
    if result.is_err():
        logger.warning("⚠️ [OrderProcessor] Cannot confirm order %s: %s", order.order_number, result.unwrap_err())
        return

    order.refresh_from_db()
    order_result["action"] = "payment_confirmed"
    order_result["status"] = order.status
    results["confirmed_orders"] += 1

    # If order went to provisioning (not in_review), trigger item provisioning
    if order.status == "provisioning":
        provisioned_items = _trigger_item_provisioning(order, results)
        if provisioned_items > 0:
            results["provisioning_triggered"] += provisioned_items

    # Log order confirmation
    AuditService.log_simple_event(
        event_type="order_confirmed_auto",
        user=None,
        content_object=order,
        description=f"Order {order.order_number} automatically confirmed (status: {order.status})",
        actor_type="system",
        metadata={
            "order_id": str(order.id),
            "order_number": order.order_number,
            "customer_id": str(order.customer.id),
            "invoice_id": str(invoice.id),
            "source_app": "orders",
        },
    )


def _process_cancelled_invoice(order: Order, now: Any, order_result: dict[str, Any], results: dict[str, Any]) -> None:
    """Process orders with cancelled invoices."""
    try:
        order.cancel()
    except (TransitionNotAllowed, ConcurrentTransition):
        logger.warning("⚠️ [OrderProcessor] Cannot cancel order %s from status %s", order.order_number, order.status)
        order_result["action"] = "invoice_cancelled_skip"
        order_result["status"] = order.status
        results["failed_orders"] += 1
        return
    order.notes = f"{order.notes}\n[AUTO] Order cancelled due to cancelled invoice at {now}"
    order.save(update_fields=["status", "notes", "updated_at"])

    order_result["action"] = "invoice_cancelled"
    order_result["status"] = "cancelled"
    results["failed_orders"] += 1


def _create_order_invoice(order: Order, order_result: dict[str, Any], results: dict[str, Any]) -> None:
    """Create invoice for orders that need payment."""
    try:
        invoice_service = InvoiceService()
        invoice_result = invoice_service.create_from_order(order)

        if invoice_result.is_ok():
            invoice = invoice_result.unwrap()
            order.invoice = invoice
            order.save(update_fields=["invoice", "updated_at"])

            order_result["action"] = "invoice_created"
            order_result["status"] = "awaiting_payment"

            logger.info(f"📄 [OrderProcessor] Created invoice {invoice.number} for order {order.order_number}")
        else:
            error = invoice_result.unwrap_err()
            results["errors"].append(f"Invoice creation failed for order {order.order_number}: {error}")

    except Exception as e:
        logger.error(f"🔥 [OrderProcessor] Failed to create invoice for order {order.order_number}: {e}")
        results["errors"].append(f"Invoice creation error for {order.order_number}: {e}")


def _process_free_order(order: Order, order_result: dict[str, Any], results: dict[str, Any]) -> None:
    """Process free orders (total=0 → skip proforma, go directly to paid → provisioning).

    C4 fix: Routes through OrderPaymentConfirmationService.confirm_order() instead of
    calling mark_paid() alone. Without start_provisioning(), the order gets stuck in
    'paid' forever because the item completion check requires status=='provisioning'.
    """
    from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

    result = OrderPaymentConfirmationService.confirm_order(order)
    if result.is_err():
        logger.warning("⚠️ [OrderProcessor] Cannot confirm free order %s: %s", order.order_number, result.unwrap_err())
        return

    order.refresh_from_db()
    order_result["action"] = "free_order_confirmed"
    order_result["status"] = order.status
    results["confirmed_orders"] += 1

    # If order went to provisioning, trigger item provisioning
    if order.status == "provisioning":
        for item in order.items.filter(provisioning_status="pending"):
            try:
                async_task("apps.provisioning.tasks.provision_order_item", item.id, timeout=TASK_TIME_LIMIT)
                results["provisioning_triggered"] += 1
            except Exception as e:
                logger.error(f"🔥 [OrderProcessor] Failed to trigger provisioning for free order item {item.id}: {e}")
                results["errors"].append(f"Free order provisioning trigger failed: {e}")


def _check_service_availability() -> bool:
    """Check if Service model is available."""
    return Service is not None


def _find_services_to_renew() -> Any:
    """Find services that need renewal in the next 30 days."""
    expiry_threshold = timezone.now() + timedelta(days=30)

    return (
        Service.objects.filter(
            status="active",
            expires_at__lte=expiry_threshold,
            expires_at__gte=timezone.now(),  # Not already expired
            auto_renew=True,
        )
        .select_related("customer", "plan")
        .prefetch_related("orders")
    )


def _create_renewal_order_data(service: Any) -> dict[str, Any]:
    """Create renewal order data structure."""
    return {
        "customer_id": service.customer.id,
        "items": [
            {
                "product_type": "service_renewal",
                "product_id": str(service.plan.id) if service.plan else None,
                "quantity": 1,
                "unit_price_cents": service.plan.price_cents if service.plan else 0,
                "name": f"Service Renewal - {service.name}",
                "meta": {
                    "renewal_service_id": str(service.id),
                    "original_expires_at": service.expires_at.isoformat(),
                    "renewal_period": "1_year",
                },
            }
        ],
        "status": "awaiting_payment",
        "meta": {"auto_renewal": True, "original_service_id": str(service.id)},
    }


def _create_renewal_invoice(renewal_order: Any, service: Any, results: dict[str, Any]) -> None:
    """Create invoice for renewal order and handle auto-payment."""
    if renewal_order.total_cents <= 0:
        return

    try:
        invoice_service = InvoiceService()
        invoice_result = invoice_service.create_from_order(renewal_order)

        if invoice_result.is_ok():
            invoice = invoice_result.unwrap()
            renewal_order.invoice = invoice
            renewal_order.save(update_fields=["invoice", "updated_at"])

            # If customer has auto-pay enabled, attempt payment
            if hasattr(service.customer, "auto_pay_enabled") and service.customer.auto_pay_enabled:
                async_task("apps.billing.tasks.process_auto_payment", invoice.id, timeout=TASK_TIME_LIMIT)
                results["auto_renewals_processed"] += 1
                logger.info(
                    f"💳 [RecurringOrders] Triggered auto-payment for renewal order {renewal_order.order_number}"
                )
        else:
            error = invoice_result.unwrap_err()
            logger.error(
                f"🔥 [RecurringOrders] Failed to create invoice for renewal order {renewal_order.order_number}: {error}"
            )
            results["errors"].append(f"Invoice creation failed for renewal {renewal_order.order_number}: {error}")

    except Exception as e:
        logger.error(f"🔥 [RecurringOrders] Error creating invoice for renewal: {e}")
        results["errors"].append(f"Invoice creation error: {e}")


def _log_renewal_order_creation(renewal_order: Any, service: Any) -> None:
    """Log renewal order creation event."""
    AuditService.log_simple_event(
        event_type="renewal_order_created",
        user=None,
        content_object=renewal_order,
        description=f"Renewal order {renewal_order.order_number} created for service {service.name}",
        actor_type="system",
        metadata={
            "order_id": str(renewal_order.id),
            "order_number": renewal_order.order_number,
            "service_id": str(service.id),
            "customer_id": str(service.customer.id),
            "expires_at": service.expires_at.isoformat(),
            "renewal_amount_cents": renewal_order.total_cents,
            "auto_payment_triggered": hasattr(service.customer, "auto_pay_enabled")
            and service.customer.auto_pay_enabled,
            "source_app": "orders",
        },
    )


def sync_order_payment_status() -> dict[str, Any]:
    """
    Check payment gateway for status updates and sync with orders.

    This task handles:
    - Check payment gateway for status updates
    - Handle delayed payment confirmations
    - Process partial payments and refunds
    - Update order status accordingly

    Runs every 15 minutes to catch payment status changes.

    Returns:
        Dictionary with sync results
    """
    logger.info("💳 [PaymentSync] Starting payment status synchronization")

    results: dict[str, Any] = {
        "checked_payments": 0,
        "updated_orders": [],
        "payment_confirmations": 0,
        "payment_failures": 0,
        "refunds_processed": 0,
        "errors": [],
    }

    try:
        # Get orders with pending payments (last 7 days to catch delayed confirmations)
        cutoff_date = timezone.now() - timedelta(days=7)

        orders_to_check = Order.objects.filter(
            Q(status__in=["awaiting_payment", "paid", "provisioning"])
            & Q(invoice__isnull=False)
            & Q(created_at__gte=cutoff_date)
        ).select_related("invoice", "customer", "currency")

        for order in orders_to_check:
            try:
                invoice = order.invoice
                if not invoice:
                    continue

                # Check payments for this invoice
                payments = Payment.objects.filter(invoice=invoice)
                results["checked_payments"] += payments.count()

                old_status = order.status
                payment_updated = False

                # Calculate total successful payments
                total_paid_cents = sum(p.amount_cents for p in payments if p.status == "succeeded")

                # Process payment confirmation
                if _process_payment_confirmation(order, invoice, total_paid_cents, results):
                    payment_updated = True

                # Process payment failures
                if _process_payment_failures(order, list(payments), results):
                    payment_updated = True

                # Process refunds
                if _process_refunds(order, list(payments), total_paid_cents, results):
                    payment_updated = True

                # Track updated order details
                if payment_updated:
                    total_refunded_cents = sum(
                        p.amount_cents for p in payments if p.status in ["refunded", "partially_refunded"]
                    )
                    _add_updated_order_result(order, old_status, total_paid_cents, total_refunded_cents, results)

            except Exception as e:
                logger.error(f"🔥 [PaymentSync] Error processing order {order.order_number}: {e}")
                results["errors"].append(f"Order {order.order_number}: {e}")

        logger.info(
            f"✅ [PaymentSync] Payment sync completed: "
            f"{results['checked_payments']} payments checked, "
            f"{results['payment_confirmations']} confirmations, "
            f"{results['refunds_processed']} refunds processed"
        )

        return {"success": True, "results": results}

    except Exception as e:
        logger.exception(f"💥 [PaymentSync] Critical error in payment synchronization: {e}")
        results["errors"].append(str(e))
        return {"success": False, "error": str(e), "results": results}


def process_recurring_orders() -> dict[str, Any]:
    """
    Generate renewal orders for expiring services.

    This task handles:
    - Generate renewal orders for expiring services
    - Create invoices for subscription services
    - Handle automatic renewals
    - Process payment for auto-renew orders

    Runs daily at 1 AM to process renewals.

    Returns:
        Dictionary with recurring order processing results
    """
    logger.info("🔄 [RecurringOrders] Starting recurring order processing")

    results: dict[str, Any] = {
        "services_checked": 0,
        "renewal_orders_created": 0,
        "auto_renewals_processed": 0,
        "renewal_failures": 0,
        "created_orders": [],
        "errors": [],
    }

    try:
        # Prevent concurrent processing (atomic lock acquisition)
        lock_key = "process_recurring_orders_lock"
        if not cache.add(lock_key, True, 1800):
            logger.info("⏭️ [RecurringOrders] Recurring order processing already running, skipping")
            return {"success": True, "message": "Already running"}

        try:
            # Check if Service model is available
            if not _check_service_availability():
                return {"success": True, "message": "Service model not available", "results": results}

            # Find services expiring in the next 30 days that need renewal
            services_to_renew = _find_services_to_renew()

            results["services_checked"] = services_to_renew.count()

            for service in services_to_renew:
                try:
                    # Check if renewal order already exists
                    existing_renewal = Order.objects.filter(
                        customer=service.customer,
                        status__in=["draft", "awaiting_payment", "paid", "provisioning"],
                        items__meta__contains={"renewal_service_id": str(service.id)},
                    ).exists()

                    if existing_renewal:
                        logger.debug(f"⏭️ [RecurringOrders] Renewal order already exists for service {service.id}")
                        continue

                    # Create renewal order
                    order_service = OrderService()
                    renewal_order_data = _create_renewal_order_data(service)

                    create_result = order_service.create_order(renewal_order_data)  # type: ignore[arg-type]

                    if create_result.is_ok():
                        renewal_order = create_result.unwrap()
                        results["renewal_orders_created"] += 1

                        results["created_orders"].append(
                            {
                                "order_id": str(renewal_order.id),
                                "order_number": renewal_order.order_number,
                                "service_id": str(service.id),
                                "customer_id": str(service.customer.id),
                                "expires_at": service.expires_at.isoformat(),
                                "total_cents": renewal_order.total_cents,
                            }
                        )

                        # Create invoice for the renewal order
                        _create_renewal_invoice(renewal_order, service, results)

                        # Log renewal order creation
                        _log_renewal_order_creation(renewal_order, service)

                        logger.info(
                            f"🔄 [RecurringOrders] Created renewal order {renewal_order.order_number} for service {service.id}"
                        )

                    else:
                        error = create_result.unwrap_err()
                        logger.error(
                            f"🔥 [RecurringOrders] Failed to create renewal order for service {service.id}: {error}"
                        )
                        results["errors"].append(f"Service {service.id}: {error}")
                        results["renewal_failures"] += 1

                except Exception as e:
                    logger.error(f"🔥 [RecurringOrders] Error processing service {service.id}: {e}")
                    results["errors"].append(f"Service {service.id}: {e}")
                    results["renewal_failures"] += 1

            logger.info(
                f"✅ [RecurringOrders] Recurring order processing completed: "
                f"{results['services_checked']} services checked, "
                f"{results['renewal_orders_created']} renewal orders created, "
                f"{results['auto_renewals_processed']} auto-renewals processed"
            )

            return {"success": True, "results": results}

        finally:
            # Always release lock
            cache.delete(lock_key)

    except Exception as e:
        logger.exception(f"💥 [RecurringOrders] Critical error in recurring order processing: {e}")
        results["errors"].append(str(e))
        return {"success": False, "error": str(e), "results": results}


# ===============================================================================
# TASK QUEUE WRAPPER FUNCTIONS
# ===============================================================================


def process_pending_orders_async() -> str:
    """Queue pending order processing task."""
    return async_task("apps.orders.tasks.process_pending_orders", timeout=TASK_TIME_LIMIT)


def sync_order_payment_status_async() -> str:
    """Queue payment status synchronization task."""
    return async_task("apps.orders.tasks.sync_order_payment_status", timeout=TASK_TIME_LIMIT)


def process_recurring_orders_async() -> str:
    """Queue recurring order processing task."""
    return async_task("apps.orders.tasks.process_recurring_orders", timeout=TASK_TIME_LIMIT)


# ===============================================================================
# SCHEDULED TASKS SETUP
# ===============================================================================


def setup_order_scheduled_tasks() -> dict[str, str]:
    """Set up all order processing scheduled tasks."""
    from django_q.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        Schedule as ScheduleModel,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    tasks_created = {}

    # Check for existing tasks first
    existing_tasks = list(
        ScheduleModel.objects.filter(
            name__in=["order-process-pending", "order-sync-payment-status", "order-process-recurring"]
        ).values_list("name", flat=True)
    )

    # Process pending orders every 5 minutes
    if "order-process-pending" not in existing_tasks:
        schedule(
            "apps.orders.tasks.process_pending_orders",
            schedule_type=Schedule.MINUTES,
            minutes=5,
            name="order-process-pending",
            cluster="praho-cluster",
        )
        tasks_created["process_pending"] = "created"
    else:
        tasks_created["process_pending"] = "already_exists"

    # Sync payment status every 15 minutes
    if "order-sync-payment-status" not in existing_tasks:
        schedule(
            "apps.orders.tasks.sync_order_payment_status",
            schedule_type=Schedule.MINUTES,
            minutes=15,
            name="order-sync-payment-status",
            cluster="praho-cluster",
        )
        tasks_created["sync_payments"] = "created"
    else:
        tasks_created["sync_payments"] = "already_exists"

    # Process recurring orders daily at 1 AM
    if "order-process-recurring" not in existing_tasks:
        schedule(
            "apps.orders.tasks.process_recurring_orders",
            schedule_type=Schedule.CRON,
            cron="0 1 * * *",  # 1 AM daily
            name="order-process-recurring",
            cluster="praho-cluster",
        )
        tasks_created["process_recurring"] = "created"
    else:
        tasks_created["process_recurring"] = "already_exists"

    logger.info(f"✅ [OrderTasks] Scheduled tasks setup: {tasks_created}")
    return tasks_created


def generate_invoice_for_order(order_id: str) -> dict[str, Any]:
    """
    Generate invoice for an order asynchronously.

    Args:
        order_id: Order UUID to generate invoice for

    Returns:
        Dictionary with invoice generation result
    """
    logger.info(f"📋 [OrderInvoice] Generating invoice for order {order_id}")

    try:
        order = Order.objects.get(id=order_id)

        if order.invoice:
            logger.info(f"📋 [OrderInvoice] Order {order.order_number} already has invoice {order.invoice.number}")
            return {
                "success": True,
                "order_id": str(order.id),
                "invoice_id": str(order.invoice.id),
                "message": "Order already has invoice",
            }

        # Generate invoice using InvoiceService
        invoice_service = InvoiceService()
        result = invoice_service.create_from_order(order)

        if result.is_ok():
            invoice = result.unwrap()
            logger.info(f"📋 [OrderInvoice] Generated invoice {invoice.number} for order {order.order_number}")

            # Log the invoice generation
            AuditService.log_simple_event(
                event_type="invoice_generated_from_order",
                user=None,
                content_object=order,
                description=f"Invoice {invoice.number} generated for order {order.order_number}",
                actor_type="system",
                metadata={
                    "order_id": str(order.id),
                    "order_number": order.order_number,
                    "invoice_id": str(invoice.id),
                    "invoice_number": invoice.number,
                    "customer_id": str(order.customer.id),
                    "amount_cents": invoice.total_cents,
                    "source_app": "orders",
                },
            )

            return {
                "success": True,
                "order_id": str(order.id),
                "invoice_id": str(invoice.id),
                "invoice_number": invoice.number,
                "message": "Invoice generated successfully",
            }
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [OrderInvoice] Failed to generate invoice for order {order.order_number}: {error_msg}")
            return {"success": False, "error": error_msg}

    except Order.DoesNotExist:
        error_msg = f"Order {order_id} not found"
        logger.error(f"❌ [OrderInvoice] {error_msg}")
        return {"success": False, "error": error_msg}
    except Exception as e:
        logger.exception(f"💥 [OrderInvoice] Error generating invoice for order {order_id}: {e}")
        return {"success": False, "error": str(e)}


def provision_order_item(item_id: str) -> dict[str, Any]:
    """
    Provision an individual order item asynchronously.

    Args:
        item_id: OrderItem UUID to provision

    Returns:
        Dictionary with provisioning result
    """
    logger.info(f"⚡ [OrderProvisioning] Provisioning order item {item_id}")

    try:
        # Import at function level to avoid circular imports
        from apps.orders.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            OrderItem,  # Deferred: django-q task  # Deferred: avoids circular import
        )
        from apps.provisioning.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            ProvisioningService,  # Deferred: django-q task  # Deferred: avoids circular import
        )

        item = OrderItem.objects.get(id=item_id)

        if item.provisioning_status != "pending":
            logger.info(f"⚡ [OrderProvisioning] Item {item_id} status is {item.provisioning_status}, skipping")
            return {"success": True, "item_id": str(item.id), "message": f"Item already {item.provisioning_status}"}

        # Provision the item using ProvisioningService
        provisioning_service = ProvisioningService()
        result = provisioning_service.provision_order_item(item)

        if result.is_ok():
            provisioning_data = result.unwrap()
            logger.info(f"⚡ [OrderProvisioning] Provisioned item {item_id} successfully")

            # Log the provisioning
            AuditService.log_simple_event(
                event_type="order_item_provisioned",
                user=None,
                content_object=item,
                description=f"Order item {item.name} provisioned successfully",
                actor_type="system",
                metadata={
                    "item_id": str(item.id),
                    "item_name": item.name,
                    "order_id": str(item.order.id),
                    "order_number": item.order.order_number,
                    "customer_id": str(item.order.customer.id),
                    "provisioning_data": provisioning_data,
                    "source_app": "orders",
                },
            )

            return {
                "success": True,
                "item_id": str(item.id),
                "item_name": item.name,
                "provisioning_data": provisioning_data,
                "message": "Item provisioned successfully",
            }
        else:
            error_msg = result.unwrap_err()
            logger.error(f"❌ [OrderProvisioning] Failed to provision item {item_id}: {error_msg}")
            return {"success": False, "error": error_msg}

    except Exception as e:
        logger.exception(f"💥 [OrderProvisioning] Error provisioning item {item_id}: {e}")
        return {"success": False, "error": str(e)}


# ===============================================================================
# ADDITIONAL ASYNC WRAPPER FUNCTIONS
# ===============================================================================


def generate_invoice_for_order_async(order_id: str) -> str:
    """Queue invoice generation task for order."""
    return async_task("apps.orders.tasks.generate_invoice_for_order", order_id, timeout=TASK_TIME_LIMIT)


def provision_order_item_async(item_id: str) -> str:
    """Queue order item provisioning task."""
    return async_task("apps.orders.tasks.provision_order_item", item_id, timeout=TASK_TIME_LIMIT)
