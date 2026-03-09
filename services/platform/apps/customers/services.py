"""
Customer services re-export hub for PRAHO Platform.
Maintains backward compatibility after ADR-0012 feature-based reorganization.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, cast

from django.db import transaction
from django.db.models import Avg, Count, Q, Sum
from django.utils import timezone

# Core customer service
# Contact service
from .contact_service import ContactService

# Credit service
from .credit_service import CustomerCreditService
from .customer_service import CustomerService

# Profile service
from .profile_service import ProfileService

logger = logging.getLogger(__name__)

# Engagement scoring thresholds
DAYS_YEAR = 365
DAYS_HALF_YEAR = 180
DAYS_QUARTER = 90
DAYS_MONTH = 30
ORDERS_HIGH_THRESHOLD = 10
ORDERS_MEDIUM_THRESHOLD = 5
ORDERS_LOW_THRESHOLD = 2
PAYMENT_RATE_EXCELLENT = 95
PAYMENT_RATE_GOOD = 80
PAYMENT_RATE_FAIR = 60
SERVICES_HIGH_THRESHOLD = 3
SERVICES_MEDIUM_THRESHOLD = 2


def _get_orders_high_threshold() -> int:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("customers.orders_high_threshold", ORDERS_HIGH_THRESHOLD)


def _get_orders_medium_threshold() -> int:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("customers.orders_medium_threshold", ORDERS_MEDIUM_THRESHOLD)


def _get_orders_low_threshold() -> int:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("customers.orders_low_threshold", ORDERS_LOW_THRESHOLD)


def _get_payment_rate_excellent() -> int:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("customers.payment_rate_excellent", PAYMENT_RATE_EXCELLENT)


def _get_payment_rate_good() -> int:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("customers.payment_rate_good", PAYMENT_RATE_GOOD)


def _get_payment_rate_fair() -> int:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("customers.payment_rate_fair", PAYMENT_RATE_FAIR)


def _get_services_high_threshold() -> int:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("customers.services_high_threshold", SERVICES_HIGH_THRESHOLD)


def _get_services_medium_threshold() -> int:
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("customers.services_medium_threshold", SERVICES_MEDIUM_THRESHOLD)


class CustomerAnalyticsService:
    """Service for customer analytics and metrics tracking."""

    @staticmethod
    def get_customer_metrics(customer_id: str) -> dict[str, Any]:
        """
        Get comprehensive metrics for a customer.

        Args:
            customer_id: UUID of the customer

        Returns:
            Dictionary containing customer metrics
        """
        from apps.customers.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Customer,  # Circular: cross-app  # Deferred: avoids circular import
        )

        try:
            customer = Customer.objects.get(id=customer_id)
        except Customer.DoesNotExist:
            logger.warning(f"Customer {customer_id} not found for analytics")
            return {"error": "Customer not found"}

        try:
            metrics = {
                "customer_id": str(customer.id),
                "customer_name": customer.get_display_name(),
                "account_age_days": (timezone.now() - customer.created_at).days if customer.created_at else 0,
                "customer_type": customer.customer_type,
            }

            # Order metrics
            order_metrics = CustomerAnalyticsService._get_order_metrics(customer)
            metrics.update(order_metrics)

            # Billing metrics
            billing_metrics = CustomerAnalyticsService._get_billing_metrics(customer)
            metrics.update(billing_metrics)

            # Service metrics
            service_metrics = CustomerAnalyticsService._get_service_metrics(customer)
            metrics.update(service_metrics)

            # Credit metrics
            metrics["credit_score"] = CustomerCreditService.calculate_credit_score(customer)
            metrics["credit_rating"] = CustomerCreditService.get_credit_rating(cast(int, metrics["credit_score"]))

            # Calculate LTV (Lifetime Value)
            metrics["lifetime_value"] = billing_metrics.get("total_revenue", Decimal("0"))

            # Engagement score (0-100)
            metrics["engagement_score"] = CustomerAnalyticsService._calculate_engagement_score(customer, metrics)

            metrics["calculated_at"] = timezone.now().isoformat()

            logger.debug(f"📊 [Analytics] Generated metrics for customer {customer_id}")
            return metrics

        except Exception as e:
            logger.error(f"🔥 [Analytics] Failed to get metrics for customer {customer_id}: {e}")
            return {"error": str(e), "customer_id": customer_id}

    @staticmethod
    def _get_order_metrics(customer: Any) -> dict[str, Any]:
        """Get order-related metrics for a customer (single aggregate query)."""
        try:
            from django.db.models import Max  # noqa: PLC0415  # Deferred: avoids circular import

            from apps.orders.models import (  # noqa: PLC0415  # Deferred: avoids circular import
                Order,  # Circular: cross-app  # Deferred: avoids circular import
            )

            stats = Order.objects.filter(customer=customer).aggregate(
                total=Count("id"),
                completed=Count("id", filter=Q(status="completed")),
                cancelled=Count("id", filter=Q(status="cancelled")),
                pending=Count("id", filter=Q(status__in=["pending", "processing"])),
                avg_value=Avg("total_cents"),
                last_date=Max("created_at"),
            )

            total = stats["total"] or 0
            completed = stats["completed"] or 0

            return {
                "total_orders": total,
                "completed_orders": completed,
                "cancelled_orders": stats["cancelled"] or 0,
                "pending_orders": stats["pending"] or 0,
                "average_order_value": float(stats["avg_value"]) / 100 if stats["avg_value"] else 0,
                "last_order_date": stats["last_date"].isoformat() if stats["last_date"] else None,
                "order_completion_rate": (completed / total * 100) if total > 0 else 0,
            }
        except Exception as e:
            logger.warning(f"Failed to get order metrics: {e}")
            return {
                "total_orders": 0,
                "completed_orders": 0,
                "cancelled_orders": 0,
                "pending_orders": 0,
                "average_order_value": 0,
                "last_order_date": None,
                "order_completion_rate": 0,
            }

    @staticmethod
    def _get_billing_metrics(customer: Any) -> dict[str, Any]:
        """Get billing-related metrics for a customer (2 aggregate queries)."""
        try:
            from apps.billing.models import (  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import
                Invoice,
                Payment,
            )

            invoice_stats = Invoice.objects.filter(customer=customer).aggregate(
                total_cents=Sum("total_cents"),
                issued=Count("id", filter=Q(status="issued")),
                overdue=Count("id", filter=Q(status="overdue")),
            )
            total_paid = (
                Payment.objects.filter(invoice__customer=customer, status="succeeded").aggregate(
                    total=Sum("amount_cents")
                )["total"]
                or 0
            )

            total_invoiced = invoice_stats["total_cents"] or 0

            return {
                "total_invoiced": Decimal(total_invoiced) / 100,
                "total_paid": Decimal(total_paid) / 100,
                "total_revenue": Decimal(total_paid) / 100,
                "outstanding_balance": Decimal(total_invoiced - total_paid) / 100,
                "pending_invoices": invoice_stats["issued"] or 0,
                "overdue_invoices": invoice_stats["overdue"] or 0,
                "payment_rate": round(total_paid / total_invoiced * 100) if total_invoiced > 0 else None,
            }
        except Exception as e:
            logger.warning(f"Failed to get billing metrics: {e}")
            return {
                "total_invoiced": Decimal("0"),
                "total_paid": Decimal("0"),
                "total_revenue": Decimal("0"),
                "outstanding_balance": Decimal("0"),
                "pending_invoices": 0,
                "overdue_invoices": 0,
                "payment_rate": None,
            }

    @staticmethod
    def _get_service_metrics(customer: Any) -> dict[str, Any]:
        """Get service-related metrics for a customer (single aggregate query)."""
        try:
            from apps.provisioning.models import (  # noqa: PLC0415  # Deferred: avoids circular import
                Service,  # Circular: cross-app  # Deferred: avoids circular import
            )

            stats = Service.objects.filter(customer=customer).aggregate(
                total=Count("id"),
                active=Count("id", filter=Q(status="active")),
                suspended=Count("id", filter=Q(status="suspended")),
                pending=Count("id", filter=Q(status__in=["pending", "provisioning"])),
            )

            return {
                "total_services": stats["total"] or 0,
                "active_services": stats["active"] or 0,
                "suspended_services": stats["suspended"] or 0,
                "pending_services": stats["pending"] or 0,
            }
        except Exception as e:
            logger.warning(f"Failed to get service metrics: {e}")
            return {
                "total_services": 0,
                "active_services": 0,
                "suspended_services": 0,
                "pending_services": 0,
            }

    @staticmethod
    def _calculate_engagement_score(  # noqa: C901, PLR0912  # Complexity: multi-step business logic
        customer: Any, metrics: dict[str, Any]
    ) -> int:  # Complexity: customer processing  # Complexity: multi-step business logic
        """
        Tier-based engagement scoring for synchronous customer metrics.
        Uses threshold comparison (not weights). Max score is 100 (20+30+25+25).
        """
        score = 0

        # Account age factor (max 20 points)
        account_age_days = metrics.get("account_age_days", 0)
        if account_age_days > DAYS_YEAR:
            score += 20
        elif account_age_days > DAYS_HALF_YEAR:
            score += 15
        elif account_age_days > DAYS_QUARTER:
            score += 10
        elif account_age_days > DAYS_MONTH:
            score += 5

        # Order activity factor (max 30 points)
        total_orders = metrics.get("total_orders", 0)
        if total_orders >= _get_orders_high_threshold():
            score += 30
        elif total_orders >= _get_orders_medium_threshold():
            score += 20
        elif total_orders >= _get_orders_low_threshold():
            score += 10
        elif total_orders >= 1:
            score += 5

        # Payment behavior factor (max 25 points)
        payment_rate = metrics.get("payment_rate")
        if payment_rate is None:
            pass  # No payment history — skip payment factor
        elif payment_rate >= _get_payment_rate_excellent():
            score += 25
        elif payment_rate >= _get_payment_rate_good():
            score += 15
        elif payment_rate >= _get_payment_rate_fair():
            score += 5

        # Active services factor (max 25 points)
        active_services = metrics.get("active_services", 0)
        if active_services >= _get_services_high_threshold():
            score += 25
        elif active_services >= _get_services_medium_threshold():
            score += 15
        elif active_services >= 1:
            score += 10

        return min(100, score)

    @staticmethod
    def record_invoice_event(
        customer: Any,
        event_type: str,
        invoice_amount_cents: int,
        invoice_id: Any,
    ) -> None:
        """
        Record an invoice event for customer analytics tracking.

        Called from billing signals to track invoice lifecycle events
        (e.g., paid, refunded) for customer payment pattern analysis.
        """
        from apps.audit.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            AuditService,  # Circular: cross-app  # Deferred: avoids circular import
        )

        AuditService.log_simple_event(
            event_type=f"invoice_{event_type}",
            user=None,
            content_object=customer,
            description=f"Invoice event '{event_type}' for customer {customer.id} — {invoice_amount_cents} cents",
            actor_type="system",
            metadata={
                "customer_id": str(customer.id),
                "event_type": event_type,
                "invoice_id": str(invoice_id),
                "invoice_amount_cents": invoice_amount_cents,
                "source_app": "billing",
            },
        )
        logger.info(f"📊 [Analytics] Recorded invoice event '{event_type}' for customer {customer.id}")


class CustomerStatsService:
    """Service for updating and managing customer statistics."""

    @staticmethod
    def update_stats(customer_id: str) -> dict[str, Any]:
        """
        Update statistics for a customer.

        Args:
            customer_id: UUID of the customer

        Returns:
            Dictionary with update results
        """
        from apps.audit.services import (  # noqa: PLC0415  # Deferred: avoids circular import
            AuditService,  # Circular: cross-app  # Deferred: avoids circular import
        )
        from apps.customers.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Customer,  # Circular: cross-app  # Deferred: avoids circular import
        )

        try:
            customer = Customer.objects.get(id=customer_id)
        except Customer.DoesNotExist:
            logger.warning(f"Customer {customer_id} not found for stats update")
            return {"success": False, "error": "Customer not found"}

        try:
            # Get fresh metrics
            metrics = CustomerAnalyticsService.get_customer_metrics(customer_id)

            if "error" in metrics:
                return {"success": False, "error": metrics["error"]}

            # Store stats in customer metadata (locked to prevent lost updates)
            if hasattr(customer, "meta") and customer.meta is not None:
                stats_data = {
                    "total_orders": metrics.get("total_orders", 0),
                    "total_revenue": float(metrics.get("total_revenue", 0)),
                    "active_services": metrics.get("active_services", 0),
                    "credit_score": metrics.get("credit_score", 750),
                    "engagement_score": metrics.get("engagement_score", 0),
                    "last_updated": timezone.now().isoformat(),
                }
                with transaction.atomic():
                    locked = Customer.objects.select_for_update(of=("self",)).get(id=customer_id)
                    locked.meta = locked.meta or {}
                    locked.meta["stats"] = stats_data
                    locked.save(update_fields=["meta", "updated_at"])

            AuditService.log_simple_event(
                event_type="customer_stats_updated",
                user=None,
                content_object=customer,
                description=f"Statistics updated for customer {customer.get_display_name()}",
                actor_type="system",
                metadata={
                    "customer_id": str(customer.id),
                    "metrics_summary": {
                        "total_orders": metrics.get("total_orders", 0),
                        "engagement_score": metrics.get("engagement_score", 0),
                    },
                    "source_app": "customers",
                },
            )

            logger.info(f"📊 [Stats] Updated stats for customer {customer_id}")

            return {
                "success": True,
                "customer_id": str(customer.id),
                "metrics": metrics,
            }

        except Exception as e:
            logger.error(f"🔥 [Stats] Failed to update stats for customer {customer_id}: {e}")
            return {"success": False, "error": str(e)}

    @staticmethod
    def refresh_all_customer_stats(limit: int = 100) -> dict[str, Any]:
        """
        Refresh statistics for all customers (batch operation).

        Args:
            limit: Maximum number of customers to update per run

        Returns:
            Dictionary with batch update results
        """
        from apps.customers.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Customer,  # Circular: cross-app  # Deferred: avoids circular import
        )

        # Engagement scoring thresholds

        try:
            # Update oldest first
            customers = Customer.objects.order_by("updated_at")[:limit]

            results: dict[str, Any] = {"total": customers.count(), "updated": 0, "errors": []}

            for customer in customers:
                try:
                    update_result = CustomerStatsService.update_stats(str(customer.id))
                    if update_result.get("success"):
                        results["updated"] += 1
                    else:
                        results["errors"].append(
                            {
                                "customer_id": str(customer.id),
                                "error": update_result.get("error"),
                            }
                        )
                except Exception as e:
                    results["errors"].append({"customer_id": str(customer.id), "error": str(e)})

            logger.info(f"📊 [Stats] Batch update completed: {results['updated']}/{results['total']} customers")
            return results

        except Exception as e:
            logger.error(f"🔥 [Stats] Batch stats update failed: {e}")
            return {"success": False, "error": str(e)}


# Backward compatibility: Re-export all services
__all__ = [
    "ContactService",
    "CustomerAnalyticsService",
    "CustomerCreditService",
    "CustomerService",
    "CustomerStatsService",
    "ProfileService",
]
