"""
Customer services re-export hub for PRAHO Platform.
Maintains backward compatibility after ADR-0012 feature-based reorganization.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any

from django.db.models import Avg, Sum
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
        from apps.customers.models import Customer  # noqa: PLC0415

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
                "customer_type": "business" if customer.is_business else "individual",
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
            metrics["credit_rating"] = CustomerCreditService.get_credit_rating(metrics["credit_score"])

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
        """Get order-related metrics for a customer."""
        try:
            from apps.orders.models import Order  # noqa: PLC0415

            orders = Order.objects.filter(customer=customer)

            total_orders = orders.count()
            completed_orders = orders.filter(status__in=["completed", "delivered", "fulfilled"]).count()
            cancelled_orders = orders.filter(status="cancelled").count()
            pending_orders = orders.filter(status__in=["pending", "processing"]).count()

            # Average order value
            avg_order_value = orders.aggregate(avg=Avg("total_cents"))["avg"] or 0

            # Last order date
            last_order = orders.order_by("-created_at").first()
            last_order_date = last_order.created_at.isoformat() if last_order else None

            return {
                "total_orders": total_orders,
                "completed_orders": completed_orders,
                "cancelled_orders": cancelled_orders,
                "pending_orders": pending_orders,
                "average_order_value": float(avg_order_value) / 100 if avg_order_value else 0,
                "last_order_date": last_order_date,
                "order_completion_rate": (completed_orders / total_orders * 100) if total_orders > 0 else 0,
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
        """Get billing-related metrics for a customer."""
        try:
            from apps.billing.models import Invoice, Payment  # noqa: PLC0415

            invoices = Invoice.objects.filter(customer=customer)
            payments = Payment.objects.filter(invoice__customer=customer)

            total_invoiced = invoices.aggregate(total=Sum("total_cents"))["total"] or 0
            total_paid = payments.filter(status="succeeded").aggregate(total=Sum("amount_cents"))["total"] or 0

            pending_invoices = invoices.filter(status="pending").count()
            overdue_invoices = invoices.filter(status="overdue").count()

            return {
                "total_invoiced": Decimal(total_invoiced) / 100,
                "total_paid": Decimal(total_paid) / 100,
                "total_revenue": Decimal(total_paid) / 100,
                "outstanding_balance": Decimal(total_invoiced - total_paid) / 100,
                "pending_invoices": pending_invoices,
                "overdue_invoices": overdue_invoices,
                "payment_rate": (total_paid / total_invoiced * 100) if total_invoiced > 0 else 100,
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
                "payment_rate": 100,
            }

    @staticmethod
    def _get_service_metrics(customer: Any) -> dict[str, Any]:
        """Get service-related metrics for a customer."""
        try:
            from apps.provisioning.models import Service  # noqa: PLC0415

            services = Service.objects.filter(customer=customer)

            return {
                "total_services": services.count(),
                "active_services": services.filter(status="active").count(),
                "suspended_services": services.filter(status="suspended").count(),
                "pending_services": services.filter(status__in=["pending", "provisioning"]).count(),
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
    def _calculate_engagement_score(customer: Any, metrics: dict[str, Any]) -> int:  # noqa: C901, PLR0912
        """Calculate customer engagement score (0-100)."""
        score = 0

        # Account age factor (max 20 points)
        account_age_days = metrics.get("account_age_days", 0)
        if account_age_days > 365:
            score += 20
        elif account_age_days > 180:
            score += 15
        elif account_age_days > 90:
            score += 10
        elif account_age_days > 30:
            score += 5

        # Order activity factor (max 30 points)
        total_orders = metrics.get("total_orders", 0)
        if total_orders >= 10:
            score += 30
        elif total_orders >= 5:
            score += 20
        elif total_orders >= 2:
            score += 10
        elif total_orders >= 1:
            score += 5

        # Payment behavior factor (max 25 points)
        payment_rate = metrics.get("payment_rate", 100)
        if payment_rate >= 95:
            score += 25
        elif payment_rate >= 80:
            score += 15
        elif payment_rate >= 60:
            score += 5

        # Active services factor (max 25 points)
        active_services = metrics.get("active_services", 0)
        if active_services >= 3:
            score += 25
        elif active_services >= 2:
            score += 15
        elif active_services >= 1:
            score += 10

        return min(100, score)


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
        from apps.audit.services import AuditService  # noqa: PLC0415
        from apps.customers.models import Customer  # noqa: PLC0415

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

            # Store stats in customer metadata
            if hasattr(customer, "meta") and customer.meta is not None:
                customer.meta["stats"] = {
                    "total_orders": metrics.get("total_orders", 0),
                    "total_revenue": float(metrics.get("total_revenue", 0)),
                    "active_services": metrics.get("active_services", 0),
                    "credit_score": metrics.get("credit_score", 750),
                    "engagement_score": metrics.get("engagement_score", 0),
                    "last_updated": timezone.now().isoformat(),
                }
                customer.save(update_fields=["meta", "updated_at"])

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
        from apps.customers.models import Customer  # noqa: PLC0415

        try:
            # Update oldest first
            customers = Customer.objects.order_by("updated_at")[:limit]

            results = {"total": customers.count(), "updated": 0, "errors": []}

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
