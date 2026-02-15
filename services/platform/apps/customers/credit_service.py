"""
Customer Credit Service for PRAHO Platform
Manages customer credit scores and payment history.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, Any

from django.db.models import Avg, Count, Sum
from django.utils import timezone

from apps.settings.services import SettingsService

if TYPE_CHECKING:
    from apps.customers.models import Customer

logger = logging.getLogger(__name__)

# Credit score constants — defaults used as fallbacks for SettingsService
_DEFAULT_BASE_CREDIT_SCORE = 750  # Starting score for new customers
MIN_CREDIT_SCORE = 0
MAX_CREDIT_SCORE = 1000
POOR_CREDIT_THRESHOLD = 400
EXCELLENT_CREDIT_THRESHOLD = 800

# Default score adjustments for events — authoritative source is SettingsService
_DEFAULT_CREDIT_ADJUSTMENTS = {
    "positive_payment": 15,  # On-time payment
    "early_payment": 25,  # Payment before due date
    "failed_payment": -50,  # Payment failure
    "late_payment": -30,  # Payment after due date
    "chargeback": -100,  # Chargeback/dispute
    "refund_issued": -10,  # Refund processed
    "account_age_bonus": 5,  # Per year of account age
    "order_completed": 5,  # Successfully completed order
}

# Module-level alias kept for backward compatibility
BASE_CREDIT_SCORE = _DEFAULT_BASE_CREDIT_SCORE
CREDIT_ADJUSTMENTS = _DEFAULT_CREDIT_ADJUSTMENTS


class CustomerCreditService:
    """
    Service for managing customer credit scores and payment behavior.

    This service tracks customer payment patterns and calculates credit scores
    based on payment history, providing risk assessment for hosting services.
    """

    @staticmethod
    def update_credit_score(customer: Any, event_type: str, event_date: datetime) -> dict[str, Any]:
        """
        Update customer credit score based on payment events.

        Args:
            customer: Customer instance
            event_type: Type of payment event ('positive_payment', 'failed_payment', etc.)
            event_date: When the event occurred

        Returns:
            Dictionary with score update details
        """
        from apps.audit.services import AuditService  # noqa: PLC0415

        try:
            # Get current credit score
            current_score = CustomerCreditService.calculate_credit_score(customer)

            # Calculate score adjustment based on event type
            adjustment = CREDIT_ADJUSTMENTS.get(event_type, 0)

            # Apply additional modifiers based on customer history
            if event_type == "positive_payment":
                # Bonus for consistent payers — thresholds from SettingsService
                consecutive_on_time = CustomerCreditService._get_consecutive_on_time_payments(customer)
                consecutive_bonus_6 = SettingsService.get_integer_setting("billing.credit_consecutive_bonus_6", 10)
                consecutive_bonus_12 = SettingsService.get_integer_setting("billing.credit_consecutive_bonus_12", 20)
                if consecutive_on_time >= 12:
                    adjustment += consecutive_bonus_12  # Larger bonus for 12+ consecutive
                elif consecutive_on_time >= 6:
                    adjustment += consecutive_bonus_6  # Bonus for 6+ consecutive on-time payments

            # Calculate new score (clamped to valid range)
            new_score = max(MIN_CREDIT_SCORE, min(MAX_CREDIT_SCORE, current_score + adjustment))

            # Store credit event in customer metadata
            credit_history = customer.meta.get("credit_history", []) if hasattr(customer, "meta") else []
            credit_event = {
                "event_type": event_type,
                "event_date": event_date.isoformat(),
                "score_before": current_score,
                "score_after": new_score,
                "adjustment": adjustment,
                "recorded_at": timezone.now().isoformat(),
            }
            credit_history.append(credit_event)

            # Keep only last 100 events
            if len(credit_history) > 100:
                credit_history = credit_history[-100:]

            if hasattr(customer, "meta"):
                customer.meta["credit_history"] = credit_history
                customer.meta["credit_score"] = new_score
                customer.meta["credit_updated_at"] = timezone.now().isoformat()
                customer.save(update_fields=["meta", "updated_at"])

            # Log audit event
            AuditService.log_simple_event(
                event_type="credit_score_updated",
                user=None,
                content_object=customer,
                description=f"Credit score updated for {customer}: {event_type} ({adjustment:+d})",
                actor_type="system",
                metadata={
                    "customer_id": str(customer.id),
                    "event_type": event_type,
                    "score_before": current_score,
                    "score_after": new_score,
                    "adjustment": adjustment,
                    "source_app": "customers",
                },
            )

            logger.info(
                f"📊 [Credit] Updated score for {customer}: {event_type} "
                f"({current_score} -> {new_score}, {adjustment:+d})"
            )

            return {
                "success": True,
                "customer_id": str(customer.id),
                "event_type": event_type,
                "score_before": current_score,
                "score_after": new_score,
                "adjustment": adjustment,
            }

        except Exception as e:
            logger.error(f"🔥 [Credit] Failed to update credit score for {customer}: {e}")
            raise

    @staticmethod
    def revert_credit_change(customer: Any, event_type: str, event_date: datetime) -> dict[str, Any]:
        """
        Revert a previously applied credit score change.

        Args:
            customer: Customer instance
            event_type: Type of event to revert
            event_date: When the original event occurred

        Returns:
            Dictionary with reversion details
        """
        from apps.audit.services import AuditService  # noqa: PLC0415

        try:
            current_score = CustomerCreditService.calculate_credit_score(customer)

            # Get the original adjustment and reverse it
            original_adjustment = CREDIT_ADJUSTMENTS.get(event_type, 0)
            reversion_adjustment = -original_adjustment

            new_score = max(MIN_CREDIT_SCORE, min(MAX_CREDIT_SCORE, current_score + reversion_adjustment))

            # Record reversion in credit history
            if hasattr(customer, "meta"):
                credit_history = customer.meta.get("credit_history", [])
                reversion_event = {
                    "event_type": f"revert_{event_type}",
                    "original_event_date": event_date.isoformat(),
                    "score_before": current_score,
                    "score_after": new_score,
                    "adjustment": reversion_adjustment,
                    "recorded_at": timezone.now().isoformat(),
                }
                credit_history.append(reversion_event)
                customer.meta["credit_history"] = credit_history[-100:]  # Keep last 100
                customer.meta["credit_score"] = new_score
                customer.meta["credit_updated_at"] = timezone.now().isoformat()
                customer.save(update_fields=["meta", "updated_at"])

            AuditService.log_simple_event(
                event_type="credit_score_reverted",
                user=None,
                content_object=customer,
                description=f"Credit score reverted for {customer}: {event_type}",
                actor_type="system",
                metadata={
                    "customer_id": str(customer.id),
                    "original_event_type": event_type,
                    "original_event_date": event_date.isoformat(),
                    "score_before": current_score,
                    "score_after": new_score,
                    "adjustment": reversion_adjustment,
                    "source_app": "customers",
                },
            )

            logger.info(
                f"↩️ [Credit] Reverted score change for {customer}: {event_type} "
                f"({current_score} -> {new_score}, {reversion_adjustment:+d})"
            )

            return {
                "success": True,
                "customer_id": str(customer.id),
                "event_type": event_type,
                "score_before": current_score,
                "score_after": new_score,
                "adjustment": reversion_adjustment,
            }

        except Exception as e:
            logger.error(f"🔥 [Credit] Failed to revert credit change for {customer}: {e}")
            raise

    @staticmethod
    def calculate_credit_score(customer: Any) -> int:
        """
        Calculate current credit score for a customer.

        The score is calculated based on:
        - Payment history (on-time vs late payments)
        - Account age
        - Order history
        - Previous credit events

        Args:
            customer: Customer instance

        Returns:
            Credit score (0-1000, higher is better)
        """
        try:
            # Check if we have a cached score
            if hasattr(customer, "meta") and customer.meta:
                cached_score = customer.meta.get("credit_score")
                cached_at = customer.meta.get("credit_updated_at")
                if cached_score is not None and cached_at:
                    # Use cached score if updated within last hour
                    try:
                        cached_time = datetime.fromisoformat(cached_at)
                        if timezone.now() - cached_time < timedelta(hours=1):
                            return int(cached_score)
                    except (ValueError, TypeError):
                        pass

            # Start with base score
            score = BASE_CREDIT_SCORE

            # Factor 1: Account age (up to +50 points for 5+ years)
            if hasattr(customer, "created_at") and customer.created_at:
                account_age_days = (timezone.now() - customer.created_at).days
                account_age_years = account_age_days / 365
                age_bonus = min(50, int(account_age_years * CREDIT_ADJUSTMENTS["account_age_bonus"]))
                score += age_bonus

            # Factor 2: Payment history
            payment_stats = CustomerCreditService._get_payment_statistics(customer)
            if payment_stats["total_payments"] > 0:
                on_time_ratio = payment_stats["on_time_payments"] / payment_stats["total_payments"]
                # Up to +100 for perfect payment history, or down to -100 for poor
                payment_factor = int((on_time_ratio - 0.5) * 200)
                score += payment_factor

            # Factor 3: Failed payments penalty
            if payment_stats["failed_payments"] > 0:
                failed_penalty = min(200, payment_stats["failed_payments"] * 25)
                score -= failed_penalty

            # Factor 4: Order history (completed orders add credibility)
            order_stats = CustomerCreditService._get_order_statistics(customer)
            if order_stats["completed_orders"] > 0:
                order_bonus = min(50, order_stats["completed_orders"] * 5)
                score += order_bonus

            # Clamp to valid range
            final_score = max(MIN_CREDIT_SCORE, min(MAX_CREDIT_SCORE, score))

            logger.debug(f"📊 [Credit] Calculated score for {customer}: {final_score}")
            return final_score

        except Exception as e:
            logger.error(f"🔥 [Credit] Failed to calculate credit score for {customer}: {e}")
            return BASE_CREDIT_SCORE  # Return base score on error

    @staticmethod
    def get_credit_rating(score: int) -> str:
        """Get a human-readable credit rating from score."""
        if score >= EXCELLENT_CREDIT_THRESHOLD:
            return "Excellent"
        elif score >= 700:
            return "Good"
        elif score >= 600:
            return "Fair"
        elif score >= POOR_CREDIT_THRESHOLD:
            return "Poor"
        else:
            return "Very Poor"

    @staticmethod
    def _get_payment_statistics(customer: Any) -> dict[str, int]:
        """Get payment statistics for credit calculation."""
        try:
            from apps.billing.models import Payment  # noqa: PLC0415

            payments = Payment.objects.filter(invoice__customer=customer)

            total = payments.count()
            successful = payments.filter(status="succeeded").count()
            failed = payments.filter(status="failed").count()

            # Calculate on-time payments (payments made before or on due date)
            on_time = payments.filter(
                status="succeeded", created_at__lte=models.F("invoice__due_date")
            ).count() if hasattr(Payment, "invoice") else successful

            return {
                "total_payments": total,
                "successful_payments": successful,
                "failed_payments": failed,
                "on_time_payments": on_time,
            }
        except Exception:
            return {"total_payments": 0, "successful_payments": 0, "failed_payments": 0, "on_time_payments": 0}

    @staticmethod
    def _get_order_statistics(customer: Any) -> dict[str, int]:
        """Get order statistics for credit calculation."""
        try:
            from apps.orders.models import Order  # noqa: PLC0415

            orders = Order.objects.filter(customer=customer)

            return {
                "total_orders": orders.count(),
                "completed_orders": orders.filter(status__in=["completed", "delivered", "fulfilled"]).count(),
                "cancelled_orders": orders.filter(status="cancelled").count(),
            }
        except Exception:
            return {"total_orders": 0, "completed_orders": 0, "cancelled_orders": 0}

    @staticmethod
    def _get_consecutive_on_time_payments(customer: Any) -> int:
        """Count consecutive on-time payments (for bonus calculation)."""
        try:
            from apps.billing.models import Payment  # noqa: PLC0415

            # Get recent payments ordered by date
            recent_payments = Payment.objects.filter(
                invoice__customer=customer
            ).order_by("-created_at")[:20]

            consecutive = 0
            for payment in recent_payments:
                if payment.status == "succeeded":
                    consecutive += 1
                else:
                    break  # Stop counting on first non-successful payment

            return consecutive
        except Exception:
            return 0


# Import models at module level for type checking
try:
    from django.db import models
except ImportError:
    models = None  # type: ignore
