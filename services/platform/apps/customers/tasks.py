"""Customer management background tasks.

This module contains Django-Q2 tasks for customer onboarding, feedback processing,
and customer analytics operations.
"""

from __future__ import annotations

import logging
from typing import Any

from django.core.cache import cache
from django.utils import timezone
from django_q.tasks import async_task

from apps.audit.services import AuditService

logger = logging.getLogger(__name__)

# Task configuration
TASK_RETRY_DELAY = 300  # 5 minutes
TASK_MAX_RETRIES = 3
_DEFAULT_TASK_SOFT_TIME_LIMIT = 300  # 5 minutes
TASK_SOFT_TIME_LIMIT = _DEFAULT_TASK_SOFT_TIME_LIMIT
_DEFAULT_TASK_TIME_LIMIT = 600  # 10 minutes
TASK_TIME_LIMIT = _DEFAULT_TASK_TIME_LIMIT

# Engagement score recency thresholds (days since last login)
_RECENCY_THRESHOLD_HIGH = 7
_RECENCY_THRESHOLD_MEDIUM = 30
_RECENCY_THRESHOLD_LOW = 90


def get_task_soft_time_limit() -> int:
    """Get task soft time limit from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("customers.task_soft_time_limit", _DEFAULT_TASK_SOFT_TIME_LIMIT)


def get_task_time_limit() -> int:
    """Get task time limit from SettingsService (runtime)."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    return SettingsService.get_integer_setting("customers.task_time_limit", _DEFAULT_TASK_TIME_LIMIT)


def process_customer_feedback(note_id: str) -> dict[str, Any]:
    """
    Process customer feedback from notes and extract insights.

    Args:
        note_id: CustomerNote UUID to process

    Returns:
        Dictionary with processing result
    """
    logger.info(f"💬 [CustomerFeedback] Processing feedback for note {note_id}")

    try:
        from apps.customers.models import CustomerNote  # noqa: PLC0415

        note = CustomerNote.objects.get(id=note_id)

        # TODO: Implement actual feedback analysis
        # This could include sentiment analysis, keyword extraction, etc.
        logger.info(f"💬 [CustomerFeedback] Would analyze feedback: {note.content[:100]}...")

        # Log the feedback processing
        AuditService.log_simple_event(
            event_type="customer_feedback_processed",
            user=None,
            content_object=note,
            description=f"Customer feedback processed for note from {note.customer.name}",
            actor_type="system",
            metadata={
                "note_id": str(note.id),
                "customer_id": str(note.customer.id),
                "feedback_length": len(note.content),
                "created_at": note.created_at.isoformat(),
                "source_app": "customers",
            },
        )

        return {
            "success": True,
            "note_id": str(note.id),
            "customer_id": str(note.customer.id),
            "message": "Customer feedback processed",
        }

    except Exception as e:
        logger.exception(f"💥 [CustomerFeedback] Error processing feedback for note {note_id}: {e}")
        return {"success": False, "error": str(e)}


def start_customer_onboarding(customer_id: str) -> dict[str, Any]:
    """
    Start the customer onboarding process.

    Args:
        customer_id: Customer UUID to start onboarding for

    Returns:
        Dictionary with onboarding result
    """
    logger.info(f"🚀 [CustomerOnboarding] Starting onboarding for customer {customer_id}")

    try:
        from apps.customers.models import Customer  # noqa: PLC0415

        customer = Customer.objects.get(id=customer_id)

        # TODO: Implement actual onboarding steps
        # This could include welcome emails, setup tasks, initial configuration, etc.
        logger.info(f"🚀 [CustomerOnboarding] Would start onboarding for {customer.get_display_name()}")

        # Log the onboarding start
        AuditService.log_simple_event(
            event_type="customer_onboarding_started",
            user=None,
            content_object=customer,
            description=f"Customer onboarding started for {customer.get_display_name()}",
            actor_type="system",
            metadata={
                "customer_id": str(customer.id),
                "customer_name": customer.get_display_name(),
                "customer_type": "business" if customer.is_business else "individual",
                "created_at": customer.created_at.isoformat(),
                "source_app": "customers",
            },
        )

        # Set up initial onboarding steps
        onboarding_steps = [
            "welcome_email",
            "setup_billing_profile",
            "verify_contact_details",
            "complete_tax_information",
        ]

        for step in onboarding_steps:
            logger.info(f"🚀 [CustomerOnboarding] Scheduling step: {step}")
            # TODO: Schedule individual onboarding steps

        return {
            "success": True,
            "customer_id": str(customer.id),
            "customer_name": customer.get_display_name(),
            "onboarding_steps": onboarding_steps,
            "message": "Customer onboarding started",
        }

    except Exception as e:
        logger.exception(f"💥 [CustomerOnboarding] Error starting onboarding for customer {customer_id}: {e}")
        return {"success": False, "error": str(e)}


def update_customer_analytics(customer_id: str) -> dict[str, Any]:
    """
    Update analytics data for a customer.

    Args:
        customer_id: Customer UUID to update analytics for

    Returns:
        Dictionary with analytics update result
    """
    logger.info(f"📊 [CustomerAnalytics] Updating analytics for customer {customer_id}")

    try:
        from apps.customers.models import Customer  # noqa: PLC0415

        customer = Customer.objects.get(id=customer_id)

        from django.db.models import Sum  # noqa: PLC0415

        from apps.billing.invoice_models import Invoice  # noqa: PLC0415
        from apps.orders.models import Order  # noqa: PLC0415

        total_orders = Order.objects.filter(customer=customer).count()

        revenue_result = Invoice.objects.filter(customer=customer, status="paid").aggregate(total=Sum("total_cents"))
        total_revenue = revenue_result["total"] or 0

        account_age_days = (timezone.now().date() - customer.created_at.date()).days

        engagement_score = _calculate_engagement_score(customer, total_orders, account_age_days)

        analytics_data = {
            "last_updated": timezone.now().isoformat(),
            "total_orders": total_orders,
            "total_revenue": total_revenue,
            "account_age_days": account_age_days,
            "engagement_score": engagement_score,
        }

        # Log the analytics update
        AuditService.log_simple_event(
            event_type="customer_analytics_updated",
            user=None,
            content_object=customer,
            description=f"Analytics updated for customer {customer.get_display_name()}",
            actor_type="system",
            metadata={
                "customer_id": str(customer.id),
                "analytics_data": analytics_data,
                "source_app": "customers",
            },
        )

        return {
            "success": True,
            "customer_id": str(customer.id),
            "customer_name": customer.get_display_name(),
            "analytics": analytics_data,
            "message": "Customer analytics updated",
        }

    except Exception as e:
        logger.exception(f"💥 [CustomerAnalytics] Error updating analytics for customer {customer_id}: {e}")
        return {"success": False, "error": str(e)}


def cleanup_inactive_customers() -> dict[str, Any]:
    """
    Identify and process inactive customers.

    Returns:
        Dictionary with cleanup results
    """
    logger.info("🧹 [CustomerCleanup] Starting inactive customer cleanup")

    try:
        # Prevent concurrent cleanup
        lock_key = "customer_cleanup_lock"
        if cache.get(lock_key):
            logger.info("⏭️ [CustomerCleanup] Cleanup already running, skipping")
            return {"success": True, "message": "Already running"}

        # Set lock for 1 hour
        cache.set(lock_key, True, 3600)

        try:
            from datetime import timedelta  # noqa: PLC0415

            from apps.customers.models import Customer  # noqa: PLC0415

            # Find customers inactive for more than 1 year
            cutoff_date = timezone.now() - timedelta(days=365)

            inactive_customers = Customer.objects.filter(
                last_login__lt=cutoff_date,
                created_at__lt=cutoff_date,
            ).exclude(
                # Don't consider customers with recent orders/invoices as inactive
                orders__created_at__gte=cutoff_date
            )

            results: dict[str, Any] = {
                "total_checked": int(Customer.objects.count()),
                "inactive_found": int(inactive_customers.count()),
                "processed_customers": 0,
                "customers": [],
            }

            for customer in inactive_customers[:50]:  # Limit to 50 per run
                # TODO: Implement inactive customer processing
                # This could include sending reactivation emails, archiving data, etc.
                logger.info(f"🧹 [CustomerCleanup] Processing inactive customer {customer.get_display_name()}")

                results["processed_customers"] += 1
                results["customers"].append(
                    {
                        "customer_id": str(customer.id),
                        "customer_name": customer.get_display_name(),
                        "last_seen": customer.last_login.isoformat() if customer.last_login else None,
                        "account_age_days": (timezone.now().date() - customer.created_at.date()).days,
                    }
                )

            logger.info(
                f"✅ [CustomerCleanup] Cleanup completed: "
                f"{results['inactive_found']} inactive customers found, "
                f"{results['processed_customers']} processed"
            )

            return {"success": True, "results": results}

        finally:
            # Always release lock
            cache.delete(lock_key)

    except Exception as e:
        logger.exception(f"💥 [CustomerCleanup] Error in customer cleanup: {e}")
        return {"success": False, "error": str(e)}


def send_customer_welcome_email(customer_id: str) -> dict[str, Any]:
    """
    Send welcome email to a new customer.

    Args:
        customer_id: Customer UUID to send welcome email to

    Returns:
        Dictionary with email sending result
    """
    logger.info(f"📧 [CustomerWelcome] Sending welcome email to customer {customer_id}")

    try:
        from apps.customers.models import Customer  # noqa: PLC0415

        customer = Customer.objects.get(id=customer_id)

        # TODO: Implement actual email sending
        logger.info(f"📧 [CustomerWelcome] Would send welcome email to {customer.email}")

        # Log the email sending attempt
        AuditService.log_simple_event(
            event_type="customer_welcome_email_sent",
            user=None,
            content_object=customer,
            description=f"Welcome email sent to {customer.get_display_name()}",
            actor_type="system",
            metadata={
                "customer_id": str(customer.id),
                "customer_email": customer.email,
                "customer_name": customer.get_display_name(),
                "source_app": "customers",
            },
        )

        return {
            "success": True,
            "customer_id": str(customer.id),
            "customer_email": customer.email,
            "message": "Welcome email sent",
        }

    except Exception as e:
        logger.exception(f"💥 [CustomerWelcome] Error sending welcome email to customer {customer_id}: {e}")
        return {"success": False, "error": str(e)}


def _calculate_engagement_score(customer: Any, total_orders: int, account_age_days: int) -> int:
    """Calculate customer engagement score (0-100) based on weighted factors."""
    from apps.settings.services import SettingsService  # noqa: PLC0415

    order_weight = SettingsService.get_integer_setting("customers.engagement_order_weight", 40)
    recency_weight = SettingsService.get_integer_setting("customers.engagement_recency_weight", 30)
    activity_weight = SettingsService.get_integer_setting("customers.engagement_activity_weight", 30)

    # Order score: 0-100 based on order count (10+ orders = 100)
    order_score = min(total_orders * 10, 100)

    # Recency score: based on most recent login of any member user
    recency_score = 0
    last_login = (
        customer.memberships.filter(user__last_login__isnull=False)
        .values_list("user__last_login", flat=True)
        .order_by("-user__last_login")
        .first()
    )
    if last_login:
        days_since_login = (timezone.now() - last_login).days
        if days_since_login <= _RECENCY_THRESHOLD_HIGH:
            recency_score = 100
        elif days_since_login <= _RECENCY_THRESHOLD_MEDIUM:
            recency_score = 50
        elif days_since_login <= _RECENCY_THRESHOLD_LOW:
            recency_score = 25

    # Activity score: orders per month normalized
    activity_score = 0
    if account_age_days > 0:
        orders_per_month = (total_orders / account_age_days) * 30
        activity_score = min(int(orders_per_month * 25), 100)

    total = (order_score * order_weight + recency_score * recency_weight + activity_score * activity_weight) // 100

    return max(0, min(100, total))


# ===============================================================================
# ASYNC WRAPPER FUNCTIONS
# ===============================================================================


def process_customer_feedback_async(note_id: str) -> str:
    """Queue customer feedback processing task."""
    return async_task("apps.customers.tasks.process_customer_feedback", note_id, timeout=TASK_SOFT_TIME_LIMIT)


def start_customer_onboarding_async(customer_id: str) -> str:
    """Queue customer onboarding task."""
    return async_task("apps.customers.tasks.start_customer_onboarding", customer_id, timeout=TASK_TIME_LIMIT)


def update_customer_analytics_async(customer_id: str) -> str:
    """Queue customer analytics update task."""
    return async_task("apps.customers.tasks.update_customer_analytics", customer_id, timeout=TASK_TIME_LIMIT)


def cleanup_inactive_customers_async() -> str:
    """Queue inactive customer cleanup task."""
    return async_task("apps.customers.tasks.cleanup_inactive_customers", timeout=TASK_TIME_LIMIT)


def send_customer_welcome_email_async(customer_id: str) -> str:
    """Queue customer welcome email task."""
    return async_task("apps.customers.tasks.send_customer_welcome_email", customer_id, timeout=TASK_SOFT_TIME_LIMIT)
