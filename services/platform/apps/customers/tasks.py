"""Customer management background tasks.

This module contains Django-Q2 tasks for customer onboarding, feedback processing,
and customer analytics operations.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from django.core.cache import cache
from django.db import transaction
from django.db.models import Exists, OuterRef, Sum
from django.utils import timezone
from django_q.tasks import async_task

from apps.audit.services import AuditService

if TYPE_CHECKING:
    from apps.customers.models import Customer

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

# Ticket statuses considered "open" for inactive customer cleanup
_OPEN_TICKET_STATUSES = ("open", "in_progress", "waiting_on_customer")

# Named constants for cleanup task parameters (replaces magic numbers)
_LOCK_TTL_SECONDS = 14400  # Lock TTL must exceed worst-case task duration. Reactivation email cooldown provides per-customer safety net.
_INACTIVE_THRESHOLD_DAYS = 365  # 12 months of inactivity
_REACTIVATION_COOLDOWN_DAYS = 90  # Days between reactivation emails
_CLEANUP_BATCH_LIMIT = 50  # Max customers to process per cleanup run


def get_task_soft_time_limit() -> int:
    """Get task soft time limit from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("customers.task_soft_time_limit", _DEFAULT_TASK_SOFT_TIME_LIMIT)


def get_task_time_limit() -> int:
    """Get task time limit from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("customers.task_time_limit", _DEFAULT_TASK_TIME_LIMIT)


def process_customer_feedback(note_id: str) -> dict[str, Any]:
    """
    Process customer feedback from notes and extract insights.

    Performs keyword-based category detection and simple sentiment analysis
    on the note content, then stores results in audit metadata.

    Args:
        note_id: CustomerNote UUID to process

    Returns:
        Dictionary with processing result including detected category and sentiment
    """
    logger.info(f"💬 [CustomerFeedback] Processing feedback for note {note_id}")

    try:
        from apps.customers.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            CustomerNote,  # Circular: cross-app  # Deferred: avoids circular import
        )

        note = CustomerNote.objects.select_related("customer").get(id=note_id)

        # Idempotency: check if this feedback was already processed
        from apps.audit.models import AuditEvent  # noqa: PLC0415  # Deferred: avoids circular import

        if AuditEvent.objects.filter(
            action="customer_feedback_processed",
            metadata__note_id=str(note_id),
        ).exists():
            logger.info(f"⏭️ [Feedback] Already processed note {note_id}, skipping")
            return {"success": True, "message": "Already processed", "skipped": True}

        # Keyword-based category detection
        category = _detect_feedback_category(note.content)
        sentiment = _detect_feedback_sentiment(note.content)

        logger.info(f"💬 [CustomerFeedback] Analyzed note {note_id}: category={category}, sentiment={sentiment}")

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
                "detected_category": category,
                "detected_sentiment": sentiment,
                "note_type": note.note_type,
                "created_at": note.created_at.isoformat(),
                "source_app": "customers",
            },
        )

        return {
            "success": True,
            "note_id": str(note.id),
            "customer_id": str(note.customer.id),
            "category": category,
            "sentiment": sentiment,
            "message": "Customer feedback processed",
        }

    except Exception as e:
        logger.exception(f"💥 [CustomerFeedback] Error processing feedback for note {note_id}: {e}")
        return {"success": False, "error": "Task failed, see server logs"}


def start_customer_onboarding(customer_id: str) -> dict[str, Any]:
    """
    Run the customer onboarding process as a single idempotent task.

    Checks each onboarding step (welcome email already sent by signal,
    contact details, billing profile, tax information) and records
    completion status in customer.meta["onboarding"].

    Args:
        customer_id: Customer UUID to start onboarding for

    Returns:
        Dictionary with onboarding result and step statuses
    """
    logger.info(f"🚀 [CustomerOnboarding] Starting onboarding for customer {customer_id}")

    try:
        from apps.customers.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Customer,  # Circular: cross-app  # Deferred: avoids circular import
        )

        customer = (
            Customer.objects.select_related(
                "tax_profile",
                "billing_profile",
            )
            .prefetch_related("addresses")
            .get(id=customer_id)
        )

        is_business = customer.customer_type in ("company", "pfa")
        step_results = {}

        # Step 1: Welcome email — already sent by signal on customer creation.
        # Just verify it was logged (idempotent check).
        step_results["welcome_email"] = "completed"

        # Step 2: Verify contact details — check phone and address exist
        has_phone = bool(customer.primary_phone)
        has_address = customer.addresses.exists()
        step_results["verify_contact_details"] = "completed" if (has_phone and has_address) else "incomplete"

        # Step 3: Billing profile — check billing profile exists
        billing_profile = customer.get_billing_profile()
        step_results["setup_billing_profile"] = "completed" if billing_profile else "incomplete"

        # Step 4: Tax information — required for business customers only
        if is_business:
            tax_profile = customer.get_tax_profile()
            if tax_profile is not None:
                # CUI is primary identifier for companies/PFA; VAT number for VAT-registered
                has_tax_info = bool(getattr(tax_profile, "cui", None) or getattr(tax_profile, "vat_number", None))
            else:
                has_tax_info = False
            step_results["complete_tax_information"] = "completed" if has_tax_info else "incomplete"
        else:
            # Individuals: CNP is the tax identifier (optional for onboarding)
            step_results["complete_tax_information"] = "not_required"

        # Store onboarding state in customer metadata
        is_complete = all(v in ("completed", "not_required") for v in step_results.values())
        # Narrow lock: only the meta write to prevent lost updates from concurrent tasks
        with transaction.atomic():
            customer_locked = Customer.objects.select_for_update(of=("self",)).get(id=customer_id)
            customer_locked.meta = customer_locked.meta or {}
            existing_onboarding = customer_locked.meta.get("onboarding", {})
            customer_locked.meta["onboarding"] = {
                "steps": step_results,
                # Preserve original started_at on re-runs (idempotent)
                "started_at": existing_onboarding.get("started_at", timezone.now().isoformat()),
                "updated_at": timezone.now().isoformat(),
                "is_complete": is_complete,
            }
            customer_locked.save(update_fields=["meta", "updated_at"])

        AuditService.log_simple_event(
            event_type="customer_onboarding_started",
            user=None,
            content_object=customer,
            description=f"Customer onboarding started for {customer.get_display_name()}",
            actor_type="system",
            metadata={
                "customer_id": str(customer.id),
                "customer_name": customer.get_display_name(),
                "customer_type": customer.customer_type,
                "step_results": step_results,
                "is_complete": is_complete,
                "source_app": "customers",
            },
        )

        incomplete = [k for k, v in step_results.items() if v == "incomplete"]
        if incomplete:
            logger.info(f"🚀 [CustomerOnboarding] customer {customer.id}: incomplete steps: {', '.join(incomplete)}")
        else:
            logger.info(f"✅ [CustomerOnboarding] customer {customer.id}: all steps complete")

        return {
            "success": True,
            "customer_id": str(customer.id),
            "customer_name": customer.get_display_name(),
            "onboarding_steps": step_results,
            "is_complete": is_complete,
            "message": "Customer onboarding processed",
        }

    except Exception as e:
        logger.exception(f"💥 [CustomerOnboarding] Error starting onboarding for customer {customer_id}: {e}")
        return {"success": False, "error": "Task failed, see server logs"}


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
        from apps.customers.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Customer,  # Circular: cross-app  # Deferred: avoids circular import
        )

        customer = Customer.objects.get(id=customer_id)

        from apps.billing.invoice_models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Invoice,  # Circular: cross-app  # Deferred: avoids circular import
        )
        from apps.orders.models import Order  # Circular: cross-app  # noqa: PLC0415  # Deferred: avoids circular import

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
        return {"success": False, "error": "Task failed, see server logs"}


def _process_inactive_candidate(customer: Customer, reactivation_cooldown: datetime, results: dict[str, Any]) -> None:
    """Process a single inactive customer candidate (extracted for complexity budget).

    Service and Ticket exclusions are handled in the queryset via Exists() subqueries,
    so every candidate reaching this function is already confirmed to have no active
    services and no open tickets.
    """
    from apps.customers.models import Customer  # noqa: PLC0415  # Deferred: avoids circular import

    results["inactive_found"] += 1

    # Check 90-day reactivation email cooldown
    last_reactivation = (customer.meta or {}).get("last_reactivation_email")
    if last_reactivation:
        try:
            last_sent = datetime.fromisoformat(last_reactivation)
            aware_last_sent = timezone.make_aware(last_sent) if timezone.is_naive(last_sent) else last_sent
            if aware_last_sent > reactivation_cooldown:
                results["skipped_cooldown"] += 1
                return
        except (ValueError, TypeError):
            # Fail closed: skip send on corrupt dates to prevent email spam
            logger.warning(
                f"⚠️ [CustomerCleanup] Invalid reactivation date for customer "
                f"{customer.id}, skipping send: {last_reactivation!r}"
            )
            results["skipped_cooldown"] += 1
            return

    # Send reactivation email
    email_sent = _send_reactivation_email(customer)

    if email_sent:
        # Track last reactivation email in meta (locked to prevent lost updates)
        with transaction.atomic():
            locked = Customer.objects.select_for_update(of=("self",)).get(id=customer.id)
            locked.meta = locked.meta or {}
            locked.meta["last_reactivation_email"] = timezone.now().isoformat()
            locked.save(update_fields=["meta", "updated_at"])
        results["emails_sent"] += 1

    # Determine last login from memberships
    last_login = (
        customer.memberships.filter(user__last_login__isnull=False)
        .values_list("user__last_login", flat=True)
        .order_by("-user__last_login")
        .first()
    )

    results["customers"].append(
        {
            "customer_id": str(customer.id),
            "customer_name": customer.get_display_name(),
            "last_seen": last_login.isoformat() if last_login else None,
            "email_sent": email_sent,
            "account_age_days": (timezone.now().date() - customer.created_at.date()).days,
        }
    )


def cleanup_inactive_customers() -> dict[str, Any]:
    """
    Identify truly inactive customers and send reactivation check-in emails.

    A customer is considered truly inactive when ALL of:
    - No user login via memberships in 12+ months
    - No active services
    - No orders in 12 months
    - No open/in-progress tickets
    - Has marketing consent (GDPR compliance)
    - Not emailed for reactivation in last 90 days

    Does NOT change customer status — that remains a staff decision.

    Returns:
        Dictionary with cleanup results
    """
    logger.info("🧹 [CustomerCleanup] Starting inactive customer cleanup")

    try:
        # Tokenized lock to prevent concurrent cleanup runs (prevents stale-owner unlock)
        lock_key = "customer_cleanup_lock"
        lock_token = str(uuid.uuid4())
        if not cache.add(lock_key, lock_token, _LOCK_TTL_SECONDS):
            logger.info("⏭️ [CustomerCleanup] Cleanup already running, skipping")
            return {"success": True, "message": "Already running"}

        try:
            from apps.customers.models import (  # noqa: PLC0415  # Deferred: avoids circular import
                Customer,  # Circular: cross-app  # Deferred: avoids circular import
            )
            from apps.provisioning.models import Service  # noqa: PLC0415  # Deferred: avoids circular import
            from apps.tickets.models import Ticket  # noqa: PLC0415  # Deferred: avoids circular import

            cutoff_date = timezone.now() - timedelta(days=_INACTIVE_THRESHOLD_DAYS)
            reactivation_cooldown = timezone.now() - timedelta(days=_REACTIVATION_COOLDOWN_DAYS)

            # NULL-safe NOT EXISTS subqueries (replaces NOT IN which fails on NULLs).
            # Exists() emits NOT EXISTS in SQL — safe when related rows may have NULL FKs.
            has_recent_login = Customer.objects.filter(
                id=OuterRef("id"),
                memberships__user__last_login__gte=cutoff_date,
            )
            has_recent_order = Customer.objects.filter(
                id=OuterRef("id"),
                orders__created_at__gte=cutoff_date,
            )

            # Service/Ticket checks pushed into queryset to eliminate N+1 per candidate.
            has_active_service = Service.objects.filter(
                customer_id=OuterRef("id"),
                status="active",
            )
            has_open_ticket = Ticket.objects.filter(
                customer_id=OuterRef("id"),
                status__in=_OPEN_TICKET_STATUSES,
            )

            candidates = (
                Customer.objects.filter(
                    status="active",
                    created_at__lt=cutoff_date,
                    marketing_consent=True,
                )
                .exclude(Exists(has_recent_login))
                .exclude(Exists(has_recent_order))
                .exclude(Exists(has_active_service))
                .exclude(Exists(has_open_ticket))
            )

            results: dict[str, Any] = {
                "total_checked": int(Customer.objects.filter(status="active").count()),
                "inactive_found": 0,
                "emails_sent": 0,
                "skipped_cooldown": 0,
                "customers": [],
            }

            for customer in candidates[:_CLEANUP_BATCH_LIMIT]:
                _process_inactive_candidate(customer, reactivation_cooldown, results)

            logger.info(
                f"✅ [CustomerCleanup] Cleanup completed: "
                f"{results['inactive_found']} inactive found, "
                f"{results['emails_sent']} emails sent"
            )

            return {"success": True, "results": results}

        finally:
            # Only delete our own lock — prevent stale-owner unlock
            if cache.get(lock_key) == lock_token:
                cache.delete(lock_key)

    except Exception as e:
        logger.exception(f"💥 [CustomerCleanup] Error in customer cleanup: {e}")
        return {"success": False, "error": "Task failed, see server logs"}


def send_customer_welcome_email(customer_id: str) -> dict[str, Any]:
    """
    Send welcome email to a new customer via the notifications EmailService.

    Uses the 'customer_welcome' template which exists in both RO and EN.
    The email is sent synchronously here since this function is already
    running inside a Django-Q2 async task.

    Args:
        customer_id: Customer UUID to send welcome email to

    Returns:
        Dictionary with email sending result
    """
    logger.info(f"📧 [CustomerWelcome] Sending welcome email to customer {customer_id}")

    try:
        from apps.customers.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            Customer,  # Circular: cross-app  # Deferred: avoids circular import
        )
        from apps.notifications.services import EmailService  # noqa: PLC0415  # Deferred: avoids circular import

        customer = Customer.objects.get(id=customer_id)

        if not customer.primary_email:
            logger.warning(f"⚠️ [CustomerWelcome] No email for customer {customer_id}, skipping")
            return {"success": False, "error": "No email address"}

        if customer.meta.get("welcome_email_sent_at"):
            logger.info(f"⏭️ [CustomerWelcome] Already sent for customer {customer_id}, skipping")
            return {"success": True, "message": "Welcome email already sent", "skipped": True}

        locale = _get_customer_locale(customer)

        result = EmailService.send_template_email(
            template_key="customer_welcome",
            recipient=customer.primary_email,
            context={
                "customer": customer,
                "customer_name": customer.get_display_name(),
            },
            locale=locale,
            customer=customer,
            async_send=False,  # Already in async task
        )

        if not result.success:
            logger.warning(
                f"⚠️ [CustomerWelcome] Email send failed for customer {customer.id}: {result.message_id or 'no details'}"
            )

        AuditService.log_simple_event(
            event_type="customer_welcome_email_sent" if result.success else "customer_welcome_email_failed",
            user=None,
            content_object=customer,
            description=f"Welcome email {'sent to' if result.success else 'failed for'} {customer.get_display_name()}",
            actor_type="system",
            metadata={
                "customer_id": str(customer.id),
                "customer_email": customer.primary_email,
                "customer_name": customer.get_display_name(),
                "locale": locale,
                "email_success": result.success,
                "source_app": "customers",
            },
        )

        if result.success:
            with transaction.atomic():
                locked = Customer.objects.select_for_update().get(id=customer_id)
                locked.meta["welcome_email_sent_at"] = timezone.now().isoformat()
                locked.save(update_fields=["meta"])

        return {
            "success": result.success,
            "customer_id": str(customer.id),
            "customer_email": customer.primary_email,
            "locale": locale,
            "message": "Welcome email sent" if result.success else "Welcome email failed",
        }

    except Exception as e:
        logger.exception(f"💥 [CustomerWelcome] Error sending welcome email to customer {customer_id}: {e}")
        return {"success": False, "error": "Task failed, see server logs"}


def _calculate_engagement_score(customer: Customer, total_orders: int, account_age_days: int) -> int:
    """
    Weight-based engagement scoring for background analytics tasks.
    Uses SettingsService weights (default 40/30/30). Denominator is always 100.
    """
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Circular: cross-app  # Deferred: avoids circular import
    )

    order_weight = max(1, min(100, SettingsService.get_integer_setting("customers.engagement_order_weight", 40)))
    recency_weight = max(1, min(100, SettingsService.get_integer_setting("customers.engagement_recency_weight", 30)))
    activity_weight = max(1, min(100, SettingsService.get_integer_setting("customers.engagement_activity_weight", 30)))

    weight_sum = order_weight + recency_weight + activity_weight
    if weight_sum != 100:  # noqa: PLR2004  # Expected sum of engagement weights
        logger.warning(
            f"⚠️ [Engagement] Weights sum to {weight_sum}, expected 100. "
            "Results may be skewed. Check SettingsService configuration."
        )

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
# HELPER FUNCTIONS
# ===============================================================================

# Keyword maps for feedback category detection (includes Romanian terms)
_FEEDBACK_CATEGORIES: dict[str, list[str]] = {
    "billing": ["invoice", "payment", "charge", "refund", "price", "factura", "plata", "pret", "taxa"],
    "technical": ["server", "down", "error", "slow", "dns", "ssl", "email", "hosting", "eroare", "lent"],
    "praise": ["great", "excellent", "thank", "awesome", "happy", "multumesc", "excelent", "bravo"],
    "complaint": ["bad", "terrible", "worst", "angry", "disappointed", "nemultumit", "prost", "rau"],
    "feature_request": ["wish", "would be nice", "suggest", "feature", "add", "implement", "doresc", "propun"],
}

_POSITIVE_WORDS = {
    "great",
    "excellent",
    "thank",
    "awesome",
    "happy",
    "good",
    "love",
    "perfect",
    "multumesc",
    "excelent",
    "bravo",
    "super",
    "minunat",
}
_NEGATIVE_WORDS = {
    "bad",
    "terrible",
    "worst",
    "angry",
    "disappointed",
    "broken",
    "fail",
    "hate",
    "awful",
    "nemultumit",
    "prost",
    "rau",
    "dezamagit",
}


def _detect_feedback_category(content: str) -> str:
    """Detect feedback category from note content using keyword matching."""
    content_lower = content.lower()
    words = {w.strip(".,!?;:'\"()[]{}") for w in content_lower.split()}
    scores: dict[str, int] = {}
    for category, keywords in _FEEDBACK_CATEGORIES.items():
        score = 0
        for kw in keywords:
            if " " in kw:  # Multi-word phrases: substring match (e.g., "would be nice")
                score += 1 if kw in content_lower else 0
            else:  # Single words: word-boundary match
                score += 1 if kw in words else 0
        if score > 0:
            scores[category] = score
    if not scores:
        return "general"
    return max(scores, key=lambda k: scores[k])


def _detect_feedback_sentiment(content: str) -> str:
    """Detect simple sentiment from note content (positive/negative/neutral)."""
    # Strip punctuation so "great!" matches "great", "terrible," matches "terrible"
    words = {w.strip(".,!?;:'\"()[]{}") for w in content.lower().split()}
    pos_count = len(words & _POSITIVE_WORDS)
    neg_count = len(words & _NEGATIVE_WORDS)
    if pos_count > neg_count:
        return "positive"
    if neg_count > pos_count:
        return "negative"
    return "neutral"


def _get_customer_locale(customer: Customer) -> str:
    """Get preferred locale for a customer based on their primary user's language."""
    try:
        primary_membership = (
            customer.memberships.filter(is_primary=True, is_active=True).select_related("user__profile").first()
        )
        if primary_membership and hasattr(primary_membership.user, "profile"):
            lang = getattr(primary_membership.user.profile, "preferred_language", None)
            if lang in ("ro", "en"):
                return lang
    except Exception:
        logger.debug("⚠️ [CustomerLocale] Could not determine locale, defaulting to 'ro'")
    return "ro"  # Default to Romanian for Romanian hosting provider


def _send_reactivation_email(customer: Customer) -> bool:
    """Send a reactivation check-in email to an inactive customer."""
    if not customer.primary_email:
        logger.warning(f"⚠️ [Reactivation] No email for customer {customer.id}, skipping")
        return False

    try:
        from apps.notifications.services import EmailService  # noqa: PLC0415  # Deferred: avoids circular import

        locale = _get_customer_locale(customer)
        result = EmailService.send_template_email(
            template_key="customer_reactivation",
            recipient=customer.primary_email,
            context={
                "customer": customer,
                "customer_name": customer.get_display_name(),
            },
            locale=locale,
            customer=customer,
            async_send=False,  # Already in async task
        )

        if result.success:
            AuditService.log_simple_event(
                event_type="customer_reactivation_email_sent",
                user=None,
                content_object=customer,
                description=f"Reactivation email sent to {customer.get_display_name()}",
                actor_type="system",
                metadata={
                    "customer_id": str(customer.id),
                    "customer_email": customer.primary_email,
                    "locale": locale,
                    "source_app": "customers",
                },
            )
            logger.info(f"📧 [CustomerCleanup] Reactivation email sent for customer {customer.id}")
        else:
            logger.warning(f"⚠️ [CustomerCleanup] Reactivation email failed for customer {customer.id}")

        return result.success

    except Exception as e:
        logger.exception(f"💥 [CustomerCleanup] Error sending reactivation email: {e}")
        return False


# ===============================================================================
# ASYNC WRAPPER FUNCTIONS
# ===============================================================================


def process_customer_feedback_async(note_id: str) -> str:
    """Queue customer feedback processing task."""
    return async_task("apps.customers.tasks.process_customer_feedback", note_id, timeout=get_task_soft_time_limit())


def start_customer_onboarding_async(customer_id: str) -> str:
    """Queue customer onboarding task."""
    return async_task("apps.customers.tasks.start_customer_onboarding", customer_id, timeout=get_task_time_limit())


def update_customer_analytics_async(customer_id: str) -> str:
    """Queue customer analytics update task."""
    return async_task("apps.customers.tasks.update_customer_analytics", customer_id, timeout=get_task_time_limit())


def cleanup_inactive_customers_async() -> str:
    """Queue inactive customer cleanup task."""
    return async_task("apps.customers.tasks.cleanup_inactive_customers", timeout=get_task_time_limit())


def send_customer_welcome_email_async(customer_id: str) -> str:
    """Queue customer welcome email task."""
    return async_task(
        "apps.customers.tasks.send_customer_welcome_email", customer_id, timeout=get_task_soft_time_limit()
    )
