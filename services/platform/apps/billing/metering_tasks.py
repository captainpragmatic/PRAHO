"""
Metering Background Tasks for PRAHO Platform
Django-Q2 tasks for usage-based billing operations.

This module provides scheduled and async tasks for:
- Usage event aggregation
- Billing cycle management
- Invoice generation
- Alert notifications
- Stripe synchronization
- Usage data collection from Virtualmin
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any

from django_q.tasks import async_task

from apps.audit.services import AuditService

from . import config as billing_config

logger = logging.getLogger(__name__)

# Task configuration
TASK_TIMEOUT = 300  # 5 minutes
TASK_RETRY_DELAY = 60  # 1 minute


# ===============================================================================
# AGGREGATION TASKS
# ===============================================================================


def update_aggregation_for_event(event_id: str) -> dict[str, Any]:
    """
    Process a single usage event into its aggregation.

    Called asynchronously after each event is recorded.
    """
    from .metering_models import UsageEvent
    from .metering_service import MeteringService

    logger.debug(f"Processing aggregation for event {event_id}")

    try:
        event = UsageEvent.objects.get(id=event_id)
    except UsageEvent.DoesNotExist:
        logger.error(f"Event not found: {event_id}")
        return {"success": False, "error": "Event not found"}

    if event.is_processed:
        return {"success": True, "message": "Event already processed"}

    try:
        service = MeteringService()
        service._update_aggregation_sync(event)

        return {
            "success": True,
            "event_id": event_id,
            "message": "Aggregation updated",
        }
    except Exception as e:
        logger.exception(f"Error updating aggregation for event {event_id}: {e}")
        return {"success": False, "error": str(e)}


def process_pending_usage_events(limit: int = 1000, meter_id: str | None = None) -> dict[str, Any]:
    """
    Batch process all pending usage events.

    Should be run periodically to catch any events that weren't
    processed immediately.
    """
    from .metering_service import AggregationService

    logger.info(f"Processing pending usage events (limit={limit})")

    try:
        service = AggregationService()
        processed, errors = service.process_pending_events(meter_id=meter_id, limit=limit)

        # Log the batch processing
        AuditService.log_simple_event(
            event_type="usage_events_batch_processed",
            user=None,
            content_object=None,
            description=f"Processed {processed} pending events, {errors} errors",
            actor_type="system",
            metadata={
                "processed_count": processed,
                "error_count": errors,
                "limit": limit,
                "meter_id": meter_id,
            },
        )

        return {
            "success": True,
            "processed": processed,
            "errors": errors,
        }
    except Exception as e:
        logger.exception(f"Error processing pending events: {e}")
        return {"success": False, "error": str(e)}


# ===============================================================================
# BILLING CYCLE TASKS
# ===============================================================================


def advance_billing_cycles() -> dict[str, Any]:
    """
    Create new billing cycles for subscriptions that need them.

    Should be run daily to ensure billing cycles are created ahead of time.
    """
    from .usage_invoice_service import BillingCycleManager

    logger.info("Advancing billing cycles")

    try:
        manager = BillingCycleManager()
        created, errors, error_messages = manager.advance_all_subscriptions()

        # Log the advancement
        AuditService.log_simple_event(
            event_type="billing_cycles_advanced",
            user=None,
            content_object=None,
            description=f"Created {created} billing cycles, {errors} errors",
            actor_type="system",
            metadata={
                "created_count": created,
                "error_count": errors,
                "errors": error_messages[:10],  # Limit logged errors
            },
        )

        return {
            "success": True,
            "created": created,
            "errors": errors,
            "error_messages": error_messages,
        }
    except Exception as e:
        logger.exception(f"Error advancing billing cycles: {e}")
        return {"success": False, "error": str(e)}


def close_expired_billing_cycles() -> dict[str, Any]:
    """
    Close billing cycles that have passed their end date.

    Should be run hourly to ensure timely cycle closure.
    """
    from .usage_invoice_service import BillingCycleManager

    logger.info("Closing expired billing cycles")

    try:
        manager = BillingCycleManager()
        closed, errors = manager.close_expired_cycles()

        return {
            "success": True,
            "closed": closed,
            "errors": errors,
        }
    except Exception as e:
        logger.exception(f"Error closing billing cycles: {e}")
        return {"success": False, "error": str(e)}


def rate_pending_aggregations(billing_cycle_id: str | None = None) -> dict[str, Any]:
    """
    Rate all pending aggregations.

    Can be run for a specific billing cycle or all pending.
    """
    from .metering_models import BillingCycle
    from .metering_service import RatingEngine

    logger.info(f"Rating pending aggregations (cycle={billing_cycle_id})")

    try:
        engine = RatingEngine()

        if billing_cycle_id:
            result = engine.rate_billing_cycle(billing_cycle_id)
            return result.unwrap() if result.is_ok() else {"success": False, "error": result.error}

        # Rate all pending
        pending_cycles = BillingCycle.objects.filter(status="closed")
        total_rated = 0
        total_errors = 0

        for cycle in pending_cycles:
            result = engine.rate_billing_cycle(str(cycle.id))
            if result.is_ok():
                total_rated += result.unwrap().get("rated_count", 0)
            else:
                total_errors += 1

        return {
            "success": True,
            "rated": total_rated,
            "errors": total_errors,
        }
    except Exception as e:
        logger.exception(f"Error rating aggregations: {e}")
        return {"success": False, "error": str(e)}


def generate_pending_invoices() -> dict[str, Any]:
    """
    Generate invoices for all ready billing cycles.

    Should be run after closing and rating cycles.
    """
    from .usage_invoice_service import BillingCycleManager

    logger.info("Generating pending invoices")

    try:
        manager = BillingCycleManager()
        generated, errors = manager.generate_pending_invoices()

        return {
            "success": True,
            "generated": generated,
            "errors": errors,
        }
    except Exception as e:
        logger.exception(f"Error generating invoices: {e}")
        return {"success": False, "error": str(e)}


def run_billing_cycle_workflow() -> dict[str, Any]:
    """
    Run the complete billing cycle workflow.

    This is the main scheduled task that:
    1. Closes expired cycles
    2. Rates pending aggregations
    3. Generates invoices
    4. Creates new cycles

    Should be run hourly.
    """
    logger.info("Running billing cycle workflow")

    results = {
        "closed_cycles": None,
        "rated": None,
        "invoices": None,
        "new_cycles": None,
    }

    try:
        # Step 1: Close expired cycles
        results["closed_cycles"] = close_expired_billing_cycles()

        # Step 2: Rate pending aggregations
        results["rated"] = rate_pending_aggregations()

        # Step 3: Generate invoices
        results["invoices"] = generate_pending_invoices()

        # Step 4: Create new cycles
        results["new_cycles"] = advance_billing_cycles()

        # Log workflow completion
        AuditService.log_simple_event(
            event_type="billing_workflow_completed",
            user=None,
            content_object=None,
            description="Billing cycle workflow completed",
            actor_type="system",
            metadata=results,
        )

        return {"success": True, "results": results}
    except Exception as e:
        logger.exception(f"Error in billing workflow: {e}")
        return {"success": False, "error": str(e), "partial_results": results}


# ===============================================================================
# ALERT TASKS
# ===============================================================================


def check_usage_thresholds(customer_id: str, meter_id: str, subscription_id: str | None = None) -> dict[str, Any]:
    """
    Check if usage thresholds have been breached.

    Called asynchronously after usage events are recorded.
    """
    from .metering_service import UsageAlertService

    logger.debug(f"Checking thresholds for customer {customer_id}, meter {meter_id}")

    try:
        service = UsageAlertService()
        alerts = service.check_thresholds(customer_id, meter_id, subscription_id)

        return {
            "success": True,
            "alerts_created": len(alerts),
            "alert_ids": [str(a.id) for a in alerts],
        }
    except Exception as e:
        logger.exception(f"Error checking thresholds: {e}")
        return {"success": False, "error": str(e)}


def send_usage_alert_notification(alert_id: str) -> dict[str, Any]:
    """
    Send notification for a usage alert.
    """
    from .metering_service import UsageAlertService

    logger.info(f"Sending usage alert notification: {alert_id}")

    try:
        service = UsageAlertService()
        result = service.send_alert_notification(alert_id)

        if result.is_ok():
            return {"success": True, "alert_id": alert_id}
        else:
            return {"success": False, "error": result.error}
    except Exception as e:
        logger.exception(f"Error sending alert notification: {e}")
        return {"success": False, "error": str(e)}


def check_all_usage_thresholds() -> dict[str, Any]:
    """
    Check all active subscriptions for threshold breaches.

    Should be run periodically (e.g., every 15 minutes).
    """
    from .metering_service import UsageAlertService
    from .subscription_models import Subscription

    logger.info("Checking all usage thresholds")

    try:
        service = UsageAlertService()
        total_alerts = 0

        # Get all active subscriptions with metered items
        active_subs = Subscription.objects.filter(status__in=("active", "trialing")).prefetch_related("items")

        for subscription in active_subs:
            for item in subscription.items.all():
                alerts = service.check_thresholds(
                    str(subscription.customer_id), str(item.product_id), str(subscription.id)
                )
                total_alerts += len(alerts)

        return {
            "success": True,
            "alerts_created": total_alerts,
            "subscriptions_checked": active_subs.count(),
        }
    except Exception as e:
        logger.exception(f"Error checking all thresholds: {e}")
        return {"success": False, "error": str(e)}


# ===============================================================================
# STRIPE SYNC TASKS
# ===============================================================================


def sync_aggregation_to_stripe(aggregation_id: str) -> dict[str, Any]:
    """
    Sync a usage aggregation to Stripe.
    """
    from .stripe_metering import StripeUsageSyncService

    logger.info(f"Syncing aggregation {aggregation_id} to Stripe")

    try:
        service = StripeUsageSyncService()
        result = service.sync_aggregation_to_stripe(aggregation_id)

        if result.is_ok():
            return {"success": True, **result.unwrap()}
        else:
            return {"success": False, "error": result.error}
    except Exception as e:
        logger.exception(f"Error syncing to Stripe: {e}")
        return {"success": False, "error": str(e)}


def sync_billing_cycle_to_stripe(billing_cycle_id: str) -> dict[str, Any]:
    """
    Sync all aggregations in a billing cycle to Stripe.
    """
    from .stripe_metering import StripeUsageSyncService

    logger.info(f"Syncing billing cycle {billing_cycle_id} to Stripe")

    try:
        service = StripeUsageSyncService()
        result = service.sync_billing_cycle_to_stripe(billing_cycle_id)

        if result.is_ok():
            return {"success": True, **result.unwrap()}
        else:
            return {"success": False, "error": result.error}
    except Exception as e:
        logger.exception(f"Error syncing billing cycle to Stripe: {e}")
        return {"success": False, "error": str(e)}


def sync_pending_to_stripe() -> dict[str, Any]:
    """
    Sync all rated but unsynced aggregations to Stripe.

    Should be run periodically (e.g., every hour).
    """
    from .metering_models import UsageAggregation
    from .stripe_metering import StripeUsageSyncService

    logger.info("Syncing pending aggregations to Stripe")

    try:
        service = StripeUsageSyncService()

        # Find rated aggregations that haven't been synced
        # Use select_related to avoid N+1 queries
        pending_qs = (
            UsageAggregation.objects.filter(
                status="rated", stripe_synced_at__isnull=True, meter__stripe_meter_event_name__isnull=False
            )
            .exclude(meter__stripe_meter_event_name="")
            .select_related("meter", "customer", "subscription")
        )

        # Get count before processing (single query)
        total_pending = pending_qs.count()

        # Process batch using configured batch size
        batch = list(pending_qs[: billing_config.BATCH_SIZE_STRIPE_SYNC])
        success_count = 0
        error_count = 0

        for agg in batch:
            result = service.sync_aggregation_to_stripe(str(agg.id))
            if result.is_ok():
                success_count += 1
            else:
                error_count += 1

        return {
            "success": True,
            "synced": success_count,
            "errors": error_count,
            "pending_remaining": max(0, total_pending - len(batch)),
        }
    except Exception as e:
        logger.exception(f"Error syncing to Stripe: {e}")
        return {"success": False, "error": str(e)}


# ===============================================================================
# VIRTUALMIN USAGE COLLECTION TASKS
# ===============================================================================


def collect_virtualmin_usage() -> dict[str, Any]:
    """
    Collect usage data from Virtualmin servers.

    Queries all active Virtualmin accounts for:
    - Disk usage
    - Bandwidth usage

    Should be run hourly or more frequently.
    Uses iterator() for memory-efficient processing of large datasets.
    """
    from apps.provisioning.models import VirtualminAccount

    from .metering_models import UsageMeter
    from .metering_service import MeteringService, UsageEventData

    logger.info("Collecting Virtualmin usage data")

    try:
        service = MeteringService()

        # Get meters first (fail fast if not configured)
        disk_meter = UsageMeter.objects.filter(name="disk_usage_gb").first()
        bandwidth_meter = UsageMeter.objects.filter(name="bandwidth_gb").first()

        if not disk_meter or not bandwidth_meter:
            logger.warning("Usage meters not configured for Virtualmin")
            return {"success": False, "error": "Meters not configured"}

        # Get count first for reporting
        total_accounts = VirtualminAccount.objects.filter(status="active").count()

        # Use iterator() for memory-efficient processing
        accounts = (
            VirtualminAccount.objects.filter(status="active")
            .select_related("service", "service__customer")
            .iterator(chunk_size=billing_config.ITERATOR_CHUNK_SIZE)
        )

        events_created = 0
        errors = 0
        accounts_processed = 0

        for account in accounts:
            if not account.service or not account.service.customer:
                continue

            accounts_processed += 1
            customer = account.service.customer

            try:
                # Record disk usage
                disk_gb = Decimal(account.current_disk_usage_gb or 0)
                if disk_gb > 0:
                    result = service.record_event(
                        UsageEventData(
                            meter_name="disk_usage_gb",
                            customer_id=str(customer.id),
                            value=disk_gb,
                            service_id=str(account.service.id),
                            source="virtualmin",
                            properties={
                                "virtualmin_account_id": str(account.id),
                                "domain": account.domain,
                            },
                        )
                    )
                    if result.is_ok():
                        events_created += 1
                    else:
                        errors += 1

                # Record bandwidth usage
                bandwidth_gb = Decimal(account.current_bandwidth_usage_gb or 0)
                if bandwidth_gb > 0:
                    result = service.record_event(
                        UsageEventData(
                            meter_name="bandwidth_gb",
                            customer_id=str(customer.id),
                            value=bandwidth_gb,
                            service_id=str(account.service.id),
                            source="virtualmin",
                            properties={
                                "virtualmin_account_id": str(account.id),
                                "domain": account.domain,
                            },
                        )
                    )
                    if result.is_ok():
                        events_created += 1
                    else:
                        errors += 1

            except Exception as e:
                logger.error(f"Error recording usage for account {account.id}: {e}")
                errors += 1

        # Log collection
        AuditService.log_simple_event(
            event_type="virtualmin_usage_collected",
            user=None,
            content_object=None,
            description=f"Collected {events_created} usage events from Virtualmin",
            actor_type="system",
            metadata={
                "accounts_processed": accounts_processed,
                "total_accounts": total_accounts,
                "events_created": events_created,
                "errors": errors,
            },
        )

        return {
            "success": True,
            "accounts_processed": accounts_processed,
            "events_created": events_created,
            "errors": errors,
        }
    except Exception as e:
        logger.exception(f"Error collecting Virtualmin usage: {e}")
        return {"success": False, "error": str(e)}


def collect_service_usage() -> dict[str, Any]:
    """
    Collect usage data from all active services.

    Aggregates usage from various sources into usage events.
    Should be run hourly.
    Uses iterator() for memory-efficient processing of large datasets.
    """
    from apps.provisioning.models import Service

    from .metering_service import MeteringService, UsageEventData

    try:
        metering_service = MeteringService()

        # Get count first (single query for reporting)
        total_services = Service.objects.filter(status="active").count()
        logger.info("Collecting service usage data from %s active services", total_services)

        # Use iterator() for memory-efficient processing
        services = (
            Service.objects.filter(status="active")
            .select_related("customer", "service_plan")
            .iterator(chunk_size=billing_config.ITERATOR_CHUNK_SIZE)
        )

        events_created = 0
        errors = 0
        services_processed = 0

        for svc in services:
            services_processed += 1
            try:
                customer = svc.customer

                # Record disk usage if tracked
                if svc.disk_usage_mb and svc.disk_usage_mb > 0:
                    disk_gb = Decimal(svc.disk_usage_mb) / 1024
                    result = metering_service.record_event(
                        UsageEventData(
                            meter_name="disk_usage_gb",
                            customer_id=str(customer.id),
                            value=disk_gb,
                            service_id=str(svc.id),
                            source="service_monitor",
                            properties={
                                "service_name": svc.service_name,
                                "domain": svc.domain,
                            },
                        )
                    )
                    if result.is_ok():
                        events_created += 1
                    else:
                        errors += 1

                # Record bandwidth usage if tracked
                if svc.bandwidth_usage_mb and svc.bandwidth_usage_mb > 0:
                    bw_gb = Decimal(svc.bandwidth_usage_mb) / 1024
                    result = metering_service.record_event(
                        UsageEventData(
                            meter_name="bandwidth_gb",
                            customer_id=str(customer.id),
                            value=bw_gb,
                            service_id=str(svc.id),
                            source="service_monitor",
                            properties={
                                "service_name": svc.service_name,
                                "domain": svc.domain,
                            },
                        )
                    )
                    if result.is_ok():
                        events_created += 1
                    else:
                        errors += 1

            except Exception as e:
                logger.error(f"Error recording usage for service {svc.id}: {e}")
                errors += 1

        return {
            "success": True,
            "services_processed": services_processed,
            "events_created": events_created,
            "errors": errors,
        }
    except Exception as e:
        logger.exception(f"Error collecting service usage: {e}")
        return {"success": False, "error": str(e)}


# ===============================================================================
# ASYNC WRAPPER FUNCTIONS
# ===============================================================================


def update_aggregation_for_event_async(event_id: str) -> str:
    """Queue aggregation update task."""
    return async_task("apps.billing.metering_tasks.update_aggregation_for_event", event_id, timeout=TASK_TIMEOUT)


def check_usage_thresholds_async(customer_id: str, meter_id: str, subscription_id: str | None = None) -> str:
    """Queue threshold check task."""
    return async_task(
        "apps.billing.metering_tasks.check_usage_thresholds",
        customer_id,
        meter_id,
        subscription_id,
        timeout=TASK_TIMEOUT,
    )


def send_usage_alert_notification_async(alert_id: str) -> str:
    """Queue alert notification task."""
    return async_task("apps.billing.metering_tasks.send_usage_alert_notification", alert_id, timeout=TASK_TIMEOUT)


def sync_aggregation_to_stripe_async(aggregation_id: str) -> str:
    """Queue Stripe sync task."""
    return async_task("apps.billing.metering_tasks.sync_aggregation_to_stripe", aggregation_id, timeout=TASK_TIMEOUT)


# ===============================================================================
# SCHEDULED TASK REGISTRATION
# ===============================================================================


def register_scheduled_tasks() -> None:
    """
    Register all scheduled tasks with Django-Q.

    Call this from a management command or app ready signal.
    """
    from django_q.models import Schedule

    schedules = [
        {
            "name": "Process Pending Usage Events",
            "func": "apps.billing.metering_tasks.process_pending_usage_events",
            "schedule_type": Schedule.MINUTES,
            "minutes": 5,
        },
        {
            "name": "Run Billing Cycle Workflow",
            "func": "apps.billing.metering_tasks.run_billing_cycle_workflow",
            "schedule_type": Schedule.HOURLY,
        },
        {
            "name": "Check All Usage Thresholds",
            "func": "apps.billing.metering_tasks.check_all_usage_thresholds",
            "schedule_type": Schedule.MINUTES,
            "minutes": 15,
        },
        {
            "name": "Sync Pending to Stripe",
            "func": "apps.billing.metering_tasks.sync_pending_to_stripe",
            "schedule_type": Schedule.HOURLY,
        },
        {
            "name": "Collect Virtualmin Usage",
            "func": "apps.billing.metering_tasks.collect_virtualmin_usage",
            "schedule_type": Schedule.HOURLY,
        },
        {
            "name": "Collect Service Usage",
            "func": "apps.billing.metering_tasks.collect_service_usage",
            "schedule_type": Schedule.HOURLY,
        },
    ]

    for config in schedules:
        Schedule.objects.update_or_create(
            name=config["name"],
            defaults={
                "func": config["func"],
                "schedule_type": config["schedule_type"],
                "minutes": config.get("minutes"),
            },
        )
        logger.info(f"Registered scheduled task: {config['name']}")
