"""
Metering Background Tasks for PRAHO Platform
Django-Q2 tasks for usage-based billing operations.

This module provides scheduled and async tasks for:
- Usage event aggregation
- Billing cycle management
- Invoice generation
- Alert notifications
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
_DEFAULT_TASK_TIMEOUT = 300  # 5 minutes
TASK_TIMEOUT = _DEFAULT_TASK_TIMEOUT


def get_task_timeout() -> int:
    """Get task timeout from SettingsService (runtime)."""
    from apps.settings.services import (  # noqa: PLC0415  # Deferred: avoids circular import
        SettingsService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    return SettingsService.get_integer_setting("billing.metering_task_timeout", _DEFAULT_TASK_TIMEOUT)


TASK_RETRY_DELAY = 60  # 1 minute


# ===============================================================================
# AGGREGATION TASKS
# ===============================================================================


def update_aggregation_for_event(event_id: str) -> dict[str, Any]:
    """
    Process a single usage event into its aggregation.

    Called asynchronously after each event is recorded.
    """
    from .metering_models import (  # noqa: PLC0415  # Deferred: avoids circular import
        UsageEvent,  # Deferred: django-q task  # Deferred: avoids circular import
    )
    from .metering_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        MeteringService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

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
    from .metering_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        AggregationService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

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


def close_expired_billing_cycles() -> dict[str, Any]:
    """
    Close billing cycles that have passed their end date.

    Should be run hourly to ensure timely cycle closure.
    """
    from .usage_invoice_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        UsageBillingService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    logger.info("Closing expired billing cycles")

    try:
        closed, errors = UsageBillingService.close_expired_cycles()

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
    from .metering_models import (  # noqa: PLC0415  # Deferred: avoids circular import
        BillingCycle,  # Deferred: django-q task  # Deferred: avoids circular import
    )
    from .metering_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        RatingEngine,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    logger.info(f"Rating pending aggregations (cycle={billing_cycle_id})")

    try:
        engine = RatingEngine()

        if billing_cycle_id:
            result = engine.rate_billing_cycle(billing_cycle_id)
            return result.unwrap() if result.is_ok() else {"success": False, "error": result.unwrap_err()}

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
    from .usage_invoice_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        UsageBillingService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    logger.info("Generating pending invoices")

    try:
        generated, errors = UsageBillingService.generate_pending_invoices()

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
    Should be run hourly.
    """
    logger.info("Running billing cycle workflow")

    results: dict[str, Any] = {
        "closed_cycles": None,
        "rated": None,
        "invoices": None,
    }

    try:
        # Step 1: Close expired cycles
        results["closed_cycles"] = close_expired_billing_cycles()

        # Step 2: Rate pending aggregations
        results["rated"] = rate_pending_aggregations()

        # Step 3: Generate invoices
        results["invoices"] = generate_pending_invoices()

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
    from .metering_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        UsageAlertService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

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
    from .metering_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        UsageAlertService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    logger.info(f"Sending usage alert notification: {alert_id}")

    try:
        service = UsageAlertService()
        result = service.send_alert_notification(alert_id)

        if result.is_ok():
            return {"success": True, "alert_id": alert_id}
        else:
            return {"success": False, "error": result.unwrap_err()}
    except Exception as e:
        logger.exception(f"Error sending alert notification: {e}")
        return {"success": False, "error": str(e)}


def check_all_usage_thresholds() -> dict[str, Any]:
    """
    Check all active subscriptions for threshold breaches.

    Should be run periodically (e.g., every 15 minutes).
    """
    from .metering_models import (  # noqa: PLC0415  # Deferred: avoids circular import
        UsageAggregation,  # Deferred: django-q task  # Deferred: avoids circular import
    )
    from .metering_service import (  # noqa: PLC0415  # Deferred: avoids circular import
        UsageAlertService,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    logger.info("Checking all usage thresholds")

    try:
        service = UsageAlertService()
        total_alerts = 0

        scopes = list(
            UsageAggregation.objects.filter(
                subscription__status__in=("active", "trialing"),
                status__in=("accumulating", "pending_rating"),
            )
            .values_list("customer_id", "meter_id", "subscription_id")
            .distinct()
        )
        subscription_ids: set[object] = set()

        for customer_id, meter_id, subscription_id in scopes:
            alerts = service.check_thresholds(str(customer_id), str(meter_id), str(subscription_id))
            total_alerts += len(alerts)
            subscription_ids.add(subscription_id)

        return {
            "success": True,
            "alerts_created": total_alerts,
            "subscriptions_checked": len(subscription_ids),
        }
    except Exception as e:
        logger.exception(f"Error checking all thresholds: {e}")
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
    from apps.provisioning.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        VirtualminAccount,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    from .metering_models import (  # noqa: PLC0415  # Deferred: avoids circular import
        UsageMeter,  # Deferred: django-q task  # Deferred: avoids circular import
    )
    from .metering_service import (  # Deferred: django-q task  # noqa: PLC0415  # Deferred: avoids circular import
        MeteringService,
        UsageEventData,
    )

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
                disk_gb = Decimal(account.current_disk_usage_gb or 0)  # type: ignore[attr-defined]
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
                bandwidth_gb = Decimal(account.current_bandwidth_usage_gb or 0)  # type: ignore[attr-defined]
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
    from apps.provisioning.models import (  # noqa: PLC0415  # Deferred: avoids circular import
        Service,  # Deferred: django-q task  # Deferred: avoids circular import
    )

    from .metering_service import (  # Deferred: django-q task  # noqa: PLC0415  # Deferred: avoids circular import
        MeteringService,
        UsageEventData,
    )

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
    return str(async_task("apps.billing.metering_tasks.update_aggregation_for_event", event_id, timeout=TASK_TIMEOUT))


def check_usage_thresholds_async(customer_id: str, meter_id: str, subscription_id: str | None = None) -> str:
    """Queue threshold check task."""
    return str(
        async_task(
            "apps.billing.metering_tasks.check_usage_thresholds",
            customer_id,
            meter_id,
            subscription_id,
            timeout=TASK_TIMEOUT,
        )
    )


def send_usage_alert_notification_async(alert_id: str) -> str:
    """Queue alert notification task."""
    return str(async_task("apps.billing.metering_tasks.send_usage_alert_notification", alert_id, timeout=TASK_TIMEOUT))


# ===============================================================================
# SCHEDULED TASK REGISTRATION
# ===============================================================================


def register_scheduled_tasks() -> None:
    """
    Register all scheduled tasks with Django-Q.

    Call this from a management command or app ready signal.
    """
    from django_q.models import Schedule  # Deferred: django-q task  # noqa: PLC0415  # Deferred: avoids circular import

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
