"""
Stripe Metering Integration for PRAHO Platform
Handles synchronization with Stripe Billing Meters.

This module provides:
- Stripe Meter creation and management
- Usage event reporting to Stripe
- Subscription metered billing sync
- Webhook handling for meter events

Note: Stripe deprecated legacy usage records APIs in version 2025-03-31.
This implementation uses the new Meters API.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)


@dataclass
class Result:
    """Result pattern for operations"""
    _value: Any
    _error: str | None

    @classmethod
    def ok(cls, value: Any) -> "Result":
        return cls(_value=value, _error=None)

    @classmethod
    def err(cls, error: str) -> "Result":
        return cls(_value=None, _error=error)

    def is_ok(self) -> bool:
        return self._error is None

    def is_err(self) -> bool:
        return self._error is not None

    def unwrap(self) -> Any:
        if self._error:
            raise ValueError(f"Called unwrap on error: {self._error}")
        return self._value

    @property
    def error(self) -> str | None:
        return self._error


def get_stripe():
    """Get configured Stripe module"""
    try:
        import stripe
        stripe.api_key = getattr(settings, "STRIPE_SECRET_KEY", None)
        return stripe
    except ImportError:
        logger.error("Stripe library not installed")
        return None


class StripeMeterService:
    """
    Service for managing Stripe Billing Meters.

    Stripe Meters are the new way to track and bill usage.
    Each meter aggregates events and can be linked to prices.
    """

    def __init__(self):
        self.stripe = get_stripe()

    def create_meter(
        self,
        display_name: str,
        event_name: str,
        aggregation_formula: str = "sum",
        event_time_window: str = "day"
    ) -> Result:
        """
        Create a new Stripe Meter.

        Args:
            display_name: Human-readable name
            event_name: Unique event name for sending usage
            aggregation_formula: How to aggregate ('sum' or 'count')
            event_time_window: Aggregation window ('hour' or 'day')
        """
        if not self.stripe:
            return Result.err("Stripe not configured")

        try:
            meter = self.stripe.billing.Meter.create(
                display_name=display_name,
                event_name=event_name,
                default_aggregation={"formula": aggregation_formula},
                customer_mapping={
                    "event_payload_key": "stripe_customer_id",
                    "type": "by_id"
                },
                value_settings={
                    "event_payload_key": "value"
                },
            )

            logger.info(f"Created Stripe Meter: {meter.id} ({event_name})")

            return Result.ok({
                "meter_id": meter.id,
                "event_name": event_name,
                "display_name": display_name,
            })

        except self.stripe.error.StripeError as e:
            logger.error(f"Stripe error creating meter: {e}")
            return Result.err(str(e))
        except Exception as e:
            logger.exception(f"Error creating Stripe Meter: {e}")
            return Result.err(str(e))

    def get_meter(self, meter_id: str) -> Result:
        """Retrieve a Stripe Meter by ID"""
        if not self.stripe:
            return Result.err("Stripe not configured")

        try:
            meter = self.stripe.billing.Meter.retrieve(meter_id)
            return Result.ok(meter)
        except self.stripe.error.StripeError as e:
            return Result.err(str(e))

    def list_meters(self, limit: int = 100) -> Result:
        """List all Stripe Meters"""
        if not self.stripe:
            return Result.err("Stripe not configured")

        try:
            meters = self.stripe.billing.Meter.list(limit=limit)
            return Result.ok(list(meters.data))
        except self.stripe.error.StripeError as e:
            return Result.err(str(e))

    def deactivate_meter(self, meter_id: str) -> Result:
        """Deactivate a Stripe Meter"""
        if not self.stripe:
            return Result.err("Stripe not configured")

        try:
            meter = self.stripe.billing.Meter.modify(
                meter_id,
                status="inactive"
            )
            logger.info(f"Deactivated Stripe Meter: {meter_id}")
            return Result.ok(meter)
        except self.stripe.error.StripeError as e:
            return Result.err(str(e))


class StripeMeterEventService:
    """
    Service for reporting usage events to Stripe Meters.

    Meter events are the building blocks of usage-based billing.
    Each event represents a unit of usage to be billed.
    """

    def __init__(self):
        self.stripe = get_stripe()

    def report_usage(
        self,
        event_name: str,
        stripe_customer_id: str,
        value: Decimal | int | float,
        timestamp: datetime | None = None,
        identifier: str | None = None
    ) -> Result:
        """
        Report a usage event to Stripe.

        Args:
            event_name: The event name configured on the Stripe Meter
            stripe_customer_id: The Stripe Customer ID
            value: The usage value to report
            timestamp: When the usage occurred (defaults to now)
            identifier: Unique identifier for idempotency
        """
        if not self.stripe:
            return Result.err("Stripe not configured")

        if not stripe_customer_id:
            return Result.err("Stripe customer ID is required")

        try:
            # Prepare event payload
            payload = {
                "stripe_customer_id": stripe_customer_id,
                "value": str(value),
            }

            # Prepare event params
            event_params = {
                "event_name": event_name,
                "payload": payload,
            }

            if timestamp:
                # Stripe expects Unix timestamp
                event_params["timestamp"] = int(timestamp.timestamp())

            if identifier:
                event_params["identifier"] = identifier

            # Send meter event
            event = self.stripe.billing.MeterEvent.create(**event_params)

            logger.info(
                f"Reported usage to Stripe: {event_name} = {value} "
                f"for customer {stripe_customer_id}"
            )

            return Result.ok({
                "event_id": event.identifier,
                "event_name": event_name,
                "value": str(value),
                "timestamp": timestamp.isoformat() if timestamp else None,
            })

        except self.stripe.error.StripeError as e:
            logger.error(f"Stripe error reporting usage: {e}")
            return Result.err(str(e))
        except Exception as e:
            logger.exception(f"Error reporting usage to Stripe: {e}")
            return Result.err(str(e))

    def report_bulk_usage(
        self,
        events: list[dict[str, Any]]
    ) -> tuple[int, int, list[str]]:
        """
        Report multiple usage events to Stripe.

        Each event dict should have:
        - event_name: str
        - stripe_customer_id: str
        - value: Decimal/int/float
        - timestamp: datetime (optional)
        - identifier: str (optional)

        Returns: (success_count, error_count, error_messages)
        """
        success_count = 0
        error_count = 0
        errors = []

        for event_data in events:
            result = self.report_usage(
                event_name=event_data.get("event_name", ""),
                stripe_customer_id=event_data.get("stripe_customer_id", ""),
                value=event_data.get("value", 0),
                timestamp=event_data.get("timestamp"),
                identifier=event_data.get("identifier"),
            )

            if result.is_ok():
                success_count += 1
            else:
                error_count += 1
                errors.append(result.error or "Unknown error")

        return success_count, error_count, errors


class StripeSubscriptionMeterService:
    """
    Service for managing metered subscriptions in Stripe.

    Links Stripe subscriptions to meters for usage-based billing.
    """

    def __init__(self):
        self.stripe = get_stripe()

    def create_metered_subscription(
        self,
        customer_id: str,
        price_id: str,
        meter_id: str | None = None,
        payment_behavior: str = "default_incomplete",
        trial_days: int | None = None
    ) -> Result:
        """
        Create a subscription with metered billing.

        The price must be configured for metered billing in Stripe.
        """
        if not self.stripe:
            return Result.err("Stripe not configured")

        try:
            sub_params: dict[str, Any] = {
                "customer": customer_id,
                "items": [{"price": price_id}],
                "payment_behavior": payment_behavior,
            }

            if trial_days:
                from datetime import timedelta
                trial_end = timezone.now() + timedelta(days=trial_days)
                sub_params["trial_end"] = int(trial_end.timestamp())

            subscription = self.stripe.Subscription.create(**sub_params)

            logger.info(
                f"Created metered subscription: {subscription.id} "
                f"for customer {customer_id}"
            )

            return Result.ok({
                "subscription_id": subscription.id,
                "status": subscription.status,
                "current_period_start": subscription.current_period_start,
                "current_period_end": subscription.current_period_end,
            })

        except self.stripe.error.StripeError as e:
            logger.error(f"Stripe error creating subscription: {e}")
            return Result.err(str(e))

    def add_metered_item(
        self,
        subscription_id: str,
        price_id: str
    ) -> Result:
        """Add a metered item to an existing subscription"""
        if not self.stripe:
            return Result.err("Stripe not configured")

        try:
            item = self.stripe.SubscriptionItem.create(
                subscription=subscription_id,
                price=price_id,
            )

            logger.info(
                f"Added metered item {item.id} to subscription {subscription_id}"
            )

            return Result.ok({
                "subscription_item_id": item.id,
                "price_id": price_id,
            })

        except self.stripe.error.StripeError as e:
            return Result.err(str(e))

    def get_usage_summary(
        self,
        subscription_item_id: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None
    ) -> Result:
        """
        Get usage summary for a metered subscription item.
        """
        if not self.stripe:
            return Result.err("Stripe not configured")

        try:
            # Build params
            params: dict[str, Any] = {"id": subscription_item_id}

            if start_time:
                params["starting_after"] = int(start_time.timestamp())
            if end_time:
                params["ending_before"] = int(end_time.timestamp())

            # Get usage record summaries
            summaries = self.stripe.SubscriptionItem.list_usage_record_summaries(
                **params
            )

            return Result.ok({
                "subscription_item_id": subscription_item_id,
                "summaries": [
                    {
                        "id": s.id,
                        "total_usage": s.total_usage,
                        "period_start": s.period.start,
                        "period_end": s.period.end,
                    }
                    for s in summaries.data
                ],
            })

        except self.stripe.error.StripeError as e:
            return Result.err(str(e))


class StripeUsageSyncService:
    """
    Service for synchronizing local usage with Stripe.

    Handles the flow of:
    1. Local usage events → Stripe Meter Events
    2. Local aggregations → Stripe usage records
    3. Stripe invoices → Local billing records
    """

    def __init__(self):
        self.stripe = get_stripe()
        self.event_service = StripeMeterEventService()

    def sync_aggregation_to_stripe(self, aggregation_id: str) -> Result:
        """
        Sync a usage aggregation to Stripe.

        Reports the aggregated usage as a meter event to Stripe.
        """
        from .metering_models import UsageAggregation

        try:
            aggregation = UsageAggregation.objects.select_related(
                "meter", "customer", "subscription"
            ).get(id=aggregation_id)
        except UsageAggregation.DoesNotExist:
            return Result.err(f"Aggregation not found: {aggregation_id}")

        # Get Stripe IDs
        meter = aggregation.meter
        if not meter.stripe_meter_event_name:
            return Result.err(f"Meter {meter.name} has no Stripe event name configured")

        subscription = aggregation.subscription
        stripe_customer_id = subscription.stripe_customer_id if subscription else None

        if not stripe_customer_id:
            # Try to get from customer
            customer = aggregation.customer
            stripe_customer_id = getattr(customer, "stripe_customer_id", None)

        if not stripe_customer_id:
            return Result.err("No Stripe customer ID found")

        # Report usage to Stripe
        result = self.event_service.report_usage(
            event_name=meter.stripe_meter_event_name,
            stripe_customer_id=stripe_customer_id,
            value=aggregation.billable_value,
            timestamp=aggregation.period_end,
            identifier=str(aggregation.id),
        )

        if result.is_ok():
            # Update aggregation with Stripe sync info
            with transaction.atomic():
                aggregation.stripe_synced_at = timezone.now()
                aggregation.stripe_usage_record_id = result.unwrap().get("event_id", "")
                aggregation.save(update_fields=[
                    "stripe_synced_at", "stripe_usage_record_id"
                ])

            logger.info(f"Synced aggregation {aggregation_id} to Stripe")

        return result

    def sync_billing_cycle_to_stripe(self, billing_cycle_id: str) -> Result:
        """
        Sync all aggregations in a billing cycle to Stripe.
        """
        from .metering_models import BillingCycle, UsageAggregation

        try:
            billing_cycle = BillingCycle.objects.get(id=billing_cycle_id)
        except BillingCycle.DoesNotExist:
            return Result.err(f"Billing cycle not found: {billing_cycle_id}")

        aggregations = UsageAggregation.objects.filter(
            billing_cycle=billing_cycle,
            status="rated",
            stripe_synced_at__isnull=True
        ).select_related("meter")

        success_count = 0
        error_count = 0
        errors = []

        for agg in aggregations:
            # Only sync if meter has Stripe integration
            if not agg.meter.stripe_meter_event_name:
                continue

            result = self.sync_aggregation_to_stripe(str(agg.id))
            if result.is_ok():
                success_count += 1
            else:
                error_count += 1
                errors.append(f"{agg.meter.name}: {result.error}")

        logger.info(
            f"Synced billing cycle {billing_cycle_id}: "
            f"{success_count} succeeded, {error_count} failed"
        )

        return Result.ok({
            "billing_cycle_id": billing_cycle_id,
            "success_count": success_count,
            "error_count": error_count,
            "errors": errors,
        })


class StripeMeterWebhookHandler:
    """
    Handler for Stripe Meter-related webhooks.

    Processes webhook events related to usage billing.
    """

    def __init__(self):
        self.stripe = get_stripe()

    def handle_event(self, event: Any) -> Result:
        """
        Handle a Stripe webhook event.

        Supported event types:
        - billing.meter.created
        - billing.meter.updated
        - billing.meter.no_meter_found
        - billing.meter.error_report
        - invoice.created (for metered invoices)
        - invoice.finalized
        """
        event_type = event.type

        handlers = {
            "billing.meter.created": self._handle_meter_created,
            "billing.meter.updated": self._handle_meter_updated,
            "billing.meter.no_meter_found": self._handle_no_meter_found,
            "billing.meter.error_report_triggered": self._handle_meter_error,
            "invoice.created": self._handle_invoice_created,
            "invoice.finalized": self._handle_invoice_finalized,
        }

        handler = handlers.get(event_type)
        if handler:
            return handler(event)

        logger.debug(f"Unhandled meter event type: {event_type}")
        return Result.ok({"handled": False, "event_type": event_type})

    def _handle_meter_created(self, event: Any) -> Result:
        """Handle meter creation event"""
        meter_data = event.data.object
        logger.info(f"Stripe Meter created: {meter_data.id}")

        # Could auto-create local UsageMeter here if needed
        return Result.ok({"handled": True, "meter_id": meter_data.id})

    def _handle_meter_updated(self, event: Any) -> Result:
        """Handle meter update event"""
        meter_data = event.data.object
        logger.info(f"Stripe Meter updated: {meter_data.id}")

        # Update local meter if it exists
        from .metering_models import UsageMeter
        try:
            local_meter = UsageMeter.objects.get(stripe_meter_id=meter_data.id)
            local_meter.stripe_meter_event_name = meter_data.event_name
            local_meter.save(update_fields=["stripe_meter_event_name"])
        except UsageMeter.DoesNotExist:
            pass

        return Result.ok({"handled": True, "meter_id": meter_data.id})

    def _handle_no_meter_found(self, event: Any) -> Result:
        """Handle event when no meter found for usage report"""
        logger.warning(f"No Stripe Meter found for event: {event.data}")
        return Result.ok({"handled": True, "warning": "No meter found"})

    def _handle_meter_error(self, event: Any) -> Result:
        """Handle meter error report"""
        logger.error(f"Stripe Meter error: {event.data}")

        # Could trigger alert to ops team here
        return Result.ok({"handled": True, "error": True})

    def _handle_invoice_created(self, event: Any) -> Result:
        """Handle metered invoice creation"""
        invoice_data = event.data.object
        logger.info(f"Stripe invoice created: {invoice_data.id}")

        # Check if this has metered line items
        has_metered = any(
            line.get("price", {}).get("recurring", {}).get("usage_type") == "metered"
            for line in invoice_data.get("lines", {}).get("data", [])
        )

        if has_metered:
            logger.info(f"Invoice {invoice_data.id} has metered usage")
            # Could link to local billing cycle here

        return Result.ok({
            "handled": True,
            "invoice_id": invoice_data.id,
            "has_metered_usage": has_metered,
        })

    def _handle_invoice_finalized(self, event: Any) -> Result:
        """Handle finalized metered invoice"""
        invoice_data = event.data.object
        logger.info(f"Stripe invoice finalized: {invoice_data.id}")

        # Update local billing cycle if linked
        from .metering_models import BillingCycle

        # Try to find billing cycle by Stripe subscription
        subscription_id = invoice_data.get("subscription")
        if subscription_id:
            try:
                from .metering_models import Subscription
                subscription = Subscription.objects.get(
                    stripe_subscription_id=subscription_id
                )
                billing_cycle = subscription.billing_cycles.filter(
                    status="invoiced"
                ).order_by("-period_start").first()

                if billing_cycle:
                    billing_cycle.meta["stripe_invoice_id"] = invoice_data.id
                    billing_cycle.meta["stripe_invoice_total"] = invoice_data.total
                    billing_cycle.finalized_at = timezone.now()
                    billing_cycle.status = "finalized"
                    billing_cycle.save()

            except Subscription.DoesNotExist:
                pass

        return Result.ok({
            "handled": True,
            "invoice_id": invoice_data.id,
        })
