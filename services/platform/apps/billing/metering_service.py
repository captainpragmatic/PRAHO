"""
Metering Service for PRAHO Platform
Handles usage event processing, aggregation, and rating for billing.

This service provides:
- Event ingestion with idempotency
- Usage aggregation by billing period
- Rating engine for charge calculation
- Stripe Meter integration
- Alert threshold checking
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, TypeVar

from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from apps.audit.services import AuditService

from . import config as billing_config

logger = logging.getLogger(__name__)

# Type variables for Result pattern
T = TypeVar("T")
E = TypeVar("E")


def _parse_decimal(value: Any) -> Decimal:
    if value is None or value == "":
        return Decimal("0")
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return Decimal("0")


def _get_subscription_item_for_meter(subscription: Any, meter: Any) -> Any | None:
    if not subscription or not meter:
        return None

    from .subscription_models import SubscriptionItem

    items = SubscriptionItem.objects.filter(subscription=subscription, product__is_active=True)
    if not items.exists():
        return None

    active_items = items.filter(meta__is_active=True)
    if active_items.exists():
        items = active_items

    meter_id = str(meter.id)
    candidates = items.filter(
        Q(meta__meter_id=meter_id)
        | Q(meta__meter_name=meter.name)
        | Q(product__meta__meter_id=meter_id)
        | Q(product__meta__meter_name=meter.name)
        | Q(product__slug=meter.name)
        | Q(product__name=meter.display_name)
    )

    return candidates.first() or items.first()


def _get_allowance_from_subscription_item(sub_item: Any | None) -> Decimal:
    if not sub_item:
        return Decimal("0")

    meta = sub_item.meta or {}
    for key in ("included_quantity", "included_allowance", "allowance", "included"):
        if key in meta:
            return _parse_decimal(meta.get(key))

    product_meta = getattr(sub_item.product, "meta", None) or {}
    for key in ("included_quantity", "included_allowance", "allowance", "included"):
        if key in product_meta:
            return _parse_decimal(product_meta.get(key))

    return Decimal("0")


def _get_allowance_from_service_plan(meter: Any, service_plan: Any | None) -> Decimal:
    if not service_plan or not meter:
        return Decimal("0")

    category = meter.category
    if category == "storage" and service_plan.disk_space_gb:
        return _parse_decimal(service_plan.disk_space_gb)
    if category == "bandwidth" and service_plan.bandwidth_gb:
        return _parse_decimal(service_plan.bandwidth_gb)
    if category == "email" and service_plan.email_accounts:
        return _parse_decimal(service_plan.email_accounts)
    if category == "database" and service_plan.databases:
        return _parse_decimal(service_plan.databases)
    if category == "domain" and service_plan.domains:
        return _parse_decimal(service_plan.domains)

    return Decimal("0")


@dataclass
class Result:
    """Result pattern for operations that can fail"""

    _value: Any
    _error: str | None

    @classmethod
    def ok(cls, value: Any) -> Result:
        return cls(_value=value, _error=None)

    @classmethod
    def err(cls, error: str) -> Result:
        return cls(_value=None, _error=error)

    def is_ok(self) -> bool:
        return self._error is None

    def is_err(self) -> bool:
        return self._error is not None

    def unwrap(self) -> Any:
        if self._error:
            raise ValueError(f"Called unwrap on error: {self._error}")
        return self._value

    def unwrap_or(self, default: Any) -> Any:
        return self._value if self._error is None else default

    @property
    def error(self) -> str | None:
        return self._error

    @property
    def value(self) -> Any:
        return self._value


@dataclass
class UsageEventData:
    """Data for creating a usage event"""

    meter_name: str
    customer_id: str
    value: Decimal
    timestamp: datetime | None = None
    subscription_id: str | None = None
    service_id: str | None = None
    idempotency_key: str | None = None
    properties: dict[str, Any] | None = None
    source: str = ""
    source_ip: str | None = None


class MeteringService:
    """
    Service for processing usage events and managing metering.

    Responsible for:
    - Ingesting usage events with idempotency
    - Real-time aggregation updates
    - Threshold checking and alerting
    - Stripe Meter event synchronization
    """

    def record_event(self, event_data: UsageEventData) -> Result:
        """
        Record a usage event with idempotency protection.

        Returns Result containing the UsageEvent if successful.
        """
        from .metering_models import UsageEvent, UsageMeter

        try:
            # Get the meter
            try:
                meter = UsageMeter.objects.get(name=event_data.meter_name)
            except UsageMeter.DoesNotExist:
                return Result.err(f"Meter not found: {event_data.meter_name}")

            if not meter.is_active:
                return Result.err(f"Meter is inactive: {event_data.meter_name}")

            # Get customer
            from apps.customers.models import Customer

            try:
                customer = Customer.objects.get(id=event_data.customer_id)
            except Customer.DoesNotExist:
                return Result.err(f"Customer not found: {event_data.customer_id}")

            # Validate timestamp
            timestamp = event_data.timestamp or timezone.now()
            grace_period = timedelta(hours=meter.event_grace_period_hours)
            min_timestamp = timezone.now() - grace_period
            max_timestamp = timezone.now() + timedelta(minutes=billing_config.get_future_event_drift_minutes())

            if timestamp < min_timestamp:
                return Result.err(
                    f"Event timestamp too old: {timestamp}. " f"Grace period is {meter.event_grace_period_hours} hours."
                )
            if timestamp > max_timestamp:
                return Result.err(f"Event timestamp in future: {timestamp}")

            # Get optional relationships
            subscription = None
            service = None

            if event_data.subscription_id:
                from .subscription_models import Subscription

                try:
                    subscription = Subscription.objects.get(id=event_data.subscription_id)
                except Subscription.DoesNotExist:
                    logger.warning(f"Subscription not found: {event_data.subscription_id}")

            if event_data.service_id:
                from apps.provisioning.models import Service

                try:
                    service = Service.objects.get(id=event_data.service_id)
                except Service.DoesNotExist:
                    logger.warning(f"Service not found: {event_data.service_id}")

            # Create the event with idempotency using database constraint
            # This is race-condition-safe: we try to insert and catch duplicate
            from django.db import IntegrityError

            try:
                with transaction.atomic():
                    event = UsageEvent.objects.create(
                        meter=meter,
                        customer=customer,
                        subscription=subscription,
                        service=service,
                        value=event_data.value,
                        timestamp=timestamp,
                        idempotency_key=event_data.idempotency_key or "",
                        properties=event_data.properties or {},
                        source=event_data.source,
                        source_ip=event_data.source_ip,
                    )
            except IntegrityError:
                # Duplicate idempotency key - return existing event
                if event_data.idempotency_key:
                    existing = UsageEvent.objects.filter(
                        meter=meter, customer=customer, idempotency_key=event_data.idempotency_key
                    ).first()
                    if existing:
                        logger.info(f"Duplicate event ignored (idempotency): {event_data.idempotency_key}")
                        return Result.ok(existing)
                raise  # Re-raise if not an idempotency issue

            # Log the event
            logger.info(f"Usage event recorded: {meter.name} = {event_data.value} " f"for customer {customer.id}")

            # Trigger async aggregation update
            self._schedule_aggregation_update(event)

            # Check thresholds
            self._check_thresholds_async(customer, meter, subscription)

            return Result.ok(event)

        except Exception as e:
            logger.exception(f"Error recording usage event: {e}")
            return Result.err(str(e))

    def record_bulk_events(
        self, events: list[UsageEventData], stop_on_error: bool = False
    ) -> tuple[list[Result], int, int]:
        """
        Record multiple usage events efficiently.

        Returns (results, success_count, error_count)
        """
        results = []
        success_count = 0
        error_count = 0

        for event_data in events:
            result = self.record_event(event_data)
            results.append(result)

            if result.is_ok():
                success_count += 1
            else:
                error_count += 1
                if stop_on_error:
                    break

        logger.info(f"Bulk event recording: {success_count} succeeded, {error_count} failed")

        return results, success_count, error_count

    def _schedule_aggregation_update(self, event: Any) -> None:
        """Schedule async update of aggregation for this event"""
        try:
            from django_q.tasks import async_task

            async_task("apps.billing.metering_tasks.update_aggregation_for_event", str(event.id), timeout=60)
        except Exception as e:
            logger.warning(f"Could not schedule aggregation update: {e}")
            # Fall back to sync update
            self._update_aggregation_sync(event)

    def _update_aggregation_sync(self, event: Any) -> None:
        """Synchronously update aggregation for an event"""
        try:
            from .metering_models import UsageAggregation
            from .subscription_models import Subscription

            # Find the billing cycle for this event
            subscription = event.subscription
            if not subscription:
                # Try to find active subscription for customer
                subscription = Subscription.objects.filter(
                    customer=event.customer, status__in=["active", "trialing"]
                ).first()

            if not subscription:
                logger.warning(
                    f"No subscription found for customer {event.customer.id}, "
                    "event will be aggregated when subscription is created"
                )
                return

            # Get or create billing cycle
            billing_cycle = subscription.get_current_billing_cycle()
            if not billing_cycle:
                logger.warning(f"No billing cycle found for subscription {subscription.id}")
                return

            # Get or create aggregation
            aggregation, _created = UsageAggregation.objects.get_or_create(
                meter=event.meter,
                customer=event.customer,
                billing_cycle=billing_cycle,
                defaults={
                    "subscription": subscription,
                    "period_start": billing_cycle.period_start,
                    "period_end": billing_cycle.period_end,
                    "status": "accumulating",
                },
            )

            # Update aggregation
            self._apply_event_to_aggregation(event, aggregation)

            # Mark event as processed
            event.is_processed = True
            event.processed_at = timezone.now()
            event.aggregation = aggregation
            event.save(update_fields=["is_processed", "processed_at", "aggregation"])

        except Exception as e:
            logger.exception(f"Error updating aggregation: {e}")

    def _apply_event_to_aggregation(self, event: Any, aggregation: Any) -> None:
        """Apply an event to an aggregation based on meter type"""
        with transaction.atomic():
            meter = event.meter

            if meter.aggregation_type == "sum":
                aggregation.total_value = F("total_value") + event.value
            elif meter.aggregation_type == "count":
                aggregation.total_value = F("total_value") + 1
            elif meter.aggregation_type == "max":
                if aggregation.max_value is None or event.value > aggregation.max_value:
                    aggregation.max_value = event.value
                    aggregation.total_value = event.value
            elif meter.aggregation_type == "last":
                if aggregation.last_value_at is None or event.timestamp > aggregation.last_value_at:
                    aggregation.last_value = event.value
                    aggregation.last_value_at = event.timestamp
                    aggregation.total_value = event.value
            elif meter.aggregation_type == "unique":
                unique_values = set(aggregation.unique_values or [])
                unique_values.add(str(event.value))
                aggregation.unique_values = list(unique_values)
                aggregation.total_value = Decimal(len(unique_values))

            aggregation.event_count = F("event_count") + 1
            aggregation.save()
            aggregation.refresh_from_db()

    def _check_thresholds_async(self, customer: Any, meter: Any, subscription: Any | None) -> None:
        """Schedule async threshold check"""
        try:
            from django_q.tasks import async_task

            async_task(
                "apps.billing.metering_tasks.check_usage_thresholds",
                str(customer.id),
                str(meter.id),
                str(subscription.id) if subscription else None,
                timeout=30,
            )
        except Exception as e:
            logger.warning(f"Could not schedule threshold check: {e}")


class AggregationService:
    """
    Service for managing usage aggregations.

    Handles:
    - Processing pending events into aggregations
    - Closing billing cycles
    - Preparing aggregations for invoicing
    """

    def process_pending_events(
        self, meter_id: str | None = None, customer_id: str | None = None, limit: int = 1000
    ) -> tuple[int, int]:
        """
        Process pending usage events into aggregations.

        Returns (processed_count, error_count)
        """
        from .metering_models import UsageEvent

        query = UsageEvent.objects.filter(is_processed=False)

        if meter_id:
            query = query.filter(meter_id=meter_id)
        if customer_id:
            query = query.filter(customer_id=customer_id)

        events = query.select_related("meter", "customer", "subscription")[:limit]

        metering_service = MeteringService()
        processed = 0
        errors = 0

        for event in events:
            try:
                metering_service._update_aggregation_sync(event)
                processed += 1
            except Exception as e:
                logger.error(f"Error processing event {event.id}: {e}")
                errors += 1

        logger.info(f"Processed {processed} events, {errors} errors")
        return processed, errors

    def close_billing_cycle(self, billing_cycle_id: str) -> Result:
        """
        Close a billing cycle and prepare aggregations for rating.
        """
        from .metering_models import BillingCycle, UsageAggregation

        try:
            billing_cycle = BillingCycle.objects.get(id=billing_cycle_id)
        except BillingCycle.DoesNotExist:
            return Result.err(f"Billing cycle not found: {billing_cycle_id}")

        if billing_cycle.status not in ("active", "upcoming"):
            return Result.err(f"Billing cycle cannot be closed: status is {billing_cycle.status}")

        with transaction.atomic():
            # Process any remaining pending events
            self.process_pending_events(customer_id=str(billing_cycle.subscription.customer_id))

            # Update all aggregations to pending_rating
            UsageAggregation.objects.filter(billing_cycle=billing_cycle, status="accumulating").update(
                status="pending_rating"
            )

            # Close the billing cycle
            billing_cycle.close()

            # Log the closure
            AuditService.log_simple_event(
                event_type="billing_cycle_closed",
                user=None,
                content_object=billing_cycle,
                description=f"Billing cycle closed for {billing_cycle.subscription}",
                actor_type="system",
                metadata={
                    "billing_cycle_id": str(billing_cycle.id),
                    "subscription_id": str(billing_cycle.subscription_id),
                    "period_start": billing_cycle.period_start.isoformat(),
                    "period_end": billing_cycle.period_end.isoformat(),
                },
            )

        return Result.ok(billing_cycle)

    def get_customer_usage_summary(
        self, customer_id: str, period_start: datetime | None = None, period_end: datetime | None = None
    ) -> dict[str, Any]:
        """
        Get a summary of customer usage for a period.
        """
        from .metering_models import UsageAggregation

        query = UsageAggregation.objects.filter(customer_id=customer_id)

        if period_start:
            query = query.filter(period_start__gte=period_start)
        if period_end:
            query = query.filter(period_end__lte=period_end)

        aggregations = query.select_related("meter")

        summary = {
            "customer_id": customer_id,
            "period_start": period_start,
            "period_end": period_end,
            "meters": {},
            "total_charge_cents": 0,
        }

        for agg in aggregations:
            meter_name = agg.meter.name
            summary["meters"][meter_name] = {
                "display_name": agg.meter.display_name,
                "total_value": float(agg.total_value),
                "billable_value": float(agg.billable_value),
                "included_allowance": float(agg.included_allowance),
                "overage_value": float(agg.overage_value),
                "charge_cents": agg.charge_cents,
                "unit": agg.meter.unit_display or agg.meter.unit,
                "status": agg.status,
            }
            summary["total_charge_cents"] += agg.charge_cents

        return summary


class RatingEngine:
    """
    Rating engine for calculating charges from usage.

    Supports:
    - Per-unit pricing
    - Volume pricing (all units at volume-based rate)
    - Graduated/tiered pricing (different rates per bracket)
    - Package pricing (fixed price for package)
    - Minimum charges
    - Overage calculation
    """

    def rate_aggregation(self, aggregation_id: str) -> Result:
        """
        Calculate charges for a usage aggregation.
        """
        from .metering_models import PricingTier, UsageAggregation

        try:
            aggregation = UsageAggregation.objects.select_related("meter", "subscription", "billing_cycle").get(
                id=aggregation_id
            )
        except UsageAggregation.DoesNotExist:
            return Result.err(f"Aggregation not found: {aggregation_id}")

        if aggregation.status not in ("accumulating", "pending_rating"):
            return Result.err(f"Aggregation already rated or finalized: {aggregation.status}")

        meter = aggregation.meter
        subscription = aggregation.subscription

        # Get included allowance from subscription item
        included_quantity = Decimal("0")
        pricing_tier = None
        unit_price_cents = None

        if subscription:
            sub_item = _get_subscription_item_for_meter(subscription, meter)

            if sub_item:
                included_quantity = _get_allowance_from_subscription_item(sub_item)
                pricing_tier = None
                unit_price_cents = sub_item.effective_price_cents

            service_plan = getattr(subscription.product, "default_service_plan", None)
            if included_quantity <= 0:
                included_quantity = _get_allowance_from_service_plan(meter, service_plan)

        # Calculate billable value after rounding
        billable_value = self._apply_rounding(aggregation.total_value, meter.rounding_mode, meter.rounding_increment)

        # Calculate overage
        overage_value = max(Decimal("0"), billable_value - included_quantity)

        # Calculate charge
        charge_cents = 0

        if overage_value > 0 and meter.is_billable:
            if pricing_tier:
                charge_cents = self._calculate_tiered_charge(overage_value, pricing_tier)
            elif unit_price_cents is not None:
                charge_cents = int(overage_value * unit_price_cents)
            else:
                # Try to find default pricing tier
                default_tier = PricingTier.objects.filter(meter=meter, is_default=True, is_active=True).first()
                if default_tier:
                    charge_cents = self._calculate_tiered_charge(overage_value, default_tier)

        # Update aggregation
        with transaction.atomic():
            aggregation.billable_value = billable_value
            aggregation.included_allowance = included_quantity
            aggregation.overage_value = overage_value
            aggregation.charge_cents = charge_cents
            aggregation.charge_calculated_at = timezone.now()
            aggregation.status = "rated"
            aggregation.save()

            # Log the rating
            AuditService.log_simple_event(
                event_type="usage_aggregation_rated",
                user=None,
                content_object=aggregation,
                description=(
                    f"Usage rated: {meter.name} = {billable_value} " f"({overage_value} overage) = {charge_cents} cents"
                ),
                actor_type="system",
                metadata={
                    "aggregation_id": str(aggregation.id),
                    "meter_name": meter.name,
                    "total_value": str(aggregation.total_value),
                    "billable_value": str(billable_value),
                    "included_quantity": str(included_quantity),
                    "overage_value": str(overage_value),
                    "charge_cents": charge_cents,
                },
            )

        return Result.ok(aggregation)

    def rate_billing_cycle(self, billing_cycle_id: str) -> Result:
        """
        Rate all aggregations for a billing cycle.
        """
        from .metering_models import BillingCycle, UsageAggregation

        try:
            billing_cycle = BillingCycle.objects.get(id=billing_cycle_id)
        except BillingCycle.DoesNotExist:
            return Result.err(f"Billing cycle not found: {billing_cycle_id}")

        aggregations = UsageAggregation.objects.filter(
            billing_cycle=billing_cycle, status__in=("accumulating", "pending_rating")
        )

        total_usage_charge = 0
        rated_count = 0
        error_count = 0

        for agg in aggregations:
            result = self.rate_aggregation(str(agg.id))
            if result.is_ok():
                rated_count += 1
                total_usage_charge += result.unwrap().charge_cents
            else:
                error_count += 1
                logger.error(f"Error rating aggregation {agg.id}: {result.error}")

        # Update billing cycle totals
        with transaction.atomic():
            billing_cycle.usage_charge_cents = total_usage_charge
            billing_cycle.total_cents = (
                billing_cycle.base_charge_cents
                + billing_cycle.usage_charge_cents
                - billing_cycle.discount_cents
                - billing_cycle.credit_applied_cents
                + billing_cycle.tax_cents
            )
            billing_cycle.save()

        logger.info(
            f"Rated billing cycle {billing_cycle_id}: "
            f"{rated_count} aggregations, {total_usage_charge} cents usage charge"
        )

        return Result.ok(
            {
                "billing_cycle_id": str(billing_cycle_id),
                "rated_count": rated_count,
                "error_count": error_count,
                "total_usage_charge_cents": total_usage_charge,
            }
        )

    def _apply_rounding(self, value: Decimal, mode: str, increment: Decimal) -> Decimal:
        """Apply rounding to a usage value"""
        if mode == "none":
            return value

        if increment <= 0:
            increment = Decimal("1")

        # Quantize to increment
        remainder = value % increment
        base = value - remainder

        if mode == "up" and remainder > 0:
            return base + increment
        elif mode == "down":
            return base
        elif mode == "nearest":
            if remainder >= increment / 2:
                return base + increment
            return base

        return value

    def _calculate_tiered_charge(self, quantity: Decimal, pricing_tier: Any) -> int:
        """Calculate charge using tiered pricing"""
        from .metering_models import PricingTierBracket

        if pricing_tier.pricing_model == "per_unit":
            # Simple per-unit pricing
            if pricing_tier.unit_price_cents:
                charge = int(quantity * pricing_tier.unit_price_cents)
                return max(charge, pricing_tier.minimum_charge_cents)
            return pricing_tier.minimum_charge_cents

        if pricing_tier.pricing_model == "volume":
            # All units priced at the volume rate
            brackets = PricingTierBracket.objects.filter(pricing_tier=pricing_tier).order_by("from_quantity")

            applicable_bracket = None
            for bracket in brackets:
                if bracket.to_quantity is None or quantity <= bracket.to_quantity:
                    if quantity >= bracket.from_quantity:
                        applicable_bracket = bracket
                        break

            if applicable_bracket:
                charge = int(quantity * applicable_bracket.unit_price_cents)
                charge += applicable_bracket.flat_fee_cents
                return max(charge, pricing_tier.minimum_charge_cents)

        if pricing_tier.pricing_model == "graduated":
            # Each bracket charged at its own rate
            brackets = PricingTierBracket.objects.filter(pricing_tier=pricing_tier).order_by("from_quantity")

            total_charge = 0
            remaining_quantity = quantity

            for bracket in brackets:
                if remaining_quantity <= 0:
                    break

                bracket_size = (
                    bracket.to_quantity - bracket.from_quantity if bracket.to_quantity else remaining_quantity
                )
                quantity_in_bracket = min(remaining_quantity, bracket_size)

                total_charge += int(quantity_in_bracket * bracket.unit_price_cents)
                total_charge += bracket.flat_fee_cents
                remaining_quantity -= quantity_in_bracket

            return max(total_charge, pricing_tier.minimum_charge_cents)

        if pricing_tier.pricing_model == "package":
            # Fixed price for packages
            brackets = PricingTierBracket.objects.filter(pricing_tier=pricing_tier).order_by("from_quantity")

            for bracket in brackets:
                if bracket.to_quantity is None or quantity <= bracket.to_quantity:
                    return bracket.flat_fee_cents

        return pricing_tier.minimum_charge_cents


class UsageAlertService:
    """
    Service for checking and sending usage alerts.
    """

    def check_thresholds(self, customer_id: str, meter_id: str, subscription_id: str | None = None) -> list[Any]:
        """
        Check if any usage thresholds have been breached.

        Returns list of created alerts.
        """
        from apps.customers.models import Customer

        from .metering_models import (
            UsageAggregation,
            UsageAlert,
            UsageThreshold,
        )

        try:
            customer = Customer.objects.get(id=customer_id)
        except Customer.DoesNotExist:
            logger.error(f"Customer not found: {customer_id}")
            return []

        # Get current aggregation
        agg_query = UsageAggregation.objects.filter(
            customer_id=customer_id, meter_id=meter_id, status__in=("accumulating", "pending_rating")
        )

        if subscription_id:
            agg_query = agg_query.filter(subscription_id=subscription_id)

        aggregation = agg_query.order_by("-period_start").first()
        if not aggregation:
            return []

        # Get included allowance
        allowance = Decimal("0")
        subscription = aggregation.subscription

        if subscription:
            sub_item = _get_subscription_item_for_meter(subscription, aggregation.meter)
            allowance = _get_allowance_from_subscription_item(sub_item)

        if allowance <= 0:
            allowance = _parse_decimal(aggregation.included_allowance)

        service_plan = None
        if subscription:
            service_plan = getattr(subscription.product, "default_service_plan", None)
            if allowance <= 0:
                allowance = _get_allowance_from_service_plan(aggregation.meter, service_plan)

        # Get applicable thresholds
        thresholds = UsageThreshold.objects.filter(meter_id=meter_id, is_active=True)
        if service_plan:
            thresholds = thresholds.filter(Q(service_plan__isnull=True) | Q(service_plan=service_plan))
        else:
            thresholds = thresholds.filter(Q(service_plan__isnull=True))

        created_alerts = []

        for threshold in thresholds:
            # Check if threshold is breached
            is_breached = False
            usage_percentage = None

            if threshold.threshold_type == "percentage" and allowance > 0:
                usage_percentage = (aggregation.total_value / allowance) * 100
                is_breached = usage_percentage >= threshold.threshold_value
            elif threshold.threshold_type == "absolute":
                is_breached = aggregation.total_value >= threshold.threshold_value

            if not is_breached:
                continue

            # Check if we already sent an alert for this threshold
            existing_alert = UsageAlert.objects.filter(
                threshold=threshold, customer=customer, aggregation=aggregation, status__in=("pending", "sent")
            ).exists()

            if existing_alert and not threshold.repeat_notification:
                continue

            # Create alert
            alert = UsageAlert.objects.create(
                threshold=threshold,
                customer=customer,
                subscription=subscription,
                aggregation=aggregation,
                usage_value=aggregation.total_value,
                usage_percentage=usage_percentage,
                allowance_value=allowance if allowance > 0 else None,
            )

            created_alerts.append(alert)

            # Log the alert
            AuditService.log_simple_event(
                event_type="usage_alert_created",
                user=None,
                content_object=alert,
                description=(
                    f"Usage alert triggered: {threshold.meter.name} at "
                    f"{usage_percentage or aggregation.total_value}"
                ),
                actor_type="system",
                metadata={
                    "alert_id": str(alert.id),
                    "threshold_id": str(threshold.id),
                    "customer_id": str(customer.id),
                    "meter_name": threshold.meter.name,
                    "usage_value": str(aggregation.total_value),
                    "threshold_value": str(threshold.threshold_value),
                    "threshold_type": threshold.threshold_type,
                },
            )

            # Schedule notification
            self._schedule_alert_notification(alert)

        return created_alerts

    def _schedule_alert_notification(self, alert: Any) -> None:
        """Schedule async notification for an alert"""
        try:
            from django_q.tasks import async_task

            async_task("apps.billing.metering_tasks.send_usage_alert_notification", str(alert.id), timeout=60)
        except Exception as e:
            logger.warning(f"Could not schedule alert notification: {e}")

    def send_alert_notification(self, alert_id: str) -> Result:
        """
        Send notification for a usage alert.
        """
        from .metering_models import UsageAlert

        try:
            alert = UsageAlert.objects.select_related("threshold", "customer", "threshold__meter").get(id=alert_id)
        except UsageAlert.DoesNotExist:
            return Result.err(f"Alert not found: {alert_id}")

        if alert.status not in ("pending",):
            return Result.ok(alert)  # Already sent

        threshold = alert.threshold

        # Send email notification
        if threshold.notify_customer:
            try:
                # TODO: Implement actual email sending
                # For now, just log
                logger.info(
                    f"Would send usage alert email to {alert.customer.primary_email}: "
                    f"{threshold.meter.display_name} at {alert.usage_value}"
                )
                alert.mark_sent("email")
            except Exception as e:
                alert.mark_failed(str(e))
                return Result.err(f"Failed to send notification: {e}")

        # Take action if configured
        if threshold.action_on_breach:
            self._take_threshold_action(alert, threshold.action_on_breach)

        return Result.ok(alert)

    def _take_threshold_action(self, alert: Any, action: str) -> None:
        """Take automated action for threshold breach"""
        if action == "warn":
            # Just the notification, no service action
            pass
        elif action == "throttle":
            # TODO: Implement service throttling
            logger.info(f"Would throttle service for {alert.customer}")
        elif action == "suspend":
            # TODO: Implement service suspension
            logger.info(f"Would suspend service for {alert.customer}")
        elif action == "block_new":
            # TODO: Block new usage
            logger.info(f"Would block new usage for {alert.customer}")

        alert.action_taken = action
        alert.action_at = timezone.now()
        alert.save(update_fields=["action_taken", "action_at"])
