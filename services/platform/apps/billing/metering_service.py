"""
Metering Service for PRAHO Platform
Handles usage event processing, aggregation, and rating for billing.

This service provides:
- Event ingestion with idempotency
- Usage aggregation by billing period
- Rating engine for charge calculation
- PRAHO-owned local usage rating and billing-cycle integration
- Alert threshold checking
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from typing import Any, cast

from django.core.cache import cache as django_cache
from django.db import IntegrityError, transaction
from django.db.models import F, Q, Sum
from django.utils import timezone

from apps.audit.services import AuditService
from apps.common.types import Err, Ok, Result
from apps.customers.models import Customer
from apps.notifications.services import EmailService
from apps.provisioning.models import Service
from apps.provisioning.provisioning_service import ProvisioningService

from . import config as billing_config
from .metering_models import (
    BillingCycle,
    PricingTierBracket,
    UsageAggregation,
    UsageAlert,
    UsageEvent,
    UsageMeter,
    UsageThreshold,
)
from .subscription_models import Subscription, SubscriptionItem

logger = logging.getLogger(__name__)
_PENDING_EVENT_BATCH_SIZE = 1000


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

    return candidates.first()


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


def _get_allowance_from_service_plan(  # noqa: PLR0911  # Complexity: multi-step business logic
    meter: Any, service_plan: Any | None
) -> Decimal:  # Complexity: usage aggregation  # Complexity: multi-step business logic
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
    """

    def record_event(  # noqa: C901, PLR0911, PLR0912  # Complexity: multi-step business logic
        self, event_data: UsageEventData
    ) -> Result[Any, str]:  # Complexity: usage aggregation  # Complexity: multi-step business logic
        """
        Record a usage event with idempotency protection.

        Returns Result containing the UsageEvent if successful.
        """
        try:
            # Get the meter
            try:
                meter = UsageMeter.objects.get(name=event_data.meter_name)
            except UsageMeter.DoesNotExist:
                return Err(f"Meter not found: {event_data.meter_name}")

            if not meter.is_active:
                return Err(f"Meter is inactive: {event_data.meter_name}")
            if not isinstance(event_data.value, Decimal) or not event_data.value.is_finite() or event_data.value < 0:
                return Err("Usage event value must be a finite non-negative decimal")

            snapshot_sources = {"virtualmin", "service_monitor"}
            snapshot_meters = {"disk_usage_gb", "bandwidth_gb"}
            if (
                event_data.source in snapshot_sources
                and meter.name in snapshot_meters
                and meter.aggregation_type not in {"last", "max"}
            ):
                return Err(f"Cumulative hosting snapshot meter '{meter.name}' must use last or max aggregation")

            # Get customer
            try:
                customer = Customer.objects.get(id=event_data.customer_id)
            except Customer.DoesNotExist:
                return Err(f"Customer not found: {event_data.customer_id}")

            # Validate timestamp
            timestamp = event_data.timestamp or timezone.now()
            grace_period = timedelta(hours=meter.event_grace_period_hours)
            min_timestamp = timezone.now() - grace_period
            max_timestamp = timezone.now() + timedelta(minutes=billing_config.get_future_event_drift_minutes())

            if timestamp < min_timestamp:
                return Err(
                    f"Event timestamp too old: {timestamp}. Grace period is {meter.event_grace_period_hours} hours."
                )
            if timestamp > max_timestamp:
                return Err(f"Event timestamp in future: {timestamp}")

            # Get optional relationships
            subscription = None
            service = None

            if event_data.subscription_id:
                try:
                    subscription = Subscription.objects.get(id=event_data.subscription_id)
                except Subscription.DoesNotExist:
                    return Err(f"Subscription not found: {event_data.subscription_id}")
                if subscription.customer_id != customer.id:
                    return Err("Subscription does not belong to the usage-event customer")

            if event_data.service_id:
                try:
                    service = Service.objects.get(id=event_data.service_id)
                except Service.DoesNotExist:
                    return Err(f"Service not found: {event_data.service_id}")
                if service.customer_id != customer.id:
                    return Err("Service does not belong to the usage-event customer")
                if subscription is not None and subscription.service_id != service.id:
                    return Err("Service does not belong to the selected subscription")

            # Create the event with idempotency using database constraint
            # This is race-condition-safe: we try to insert and catch duplicate
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
                        return Ok(existing)
                raise  # Re-raise if not an idempotency issue

            # Log the event
            logger.info(f"Usage event recorded: {meter.name} = {event_data.value} for customer {customer.id}")

            # Trigger async aggregation update
            self._schedule_aggregation_update(event)

            # Check thresholds
            self._check_thresholds_async(customer, meter, subscription)

            return Ok(event)

        except Exception as e:
            logger.exception(f"Error recording usage event: {e}")
            return Err(str(e))

    def record_bulk_events(
        self, events: list[UsageEventData], stop_on_error: bool = False
    ) -> tuple[list[Result[Any, str]], int, int]:
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
            from django_q.tasks import (  # noqa: PLC0415  # Deferred: avoids circular import
                async_task,  # Deferred: optional dependency  # Deferred: avoids circular import
            )

            async_task("apps.billing.metering_tasks.update_aggregation_for_event", str(event.id), timeout=60)
        except Exception as e:
            logger.warning(f"Could not schedule aggregation update: {e}")
            # Fall back to sync update
            self._update_aggregation_sync(event)

    def _update_aggregation_sync(self, event: Any) -> None:
        """Apply one event exactly once to the cycle containing its timestamp."""
        with transaction.atomic():
            locked_event = (
                UsageEvent.objects.select_for_update(of=("self",))
                .select_related("meter", "customer", "subscription", "service")
                .get(pk=event.pk)
            )
            if locked_event.is_processed:
                return

            subscription = self._resolve_event_subscription(locked_event)
            cycles = list(
                BillingCycle.objects.select_for_update(of=("self",))
                .filter(
                    subscription=subscription,
                    period_start__lte=locked_event.timestamp,
                    period_end__gt=locked_event.timestamp,
                    status__in=["active", "closing"],
                )
                .order_by("period_start", "id")[:2]
            )
            if not cycles:
                raise ValueError(
                    f"No eligible billing cycle covers event {locked_event.id} "
                    f"for subscription {subscription.subscription_number}"
                )
            if len(cycles) > 1:
                raise ValueError(
                    f"Ambiguous billing cycles cover event {locked_event.id} "
                    f"for subscription {subscription.subscription_number}"
                )
            billing_cycle = cycles[0]

            aggregation, _created = UsageAggregation.objects.get_or_create(
                meter=locked_event.meter,
                customer=locked_event.customer,
                billing_cycle=billing_cycle,
                defaults={
                    "subscription": subscription,
                    "period_start": billing_cycle.period_start,
                    "period_end": billing_cycle.period_end,
                    "status": "accumulating",
                },
            )
            self._apply_event_to_aggregation(locked_event, aggregation)

            locked_event.subscription = subscription
            locked_event.is_processed = True
            locked_event.processed_at = timezone.now()
            locked_event.aggregation = aggregation
            locked_event.save(update_fields=["subscription", "is_processed", "processed_at", "aggregation"])

    @staticmethod
    def _resolve_event_subscription(event: Any) -> Subscription:
        """Resolve one active subscription without guessing across services."""
        eligible_statuses = ["active", "trialing", "past_due"]
        if event.subscription_id:
            subscription = cast(Subscription, event.subscription)
            if subscription.customer_id != event.customer_id:
                raise ValueError("Usage event subscription customer does not match the event customer")
            if subscription.status not in eligible_statuses:
                raise ValueError(f"Usage event subscription is not eligible in status '{subscription.status}'")
            return subscription

        candidates = Subscription.objects.filter(
            customer_id=event.customer_id,
            status__in=eligible_statuses,
            billing_cycles__period_start__lte=event.timestamp,
            billing_cycles__period_end__gt=event.timestamp,
            billing_cycles__status__in=["active", "closing", "closed"],
        )
        if event.service_id:
            candidates = candidates.filter(service_id=event.service_id)
        resolved = list(candidates.distinct().order_by("id")[:2])
        if not resolved:
            raise ValueError(f"No eligible subscription found for usage event {event.id}")
        if len(resolved) > 1:
            raise ValueError(
                f"Usage event {event.id} matches multiple subscriptions; provide subscription_id or service_id"
            )
        return resolved[0]

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
            from django_q.tasks import (  # noqa: PLC0415  # Deferred: avoids circular import
                async_task,  # Deferred: optional dependency  # Deferred: avoids circular import
            )

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
        self,
        meter_id: str | None = None,
        customer_id: str | None = None,
        billing_cycle_id: str | None = None,
        limit: int = _PENDING_EVENT_BATCH_SIZE,
    ) -> tuple[int, int]:
        """
        Process pending usage events into aggregations.

        Returns (processed_count, error_count)
        """
        query = UsageEvent.objects.filter(is_processed=False)

        if meter_id:
            query = query.filter(meter_id=meter_id)  # type: ignore[misc]
        if customer_id:
            query = query.filter(customer_id=customer_id)
        if billing_cycle_id:
            try:
                cycle = BillingCycle.objects.select_related("subscription").get(id=billing_cycle_id)
            except BillingCycle.DoesNotExist:
                return 0, 1
            subscription = cycle.subscription
            event_scope = Q(subscription_id=subscription.id)
            if subscription.service_id is not None:
                event_scope |= Q(subscription__isnull=True, service_id=subscription.service_id)
            event_scope |= Q(subscription__isnull=True, service__isnull=True)
            query = query.filter(
                event_scope,
                customer_id=subscription.customer_id,
                timestamp__gte=cycle.period_start,
                timestamp__lt=cycle.period_end,
            )

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

    def close_billing_cycle(self, billing_cycle_id: str) -> Result[Any, str]:
        """
        Close a billing cycle and prepare aggregations for rating.
        """
        try:
            billing_cycle = BillingCycle.objects.get(id=billing_cycle_id)
        except BillingCycle.DoesNotExist:
            return Err(f"Billing cycle not found: {billing_cycle_id}")
        if billing_cycle.status not in ("active", "closing"):
            return Err(f"Billing cycle cannot be closed: status is {billing_cycle.status}")

        # Process first to preserve the event -> cycle lock order used by normal
        # aggregation workers. The locked recheck below prevents closing while
        # any eligible event is still pending.
        while True:
            processed, processing_errors = self.process_pending_events(billing_cycle_id=str(billing_cycle.id))
            if processing_errors:
                return Err(f"Cannot close billing cycle while {processing_errors} pending usage event(s) failed")
            if processed < _PENDING_EVENT_BATCH_SIZE:
                break

        with transaction.atomic():
            billing_cycle = (
                BillingCycle.objects.select_for_update(of=("self",))
                .select_related("subscription")
                .get(pk=billing_cycle.pk)
            )
            if billing_cycle.status not in ("active", "closing"):
                return Err(f"Billing cycle cannot be closed: status is {billing_cycle.status}")

            # Bulk-update aggregations to pending_rating (intentional for performance — UsageAggregation is not FSM-protected)
            UsageAggregation.objects.filter(
                billing_cycle=billing_cycle, status="accumulating"
            ).update(  # fsm-bypass: UsageAggregation uses plain CharField, not FSMField
                status="pending_rating"
            )

            # Close the billing cycle (FSM transition sets closed_at)
            billing_cycle.close()
            billing_cycle.save()

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

        return Ok(billing_cycle)

    def get_customer_usage_summary(
        self, customer_id: str, period_start: datetime | None = None, period_end: datetime | None = None
    ) -> dict[str, Any]:
        """
        Get a summary of customer usage for a period.
        """
        query = UsageAggregation.objects.filter(customer_id=customer_id)

        if period_start:
            query = query.filter(period_start__gte=period_start)
        if period_end:
            query = query.filter(period_end__lte=period_end)

        aggregations = query.select_related("meter")

        summary: dict[str, Any] = {
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

    @transaction.atomic
    def rate_aggregation(  # noqa: C901, PLR0911, PLR0912, PLR0915  # Fail-closed rating validation
        self, aggregation_id: str
    ) -> Result[Any, str]:
        """
        Calculate charges for a usage aggregation.
        """
        try:
            aggregation = (
                UsageAggregation.objects.select_for_update(of=("self",))
                .select_related("meter", "subscription", "billing_cycle__subscription__currency")
                .get(id=aggregation_id)
            )
        except UsageAggregation.DoesNotExist:
            return Err(f"Aggregation not found: {aggregation_id}")

        if aggregation.status not in ("accumulating", "pending_rating"):
            return Err(f"Aggregation already rated or finalized: {aggregation.status}")

        meter = aggregation.meter
        subscription = aggregation.billing_cycle.subscription
        if aggregation.subscription_id not in {None, subscription.id}:
            return Err("Aggregation subscription does not match its billing cycle")
        if aggregation.customer_id != subscription.customer_id:
            return Err("Aggregation customer does not match its billing cycle subscription")

        # Get included allowance from subscription item
        included_quantity = Decimal("0")
        pricing_tier = None
        unit_price_cents = None

        sub_item = _get_subscription_item_for_meter(subscription, meter)

        if sub_item:
            included_quantity = _get_allowance_from_subscription_item(sub_item)
            unit_price_cents = sub_item.effective_price_cents

        effective_at = aggregation.billing_cycle.period_start
        effective_tiers = list(
            meter.pricing_tiers.filter(
                Q(valid_from__isnull=True) | Q(valid_from__lte=effective_at),
                Q(valid_until__isnull=True) | Q(valid_until__gt=effective_at),
                is_active=True,
                is_default=True,
                currency_id=subscription.currency_id,
            ).order_by("id")[:2]
        )
        if len(effective_tiers) > 1:
            return Err(
                f"Ambiguous active {subscription.currency.code} pricing for meter {meter.name} "
                f"at {effective_at.isoformat()}"
            )
        pricing_tier = effective_tiers[0] if effective_tiers else None
        service_plan = getattr(subscription.product, "default_service_plan", None)
        if included_quantity <= 0:
            included_quantity = _get_allowance_from_service_plan(meter, service_plan)

        # Calculate billable value after rounding
        billable_value = self._apply_rounding(aggregation.total_value, meter.rounding_mode, meter.rounding_increment)

        # Calculate overage
        overage_value = max(Decimal("0"), billable_value - included_quantity)

        # Calculate charge
        charge_cents = 0
        rating_snapshot: dict[str, Any] = {
            "effective_at": effective_at.isoformat(),
            "billable_value": str(billable_value),
            "included_allowance": str(included_quantity),
            "overage_value": str(overage_value),
        }

        if overage_value > 0 and meter.is_billable:
            if pricing_tier:
                pricing_error = self._validate_pricing_configuration(pricing_tier)
                if pricing_error:
                    return Err(f"Invalid pricing for meter {meter.name}: {pricing_error}")
                charge_cents = self._calculate_tiered_charge(
                    overage_value,
                    pricing_tier,
                )
                rating_snapshot.update(self._pricing_snapshot(pricing_tier))
            elif unit_price_cents is not None:
                if unit_price_cents < 0:
                    return Err(f"Invalid negative subscription-item pricing for meter {meter.name}")
                charge_cents = self._round_cents(overage_value * Decimal(unit_price_cents))
                rating_snapshot.update(
                    {
                        "source": "subscription_item",
                        "unit_price_cents": unit_price_cents,
                    }
                )
            else:
                return Err(f"No active {subscription.currency.code} pricing configured for meter {meter.name}")
        elif pricing_tier:
            rating_snapshot.update(self._pricing_snapshot(pricing_tier))
        elif unit_price_cents is not None:
            rating_snapshot.update(
                {
                    "source": "subscription_item",
                    "unit_price_cents": unit_price_cents,
                }
            )

        # Update aggregation
        aggregation.billable_value = billable_value
        aggregation.included_allowance = included_quantity
        aggregation.overage_value = overage_value
        aggregation.charge_cents = charge_cents
        aggregation.charge_calculated_at = timezone.now()
        aggregation.meta = {**(aggregation.meta or {}), "rating": rating_snapshot}
        aggregation.rate()
        aggregation.save()

        # Log the rating
        AuditService.log_simple_event(
            event_type="usage_aggregation_rated",
            user=None,
            content_object=aggregation,
            description=(
                f"Usage rated: {meter.name} = {billable_value} ({overage_value} overage) = {charge_cents} cents"
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

        return Ok(aggregation)

    @transaction.atomic
    def rate_billing_cycle(self, billing_cycle_id: str) -> Result[Any, str]:
        """
        Rate all aggregations for a billing cycle.
        """
        try:
            billing_cycle = BillingCycle.objects.select_for_update(of=("self",)).get(id=billing_cycle_id)
        except BillingCycle.DoesNotExist:
            return Err(f"Billing cycle not found: {billing_cycle_id}")

        aggregations = (
            UsageAggregation.objects.select_for_update(of=("self",))
            .filter(
                billing_cycle=billing_cycle,
                status__in=("accumulating", "pending_rating"),
            )
            .order_by("id")
        )

        rated_count = 0

        for agg in aggregations:
            result = self.rate_aggregation(str(agg.id))
            if result.is_ok():
                rated_count += 1
            else:
                error = result.unwrap_err()
                logger.error(f"Error rating aggregation {agg.id}: {error}")
                transaction.set_rollback(True)
                return Err(f"Failed to rate aggregation {agg.id}: {error}")

        # Recompute from the complete rated snapshot. A retried run may process
        # only the aggregations that failed previously; summing only this run
        # would silently discard charges already rated successfully.
        total_usage_charge = (
            UsageAggregation.objects.filter(billing_cycle=billing_cycle, status="rated").aggregate(
                total=Sum("charge_cents")
            )["total"]
            or 0
        )
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

        return Ok(
            {
                "billing_cycle_id": str(billing_cycle_id),
                "rated_count": rated_count,
                "error_count": 0,
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

    def _get_pricing_brackets(self, pricing_tier: Any) -> Any:
        return PricingTierBracket.objects.filter(pricing_tier=pricing_tier).order_by("from_quantity")

    @staticmethod
    def _round_cents(amount: Decimal) -> int:
        """Round a non-negative fractional-cent amount using PRAHO's money policy."""
        return int(amount.quantize(Decimal("1"), rounding=ROUND_HALF_EVEN))

    def _validate_pricing_configuration(  # noqa: C901, PLR0911, PLR0912  # Distinct pricing rejection reasons
        self, pricing_tier: Any
    ) -> str | None:
        """Reject incomplete price schedules instead of silently undercharging."""
        if pricing_tier.minimum_charge_cents < 0:
            return "minimum charge cannot be negative"
        if pricing_tier.pricing_model == "per_unit":
            if pricing_tier.unit_price_cents is None:
                return "per-unit pricing requires a unit price"
            if pricing_tier.unit_price_cents < 0:
                return "unit price cannot be negative"
            return None
        if pricing_tier.pricing_model not in {"volume", "graduated", "package"}:
            return f"unsupported pricing model {pricing_tier.pricing_model!r}"

        brackets = list(self._get_pricing_brackets(pricing_tier))
        if not brackets:
            return f"{pricing_tier.pricing_model} pricing requires brackets"

        expected_from = Decimal("0")
        for index, bracket in enumerate(brackets):
            if bracket.from_quantity != expected_from:
                return "pricing brackets must be contiguous and begin at zero"
            if bracket.from_quantity < 0:
                return "pricing bracket start cannot be negative"
            if bracket.unit_price_cents < 0 or bracket.flat_fee_cents < 0:
                return "pricing bracket charges cannot be negative"
            if bracket.to_quantity is None:
                if index != len(brackets) - 1:
                    return "an unlimited pricing bracket must be last"
                continue
            if bracket.to_quantity <= bracket.from_quantity:
                return "pricing bracket end must be greater than its start"
            expected_from = bracket.to_quantity

        if brackets[-1].to_quantity is not None:
            return "pricing brackets must end with an unlimited bracket"
        return None

    def _pricing_snapshot(self, pricing_tier: Any) -> dict[str, Any]:
        """Return the exact configuration used to rate an aggregation."""
        return {
            "source": "pricing_tier",
            "pricing_tier_id": str(pricing_tier.id),
            "pricing_tier_name": pricing_tier.name,
            "pricing_model": pricing_tier.pricing_model,
            "currency": pricing_tier.currency.code,
            "unit_price_cents": pricing_tier.unit_price_cents,
            "minimum_charge_cents": pricing_tier.minimum_charge_cents,
            "brackets": [
                {
                    "from_quantity": str(bracket.from_quantity),
                    "to_quantity": str(bracket.to_quantity) if bracket.to_quantity is not None else None,
                    "unit_price_cents": bracket.unit_price_cents,
                    "flat_fee_cents": bracket.flat_fee_cents,
                }
                for bracket in self._get_pricing_brackets(pricing_tier)
            ],
        }

    def _calculate_per_unit_charge(self, quantity: Decimal, pricing_tier: Any) -> int:
        if pricing_tier.unit_price_cents is None:
            return int(pricing_tier.minimum_charge_cents)
        charge = self._round_cents(quantity * Decimal(pricing_tier.unit_price_cents))
        return max(charge, int(pricing_tier.minimum_charge_cents))

    def _calculate_volume_charge(self, quantity: Decimal, pricing_tier: Any) -> int:
        applicable_bracket = next(
            (
                bracket
                for bracket in self._get_pricing_brackets(pricing_tier)
                if quantity >= bracket.from_quantity and (bracket.to_quantity is None or quantity < bracket.to_quantity)
            ),
            None,
        )
        if not applicable_bracket:
            return int(pricing_tier.minimum_charge_cents)

        charge = self._round_cents(
            quantity * Decimal(applicable_bracket.unit_price_cents) + Decimal(applicable_bracket.flat_fee_cents)
        )
        return max(charge, int(pricing_tier.minimum_charge_cents))

    def _calculate_graduated_charge(self, quantity: Decimal, pricing_tier: Any) -> int:
        total_charge = Decimal("0")
        remaining_quantity = quantity

        for bracket in self._get_pricing_brackets(pricing_tier):
            if remaining_quantity <= 0:
                break

            bracket_size = bracket.to_quantity - bracket.from_quantity if bracket.to_quantity else remaining_quantity
            quantity_in_bracket = min(remaining_quantity, bracket_size)
            total_charge += quantity_in_bracket * Decimal(bracket.unit_price_cents) + Decimal(bracket.flat_fee_cents)
            remaining_quantity -= quantity_in_bracket

        return max(self._round_cents(total_charge), int(pricing_tier.minimum_charge_cents))

    def _calculate_package_charge(self, quantity: Decimal, pricing_tier: Any) -> int:
        for bracket in self._get_pricing_brackets(pricing_tier):
            if quantity >= bracket.from_quantity and (bracket.to_quantity is None or quantity < bracket.to_quantity):
                return int(bracket.flat_fee_cents)
        return int(pricing_tier.minimum_charge_cents)

    def _calculate_tiered_charge(self, quantity: Decimal, pricing_tier: Any) -> int:
        """Calculate charge using tiered pricing"""
        calculators = {
            "per_unit": self._calculate_per_unit_charge,
            "volume": self._calculate_volume_charge,
            "graduated": self._calculate_graduated_charge,
            "package": self._calculate_package_charge,
        }
        calculator = calculators.get(pricing_tier.pricing_model)
        if not calculator:
            return int(pricing_tier.minimum_charge_cents)
        return calculator(quantity, pricing_tier)


class UsageAlertService:
    """
    Service for checking and sending usage alerts.
    """

    def check_thresholds(self, customer_id: str, meter_id: str, subscription_id: str | None = None) -> list[Any]:
        """
        Check if any usage thresholds have been breached.

        Returns list of created alerts.
        """
        customer = self._get_customer(Customer, customer_id)
        if customer is None:
            logger.error(f"Customer not found: {customer_id}")
            return []

        aggregation = self._get_latest_aggregation(UsageAggregation, customer_id, meter_id, subscription_id)
        if not aggregation:
            return []

        allowance, subscription, service_plan = self._resolve_allowance_and_plan(aggregation)
        thresholds = self._get_applicable_thresholds(UsageThreshold, meter_id, service_plan)

        created_alerts = []

        for threshold in thresholds:
            is_breached, usage_percentage = self._threshold_breach_status(threshold, aggregation, allowance)
            if not is_breached:
                continue

            if (
                self._alert_already_exists(UsageAlert, threshold, customer, aggregation)
                and not threshold.repeat_notification
            ):
                continue

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
            self._log_threshold_alert(alert, threshold, customer, aggregation, usage_percentage)
            self._schedule_alert_notification(alert)

        return created_alerts

    def _get_customer(self, customer_model: Any, customer_id: str) -> Any | None:
        try:
            return customer_model.objects.get(id=customer_id)
        except customer_model.DoesNotExist:
            return None

    def _get_latest_aggregation(
        self, usage_aggregation_model: Any, customer_id: str, meter_id: str, subscription_id: str | None
    ) -> Any | None:
        agg_query = usage_aggregation_model.objects.filter(
            customer_id=customer_id,
            meter_id=meter_id,
            status__in=("accumulating", "pending_rating"),
        )
        if subscription_id:
            agg_query = agg_query.filter(subscription_id=subscription_id)
        return agg_query.order_by("-period_start").first()

    def _resolve_allowance_and_plan(self, aggregation: Any) -> tuple[Decimal, Any | None, Any | None]:
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

        return allowance, subscription, service_plan

    def _get_applicable_thresholds(self, usage_threshold_model: Any, meter_id: str, service_plan: Any | None) -> Any:
        thresholds = usage_threshold_model.objects.filter(meter_id=meter_id, is_active=True)
        if service_plan:
            return thresholds.filter(Q(service_plan__isnull=True) | Q(service_plan=service_plan))
        return thresholds.filter(Q(service_plan__isnull=True))

    def _threshold_breach_status(self, threshold: Any, aggregation: Any, allowance: Decimal) -> tuple[bool, Any | None]:
        if threshold.threshold_type == "percentage" and allowance > 0:
            usage_percentage = (aggregation.total_value / allowance) * 100
            return usage_percentage >= threshold.threshold_value, usage_percentage
        if threshold.threshold_type == "absolute":
            return aggregation.total_value >= threshold.threshold_value, None
        return False, None

    def _alert_already_exists(self, usage_alert_model: Any, threshold: Any, customer: Any, aggregation: Any) -> bool:
        return bool(
            usage_alert_model.objects.filter(
                threshold=threshold,
                customer=customer,
                aggregation=aggregation,
                status__in=("pending", "sent"),
            ).exists()
        )

    def _log_threshold_alert(
        self,
        alert: Any,
        threshold: Any,
        customer: Any,
        aggregation: Any,
        usage_percentage: Decimal | None,
    ) -> None:
        AuditService.log_simple_event(
            event_type="usage_alert_created",
            user=None,
            content_object=alert,
            description=(
                f"Usage alert triggered: {threshold.meter.name} at {usage_percentage or aggregation.total_value}"
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

    def _schedule_alert_notification(self, alert: Any) -> None:
        """Schedule async notification for an alert"""
        try:
            from django_q.tasks import (  # noqa: PLC0415  # Deferred: avoids circular import
                async_task,  # Deferred: optional dependency  # Deferred: avoids circular import
            )

            async_task("apps.billing.metering_tasks.send_usage_alert_notification", str(alert.id), timeout=60)
        except Exception as e:
            logger.warning(f"Could not schedule alert notification: {e}")

    def send_alert_notification(self, alert_id: str) -> Result[Any, str]:
        """
        Send notification for a usage alert.
        """
        from apps.billing.metering_models import UsageAlert  # noqa: PLC0415  # Deferred: test mockability

        try:
            alert = UsageAlert.objects.select_related("threshold", "customer", "threshold__meter").get(id=alert_id)
        except UsageAlert.DoesNotExist:
            return Err(f"Alert not found: {alert_id}")

        if alert.status not in ("pending",):
            return Ok(alert)  # Already sent

        threshold = alert.threshold

        # Send email notification
        if threshold.notify_customer:
            try:
                email_result = EmailService.send_template_email(
                    template_key="usage_alert",
                    recipient=alert.customer.primary_email,
                    context={
                        "customer_name": alert.customer.name or alert.customer.primary_email,
                        "meter_name": threshold.meter.display_name,
                        "usage_value": str(alert.usage_value),
                        "threshold_value": str(threshold.threshold_value),
                        "threshold_type": threshold.threshold_type,
                        "usage_percentage": f"{alert.usage_percentage:.0f}%" if alert.usage_percentage else "N/A",
                    },
                )
                if email_result.success:
                    alert.mark_sent("email")
                    logger.info(
                        f"📧 [Alert] Sent usage alert to {alert.customer.primary_email}: "
                        f"{threshold.meter.display_name} at {alert.usage_value}"
                    )
                else:
                    alert.mark_failed(email_result.error or "Email send failed")
                    return Err(f"Failed to send notification: {email_result.error}")
            except Exception as e:
                alert.mark_failed(str(e))
                return Err(f"Failed to send notification: {e}")

        # Take action if configured
        if threshold.action_on_breach:
            self._take_threshold_action(alert, threshold.action_on_breach)

        return Ok(alert)

    def _take_threshold_action(self, alert: Any, action: str) -> None:
        """Take automated action for threshold breach"""
        if action == "warn":
            # Just the notification, no service action
            pass
        elif action == "throttle":
            ProvisioningService.suspend_services_for_customer(customer_id=alert.customer.id, reason="usage_throttled")
            AuditService.log_simple_event(
                event_type="metering_throttle_applied",
                user=None,
                content_object=alert.customer,
                description=f"Services throttled for {alert.customer} due to usage threshold breach",
                actor_type="system",
                metadata={"alert_id": str(alert.id), "action": action},
            )
            logger.info(f"⚠️ [Metering] Throttled services for {alert.customer}")
        elif action == "suspend":
            ProvisioningService.suspend_services_for_customer(customer_id=alert.customer.id, reason="usage_exceeded")
            AuditService.log_simple_event(
                event_type="metering_suspension_applied",
                user=None,
                content_object=alert.customer,
                description=f"Services suspended for {alert.customer} due to usage exceeded",
                actor_type="system",
                metadata={"alert_id": str(alert.id), "action": action},
            )
            logger.info(f"🛑 [Metering] Suspended services for {alert.customer}")
        elif action == "block_new":
            cache_key = f"usage_blocked:{alert.customer.id}"
            django_cache.set(cache_key, True, timeout=86400)  # 24 hours
            AuditService.log_simple_event(
                event_type="metering_new_usage_blocked",
                user=None,
                content_object=alert.customer,
                description=f"New usage blocked for {alert.customer} due to threshold breach",
                actor_type="system",
                metadata={"alert_id": str(alert.id), "action": action, "block_duration_hours": 24},
            )
            logger.info(f"🚫 [Metering] Blocked new usage for {alert.customer}")

        alert.action_taken = action
        alert.action_at = timezone.now()
        alert.save(update_fields=["action_taken", "action_at"])
