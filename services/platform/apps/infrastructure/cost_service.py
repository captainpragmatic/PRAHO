"""
Infrastructure Cost Tracking Service

Calculates and records costs for deployed infrastructure.
Supports hourly/daily/monthly cost calculations and aggregations.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from django.db import models
from django.db.models import Sum
from django.utils import timezone

from apps.common.types import Err, Ok, Result

if TYPE_CHECKING:
    from apps.infrastructure.models import NodeDeployment, NodeDeploymentCostRecord, NodeServerLifetime

logger = logging.getLogger(__name__)


@dataclass
class CostSummary:
    """Summary of costs for a given period"""

    total_eur: Decimal
    compute_eur: Decimal
    bandwidth_eur: Decimal
    storage_eur: Decimal
    period_start: datetime
    period_end: datetime
    node_count: int = 0


@dataclass
class DeploymentCostBreakdown:
    """Cost breakdown for a single deployment"""

    deployment_id: str
    hostname: str
    total_cost_eur: Decimal
    monthly_rate_eur: Decimal
    uptime_hours: float
    cost_per_hour_eur: Decimal


class CostTrackingService:
    """
    Service for tracking and calculating infrastructure costs.

    Features:
    - Hourly cost calculation based on node size
    - Cost aggregation by deployment, provider, region
    - Monthly cost projections
    - Historical cost analysis
    """

    # Hetzner includes 20TB bandwidth; extra bandwidth billed per TB
    HETZNER_EXTRA_BANDWIDTH_PER_TB_EUR = Decimal("1.19")

    # Hours in different periods
    HOURS_PER_MONTH = Decimal("730")  # Average hours per month
    HOURS_PER_DAY = Decimal("24")

    def calculate_deployment_costs(  # Complexity: multi-step workflow
        self,
        deployment: NodeDeployment,
        period_start: datetime,
        period_end: datetime,
    ) -> Result[NodeDeploymentCostRecord, str]:
        """
        Calculate and record costs for a deployment over a period.

        Args:
            deployment: The deployment to calculate costs for
            period_start: Start of the billing period
            period_end: End of the billing period

        Returns:
            Result with the created cost record or error
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentCostRecord,  # Circular: cross-app  # Deferred: avoids circular import
        )

        # Validate period
        if period_end <= period_start:
            return Err("Period end must be after period start")

        usage = lifetime_usage(deployment, period_start, period_end)
        if usage is not None:
            # Each server lifetime, at the rate it recorded: re-deploys and resizes keep their history.
            hours_active, compute_cost = usage
        else:
            window = self._row_window_usage(deployment, period_start, period_end)
            if window.is_err():
                return Err(window.unwrap_err())
            hours_active, compute_cost = window.unwrap()
        if hours_active <= 0:
            # Recalculation is authoritative: a record from before (an unconfirmed lifetime attested never
            # created, say) is zeroed rather than left charging.
            NodeDeploymentCostRecord.objects.filter(
                deployment=deployment, period_start=period_start, period_end=period_end
            ).update(cost_eur=0, compute_cost=0, bandwidth_cost=0, storage_cost=0)
            return Err("No active time in this period")

        # For now, bandwidth and storage are 0 (included in base price)
        # In future, could integrate with provider API to get actual usage
        bandwidth_cost = Decimal("0")
        storage_cost = Decimal("0")

        total_cost = compute_cost + bandwidth_cost + storage_cost

        # Check for existing record in this period
        existing = NodeDeploymentCostRecord.objects.filter(
            deployment=deployment,
            period_start=period_start,
            period_end=period_end,
        ).first()

        if existing:
            # Update existing record
            existing.cost_eur = total_cost
            existing.compute_cost = compute_cost
            existing.bandwidth_cost = bandwidth_cost
            existing.storage_cost = storage_cost
            existing.save()
            logger.info(f"[Cost] Updated cost record for {deployment.hostname}: {total_cost:.4f} EUR")
            return Ok(existing)

        # Create new record
        record = NodeDeploymentCostRecord.objects.create(
            deployment=deployment,
            period_start=period_start,
            period_end=period_end,
            cost_eur=total_cost,
            compute_cost=compute_cost,
            bandwidth_cost=bandwidth_cost,
            storage_cost=storage_cost,
        )

        logger.info(
            f"[Cost] Created cost record for {deployment.hostname}: {total_cost:.4f} EUR for {hours_active:.2f} hours"
        )

        return Ok(record)

    def _row_window_usage(
        self, deployment: NodeDeployment, period_start: datetime, period_end: datetime
    ) -> Result[tuple[Decimal, Decimal], str]:
        """A deployment without server lifetimes: its own started_at .. destroyed_at window at its current size.

        No ``started_at`` means no server ever ran (it is set when one is created), so no time is billed.
        """
        none = Ok((Decimal("0"), Decimal("0")))
        if deployment.started_at is None:
            return none
        effective_start = max(period_start, deployment.started_at)
        effective_end = min(period_end, deployment.destroyed_at or timezone.now())
        if effective_end <= effective_start:
            return none
        hours_active = Decimal(str((effective_end - effective_start).total_seconds() / 3600))
        if not deployment.node_size:
            return Err("Deployment has no associated node size")
        hourly_rate = deployment.node_size.monthly_cost_eur / self.HOURS_PER_MONTH
        return Ok((hours_active, hourly_rate * hours_active))

    def calculate_all_deployment_costs(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> list[Result[NodeDeploymentCostRecord, str]]:
        """
        Calculate costs for all active deployments in a period.

        Args:
            period_start: Start of the billing period
            period_end: End of the billing period

        Returns:
            List of results for each deployment
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeployment,  # Circular: cross-app  # Deferred: avoids circular import
        )

        # Deployments active during this period by their own window, or with a server lifetime overlapping it
        # (a re-deployed row's earlier server is billed whatever its new attempt's status).
        row_window = (
            models.Q(status__in=["completed", "stopped", "destroyed"])
            & (models.Q(started_at__lte=period_end) | models.Q(started_at__isnull=True))
            & (models.Q(destroyed_at__gte=period_start) | models.Q(destroyed_at__isnull=True))
        )
        lifetime_overlap = models.Q(server_lifetimes__started_at__lte=period_end) & (
            models.Q(server_lifetimes__ended_at__isnull=True) | models.Q(server_lifetimes__ended_at__gte=period_start)
        )
        active_deployments = (
            NodeDeployment.objects.filter(row_window | lifetime_overlap).distinct().select_related("node_size")
        )

        results = []
        for deployment in active_deployments:
            result = self.calculate_deployment_costs(deployment, period_start, period_end)
            results.append(result)

        successful = sum(1 for r in results if r.is_ok())
        logger.info(
            f"[Cost] Calculated costs for {successful}/{len(results)} deployments "
            f"for period {period_start.date()} to {period_end.date()}"
        )

        return results

    def get_cost_summary(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> CostSummary:
        """
        Get aggregated cost summary for a period.

        Args:
            period_start: Start of the period
            period_end: End of the period

        Returns:
            CostSummary with totals
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentCostRecord,  # Circular: cross-app  # Deferred: avoids circular import
        )

        records = NodeDeploymentCostRecord.objects.filter(
            period_start__gte=period_start,
            period_end__lte=period_end,
        )

        aggregates = records.aggregate(
            total=Sum("cost_eur"),
            compute=Sum("compute_cost"),
            bandwidth=Sum("bandwidth_cost"),
            storage=Sum("storage_cost"),
        )

        return CostSummary(
            total_eur=aggregates["total"] or Decimal("0"),
            compute_eur=aggregates["compute"] or Decimal("0"),
            bandwidth_eur=aggregates["bandwidth"] or Decimal("0"),
            storage_eur=aggregates["storage"] or Decimal("0"),
            period_start=period_start,
            period_end=period_end,
            node_count=records.values("deployment").distinct().count(),
        )

    def get_monthly_summary(self, year: int, month: int) -> CostSummary:
        """
        Get cost summary for a specific month.

        Args:
            year: Year (e.g., 2025)
            month: Month (1-12)

        Returns:
            CostSummary for the month
        """
        from calendar import monthrange  # noqa: PLC0415  # Deferred: avoids circular import

        _, days_in_month = monthrange(year, month)
        period_start = timezone.make_aware(datetime(year, month, 1))
        period_end = timezone.make_aware(datetime(year, month, days_in_month, 23, 59, 59))

        return self.get_cost_summary(period_start, period_end)

    def get_deployment_breakdown(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> list[DeploymentCostBreakdown]:
        """
        Get cost breakdown by deployment for a period.

        Args:
            period_start: Start of the period
            period_end: End of the period

        Returns:
            List of DeploymentCostBreakdown for each deployment
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentCostRecord,  # Circular: cross-app  # Deferred: avoids circular import
        )

        breakdowns = []

        records = NodeDeploymentCostRecord.objects.filter(
            period_start__gte=period_start,
            period_end__lte=period_end,
        ).select_related("deployment", "deployment__node_size")

        # Aggregate by deployment
        deployment_costs: dict[str, dict] = {}  # type: ignore[type-arg]
        for record in records:
            dep_id = str(record.deployment.id)
            if dep_id not in deployment_costs:
                deployment_costs[dep_id] = {
                    "deployment": record.deployment,
                    "total": Decimal("0"),
                    "hours": Decimal("0"),
                }

            deployment_costs[dep_id]["total"] += record.cost_eur

            # Calculate hours from period
            period_hours = (record.period_end - record.period_start).total_seconds() / 3600
            deployment_costs[dep_id]["hours"] += Decimal(str(period_hours))

        for dep_id, data in deployment_costs.items():
            deployment = data["deployment"]
            monthly_rate = deployment.node_size.monthly_cost_eur if deployment.node_size else Decimal("0")
            hours = data["hours"]
            hourly_rate = monthly_rate / self.HOURS_PER_MONTH if monthly_rate else Decimal("0")
            usage = lifetime_usage(deployment, period_start, period_end)
            if usage is not None:
                # Total, uptime and rate all describe the lifetimes' hours in this period; the rate is effective,
                # since lifetimes may carry different rates.
                hours, data["total"] = usage
                hourly_rate = data["total"] / hours if hours else Decimal("0")
                monthly_rate = hourly_rate * self.HOURS_PER_MONTH

            breakdowns.append(
                DeploymentCostBreakdown(
                    deployment_id=dep_id,
                    hostname=deployment.hostname,
                    total_cost_eur=data["total"],
                    monthly_rate_eur=monthly_rate,
                    uptime_hours=float(hours),
                    cost_per_hour_eur=hourly_rate,
                )
            )

        # Sort by total cost descending
        breakdowns.sort(key=lambda x: x.total_cost_eur, reverse=True)
        return breakdowns

    def get_provider_breakdown(
        self,
        period_start: datetime,
        period_end: datetime,
    ) -> dict[str, Decimal]:
        """
        Get cost breakdown by cloud provider.

        Args:
            period_start: Start of the period
            period_end: End of the period

        Returns:
            Dict mapping provider name to total cost
        """
        from apps.infrastructure.models import (  # noqa: PLC0415  # Deferred: avoids circular import
            NodeDeploymentCostRecord,  # Circular: cross-app  # Deferred: avoids circular import
        )

        records = NodeDeploymentCostRecord.objects.filter(
            period_start__gte=period_start,
            period_end__lte=period_end,
        ).select_related("deployment__provider")

        provider_costs: dict[str, Decimal] = {}
        for record in records:
            provider_name = record.deployment.provider.name if record.deployment.provider else "Unknown"
            provider_costs[provider_name] = provider_costs.get(provider_name, Decimal("0")) + record.cost_eur

        return provider_costs

    def project_monthly_cost(self, deployment: NodeDeployment) -> Decimal:
        """
        Project the monthly cost for a deployment.

        Args:
            deployment: The deployment to project costs for

        Returns:
            Projected monthly cost in EUR
        """
        # Check via _id to avoid RelatedObjectDoesNotExist on None FK
        if not deployment.node_size_id:
            return Decimal("0")

        return deployment.node_size.monthly_cost_eur

    def get_current_month_to_date(self) -> CostSummary:
        """
        Get costs from the start of the current month to now.

        Returns:
            CostSummary for month to date
        """
        now = timezone.now()
        month_start = timezone.make_aware(datetime(now.year, now.month, 1))
        return self.get_cost_summary(month_start, now)


def recalculate_recorded_costs(deployment: NodeDeployment) -> int:
    """Recalculate every cost record the deployment has, after its billable windows changed. Returns the count."""
    from apps.infrastructure.models import NodeDeploymentCostRecord  # noqa: PLC0415  # Deferred: avoids circular import

    service = get_cost_tracking_service()
    periods = list(
        NodeDeploymentCostRecord.objects.filter(deployment=deployment).values_list("period_start", "period_end")
    )
    for period_start, period_end in periods:
        service.calculate_deployment_costs(deployment, period_start, period_end)
    return len(periods)


def _lifetimes_of(deployment: NodeDeployment) -> list[NodeServerLifetime]:
    from apps.infrastructure.models import NodeServerLifetime  # noqa: PLC0415  # Deferred: avoids circular import

    return list(NodeServerLifetime.objects.filter(deployment=deployment))


def _priced(
    lifetimes: list[NodeServerLifetime], period_start: datetime | None, period_end: datetime
) -> tuple[Decimal, Decimal]:
    """Hours and cost of ``lifetimes`` clipped to the period (no lower bound when ``period_start`` is None)."""
    now = timezone.now()
    hours = cost = Decimal("0")
    for lifetime in lifetimes:
        start = lifetime.started_at if period_start is None else max(period_start, lifetime.started_at)
        end = min(period_end, lifetime.ended_at or now)
        if end <= start:
            continue
        span = Decimal(str((end - start).total_seconds() / 3600))
        hours += span
        cost += lifetime.monthly_cost_eur / CostTrackingService.HOURS_PER_MONTH * span
    return hours, cost


def lifetime_usage(
    deployment: NodeDeployment, period_start: datetime, period_end: datetime
) -> tuple[Decimal, Decimal] | None:
    """Hours and cost of the deployment's server lifetimes inside the period; None when it has no lifetimes."""
    lifetimes = _lifetimes_of(deployment)
    return _priced(lifetimes, period_start, period_end) if lifetimes else None


def lifetime_totals(deployment: NodeDeployment) -> tuple[Decimal, Decimal] | None:
    """Hours and cost of all the deployment's server lifetimes up to now; None when it has none."""
    lifetimes = _lifetimes_of(deployment)
    return _priced(lifetimes, None, timezone.now()) if lifetimes else None


# Module-level singleton
_cost_service: CostTrackingService | None = None


def get_cost_tracking_service() -> CostTrackingService:
    """Get global cost tracking service instance"""
    global _cost_service  # noqa: PLW0603  # Module-level singleton pattern
    if _cost_service is None:
        _cost_service = CostTrackingService()
    return _cost_service
