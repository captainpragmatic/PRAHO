"""Costs are priced per server lifetime, at the rate each lifetime recorded, so re-deploys and resizes keep history."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.infrastructure.cost_service import CostTrackingService
from apps.infrastructure.models import NodeDeployment, NodeServerLifetime
from tests.infrastructure.test_deployment_service_pipeline import _create_deployment

HOURS_PER_MONTH = Decimal("730")


def at(day: int, hour: int = 0) -> datetime:
    return timezone.make_aware(datetime(2026, 9, day, hour))


def lifetime(deployment: NodeDeployment, rate: str, start: datetime, end: datetime | None, sid: str = "s") -> None:
    NodeServerLifetime.objects.create(
        deployment=deployment, server_id=sid, node_size=deployment.node_size, monthly_cost_eur=Decimal(rate),
        started_at=start, ended_at=end,
    )


def cost(rate: str, hours: int) -> Decimal:
    return Decimal(rate) / HOURS_PER_MONTH * hours


class LifetimeCostTests(TestCase):
    def setUp(self) -> None:
        self.service = CostTrackingService()
        self.deployment = _create_deployment("destroyed")
        # The row's own window would say 1 Sep .. 30 Sep at the current size: lifetimes must win.
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(started_at=at(1), destroyed_at=at(30))
        self.deployment.refresh_from_db()

    def test_each_lifetime_is_priced_at_its_own_rate_inside_the_period(self) -> None:
        lifetime(self.deployment, "7.30", at(2), at(2, 10), "a")  # 10 h
        lifetime(self.deployment, "14.60", at(5), at(5, 4), "b")  # 4 h
        lifetime(self.deployment, "14.60", at(9), at(11), "c")  # outside the period
        record = self.service.calculate_deployment_costs(self.deployment, at(1), at(8)).unwrap()
        self.assertEqual(record.cost_eur.quantize(Decimal("0.0001")),
                         (cost("7.30", 10) + cost("14.60", 4)).quantize(Decimal("0.0001")))

    def test_a_lifetime_is_clipped_to_the_period(self) -> None:
        lifetime(self.deployment, "7.30", at(1, 20), at(2, 6))
        record = self.service.calculate_deployment_costs(self.deployment, at(2), at(3)).unwrap()
        self.assertEqual(record.cost_eur.quantize(Decimal("0.0001")), cost("7.30", 6).quantize(Decimal("0.0001")))

    def test_a_catalogue_price_change_does_not_reprice_history(self) -> None:
        lifetime(self.deployment, "7.30", at(2), at(2, 10))
        self.deployment.node_size.monthly_cost_eur = Decimal("99.00")
        self.deployment.node_size.save(update_fields=["monthly_cost_eur"])
        record = self.service.calculate_deployment_costs(self.deployment, at(1), at(8)).unwrap()
        self.assertEqual(record.cost_eur.quantize(Decimal("0.0001")), cost("7.30", 10).quantize(Decimal("0.0001")))

    def test_a_period_without_lifetime_time_has_no_cost(self) -> None:
        lifetime(self.deployment, "7.30", at(20), at(21))
        self.assertTrue(self.service.calculate_deployment_costs(self.deployment, at(1), at(8)).is_err())

    def test_a_redeployed_row_still_gets_its_earlier_lifetime_billed(self) -> None:
        lifetime(self.deployment, "7.30", at(2), at(2, 10))
        # Re-deployed: the new attempt is pending and its own window is reset.
        NodeDeployment.objects.filter(pk=self.deployment.pk).update(status="pending", started_at=None, destroyed_at=None)
        results = self.service.calculate_all_deployment_costs(at(1), at(8))
        billed = [r.unwrap() for r in results if r.is_ok() and r.unwrap().deployment_id == self.deployment.pk]
        self.assertEqual(len(billed), 1)
        self.assertEqual(billed[0].cost_eur.quantize(Decimal("0.0001")), cost("7.30", 10).quantize(Decimal("0.0001")))

    def test_breakdown_uptime_and_rate_come_from_the_lifetimes(self) -> None:
        lifetime(self.deployment, "7.30", at(2), at(2, 10), "a")
        lifetime(self.deployment, "14.60", at(5), at(5, 4), "b")
        self.service.calculate_deployment_costs(self.deployment, at(1), at(8)).unwrap()
        (row,) = self.service.get_deployment_breakdown(at(1), at(8))
        self.assertEqual(row.uptime_hours, 14.0)
        effective = (cost("7.30", 10) + cost("14.60", 4)) / 14
        self.assertEqual(row.cost_per_hour_eur.quantize(Decimal("0.000001")), effective.quantize(Decimal("0.000001")))

    def test_estimate_sums_the_lifetimes(self) -> None:
        lifetime(self.deployment, "7.30", at(2), at(2, 10), "a")
        lifetime(self.deployment, "14.60", at(5), at(5, 4), "b")
        self.assertAlmostEqual(self.deployment.calculate_running_hours(), 14.0)
        self.assertAlmostEqual(self.deployment.estimate_cost(), float(cost("7.30", 10) + cost("14.60", 4)), places=4)


class RowWindowFallbackTests(TestCase):
    def test_a_row_without_lifetimes_keeps_its_own_window(self) -> None:
        deployment = _create_deployment("destroyed")
        NodeDeployment.objects.filter(pk=deployment.pk).update(started_at=at(2), destroyed_at=at(2, 10))
        deployment.refresh_from_db()
        rate = deployment.node_size.monthly_cost_eur
        record = CostTrackingService().calculate_deployment_costs(deployment, at(1), at(8)).unwrap()
        self.assertEqual(record.cost_eur.quantize(Decimal("0.0001")),
                         (rate / HOURS_PER_MONTH * 10).quantize(Decimal("0.0001")))
