"""Retired prefix overrides cannot rename e-Factura metrics."""

from dataclasses import dataclass
from typing import cast
from unittest.mock import patch

from django.test import TestCase, override_settings

from apps.billing.efactura.metrics import _create_counter, _create_gauge, _create_histogram, _create_info
from apps.billing.efactura.settings import EFacturaSettings
from apps.settings.models import SystemSetting


@dataclass
class RecordedMetric:
    """Capture metric identities at the optional Prometheus backend boundary."""

    name: str
    description: str
    labels: list[str] | None = None
    buckets: tuple[float, ...] | None = None


@override_settings(EFACTURA_METRICS_ENABLED=True, EFACTURA_METRICS_PREFIX="django_override")
class RetiredMetricsPrefixTests(TestCase):
    def test_all_metric_factories_use_the_fixed_prefix_despite_legacy_overrides(self) -> None:
        with (
            patch("apps.billing.efactura.metrics.PROMETHEUS_AVAILABLE", True),
            patch("apps.billing.efactura.metrics.efactura_settings", EFacturaSettings()),
            patch("apps.billing.efactura.metrics.Counter", RecordedMetric, create=True),
            patch("apps.billing.efactura.metrics.Histogram", RecordedMetric, create=True),
            patch("apps.billing.efactura.metrics.Gauge", RecordedMetric, create=True),
            patch("apps.billing.efactura.metrics.Info", RecordedMetric, create=True),
        ):
            for stored in (False, True):
                with self.subTest(stored=stored):
                    if stored:
                        SystemSetting.objects.create(
                            key="efactura.metrics.prefix",
                            name="Retired prefix",
                            data_type="string",
                            value="stored_override",
                            default_value="efactura",
                        )
                    created = (
                        _create_counter("submissions_total", "Submissions", ["status"]),
                        _create_histogram("duration_seconds", "Duration", [], buckets=(0.5, 1.0)),
                        _create_histogram("default_duration_seconds", "Duration", []),
                        _create_gauge("pending_documents", "Pending", []),
                        _create_info("build", "Build"),
                    )
                    self.assertEqual(
                        [cast(RecordedMetric, metric).name for metric in created],
                        [
                            "efactura_submissions_total",
                            "efactura_duration_seconds",
                            "efactura_default_duration_seconds",
                            "efactura_pending_documents",
                            "efactura_build",
                        ],
                    )
