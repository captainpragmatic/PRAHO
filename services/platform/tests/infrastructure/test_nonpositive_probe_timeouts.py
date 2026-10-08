"""Legacy nonpositive timeouts must not turn healthy TCP probes into nonblocking probes."""

import time
from contextlib import AbstractContextManager, nullcontext
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase

from apps.infrastructure.drift_remediation import DriftRemediationService
from apps.infrastructure.drift_scanner import DriftScannerService
from apps.infrastructure.models import NodeDeployment
from tests.helpers.legacy_settings import store_legacy_integer


class NonpositiveProbeTimeoutTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)

    def test_scanner_dispatches_healthy_probes_with_default_timeouts(self) -> None:
        timeouts: list[float] = []

        def transport(address: tuple[str, int], *, timeout: float) -> AbstractContextManager[object]:
            timeouts.append(timeout)
            return nullcontext(object())

        with patch(
            "apps.infrastructure.drift_scanner.socket.create_connection",
            side_effect=transport,
        ):
            for stored in (0, -1, 1):
                store_legacy_integer("infrastructure.network_probe_timeout_seconds", stored)
                cache.clear()
                self.assertTrue(DriftScannerService()._tcp_probe("192.0.2.1", 22))
        self.assertEqual(timeouts, [10, 10, 1])

    def test_remediation_dispatches_healthy_probes_with_default_timeouts(self) -> None:
        timeouts: list[float] = []
        deployment = NodeDeployment(hostname="probe.example.test", ipv4_address="192.0.2.1")

        def transport(address: tuple[str, int], *, timeout: float) -> AbstractContextManager[object]:
            timeouts.append(timeout)
            return nullcontext(object())

        with patch(
            "apps.infrastructure.drift_remediation.socket.create_connection",
            side_effect=transport,
        ):
            for stored in (0, -1, 1):
                store_legacy_integer("infrastructure.health_check_timeout_seconds", stored)
                cache.clear()
                result = DriftRemediationService()._verify_health(deployment, time.monotonic() + 60)
                self.assertTrue(result.is_ok(), result)
                self.assertTrue(result.unwrap())
        self.assertEqual(timeouts, [10, 10, 1])
