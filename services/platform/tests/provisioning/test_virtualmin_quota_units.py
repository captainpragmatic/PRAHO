"""Create-time and recovery-time quota parameters are the same conversion (ADR-0061 P0.6)."""

from __future__ import annotations

from typing import cast
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.test import SimpleTestCase, override_settings

from apps.common.types import Ok
from apps.provisioning.virtualmin_disaster_recovery import VirtualminDisasterRecoveryService
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminProvisioningService, create_domain_params
from apps.provisioning.virtualmin_units import quota_parameters
from tests.helpers.recorded_virtualmin import recorded_http_response
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class QuotaParametersTests(SimpleTestCase):
    def test_invalid_types_and_negative_limits_are_refused(self) -> None:
        for disk, bandwidth in ((True, None), (None, False), (-1, None), (None, -2), (1.5, None)):
            with self.subTest(disk=disk, bandwidth=bandwidth), self.assertRaises(ValueError):
                quota_parameters(disk, bandwidth)

    def test_creation_suppresses_virtualmin_customer_signup_email(self) -> None:
        params = create_domain_params(
            domain="example.test",
            username="example",
            password="Example-fixture42!",
            template="Default",
            recovery_seed="fixture",
            disk_quota_mb=5632,
            bandwidth_quota_mb=20480,
        )
        self.assertIn("no-email", params)
        self.assertEqual(params["no-email"], "")

    def test_domain_and_owner_have_the_same_kernel_limit(self) -> None:
        params = quota_parameters(5632, 20480)
        self.assertEqual(params.get("quota"), "5767168")
        self.assertEqual(params.get("uquota"), "5767168")

    def test_disk_is_kib_and_bandwidth_is_bytes(self) -> None:
        self.assertEqual(
            quota_parameters(1000, 10000),
            {"quota": str(1000 * 1024), "uquota": str(1000 * 1024), "bandwidth": str(10000 * 1024 * 1024)},
        )

    def test_unlimited_means_zero_and_the_minus_one_sentinel_is_unlimited(self) -> None:
        self.assertEqual(quota_parameters(0, 0), {"quota": "0", "uquota": "0", "bandwidth": "0"})
        self.assertEqual(quota_parameters(None, -1), {"bandwidth": "0"})

    def test_unset_quotas_are_left_out(self) -> None:
        self.assertEqual(quota_parameters(None, None), {})


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class CreateAndRecoverAgreeTests(VirtualminTaskTestBase):
    def test_modify_domain_after_recovery_sends_what_create_domain_sent(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.account.disk_quota_mb = 2000
        self.account.bandwidth_quota_mb = -1
        self.account.save(update_fields=["disk_quota_mb", "bandwidth_quota_mb", "updated_at"])
        sent: list[dict[str, object]] = []

        def transport(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("dict[str, object]", kwargs["params"])
            sent.append(params)
            return recorded_http_response(str(params["program"]))

        job = VirtualminProvisioningJob.objects.create(
            operation="create_domain", server=self.server, account=self.account, correlation_id="c"
        )
        service = VirtualminProvisioningService(self.server)
        with (
            patch.object(service, "_validate_provisioning_preconditions") as preflight,
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=transport),
        ):
            preflight.return_value = Ok(True)
            service._execute_domain_creation(self.account, job)
            VirtualminDisasterRecoveryService()._restore_quotas(self.server, self.account.domain, 2000, -1)

        create = next(p for p in sent if p.get("program") == "create-domain")
        modify = next(p for p in sent if p.get("program") == "modify-domain")
        # The same numbers under each command's own name for the bandwidth limit: create-domain takes
        # --bandwidth, modify-domain takes --bw and refuses --bandwidth ("Unknown parameter", Virtualmin 8.3,
        # observed on the lab node), which would also discard the disk quota sent with it.
        self.assertEqual(modify.get("quota"), create.get("quota"))
        self.assertEqual(modify.get("bw"), create.get("bandwidth"))
        self.assertEqual(modify["bw"], "0")
        self.assertNotIn("bandwidth", modify)

    def test_a_refused_quota_restore_is_not_reported_as_restored(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

        def refuse(method: str, url: str, **kwargs: object) -> requests.Response:
            params = cast("dict[str, object]", kwargs["params"])
            return recorded_http_response(str(params["program"]), "unknown_parameter")

        with (
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=refuse),
            self.assertLogs("apps.provisioning.virtualmin_disaster_recovery", level="INFO") as logs,
        ):
            VirtualminDisasterRecoveryService()._restore_quotas(self.server, self.account.domain, 2000, 1000)

        text = "\n".join(logs.output)
        self.assertIn("Failed to restore quotas", text)
        self.assertIn("Unknown parameter --bandwidth", text)
        self.assertNotIn("Restored quotas", text)
