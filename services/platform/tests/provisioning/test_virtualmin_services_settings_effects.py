"""Runtime Virtualmin quota defaults reach domain creation and its capacity gate."""

from __future__ import annotations

import json
from decimal import Decimal
from typing import cast
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from requests import Response

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService


@override_settings(CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}})
class VirtualminServicesSettingsEffectsTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        customer = Customer.objects.create(
            name="Hosted settings customer", customer_type="individual", primary_email="hosted@example.test"
        )
        currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(name="Hosted settings plan", price_monthly=Decimal("10"))
        service = Service.objects.create(
            customer=customer,
            service_plan=plan,
            currency=currency,
            service_name="hosted.example.test",
            domain="hosted.example.test",
            billing_cycle="monthly",
            price=Decimal("10"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="hosted-settings", hostname="hosted-node.example.test", api_username="praho-api", status="active"
        )
        self.server.set_api_password("server-fixture-password")
        self.server.save()
        self.account = VirtualminAccount.objects.create(
            service=service,
            server=self.server,
            domain=service.domain,
            virtualmin_username="hosted_settings",
            template_name="Default",
        )
        self.account.set_password("AccountFixture123!")
        self.account.save()
        self.provisioner = VirtualminProvisioningService(self.server)
        self.sent: list[dict[str, object]] = []
        self.available_mb = 100000

    def set_value(self, key: str, value: int) -> None:
        result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def http_response(self, method: str, url: str, **kwargs: object) -> Response:
        self.assertEqual(method, "GET")
        self.assertEqual(url, self.server.api_url)
        params = dict(cast("dict[str, object]", kwargs["params"]))
        self.sent.append(params)
        program = params["program"]
        if program == "info":
            data: dict[str, object] = {"available_disk_mb": self.available_mb}
        elif program == "list-domains":
            data = {"data": []}
        elif program == "list-templates":
            data = {"templates": ["Default"]}
        else:
            self.assertEqual(program, "create-domain")
            data = {}
        response = Response()
        response.status_code = 200
        response._content = json.dumps({"status": "success", **data}).encode()
        response._content_consumed = True
        return response

    def create_domain(self, *, disk_mb: int | None, bandwidth_mb: int | None) -> VirtualminProvisioningJob:
        self.sent.clear()
        self.account.disk_quota_mb = disk_mb
        self.account.bandwidth_quota_mb = bandwidth_mb
        self.account.status = "provisioning"
        self.account.save(update_fields=["disk_quota_mb", "bandwidth_quota_mb", "status", "updated_at"])
        job = VirtualminProvisioningJob.objects.create(
            account=self.account, server=self.server, operation="create_domain"
        )
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http_response):
            result = self.provisioner._execute_domain_creation(self.account, job)
        self.assertTrue(result.is_ok(), result)
        self.account.refresh_from_db()
        job.refresh_from_db()
        self.assertEqual(self.account.status, "active")
        self.assertEqual(job.status, "completed")
        return job

    def creation_params(self) -> dict[str, object]:
        requests = [params for params in self.sent if params["program"] == "create-domain"]
        self.assertEqual(len(requests), 1, self.sent)
        return requests[0]

    def test_domain_quota_default_reaches_http_and_is_pinned_on_the_account(self) -> None:
        for configured in (37, 41, 0):
            with self.subTest(configured=configured):
                self.set_value("virtualmin.domain_quota_default_mb", configured)
                self.create_domain(disk_mb=None, bandwidth_mb=0)
                self.assertEqual(self.creation_params().get("quota"), str(configured * 1024))
                self.assertEqual(self.account.disk_quota_mb, configured)
        self.set_value("virtualmin.domain_quota_default_mb", 97)
        for explicit in (13, 0):
            with self.subTest(explicit=explicit):
                self.create_domain(disk_mb=explicit, bandwidth_mb=0)
                self.assertEqual(self.creation_params().get("quota"), str(explicit * 1024))
                self.assertEqual(self.account.disk_quota_mb, explicit)
        SystemSetting.objects.filter(key="virtualmin.domain_quota_default_mb").delete()
        self.create_domain(disk_mb=None, bandwidth_mb=0)
        self.assertNotIn("quota", self.creation_params())
        self.assertIsNone(self.account.disk_quota_mb)

    def test_bandwidth_quota_default_reaches_http_and_is_pinned_on_the_account(self) -> None:
        for configured in (53, 59, 0):
            with self.subTest(configured=configured):
                self.set_value("virtualmin.bandwidth_quota_default_mb", configured)
                self.create_domain(disk_mb=0, bandwidth_mb=None)
                self.assertEqual(self.creation_params().get("bandwidth"), str(configured * 1024 * 1024))
                self.assertNotIn("bw-limit", self.creation_params())
                self.assertEqual(self.account.bandwidth_quota_mb, configured)
        self.set_value("virtualmin.bandwidth_quota_default_mb", 97)
        for explicit in (17, 0, -1):
            with self.subTest(explicit=explicit):
                self.create_domain(disk_mb=0, bandwidth_mb=explicit)
                self.assertEqual(self.creation_params().get("bandwidth"), str(max(0, explicit) * 1024 * 1024))
                self.assertEqual(self.account.bandwidth_quota_mb, explicit)
        SystemSetting.objects.filter(key="virtualmin.bandwidth_quota_default_mb").delete()
        self.create_domain(disk_mb=0, bandwidth_mb=None)
        self.assertNotIn("bandwidth", self.creation_params())
        self.assertIsNone(self.account.bandwidth_quota_mb)

    def test_domain_quota_default_is_checked_against_nested_health_data(self) -> None:
        self.set_value("virtualmin.domain_quota_default_mb", 37)
        for available in (36, 37, 38):
            with self.subTest(available=available):
                self.account.disk_quota_mb = None
                self.account.bandwidth_quota_mb = 0
                self.account.save(update_fields=["disk_quota_mb", "bandwidth_quota_mb", "updated_at"])
                job = VirtualminProvisioningJob.objects.create(
                    account=self.account, server=self.server, operation="create_domain"
                )
                self.available_mb = available
                self.sent.clear()
                with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http_response):
                    result = self.provisioner._execute_domain_creation(self.account, job)
                job.refresh_from_db()
                if available < 37:
                    self.assertTrue(result.is_err(), result)
                    self.assertIn("36MB available, 37MB requested", result.unwrap_err())
                    self.assertEqual(job.status, "failed")
                    self.assertEqual([params["program"] for params in self.sent], ["info"])
                else:
                    self.assertTrue(result.is_ok(), result)
                    self.assertEqual(job.status, "completed")
                    self.assertEqual(self.creation_params().get("quota"), "37888")
