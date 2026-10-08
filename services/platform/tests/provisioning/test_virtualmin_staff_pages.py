"""Red-first regressions for Virtualmin QA defects."""

from __future__ import annotations

import json
from datetime import timedelta
from decimal import Decimal
from typing import cast
from unittest.mock import patch
from uuid import UUID

from django.contrib.messages import get_messages
from django.core.cache import cache
from django.db.models.signals import post_init, pre_save
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django_q.models import OrmQ
from django_q.signing import SignedPackage
from requests import Response

from apps.billing.models import Currency, FXRate
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan, ServicePlanPrice
from apps.provisioning.virtualmin_gateway import VirtualminConfig, VirtualminGateway
from apps.provisioning.virtualmin_migration_models import NodeDrain
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_tasks import reclaim_stalled_virtualmin_operations
from apps.settings.models import SystemSetting
from apps.users.models import User
from tests.fixtures.virtualmin.responses import list_bandwidth, list_domains

LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
QUEUE = {"name": "virtualmin-qa", "orm": "default", "sync": False, "timeout": 3600, "retry": 86400}


@override_settings(CACHES=LOCMEM, Q_CLUSTER=QUEUE)
class VirtualminQATestBase(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.client.raise_request_exception = False
        self.client.force_login(
            User.objects.create_user(email="virtualmin-qa@example.com", is_staff=True, staff_role="admin")
        )
        self.customer = Customer.objects.create(
            name="Virtualmin QA", customer_type="company", primary_email="customer@example.com"
        )
        self.currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.plan = ServicePlan.objects.create(
            name="QA hosting", plan_type="shared_hosting", price_monthly=Decimal("10")
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="qa.example.com",
            domain="qa.example.com",
            username="qa",
            price=Decimal("10"),
            billing_cycle="monthly",
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="qa-node", hostname="qa-node.example.com", api_username="qa-api", status="active"
        )
        self.server.set_api_password("QA-Server-Password123!")
        self.server.save()
        self.account = VirtualminAccount.objects.create(
            server=self.server,
            service=self.service,
            domain=self.service.domain,
            virtualmin_username="qa",
            status="active",
            praho_customer_id=self.customer.pk,
            praho_service_id=UUID(int=self.service.pk),
        )
        self.sent: list[dict[str, object]] = []
        self.payloads: dict[str, dict[str, object]] = {
            "info": {"command": "info", "status": "success", "output": "Virtualmin QA server"},
            "list-domains": list_domains.single_domain(domain=self.account.domain, username="qa"),
            "list-bandwidth": list_bandwidth.success(domain=self.account.domain),
        }

    def http(self, method: str, url: str, **kwargs: object) -> Response:
        self.assertEqual(method, "GET")
        self.assertEqual(url, self.server.api_url)
        params = cast("dict[str, object]", kwargs["params"])
        self.sent.append(dict(params))
        response = Response()
        response.status_code = 200
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps(self.payloads[str(params["program"])]).encode()
        response._content_consumed = True
        return response

    def setting(self, key: str, value: str) -> None:
        SystemSetting.objects.update_or_create(
            key=key,
            defaults={
                "name": key,
                "category": key.split(".", 1)[0],
                "data_type": "string",
                "value": value,
                "default_value": value,
            },
        )

    def assert_admitted(self, operation: str, response_status: int, location: str | None) -> None:
        job = VirtualminProvisioningJob.objects.get(account=self.account, operation=operation)
        self.assertEqual(job.status, "pending")
        packets = [cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()]
        task_name = "run_virtualmin_backup" if operation == "backup_domain" else "run_virtualmin_restore"
        packet = next(item for item in packets if item["func"] == f"apps.provisioning.virtualmin_tasks.{task_name}")
        self.assertEqual(tuple(cast("tuple[object, ...]", packet["args"])), (str(job.pk),))
        self.assertEqual(response_status, 302)
        target = reverse("provisioning:virtualmin_job_status", args=[job.pk])
        self.assertEqual(location, target)
        self.assertContains(self.client.get(target), job.correlation_id)


class VirtualminQAViewsTests(VirtualminQATestBase):
    def test_connection_exception_escapes_submitted_markup(self) -> None:
        markup = "<img src=x onerror=alert(1)>"
        response = self.client.post(
            reverse("provisioning:virtualmin_server_test_connection"),
            {
                "hostname": self.server.hostname,
                "api_username": "qa-api",
                "api_password": "QA-Server-Password123!",
                "api_port": markup,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, markup)
        self.assertContains(response, "&lt;img src=x onerror=alert(1)&gt;")

    def test_backup_admission_redirects_to_registered_job_page(self) -> None:
        response = self.client.post(
            reverse("provisioning:virtualmin_account_backup", args=[self.account.pk]),
            {"backup_type": "full", "include_files": "on"},
        )
        self.assert_admitted("backup_domain", response.status_code, response.headers.get("Location"))

    def test_backups_page_renders_empty_listing(self) -> None:
        self.setting("backup.aws_access_key_id", "qa-access")
        self.setting("backup.aws_secret_access_key", "qa-secret")
        SystemSetting.objects.filter(key="backup.s3_bucket_name").delete()
        response = self.client.get(reverse("provisioning:virtualmin_backups"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Virtualmin Backups")
        self.assertContains(response, "No backups found.")

    def test_bulk_actions_page_renders_usable_form(self) -> None:
        response = self.client.get(reverse("provisioning:virtualmin_bulk_actions"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "provisioning/virtualmin/bulk_actions.html")
        self.assertContains(response, "Bulk Actions")
        self.assertContains(response, 'name="action"')
        self.assertContains(response, 'name="selected_accounts"')
        self.assertContains(response, f'value="{self.account.pk}"')
        self.assertContains(response, 'name="confirm_bulk_action"')
        self.assertContains(response, 'type="checkbox"')
        self.assertContains(response, "<table")
        self.assertContains(response, self.account.domain)
        self.assertContains(response, self.server.name)
        self.assertContains(response, 'method="get"')
        self.assertContains(response, 'name="server"')
        self.assertContains(response, 'name="status"')
        self.assertContains(response, "Select all listed")
        self.assertContains(response, "the reconciler applies them to Virtualmin")
        self.assertEqual([account.pk for account in response.context["accounts"]], [self.account.pk])
        self.assertNotContains(response, "hx-confirm=")

    def test_job_logs_page_renders_job_details_and_escaped_error(self) -> None:
        job = VirtualminProvisioningJob.objects.create(
            server=self.server,
            account=self.account,
            operation="backup_domain",
            status="failed",
            status_message="Remote failure <script>alert(1)</script>",
        )
        response = self.client.get(reverse("provisioning:virtualmin_job_logs", args=[job.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, job.correlation_id)
        self.assertContains(response, "Remote failure &lt;script&gt;alert(1)&lt;/script&gt;")
        self.assertNotContains(response, "<script>alert(1)</script>")

    def test_sync_creates_linked_service_using_current_selling_currency(self) -> None:
        SystemSetting.objects.filter(key="billing.default_currency").delete()
        for code in ("RON", "EUR"):
            with self.subTest(currency=code):
                cache.clear()
                Currency.objects.get_or_create(code=code, defaults={"symbol": code, "decimals": 2})
                ServicePlanPrice.objects.get_or_create(
                    service_plan=self.plan, currency_id=code, defaults={"monthly_price_cents": 1000}
                )
                if code == "EUR":
                    FXRate.objects.create(
                        base_code_id="EUR",
                        quote_code_id="RON",
                        rate=Decimal("4.97"),
                        as_of=timezone.localdate(),
                        source=FXRate.Source.BNR,
                        source_reference="virtualmin-qa",
                        fetched_at=timezone.now(),
                    )
                    self.setting("billing.default_currency", code)
                domain = f"imported-{code.lower()}.example.com"
                username = f"imported{code.lower()}"
                self.payloads["list-domains"] = list_domains.single_domain(domain=domain, username=username)
                self.payloads["list-bandwidth"] = list_bandwidth.success(domain=domain)
                with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
                    response = self.client.post(
                        reverse("provisioning:virtualmin_accounts_sync"), HTTP_HX_REQUEST="true"
                    )
                self.assertTrue(VirtualminAccount.objects.filter(domain=domain).exists())
                account = VirtualminAccount.objects.select_related("service").get(domain=domain)
                self.assertEqual(account.server_id, self.server.pk)
                self.assertEqual(account.service.customer_id, self.customer.pk)
                self.assertEqual(account.service.service_plan_id, self.plan.pk)
                self.assertEqual(account.service.currency_id, code)
                self.assertEqual(account.service.username, username)
                self.assertEqual(account.service.domain, domain)
                self.assertContains(response, domain)

    def test_bulk_health_check_rejects_negative_current_disk_usage(self) -> None:
        # The DB rejects negative usage. Hydrate a legacy in-memory value without relaxing its constraint.
        def legacy_usage(sender: type[VirtualminAccount], instance: VirtualminAccount, **kwargs: object) -> None:
            if instance.pk == self.account.pk:
                instance.current_disk_usage_mb = -1

        post_init.connect(legacy_usage, sender=VirtualminAccount, weak=False)
        self.addCleanup(post_init.disconnect, legacy_usage, sender=VirtualminAccount)
        with (
            self.assertLogs("apps.provisioning.virtualmin_views", level="INFO") as logs,
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http),
        ):
            response = self.client.post(
                reverse("provisioning:virtualmin_bulk_actions"),
                {"action": "health_check", "selected_accounts": str(self.account.pk), "confirm_bulk_action": "on"},
            )
        self.assertEqual(response.status_code, 302)
        self.assertIn("Invalid disk usage data", "\n".join(logs.output))
        self.assertTrue(any("0 healthy" in str(message) for message in get_messages(response.wsgi_request)))
        self.assertEqual(self.sent, [])

    def test_invalid_backup_max_age_returns_validation_error(self) -> None:
        for value in ("not-a-number", "-1", "0"):
            with self.subTest(max_age=value):
                response = self.client.get(reverse("provisioning:virtualmin_backups"), {"max_age": value})
                self.assertEqual(response.status_code, 400)
                self.assertContains(response, "Maximum backup age must be a positive integer.", status_code=400)

    def test_retry_availability_and_display_use_job_limit(self) -> None:
        for limit, attempts, available in ((1, 1, False), (5, 3, True), (0, 0, False), (3, 2, True)):
            with self.subTest(limit=limit, attempts=attempts):
                job = VirtualminProvisioningJob.objects.create(
                    server=self.server,
                    account=self.account,
                    operation="backup_domain",
                    status="failed",
                    max_retries=limit,
                    retry_count=attempts,
                )
                response = self.client.get(reverse("provisioning:virtualmin_job_status", args=[job.pk]))
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.context["can_retry"], available)
                self.assertContains(response, f"{attempts}/{limit}")
                self.assertEqual("Retry Job" in response.content.decode(), available)

    def test_bandwidth_http_fixture_parses_nested_bytes_without_double_counting(self) -> None:
        self.payloads["list-domains"] = list_domains.single_domain(domain=self.account.domain, bandwidth_usage="0 MB")
        gateway = VirtualminGateway(VirtualminConfig(server=self.server, use_credential_vault=False))
        for shape, expected in (("total", 1500), ("components", 1500), ("lists", 1500), ("two_rows", 3000)):
            with self.subTest(shape=shape):
                cache.clear()
                payload = list_bandwidth.success(domain=self.account.domain)
                rows = cast("list[dict[str, object]]", payload["data"])
                values = cast("dict[str, object]", rows[0]["values"])
                if shape == "components":
                    values.pop("Total bytes")
                elif shape == "lists":
                    rows[0]["values"] = {key: [value] for key, value in values.items()}
                elif shape == "two_rows":
                    rows.append(dict(rows[0]))
                self.payloads["list-bandwidth"] = payload
                with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
                    result = gateway.get_domain_info(self.account.domain)
                self.assertTrue(result.is_ok(), result)
                self.assertEqual(result.unwrap()["bandwidth_usage_mb"], expected)

    def test_disk_quota_http_fixture_recognizes_server_byte_quota(self) -> None:
        gateway = VirtualminGateway(VirtualminConfig(server=self.server, use_credential_vault=False))
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
            result = gateway.get_domain_info(self.account.domain)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap()["disk_quota_mb"], 1000)
        self.assertEqual(result.unwrap()["disk_usage_mb"], 150)

    def test_drain_reclaim_counts_only_successful_broker_dispatches(self) -> None:
        def broker_failure(sender: type[OrmQ], instance: OrmQ, **kwargs: object) -> None:
            raise ConnectionError("QA broker unavailable")

        # Verify real ORM enqueue first, then a failure at that same broker boundary.
        for fail in (False, True):
            with self.subTest(broker_failure=fail):
                drain = NodeDrain.objects.create(server=self.server, status="pending")
                NodeDrain.objects.filter(pk=drain.pk).update(updated_at=timezone.now() - timedelta(hours=1))
                before = set(OrmQ.objects.values_list("pk", flat=True))
                if fail:
                    pre_save.connect(broker_failure, sender=OrmQ, weak=False)
                try:
                    counts = reclaim_stalled_virtualmin_operations()
                finally:
                    if fail:
                        pre_save.disconnect(broker_failure, sender=OrmQ)
                drain.refresh_from_db()
                packets = [
                    cast("dict[str, object]", SignedPackage.loads(row.payload))
                    for row in OrmQ.objects.exclude(pk__in=before)
                ]
                if fail:
                    self.assertEqual(drain.status, "paused_needs_review")
                    self.assertIn("QA broker unavailable", drain.error_detail)
                    self.assertEqual(packets, [])
                    self.assertEqual(counts["drains_requeued"], 0)
                else:
                    self.assertEqual(counts["drains_requeued"], 1)
                    self.assertEqual(drain.status, "pending")
                    packet = next(
                        item for item in packets if item["func"] == "apps.provisioning.virtualmin_tasks.run_node_drain"
                    )
                    self.assertEqual(
                        tuple(cast("tuple[object, ...]", packet["args"])), (str(drain.pk), str(drain.task_token))
                    )
                    # End the first fixture so the per-server active-drain constraint admits the next one.
                    NodeDrain.objects.filter(pk=drain.pk).update(status="cancelled")
