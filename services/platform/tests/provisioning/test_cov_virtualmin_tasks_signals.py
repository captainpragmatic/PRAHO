"""WP17 coverage additions for provisioning signals and encrypted dispatch."""

from __future__ import annotations

import json
from decimal import Decimal
from typing import cast
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from django_q.signing import SignedPackage
from requests import Response

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.provisioning import virtualmin_tasks
from apps.provisioning.models import ProvisioningTask, Server, Service, ServiceDomain, ServiceGroup, ServicePlan
from apps.provisioning.virtualmin_gateway import VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from tests.factories.core_factories import create_full_customer
from tests.fixtures.virtualmin.responses import info, list_domains
from tests.helpers.service_domains import ServiceDomainsFixture
from tests.helpers.task_queue import quiet_task_queue

LOCMEM = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "wp17-virtualmin-tasks",
    }
}


@override_settings(CACHES=LOCMEM, DISABLE_AUDIT_SIGNALS=False, VIRTUALMIN_AUTO_PROVISIONING_ENABLED=True)
class VirtualminCoverageCase(TestCase):
    """Shared real rows and an outer HTTP transport; no business-service mocks."""

    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.broker = quiet_task_queue(self)
        self.customer = create_full_customer()
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.plan = ServicePlan.objects.create(
            name="Coverage hosting", plan_type="shared_hosting", price_monthly=Decimal("10.00")
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="coverage.example.com",
            domain="coverage.example.com",
            username="coverage",
            price=Decimal("10.00"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="Coverage VM",
            hostname="vm-coverage.example.com",
            api_username="coverage-api",
            status="active",
            max_domains=100,
            current_domains=3,
            last_health_check=timezone.now(),
        )
        self.server.set_api_password("transport-password")
        self.server.save(update_fields=["encrypted_api_password"])
        self.requests: list[dict[str, object]] = []
        self.rejections: dict[str, str] = {}
        transport = patch.object(VirtualminGateway, "_execute_http_request", autospec=True, side_effect=self._http)
        transport.start()
        self.addCleanup(transport.stop)

    def _http(
        self,
        gateway: VirtualminGateway,
        params: dict[str, object],
        auth: tuple[str, str] | None = None,
        timeout_seconds: int | None = None,
    ) -> Response:
        self.requests.append(dict(params))
        program = str(params["program"])
        payload: dict[str, object]
        if program in self.rejections:
            payload = {"status": "failure", "error": self.rejections[program]}
        elif program == "info":
            payload = info.server_info(hostname=gateway.server.hostname)
        elif program == "list-domains":
            payload = list_domains.name_only(["other.example.com owner Other hosting"])
        elif program in ("disable-domain", "enable-domain", "delete-domain"):
            payload = {"status": "success", "data": {"domain": self.service.domain}}
        else:
            raise AssertionError(f"Unexpected Virtualmin HTTP program: {program}")
        response = Response()
        response.status_code = 200
        response._content = json.dumps(payload).encode()
        response._content_consumed = True
        response.headers["Content-Type"] = "application/json"
        return response

    def _account(self, status: str = "active") -> VirtualminAccount:
        return VirtualminAccount.objects.create(
            service=self.service,
            server=self.server,
            domain=self.service.domain,
            virtualmin_username=self.service.username,
            status=status,
            protected_from_deletion=False,
            praho_customer_id=self.customer.pk,
        )

    def _event(self, event_type: str, object_id: object) -> AuditEvent:
        return AuditEvent.objects.get(action=event_type, object_id=str(object_id))

    def _packages(self) -> list[dict[str, object]]:
        return [cast("dict[str, object]", SignedPackage.loads(package)) for package in self.broker.packages]


class ProvisioningSignalEffectsTests(VirtualminCoverageCase):
    def test_task_deletion_preserves_identity_and_last_state_in_audit(self) -> None:
        task = ProvisioningTask.objects.create(
            service=self.service, task_type="backup_service", status="failed", retry_count=2
        )
        task_id = task.pk
        task.delete()
        self.assertFalse(ProvisioningTask.objects.filter(pk=task_id).exists())
        event = self._event("provisioning_task_deleted", task_id)
        self.assertEqual(
            event.old_values,
            {
                "task_id": str(task_id),
                "service_id": str(self.service.pk),
                "task_type": "backup_service",
                "status": "failed",
                "retry_count": 2,
            },
        )
        self.assertEqual(event.metadata["model"], "ProvisioningTask")

    def test_group_deletion_records_customer_and_status(self) -> None:
        group = ServiceGroup.objects.create(customer=self.customer, name="Coverage bundle", group_type="bundle")
        group_id = group.pk
        group.delete()
        self.assertFalse(ServiceGroup.objects.filter(pk=group_id).exists())
        event = self._event("service_group_deleted", group_id)
        self.assertEqual(event.old_values["customer_id"], str(self.customer.pk))
        self.assertEqual(event.old_values["status"], "pending")
        self.assertEqual(event.old_values["name"], "Coverage bundle")

    def test_disabled_audit_allows_deletion_without_lifecycle_events(self) -> None:
        task = ProvisioningTask.objects.create(service=self.service, task_type="backup_service")
        task_id = task.pk
        with self.settings(DISABLE_AUDIT_SIGNALS=True):
            task.delete()
        self.assertFalse(ProvisioningTask.objects.filter(pk=task_id).exists())
        self.assertFalse(AuditEvent.objects.filter(action="provisioning_task_deleted", object_id=str(task_id)).exists())

    def test_plan_deactivation_records_the_new_state(self) -> None:
        self.plan.is_active = False
        self.plan.save(update_fields=["is_active"])
        self.assertFalse(ServicePlan.objects.get(pk=self.plan.pk).is_active)
        self.assertEqual(self._event("service_plan_status_changed", self.plan.pk).new_values, {"is_active": False})

    def test_server_non_status_update_does_not_emit_a_status_event(self) -> None:
        server = Server.objects.create(
            name="Coverage server",
            hostname="coverage-server.example.com",
            server_type="shared",
            primary_ip="192.0.2.10",
            cpu_cores=4,
            ram_gb=8,
            disk_capacity_gb=100,
        )
        server.name = "Renamed server"
        server.save(update_fields=["name"])
        self.assertEqual(Server.objects.get(pk=server.pk).name, "Renamed server")
        self.assertFalse(AuditEvent.objects.filter(action="server_status_changed", object_id=str(server.pk)).exists())

    def test_service_non_status_update_does_not_enqueue_reconciliation(self) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            self.service.service_name = "Renamed hosting"
            self.service.save(update_fields=["service_name"])
        self.assertEqual(Service.objects.get(pk=self.service.pk).service_name, "Renamed hosting")
        self.assertEqual(self.broker.queued(), [])

    def test_service_transition_enqueues_after_commit_even_with_audit_disabled(self) -> None:
        with self.settings(DISABLE_AUDIT_SIGNALS=True), self.captureOnCommitCallbacks(execute=True):
            self.service.suspend("Unpaid")
            self.service.save(update_fields=["status", "suspension_reason"])
            self.assertEqual(self.broker.queued(), [])
        self.assertEqual(Service.objects.get(pk=self.service.pk).status, "suspended")
        self.assertEqual(
            self.broker.queued(),
            [("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state", str(self.service.pk))],
        )

    def test_non_hosting_service_does_not_schedule_an_account(self) -> None:
        self.plan.plan_type = "domain"
        self.plan.save(update_fields=["plan_type"])
        virtualmin_tasks.reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertEqual(self.broker.queued(), [])
        self.assertFalse(VirtualminAccount.objects.filter(service=self.service).exists())

    def test_missing_domain_does_not_schedule_an_account(self) -> None:
        self.service.domain = ""
        self.service.save(update_fields=["domain"])
        virtualmin_tasks.reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertEqual(self.broker.queued(), [])
        self.assertFalse(VirtualminAccount.objects.filter(service=self.service).exists())

    def test_disabled_audit_keeps_plan_status_change_without_event(self) -> None:
        with self.settings(DISABLE_AUDIT_SIGNALS=True):
            self.plan.is_active = False
            self.plan.save(update_fields=["is_active"])
        self.assertFalse(ServicePlan.objects.get(pk=self.plan.pk).is_active)
        self.assertFalse(
            AuditEvent.objects.filter(action="service_plan_status_changed", object_id=str(self.plan.pk)).exists()
        )

    def test_group_update_audit_records_the_new_name(self) -> None:
        group = ServiceGroup.objects.create(customer=self.customer, name="Original bundle", group_type="bundle")
        group.name = "Renamed bundle"
        group.save(update_fields=["name"])
        self.assertEqual(ServiceGroup.objects.get(pk=group.pk).name, "Renamed bundle")
        event = self._event("service_group_updated", group.pk)
        self.assertEqual(event.new_values["name"], "Renamed bundle")
        self.assertEqual(event.metadata["model"], "ServiceGroup")


class ServiceDomainSignalEffectsTests(ServiceDomainsFixture):
    def test_disabled_audit_binding_still_persists_the_domain(self) -> None:
        with self.settings(DISABLE_AUDIT_SIGNALS=True):
            binding = ServiceDomain.objects.create(
                service=self.service, domain=self.primary.domain, domain_type="subdomain", subdomain="quiet"
            )
        self.assertEqual(ServiceDomain.objects.get(pk=binding.pk).full_domain_name, "quiet.wp8-example.com")
        self.assertFalse(AuditEvent.objects.filter(action="service_domain_bound", object_id=str(binding.pk)).exists())

    def test_domain_update_keeps_the_original_binding_evidence(self) -> None:
        event = AuditEvent.objects.get(action="service_domain_bound", object_id=str(self.primary.pk))
        self.primary.ssl_enabled = False
        self.primary.save(update_fields=["ssl_enabled"])
        event.refresh_from_db()
        self.assertFalse(ServiceDomain.objects.get(pk=self.primary.pk).ssl_enabled)
        self.assertEqual(event.new_values["ssl_enabled"], True)
        self.assertEqual(
            list(AuditEvent.objects.filter(action="service_domain_bound", object_id=str(self.primary.pk))),
            [event],
        )
