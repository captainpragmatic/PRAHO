"""The lab check must recover through actual failed jobs and claimed queue deliveries."""

from __future__ import annotations

import io
import json
from decimal import Decimal
from typing import Any
from unittest.mock import patch

import requests
from django.core.cache import cache
from django.core.management.base import CommandError
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.management.commands import virtualmin_lab_checks as checks
from apps.provisioning.management.commands._virtualmin_lab import LAB_STAFF_EMAIL, LabNode
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_gateway import VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.users.models import User
from tests.mocks.virtualmin_mock import MockVirtualminGateway


class _WireNode(MockVirtualminGateway):
    """External wire only: native state and responses still use the real gateway parser."""

    def __init__(self) -> None:
        super().__init__()
        self.descriptions: dict[str, str] = {}

    def _handle_create_domain(self, params: dict[str, Any]) -> dict[str, Any]:
        response = super()._handle_create_domain(params)
        self.descriptions[str(params["domain"])] = str(params.get("desc", ""))
        return response

    def _handle_list_domains(self, params: dict[str, Any]) -> dict[str, Any]:
        response = super()._handle_list_domains(params)
        for entry in response.get("data", []):
            if "values" in entry:
                entry["values"].update(
                    Template="Default Settings",
                    Features="unix dir web mysql",
                    Description=self.descriptions.get(entry["name"], ""),
                )
        return response

    def request(self, gateway: VirtualminGateway, params: dict[str, Any], **kwargs: Any) -> requests.Response:
        if params["program"] == "list-templates":
            body = json.dumps({"command": "list-templates", "status": "success", "data": ["Default Settings"]})
        else:
            result = self.call(
                str(params["program"]), {key: value for key, value in params.items() if key != "program"}
            )
            if result.is_err():
                raise result.unwrap_err()
            body = result.unwrap().raw_response
        response = requests.Response()
        response.status_code = 200
        response._content = body.encode()
        response.headers["Content-Type"] = "application/json"
        response.headers["Content-Length"] = str(len(response.content))
        return response


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "lab-create-retry"}},
    Q_CLUSTER={"name": "lab-create-retry", "orm": "default", "sync": False, "timeout": 60, "retry": 120},
)
class LabCreateRetryContractTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        Customer.objects.create(name="Virtualmin Lab SRL", primary_email="lab@praho.test")
        ServicePlan.objects.create(
            name="Virtualmin lab hosting", plan_type="shared_hosting", price_monthly=Decimal("0")
        )
        User.objects.create_user(email=LAB_STAFF_EMAIL, password="lab-only-password", is_staff=True, is_superuser=True)
        self.server = VirtualminServer.objects.create(
            name="Lab checks",
            hostname="vm-b.praho.test",
            api_username="api",
            status="active",
            max_domains=100,
            current_domains=0,
            last_health_check=timezone.now(),
        )
        self.server.set_api_password("lab-wire-password")
        self.server.save()
        self.node = LabNode("vm-b", "owned-wire-node", self.server.hostname, "fixture", 10102, 2523)
        self.wire = _WireNode()
        self.output = io.StringIO()
        self.command = checks.Command(stdout=self.output)
        self.enterContext(patch.object(checks, "CHECK_DOMAIN", "labcheck.example.com"))

        def request(gateway, params, **kwargs):
            return self.wire.request(gateway, params, **kwargs)

        self.enterContext(patch.object(VirtualminGateway, "_execute_http_request", request))

    def test_absent_then_present_recovery_uses_one_real_job_and_preserves_unrelated_queue(self) -> None:
        unrelated = OrmQ.objects.create(
            key="lab-create-retry",
            payload=SignedPackage.dumps(
                {
                    "func": "apps.provisioning.virtualmin_tasks.retry_virtualmin_job",
                    "args": ["00000000-0000-0000-0000-000000000001", "unrelated"],
                    "kwargs": {},
                }
            ),
        )

        account = self.command._check_create_domain(self.server, self.node)

        account.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(account.status, "active")
        self.assertEqual(VirtualminAccount.objects.filter(pk=account.pk).count(), 1)
        jobs = list(VirtualminProvisioningJob.objects.filter(account=account, operation="create_domain"))
        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0].status, "completed")
        self.assertEqual(jobs[0].retry_count, 2)
        self.assertEqual(jobs[0].result.get("recovered"), "remote domain already present")
        self.assertEqual(self.server.current_domains, 1)
        self.assertEqual(len(self.wire.get_calls("create-domain")), 1)
        self.assertEqual(len(self.wire.get_calls("delete-domain")), 0)
        self.assertEqual(len(self.wire.get_calls("enable-domain")), 0)
        self.assertTrue(OrmQ.objects.filter(pk=unrelated.pk).exists())
        self.assertIn("stale retry delivery performs no native I/O", self.output.getvalue())
        self.assertEqual(Service.objects.filter(pk=account.service_id).count(), 1)

    def test_owned_present_recovery_refuses_a_changed_native_owner(self) -> None:
        create = self.wire._handle_create_domain

        def foreign_owner(params):
            result = create(params)
            self.wire.domain_state_of(str(params["domain"])).username = "foreignowner"
            return result

        with (
            patch.object(self.wire, "_handle_create_domain", side_effect=foreign_owner),
            self.assertRaises(CommandError),
        ):
            self.command._check_create_domain(self.server, self.node)

        account = VirtualminAccount.objects.get(domain="labcheck.example.com")
        job = VirtualminProvisioningJob.objects.get(account=account, operation="create_domain")
        self.assertEqual(job.status, "failed")
        self.assertIsNone(job.next_retry_at)
        self.assertEqual(len(self.wire.get_calls("create-domain")), 1)
        self.assertEqual(len(self.wire.get_calls("delete-domain")), 0)
        self.assertEqual(self.wire.domain_state_of(account.domain).username, "foreignowner")
