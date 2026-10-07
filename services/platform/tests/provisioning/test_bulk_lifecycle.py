"""Bulk lifecycle actions keep Virtualmin and stored status consistent."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

import apps.provisioning.virtualmin_views as views
from apps.billing.models import Currency
from apps.common.types import Err, Ok, Result
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_gateway import VirtualminAPIError, VirtualminGateway, VirtualminResponse
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer

Operation = Callable[[list[VirtualminAccount]], views.BulkOperationResult]


class RemoteLifecycle:
    def __init__(self, accounts: list[VirtualminAccount]) -> None:
        self.statuses = {account.domain: account.status for account in accounts}
        self.failures: dict[str, str] = {}
        self.visited: list[tuple[str, str]] = []

    def call(
        self, gateway: VirtualminGateway, program: str, params: dict[str, object], *, correlation_id: str
    ) -> Result[VirtualminResponse, VirtualminAPIError]:
        domain = str(params["domain"])
        self.visited.append((program, domain))
        failure = self.failures.get(domain)
        if failure == "transport":
            return Err(VirtualminAPIError("Remote unavailable"))
        success = failure is None
        if success:
            self.statuses[domain] = "suspended" if program == "disable-domain" else "active"
        return Ok(
            VirtualminResponse(
                success=success,
                data={} if success else {"error": "Remote unavailable"},
                raw_response="",
                http_status=200,
                execution_time=0.01,
                program=program,
                server_hostname=gateway.config.server.hostname,
            )
        )


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    DISABLE_AUDIT_SIGNALS=True,
    LANGUAGE_CODE="en",
)
class BulkLifecycleTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(name="Lifecycle", primary_email="lifecycle@example.test")
        self.plan = ServicePlan.objects.create(
            name="Lifecycle", plan_type="shared_hosting", price_monthly=Decimal("10.00")
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.server = VirtualminServer.objects.create(
            name="lifecycle", hostname="lifecycle.example.test", api_username="lifecycle"
        )
        self.sequence = 0

    def accounts(self, status: str) -> list[VirtualminAccount]:
        result: list[VirtualminAccount] = []
        for _ in range(2):
            self.sequence += 1
            username = f"lifecycle{self.sequence}"
            domain = f"{username}.example.test"
            # fsm-bypass: establish existing services for lifecycle fixtures.
            service = Service.objects.create(
                customer=self.customer,
                service_plan=self.plan,
                currency=self.currency,
                service_name=domain,
                domain=domain,
                username=username,
                price=Decimal("10.00"),
                status="active",
            )
            result.append(
                VirtualminAccount.objects.create(
                    service=service,
                    server=self.server,
                    domain=domain,
                    virtualmin_username=username,
                    encrypted_password=b"",
                    status=status,
                )
            )
        return result

    def cases(self) -> list[tuple[Operation, str, str, str]]:
        return [
            (views._execute_bulk_suspend, "active", "suspended", "disable-domain"),
            (views._execute_bulk_activate, "suspended", "active", "enable-domain"),
        ]

    def test_success_confirms_each_remote_domain_before_reporting_success(self) -> None:
        for operation, initial, target, program in self.cases():
            with self.subTest(operation=operation.__name__):
                accounts = self.accounts(initial)
                remote = RemoteLifecycle(accounts)
                with (
                    patch.object(VirtualminGateway, "call", autospec=True, side_effect=remote.call),
                ):
                    result = operation(accounts)
                self.assertEqual(remote.statuses, dict.fromkeys((a.domain for a in accounts), target))
                self.assertEqual(remote.visited, [(program, a.domain) for a in accounts])
                self.assertEqual((result.successful_count, result.failed_count, result.errors), (2, 0, []))
                for account in accounts:
                    account.refresh_from_db()
                    self.assertEqual(account.status, target)
                    self.assertEqual(VirtualminProvisioningJob.objects.get(account=account).status, "completed")

    def test_remote_failure_preserves_status_and_reports_each_account(self) -> None:
        for operation, initial, _target, _program in self.cases():
            for failure in ("transport", "application"):
                with self.subTest(operation=operation.__name__, failure=failure):
                    accounts = self.accounts(initial)
                    remote = RemoteLifecycle(accounts)
                    remote.failures = dict.fromkeys((a.domain for a in accounts), failure)
                    with (
                        patch.object(VirtualminGateway, "call", autospec=True, side_effect=remote.call),
                    ):
                        result = operation(accounts)
                    for account in accounts:
                        account.refresh_from_db()
                        self.assertEqual(account.status, initial)
                        self.assertTrue(any(account.domain in error for error in result.errors), result.errors)
                        self.assertEqual(VirtualminProvisioningJob.objects.get(account=account).status, "failed")
                    self.assertEqual((result.successful_count, result.failed_count), (0, 2))
                    self.assertTrue(all("Remote unavailable" in error for error in result.errors))
                    self.assertFalse(result.rollback_performed)

    def test_retry_after_failure_reaches_virtualmin_and_completes(self) -> None:
        for operation, initial, target, program in self.cases():
            with self.subTest(operation=operation.__name__):
                accounts = self.accounts(initial)
                remote = RemoteLifecycle(accounts)
                remote.failures = dict.fromkeys((a.domain for a in accounts), "transport")
                with (
                    patch.object(VirtualminGateway, "call", autospec=True, side_effect=remote.call),
                ):
                    failed = operation(accounts)
                    self.assertEqual((failed.successful_count, failed.failed_count), (0, 2))
                    remote.failures.clear()
                    retried = operation(accounts)
                self.assertEqual(remote.visited, [(program, a.domain) for a in accounts] * 2)
                self.assertEqual(remote.statuses, dict.fromkeys((a.domain for a in accounts), target))
                self.assertEqual((retried.successful_count, retried.failed_count, retried.errors), (2, 0, []))
                for account in accounts:
                    account.refresh_from_db()
                    self.assertEqual(account.status, target)
                    self.assertCountEqual(
                        VirtualminProvisioningJob.objects.filter(account=account).values_list("status", flat=True),
                        ["failed", "completed"],
                    )

    def test_mixed_batch_saves_only_confirmed_accounts_and_can_retry_the_failure(self) -> None:
        for operation, initial, target, program in self.cases():
            with self.subTest(operation=operation.__name__):
                accounts = self.accounts(initial)
                remote = RemoteLifecycle(accounts)
                remote.failures[accounts[1].domain] = "application"
                with (
                    patch.object(VirtualminGateway, "call", autospec=True, side_effect=remote.call),
                ):
                    result = operation(accounts)
                    self.assertEqual((result.successful_count, result.failed_count), (1, 1))
                    for account, expected in zip(accounts, (target, initial), strict=True):
                        account.refresh_from_db()
                        self.assertEqual((account.status, remote.statuses[account.domain]), (expected, expected))
                    self.assertEqual(len(result.errors), 1)
                    self.assertIn(accounts[1].domain, result.errors[0])
                    self.assertIn("Remote unavailable", result.errors[0])
                    remote.failures.clear()
                    retried = operation([accounts[1]])
                self.assertEqual((retried.successful_count, retried.failed_count), (1, 0))
                self.assertEqual(remote.visited[-1], (program, accounts[1].domain))
                accounts[1].refresh_from_db()
                self.assertEqual((accounts[1].status, remote.statuses[accounts[1].domain]), (target, target))
