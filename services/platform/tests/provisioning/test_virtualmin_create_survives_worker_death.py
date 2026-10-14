"""A domain created on the server must never be left without a local record of it.

The provisioning task used to hold one transaction across the whole flow, including the HTTP
call that creates the domain. If the worker died after the server had accepted the create
(a queue timeout, a killed process, a database error), the transaction rolled back. The account
and job rows vanished while the domain stayed on the server. The retry path needs the job row,
and a fresh provision stopped at "already exists on server" as not retriable, so the service
was stuck with nobody able to say what had happened.

Intent is now committed before the HTTP call and no transaction or row lock spans it. These
tests use a real rollback, so they are TransactionTestCase.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from typing import cast
from unittest.mock import patch

from django.core.cache import cache
from django.test import TransactionTestCase, override_settings
from django.utils import timezone
from requests import Response

from apps.billing.models import Currency
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_gateway import VirtualminGateway
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.provisioning.virtualmin_tasks import VirtualminProvisioningParams, provision_virtualmin_account

LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


class WorkerDied(BaseException):
    """Stands in for a killed worker or a queue timeout.

    Not an Exception on purpose: it escapes every `except Exception` in the task.
    """


@override_settings(CACHES=LOCMEM)
class WorkerDeathAfterRemoteCreateTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        customer = Customer.objects.create(
            name="Crash hosting customer", customer_type="individual", primary_email="crash@example.com"
        )
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(name="Crash plan", plan_type="shared_hosting", price_monthly=Decimal("10"))
        self.service = Service.objects.create(
            customer=customer,
            currency=currency,
            service_plan=plan,
            service_name="crash.example.com",
            domain="crash.example.com",
            billing_cycle="monthly",
            price=Decimal("10"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="crash-node",
            hostname="crash-node.example.com",
            api_username="crash-api",
            status="active",
            last_health_check=timezone.now(),
        )
        self.server.set_api_password("CrashServerPassword123!")
        self.server.save()
        self.sent: list[dict[str, object]] = []

    def http(self, method: str, url: str, **kwargs: object) -> Response:
        params = dict(cast("dict[str, object]", kwargs["params"]))
        self.sent.append(params)
        program = params["program"]
        if program == "info":
            payload: dict[str, object] = {"output": "disk_free: 104857600000\ndisk_total: 209715200000\n"}
        elif program == "list-domains":
            payload = {"data": []}
        elif program == "list-templates":
            payload = {"data": ["Default"]}
        else:
            payload = {"output": "Domain created\n"}
        response = Response()
        response.status_code = 200
        response._content = json.dumps({"command": program, "status": "success", **payload}).encode()
        response._content_consumed = True
        return response

    def creates(self) -> int:
        return len([params for params in self.sent if params["program"] == "create-domain"])

    def provision_and_die(self) -> None:
        """Let the server accept create-domain, then kill the worker before it can record anything."""
        params = cast(
            "VirtualminProvisioningParams",
            {"service_id": self.service.pk, "domain": self.service.domain, "server_id": str(self.server.pk)},
        )
        real_call: Callable[..., object] = VirtualminGateway.call

        def call_then_die(gateway: VirtualminGateway, program: str, *args: object, **kwargs: object) -> object:
            result = real_call(gateway, program, *args, **kwargs)
            if program == "create-domain":
                raise WorkerDied
            return result

        with (
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http),
            patch.object(VirtualminGateway, "call", autospec=True, side_effect=call_then_die),
            self.assertRaises(WorkerDied),
        ):
            provision_virtualmin_account(params)

    def test_worker_death_after_remote_create_leaves_job_row_for_convergent_retry(self) -> None:
        self.provision_and_die()

        self.assertEqual(self.creates(), 1, "the server accepted the create before the worker died")
        account = VirtualminAccount.objects.get(service=self.service)
        job = VirtualminProvisioningJob.objects.get(account=account, operation="create_domain")
        self.assertEqual(account.status, "provisioning")
        self.assertEqual(job.status, "running")

        # The recovery sweep turns the stranded job into a retryable one.
        later = timezone.now() + timedelta(hours=1)
        recovered = VirtualminProvisioningJob.recover_expired_claims(later, later, now=later)
        self.assertEqual(recovered, 1)
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertIsNotNone(job.next_retry_at)

        # The domain exists on the server under the expected owner, so the retry adopts it.
        with (
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http),
            patch(
                "apps.provisioning.virtualmin_gateway.VirtualminGateway.get_domain_owner",
                return_value=Ok(account.virtualmin_username),
            ),
        ):
            outcome = VirtualminProvisioningService(self.server).retry_job(job)

        self.assertTrue(outcome.is_ok(), outcome)
        account.refresh_from_db()
        job.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(account.status, "active")
        self.assertEqual(job.status, "completed")
        self.assertEqual(self.server.current_domains, 1)
        self.assertEqual(self.creates(), 1, "the retry must adopt the domain, not create it again")
        self.assertEqual(VirtualminAccount.objects.filter(service=self.service).count(), 1)

    def test_no_row_lock_or_transaction_spans_the_remote_create(self) -> None:
        from django.db import connection  # noqa: PLC0415

        seen: list[bool] = []

        def http(method: str, url: str, **kwargs: object) -> Response:
            if cast("dict[str, object]", kwargs["params"])["program"] == "create-domain":
                seen.append(connection.in_atomic_block)
            return self.http(method, url, **kwargs)

        params = cast(
            "VirtualminProvisioningParams",
            {"service_id": self.service.pk, "domain": self.service.domain, "server_id": str(self.server.pk)},
        )
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=http):
            outcome = provision_virtualmin_account(params)

        self.assertTrue(outcome["success"], outcome)
        self.assertEqual(seen, [False], "the create-domain call must run outside any transaction")

    def test_worker_death_between_activation_and_counter_still_counts_the_domain(self) -> None:
        """The account, the server's domain count and the job complete together, or not at all.

        If the worker dies after the account is saved as active but before the server's count is
        raised, recovery sees an active account and skips the increment, so the server admits more
        domains than its limit.
        """
        from django.db import models  # noqa: PLC0415

        real_f = models.F

        def die_on_counter(name: str, *args: object, **kwargs: object) -> object:
            if name == "current_domains":
                raise WorkerDied
            return real_f(name, *args, **kwargs)

        params = cast(
            "VirtualminProvisioningParams",
            {"service_id": self.service.pk, "domain": self.service.domain, "server_id": str(self.server.pk)},
        )
        with (
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http),
            patch("apps.provisioning.virtualmin_service.models.F", side_effect=die_on_counter),
            self.assertRaises(WorkerDied),
        ):
            provision_virtualmin_account(params)

        account = VirtualminAccount.objects.get(service=self.service)
        job = VirtualminProvisioningJob.objects.get(account=account, operation="create_domain")
        later = timezone.now() + timedelta(hours=1)
        VirtualminProvisioningJob.recover_expired_claims(later, later, now=later)
        job.refresh_from_db()
        with (
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http),
            patch(
                "apps.provisioning.virtualmin_gateway.VirtualminGateway.get_domain_owner",
                return_value=Ok(account.virtualmin_username),
            ),
        ):
            outcome = VirtualminProvisioningService(self.server).retry_job(job)

        self.assertTrue(outcome.is_ok(), outcome)
        self.server.refresh_from_db()
        account.refresh_from_db()
        self.assertEqual(account.status, "active")
        self.assertEqual(self.server.current_domains, 1, "the created domain must be counted exactly once")
        self.assertEqual(self.creates(), 1)

    def test_worker_death_during_delete_bookkeeping_leaves_the_count_untouched(self) -> None:
        """The server's count, the account's terminated status and the job move together.

        A worker that died after the count went down but before the account was marked terminated
        left the domain uncounted while the account still looked live, and a retried delete took
        the count down again.
        """
        VirtualminServer.objects.filter(pk=self.server.pk).update(current_domains=2)
        self.server.refresh_from_db()
        account = VirtualminAccount.objects.create(
            domain=self.service.domain,
            service=self.service,
            server=self.server,
            virtualmin_username="crashexample",
            template_name="Default",
            status="error",
            protected_from_deletion=False,
            praho_customer_id=self.service.customer_id,
            praho_service_id=self.service.id,
        )
        real_save = VirtualminAccount.save

        def save_or_die(instance: VirtualminAccount, *args: object, **kwargs: object) -> None:
            if instance.status == "terminated":
                raise WorkerDied
            real_save(instance, *args, **kwargs)

        with (
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http),
            patch.object(VirtualminAccount, "save", autospec=True, side_effect=save_or_die),
            self.assertRaises(WorkerDied),
        ):
            VirtualminProvisioningService(self.server).delete_account(account)

        self.server.refresh_from_db()
        account.refresh_from_db()
        self.assertEqual(account.status, "error")
        self.assertEqual(self.server.current_domains, 2, "the count must not drop without the account's status")

    def test_a_failed_create_bookkeeping_does_not_take_the_count_down_twice(self) -> None:
        """The transaction already undoes the increment, so the error path must not revert it again."""
        VirtualminServer.objects.filter(pk=self.server.pk).update(current_domains=3)
        params = cast(
            "VirtualminProvisioningParams",
            {"service_id": self.service.pk, "domain": self.service.domain, "server_id": str(self.server.pk)},
        )
        with (
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http),
            patch.object(VirtualminProvisioningJob, "mark_completed", side_effect=RuntimeError("database went away")),
        ):
            outcome = provision_virtualmin_account(params)

        self.assertFalse(outcome["success"], outcome)
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 3, "a create that was undone must leave the count as it was")
