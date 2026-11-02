"""Current public revocation must survive normal failed-create sweep delivery."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from decimal import Decimal
from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.db import DatabaseError, connection
from django.test import TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.billing.models import Currency
from apps.common.types import Err, Retriability
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.services import OrderService, StatusChangeData
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_backup_service import RestoreConfig
from apps.provisioning.virtualmin_gateway import VirtualminAPIError
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_node_capability import destination_refusal
from apps.provisioning.virtualmin_service import (
    VirtualminAccountCreationData,
    VirtualminBackupManagementService,
    VirtualminProvisioningService,
)
from apps.provisioning.virtualmin_tasks import (
    RetryableProvisioningError,
    process_failed_virtualmin_jobs,
    provision_virtualmin_account,
    reconcile_divergent_services_task,
)
from apps.settings.services import SettingsService
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status
from tests.mocks.virtualmin_mock import MockVirtualminGateway

RETRY = "apps.provisioning.virtualmin_tasks.retry_virtualmin_job"
RECONCILE = "apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state"


class _RetryGateway(MockVirtualminGateway):
    """Only the external node boundary: one known-unaccepted create, then normal state."""

    fail_first_create = True
    first_create_accepted = False
    first_create_retriability = Retriability.RETRIABLE
    after_accepted_create: Callable[[], None] | None = None
    before_disable: Callable[[], None] | None = None
    lose_disable_response = False
    after_accepted_disable: Callable[[], None] | None = None
    after_state_read: Callable[[], None] | None = None
    disable_failure: Retriability | None = None

    def _handle_list_domains(self, params: dict[str, Any]) -> dict[str, Any]:
        response = super()._handle_list_domains(params)
        # The shared single-domain fixture defaults Status to Enabled even after
        # its stateful node accepted disable. Keep this external wire observation
        # faithful; the real state parser and production proof stay unchanged.
        for item in response.get("data", []):
            native = self.domain_state_of(item.get("name", ""))
            if native is not None and "values" in item:
                item["values"]["Status"] = "Enabled" if native.enabled else "Disabled"
        return response

    def get_domain_state(self, domain: str) -> Any:
        result = super().get_domain_state(domain)
        if self.after_state_read is not None:
            callback, self.after_state_read = self.after_state_read, None
            callback()
        return result

    def call(self, program: str, *args: Any, **kwargs: Any) -> Any:
        if connection.in_atomic_block:
            raise AssertionError(f"Native {program} executed inside a database transaction")
        if program == "create-domain" and self.fail_first_create:
            self.fail_first_create = False
            if self.first_create_accepted:
                super().call(program, *args, **kwargs)
            else:
                self._record_call(program, args[0] if args else {}, success=False)
            return Err(
                VirtualminAPIError("Create outcome unavailable", retriability=self.first_create_retriability),
                retriability=self.first_create_retriability,
            )
        if program == "disable-domain" and self.before_disable is not None:
            callback, self.before_disable = self.before_disable, None
            callback()
        if program == "disable-domain" and self.disable_failure is not None:
            self._record_call(program, args[0] if args else {}, success=False)
            return Err(
                VirtualminAPIError("Known unaccepted OFF failure", retriability=self.disable_failure),
                retriability=self.disable_failure,
            )
        result = super().call(program, *args, **kwargs)
        if program == "disable-domain" and result.is_ok():
            if self.after_accepted_disable is not None:
                callback, self.after_accepted_disable = self.after_accepted_disable, None
                callback()
            if self.lose_disable_response:
                return Err(
                    VirtualminAPIError("OFF response lost", retriability=Retriability.UNKNOWN),
                    retriability=Retriability.UNKNOWN,
                )
        if program == "create-domain" and result.is_ok() and self.after_accepted_create is not None:
            callback, self.after_accepted_create = self.after_accepted_create, None
            callback()
        return result


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "create-retry-policy"}},
)
class CreateRetryFixture(TransactionTestCase):
    """Real public writers, on_commit publications, claimed jobs and ORM queue payloads."""

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(
            name="Retry Buyer",
            customer_type="company",
            company_name="Retry Buyer SRL",
            primary_email="retry-buyer@example.com",
            status="active",
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.plan = ServicePlan.objects.create(
            name="Retry hosting", plan_type="shared_hosting", price_monthly=Decimal("10")
        )
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name="retry.example.com",
            domain="retry.example.com",
            username="retrybuyer",
            billing_cycle="monthly",
            price=Decimal("10"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            legacy_security_admission=True,
            name="Retry node",
            hostname="retry-node.example.com",
            api_username="api",
            status="active",
            max_domains=100,
            current_domains=0,
            last_health_check=timezone.now(),
        )
        self.server.set_api_password("fixture-password")
        self.server.save()
        self.assertIsNone(destination_refusal(self.server))
        self.product = Product.objects.create(
            slug="retry-hosting",
            name="Retry Hosting",
            product_type="shared_hosting",
            default_service_plan=self.plan,
        )
        self.order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            billing_address={},
            subtotal_cents=1000,
            total_cents=1000,
        )
        force_status(self.order, "provisioning")
        self.line = OrderItem.objects.create(
            order=self.order,
            product=self.product,
            product_name="Retry Hosting",
            product_type="shared_hosting",
            quantity=1,
            unit_price_cents=1000,
            line_total_cents=1000,
            service=self.service,
            domain_name=self.service.domain,
            provisioning_status="in_progress",
        )
        self.operator = User.objects.create_user(
            email="retry-admin@example.com",
            password="fixture-password",
            is_staff=True,
            staff_role="admin",
        )
        self.gateway = _RetryGateway()
        native = patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=self.gateway)
        native.start()
        self.addCleanup(native.stop)

    def _failed_public_create(self) -> None:
        try:
            outcome = provision_virtualmin_account(
                {
                    "service_id": str(self.service.pk),
                    "domain": self.service.domain,
                    "username": self.service.username,
                    "password": None,
                    "template": "Default Settings",
                    "server_id": str(self.server.pk),
                }
            )
        except RetryableProvisioningError:
            outcome = None
        self.assertIsNone(outcome, outcome)
        self._assert_real_failed_create("active")

    def _assert_real_failed_create(self, expected_service_status: str) -> None:
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, expected_service_status)
        self.account = VirtualminAccount.objects.get(service=self.service)
        self.job = VirtualminProvisioningJob.objects.get(account=self.account, operation="create_domain")
        self.assertEqual(self.account.status, "error")
        self.assertEqual(self.job.status, "failed")
        self.assertIsNotNone(self.job.next_retry_at)
        self.assertEqual(self.job.retry_count, 0)
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))

    def _failed_direct_create(
        self,
        service_status: str,
        *,
        attach_order: bool = False,
        domain: str = "manual-retry.example.com",
        customer: Customer | None = None,
    ) -> None:
        # This public service API accepts non-active recovery inputs independently of
        # secure task admission. Preserve that actual contract in the retry consumer.
        self.service = Service.objects.create(
            customer=customer or self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=domain,
            domain=domain,
            username=f"mretry{Service.objects.count()}",
            billing_cycle="monthly",
            price=Decimal("10"),
            status=service_status,
        )
        if attach_order:
            self.line.service = self.service
            self.line.save(update_fields=["service"])
        self.gateway.fail_first_create = True
        result = VirtualminProvisioningService(self.server).create_virtualmin_account(
            VirtualminAccountCreationData(
                service=self.service,
                domain=self.service.domain,
                username=self.service.username,
                template="Default Settings",
                server=self.server,
            )
        )
        self.assertTrue(result.is_err(), result)
        self._assert_real_failed_create(service_status)

    def _deliver_owned(self, function: str, owned_id: str) -> list[Any]:
        results = []
        for row in list(OrmQ.objects.order_by("pk")):
            task = SignedPackage.loads(row.payload)
            if task["func"] != function or not task.get("args") or str(task["args"][0]) != owned_id:
                continue
            row.delete()  # Consume only this fixture's exact normal queue publication.
            results.append(import_string(function)(*task["args"], **task.get("kwargs", {})))
        return results

    def _deliver_revocation_callbacks(self) -> None:
        # Customer cascade runs on the real POST's commit; only reconcile is queued.
        outcomes = self._deliver_owned(RECONCILE, str(self.service.pk))
        self.assertTrue(outcomes, "Public revocation did not publish its normal reconciliation")
        self.assertTrue(all(outcome.get("action") == "noop" for outcome in outcomes), outcomes)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, "error")

    def _due_sweep(self) -> dict[str, Any]:
        self.job.refresh_from_db()
        due = self.job.next_retry_at + timedelta(seconds=1)
        with patch("django.utils.timezone.now", return_value=due):
            return process_failed_virtualmin_jobs()

    def _deliver_receipt_off(self) -> dict[str, Any]:
        jobs = list(
            VirtualminProvisioningJob.objects.filter(
                operation="suspend_domain",
                account=self.account,
                parameters__revoked_create_job_id=str(self.job.pk),
            )
        )
        self.assertEqual(len(jobs), 1, "Revoked actual native success needs exactly one receipt-bound OFF job")
        delivered = self._deliver_owned(RETRY, str(jobs[0].pk))
        self.assertEqual(len(delivered), 1, delivered)
        return delivered[0]

    def _retry_through_public_sweep(self, *, before_delivery: Callable[[], None] | None = None) -> dict[str, Any]:
        self.job.refresh_from_db()
        previous_attempts = self.job.retry_count
        swept = self._due_sweep()
        self.assertTrue(swept["success"], swept)
        self.assertEqual(swept["results"]["retried_jobs"], 1, swept)
        pending = VirtualminProvisioningJob.objects.get(pk=self.job.pk)
        self.assertEqual(pending.status, "pending")
        self.assertEqual(pending.retry_count, previous_attempts + 1)
        if before_delivery is not None:
            before_delivery()
        deliveries = self._deliver_owned(RETRY, str(self.job.pk))
        self.assertEqual(len(deliveries), 1, deliveries)
        return deliveries[0]

    def _cancel_and_run_normal_reconcile(self) -> None:
        result = OrderService.update_order_status(self.order, StatusChangeData("cancelled", changed_by=self.operator))
        self.assertTrue(result.is_ok(), result)
        outcomes = self._deliver_owned(RECONCILE, str(self.service.pk))
        self.assertTrue(outcomes)
        self.assertTrue(all(outcome.get("action") == "noop" for outcome in outcomes), outcomes)


class CreateRetryCurrentPolicyTests(CreateRetryFixture):
    def test_accepted_retry_database_settlement_failure_preserves_native_review_without_delete(self) -> None:
        self._failed_public_create()
        interrupted = False

        def settlement_failure(
            execute: Callable[..., Any], sql: str, params: Any, many: bool, context: dict[str, Any]
        ) -> Any:
            nonlocal interrupted
            if (
                not interrupted
                and sql.startswith(f'UPDATE "{VirtualminAccount._meta.db_table}"')
                and len(self.gateway.get_calls("create-domain")) == 2
            ):
                interrupted = True
                raise DatabaseError("Injected one-shot accepted-create settlement failure")
            return execute(sql, params, many, context)

        with connection.execute_wrapper(settlement_failure):
            outcome = self._retry_through_public_sweep()
        self.assertTrue(interrupted, "The test never reached accepted native creation settlement")
        self.assertFalse(outcome["success"], outcome)
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(
            self.job.status, "attention", "An actual native success was left as a failed replayable create"
        )
        self.assertIsNone(self.job.next_retry_at)
        self.assertEqual(self.job.result["creation_review"]["server_id"], str(self.server.pk))
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(self.account.status, "error")
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 2)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def _enable_account_names(self) -> None:
        for key, value in (
            ("dns.account_hostname_zone", "praho-sites.net"),
            ("dns.account_hostname_zone_id", "0123456789abcdef0123456789abcdef"),
            ("dns.account_zone_api_token", "retry-fixture-token"),
            ("dns.account_hostnames_enabled", True),
        ):
            self.assertTrue(SettingsService.update_setting(key, value).is_ok(), key)

    def _ready_publications(self) -> list[dict[str, Any]]:
        return [
            task
            for row in OrmQ.objects.order_by("pk")
            if (task := SignedPackage.loads(row.payload))["func"]
            == "apps.provisioning.account_hostname_lifecycle.ensure_account_name"
            and task.get("args", [None])[0] == str(self.account.pk)
        ]

    def test_allowed_retry_publishes_the_real_enabled_account_name_hook_once(self) -> None:
        self._enable_account_names()
        self._failed_public_create()
        self.assertEqual(self._ready_publications(), [])
        outcome = self._retry_through_public_sweep()
        self.assertTrue(outcome["success"], outcome)
        self.assertEqual(len(self._ready_publications()), 1)

    def test_revocation_inside_native_retry_does_not_publish_account_name_ready(self) -> None:
        self._enable_account_names()
        self._failed_direct_create("provisioning", attach_order=True)
        self.gateway.after_accepted_create = self._cancel_and_run_normal_reconcile
        outcome = self._retry_through_public_sweep()
        self.assertFalse(outcome["success"], outcome)
        self.assertEqual(self._ready_publications(), [], "Revoked creation queued a ready hook before policy recovery")
        self.assertTrue(self._deliver_receipt_off()["success"])

    def test_real_failed_secure_create_can_retry_on_the_same_rows(self) -> None:
        self._failed_public_create()
        result = self._retry_through_public_sweep()
        self.assertTrue(result["success"], result)
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(self.account.status, "active")
        self.assertEqual(self.job.status, "completed")
        self.assertEqual(self.server.current_domains, 1)
        self.assertEqual(VirtualminAccount.objects.filter(service=self.service).count(), 1)
        self.assertEqual(
            VirtualminProvisioningJob.objects.filter(account=self.account, operation="create_domain").count(), 1
        )
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 2)  # One rejected original, one accepted retry.

    def test_direct_provisioning_service_without_order_can_retry(self) -> None:
        self._failed_direct_create("provisioning")
        self.assertFalse(OrderItem.objects.filter(service=self.service).exists())
        result = self._retry_through_public_sweep()
        self.assertTrue(result["success"], result)
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)

    def test_direct_failed_service_without_order_can_retry(self) -> None:
        self._failed_direct_create("failed")
        self.assertFalse(OrderItem.objects.filter(service=self.service).exists())
        result = self._retry_through_public_sweep()
        self.assertTrue(result["success"], result)
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)

    def test_real_failed_reprovision_retries_the_existing_account(self) -> None:
        account = VirtualminAccount.objects.create(
            domain=self.service.domain,
            service=self.service,
            server=self.server,
            virtualmin_username=self.service.username,
            template_name="Default Settings",
            status="active",
            praho_customer_id=self.customer.pk,
            praho_service_id=self.service.pk,
        )
        account.set_password("fixture-password")
        account.save()
        result = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(account, self.server)
        self.assertTrue(result.is_err(), result)
        self._assert_real_failed_create("active")
        retried = self._retry_through_public_sweep()
        self.assertTrue(retried["success"], retried)
        self.assertEqual(VirtualminAccount.objects.get(service=self.service).pk, account.pk)
        self.assertTrue(self.gateway.domain_state_of(account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 2)

    def test_cancelled_order_cannot_be_created_after_normal_reconciliation(self) -> None:
        self._failed_public_create()
        cancelled = OrderService.update_order_status(
            self.order, StatusChangeData("cancelled", changed_by=self.operator)
        )
        self.assertTrue(cancelled.is_ok(), cancelled)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "suspended")
        self._deliver_revocation_callbacks()
        self._retry_through_public_sweep()
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain), "Retry created hosting after cancellation")
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

        self.job.refresh_from_db()
        self.assertNotEqual(self.job.status, "running")

    def test_customer_suspension_cannot_be_created_after_normal_reconciliation(self) -> None:
        self._failed_public_create()
        self.client.force_login(self.operator)
        response = self.client.post(reverse("customers:status_change", args=[self.customer.pk, "suspend"]))
        self.assertEqual(response.status_code, 302)
        self._deliver_revocation_callbacks()
        self.customer.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.customer.status, "suspended")
        self.assertEqual(self.service.status, "suspended")
        swept = self._due_sweep()
        self.assertTrue(swept["success"], swept)
        self.assertEqual(swept["results"]["retried_jobs"], 0)
        self.job.refresh_from_db()
        self.assertEqual(self.job.retry_count, 0)
        self.assertEqual(self._deliver_owned(RETRY, str(self.job.pk)), [])
        self.assertIsNone(
            self.gateway.domain_state_of(self.account.domain), "Retry created hosting for suspended customer"
        )
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_customer_suspended_after_queue_publication_cannot_be_created(self) -> None:
        self._failed_public_create()

        def suspend_and_reconcile() -> None:
            self.client.force_login(self.operator)
            response = self.client.post(reverse("customers:status_change", args=[self.customer.pk, "suspend"]))
            self.assertEqual(response.status_code, 302)
            self._deliver_revocation_callbacks()

        self._retry_through_public_sweep(before_delivery=suspend_and_reconcile)
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.job.refresh_from_db()
        self.assertNotEqual(self.job.status, "running")

    def test_held_manual_service_can_resume_without_resetting_retry_budget(self) -> None:
        self._failed_direct_create("active")
        self.client.force_login(self.operator)
        suspended = self.client.post(reverse("customers:status_change", args=[self.customer.pk, "suspend"]))
        self.assertEqual(suspended.status_code, 302)
        self._deliver_revocation_callbacks()
        self.assertEqual(self._due_sweep()["results"]["retried_jobs"], 0)
        resumed = self.client.post(reverse("customers:status_change", args=[self.customer.pk, "unsuspend"]))
        self.assertEqual(resumed.status_code, 302)
        # A legitimate staff decision for this manual/no-order Service, preserving
        # the normal customer/payment controls; never revive a cancelled order.
        approved = self.client.post(reverse("provisioning:service_activate", args=[self.service.pk]))
        self.assertEqual(approved.status_code, 302)
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "active")
        result = self._retry_through_public_sweep()
        self.assertTrue(result["success"], result)
        self.job.refresh_from_db()
        self.assertEqual(self.job.retry_count, 1)
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)

    def test_cancellation_during_native_success_converges_the_created_domain_off(self) -> None:
        self._failed_public_create()
        self.gateway.after_accepted_create = self._cancel_and_run_normal_reconcile
        self._retry_through_public_sweep()
        self._deliver_owned(RECONCILE, str(self.service.pk))
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "suspended")
        self.assertFalse(
            self.gateway.domain_state_of(self.account.domain).enabled,
            "Cancellation's normal reconciliation ran before create settled; retry never converged again",
        )
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_provisioning_cancellation_during_success_requires_truthful_review(self) -> None:
        self._failed_direct_create("provisioning", attach_order=True)
        self.gateway.after_accepted_create = self._cancel_and_run_normal_reconcile
        result = self._retry_through_public_sweep()
        self._deliver_receipt_off()
        self.assertTrue(reconcile_divergent_services_task()["success"])
        self._deliver_owned(RECONCILE, str(self.service.pk))
        self.service.refresh_from_db()
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(self.service.status, "failed")
        self.assertEqual(self.account.status, "suspended")  # Exact created resource verified OFF, never deleted.
        self.assertIsNotNone(self.gateway.domain_state_of(self.account.domain))
        self.assertEqual(
            self.job.status, "attention", "Failed Service has no automatic disable policy; review required"
        )
        self.assertFalse(result["success"], result)
        self.assertIsNone(self.job.next_retry_at)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_periodic_backstop_still_corrects_suspended_family_after_late_success(self) -> None:
        self._failed_public_create()
        self.gateway.after_accepted_create = self._cancel_and_run_normal_reconcile
        self._retry_through_public_sweep()
        # Existing protection bounds the mismatch; it does not authorize create.
        backstop = reconcile_divergent_services_task()
        self.assertTrue(backstop["success"], backstop)
        self._deliver_owned(RECONCILE, str(self.service.pk))
        self.assertFalse(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_order_cancelled_after_queue_publication_cannot_be_created(self) -> None:
        self._failed_public_create()
        self._retry_through_public_sweep(before_delivery=self._cancel_and_run_normal_reconcile)
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain), "Queued retry ignored later cancellation")
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)

    def test_cancelled_provisioning_intent_cannot_be_reinterpreted_as_failed_recovery(self) -> None:
        self._failed_direct_create("provisioning", attach_order=True)
        self._cancel_and_run_normal_reconcile()
        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "failed")
        self._retry_through_public_sweep()
        self.assertIsNone(
            self.gateway.domain_state_of(self.account.domain),
            "Cancellation moved provisioning to failed; it did not grant a new failed-Service recovery intent",
        )
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)

    def test_customer_hold_during_provisioning_native_success_requires_review(self) -> None:
        self._failed_direct_create("provisioning")

        def suspend_customer() -> None:
            self.client.force_login(self.operator)
            response = self.client.post(reverse("customers:status_change", args=[self.customer.pk, "suspend"]))
            self.assertEqual(response.status_code, 302)
            self.customer.refresh_from_db()
            self.service.refresh_from_db()
            self.assertEqual(self.customer.status, "suspended")
            # The real cascade only suspends active Services, not this input.
            self.assertEqual(self.service.status, "provisioning")

        self.gateway.after_accepted_create = suspend_customer
        result = self._retry_through_public_sweep()
        self._deliver_receipt_off()
        self.assertTrue(reconcile_divergent_services_task()["success"])
        self._deliver_owned(RECONCILE, str(self.service.pk))
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")
        self.assertIsNotNone(self.gateway.domain_state_of(self.account.domain))
        self.assertEqual(self.job.status, "attention")
        self.assertFalse(result["success"], result)
        self.assertIsNone(self.job.next_retry_at)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_restore_admission_cannot_enter_while_receipt_off_is_in_native_io(self) -> None:
        self._failed_direct_create("provisioning", attach_order=True)
        self.gateway.after_accepted_create = self._cancel_and_run_normal_reconcile
        self._retry_through_public_sweep()
        admissions = []

        def attempt_public_restore() -> None:
            self.assertFalse(connection.in_atomic_block)
            admissions.append(
                VirtualminBackupManagementService(self.server).create_restore_job(
                    self.account,
                    RestoreConfig(backup_id="operator-retained-backup"),
                    initiated_by=self.operator.email,
                )
            )

        self.gateway.before_disable = attempt_public_restore
        self._deliver_receipt_off()
        self.assertEqual(len(admissions), 1)
        self.assertTrue(admissions[0].is_err(), "Public restore admission overlapped receipt-bound OFF native I/O")
        self.assertIn("active operation", admissions[0].unwrap_err())
        self.assertFalse(
            VirtualminProvisioningJob.objects.filter(account=self.account, operation="restore_domain").exists()
        )

    def test_fifty_held_public_creates_do_not_consume_attempts_or_starve_eligible_retry(self) -> None:
        held = []
        for index in range(50):
            self._failed_direct_create("active", domain=f"held-{index}.example.com")
            held.append((self.job.pk, self.job.next_retry_at))
        other = Customer.objects.create(
            name="Eligible Buyer", customer_type="individual", primary_email="eligible@example.com", status="active"
        )
        self._failed_direct_create("active", domain="eligible-retry.example.com", customer=other)
        eligible_job, eligible_account = self.job, self.account
        self.client.force_login(self.operator)
        response = self.client.post(reverse("customers:status_change", args=[self.customer.pk, "suspend"]))
        self.assertEqual(response.status_code, 302)
        with patch("django.utils.timezone.now", return_value=eligible_job.next_retry_at + timedelta(seconds=1)):
            swept = process_failed_virtualmin_jobs()
        self.assertTrue(swept["success"], swept)
        self.assertEqual(swept["results"]["retried_jobs"], 1, swept)
        for job_id, due in held:
            job = VirtualminProvisioningJob.objects.get(pk=job_id)
            self.assertEqual(job.status, "failed")
            self.assertEqual(job.retry_count, 0)
            self.assertEqual(job.next_retry_at, due)
            self.assertEqual(self._deliver_owned(RETRY, str(job_id)), [])
        delivered = self._deliver_owned(RETRY, str(eligible_job.pk))
        self.assertEqual(len(delivered), 1)
        self.assertTrue(delivered[0]["success"], delivered)
        self.assertTrue(self.gateway.domain_state_of(eligible_account.domain).enabled)
