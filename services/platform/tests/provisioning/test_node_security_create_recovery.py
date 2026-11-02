"""Node admission withdrawal must distinguish observation from fresh native creation."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from django.core.cache import cache
from django.test import Client, TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.billing.models import Currency
from apps.common.types import Err, Result, Retriability
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_gateway import VirtualminAPIError, VirtualminResponse
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_node_capability import destination_refusal
from apps.provisioning.virtualmin_security import connection_identity
from apps.provisioning.virtualmin_service import VirtualminAccountCreationData, VirtualminProvisioningService
from apps.users.models import User
from tests.mocks.virtualmin_mock import MockVirtualminGateway

SWEEP = "apps.provisioning.virtualmin_tasks.process_failed_virtualmin_jobs"
RETRY = "apps.provisioning.virtualmin_tasks.retry_virtualmin_job"
QUEUE = {"name": "node-create-recovery", "orm": "default", "sync": False, "timeout": 3600, "retry": 86400}
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


class OriginalCreateFaultGateway(MockVirtualminGateway):
    """External native boundary: either lost accepted reply or known preaccept failure."""

    def __init__(self, *, accepted_unknown: bool) -> None:
        super().__init__(server_hostname="recovery-node.example.com")
        self.accepted_unknown = accepted_unknown
        self.first_create = True
        self.after_owner_read: Callable[[], None] | None = None

    def get_domain_owner(self, domain: str) -> Result[str | None, str]:
        observed = super().get_domain_owner(domain)
        if self.after_owner_read is not None:
            callback, self.after_owner_read = self.after_owner_read, None
            callback()
        return observed

    def call(  # noqa: PLR0913 -- Keep the external gateway signature.
        self,
        program: str,
        params: dict[str, Any] | None = None,
        response_format: str = "json",
        correlation_id: str = "",
        timeout_seconds: int | None = None,
        *,
        deadline: float | None = None,
    ) -> Result[VirtualminResponse, VirtualminAPIError]:
        if program == "create-domain" and self.first_create:
            self.first_create = False
            if self.accepted_unknown:
                accepted = super().call(
                    program, params, response_format, correlation_id, timeout_seconds, deadline=deadline
                )
                if accepted.is_err() or not accepted.unwrap().success:
                    raise AssertionError("Original external create did not accept its valid request")
            else:
                self._record_call(program, params or {}, success=False)
            return Err(
                VirtualminAPIError("Original create reply unavailable", self.server_hostname, program),
                retriability=Retriability.UNKNOWN if self.accepted_unknown else Retriability.RETRIABLE,
            )
        return super().call(program, params, response_format, correlation_id, timeout_seconds, deadline=deadline)


@override_settings(CACHES=LOCMEM, Q_CLUSTER=QUEUE)
class NodeSecurityCreateRecoveryTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        customer = Customer.objects.create(
            name="Original create customer", customer_type="individual", primary_email="recovery@example.com"
        )
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(
            name="Recovery hosting", plan_type="shared_hosting", price_monthly=Decimal("10")
        )
        self.service = Service.objects.create(
            customer=customer,
            currency=currency,
            service_plan=plan,
            service_name="recovery.example.com",
            domain="recovery.example.com",
            username="recovery",
            price=Decimal("10"),
            billing_cycle="monthly",
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="Original create node",
            hostname="recovery-node.example.com",
            api_username="recovery-api",
            status="active",
            last_health_check=timezone.now(),
            legacy_security_admission=True,
        )
        self.server.set_api_password("RecoveryServerPassword123!")
        self.server.save()
        self.assertIsNone(destination_refusal(self.server))
        self.actor = User.objects.create_user(
            email="recovery-operator@example.com", is_staff=True, staff_role="admin", is_active=True
        )

    def produce_failed_create(self, *, accepted_unknown: bool) -> None:
        self.gateway = OriginalCreateFaultGateway(accepted_unknown=accepted_unknown)
        self.enterContext(patch("apps.provisioning.virtualmin_service.VirtualminGateway", return_value=self.gateway))
        created = VirtualminProvisioningService(self.server).create_virtualmin_account(
            VirtualminAccountCreationData(
                service=self.service, domain=self.service.domain, username="recovery", server=self.server
            )
        )
        self.assertTrue(created.is_err(), created)
        self.account = VirtualminAccount.objects.get(service=self.service)
        self.job = VirtualminProvisioningJob.objects.get(account=self.account, operation="create_domain")
        self.assertEqual((self.account.status, self.job.status, self.job.retry_count), ("error", "failed", 0))
        self.assertEqual(self.job.result["retriability"], "unknown" if accepted_unknown else "retriable")
        self.assertEqual(self.gateway.domain_state_of(self.account.domain) is not None, accepted_unknown)
        self.password = bytes(self.account.encrypted_password)
        self.plain_password = self.account.get_password()
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 0)

    def withdraw_admission(self) -> None:
        self.server.legacy_security_admission = False
        self.server.save(update_fields=["legacy_security_admission", "updated_at"])
        self.assertIsNotNone(destination_refusal(self.server))

    def staff_retry(self) -> tuple[dict[str, Any], dict[str, Any]]:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.actor)
        page = client.get(reverse("provisioning:virtualmin_job_status", args=[self.job.pk]))
        self.assertEqual(page.status_code, 200)
        token = client.cookies["csrftoken"].value
        route = reverse("provisioning:virtualmin_job_retry", args=[self.job.pk])
        self.assertEqual(client.post(route).status_code, 403)
        before = set(OrmQ.objects.values_list("pk", flat=True))
        self.assertEqual(client.post(route, {"csrfmiddlewaretoken": token}).status_code, 302)
        sweeps = [(row, row.task) for row in OrmQ.objects.exclude(pk__in=before) if row.task["func"] == SWEEP]
        self.assertEqual(len(sweeps), 1)
        row, task = sweeps[0]
        self.assertEqual(OrmQ.objects.filter(pk=row.pk).delete()[0], 1)
        swept = import_string(task["func"])(*task.get("args", ()), **task.get("kwargs", {}))
        self.assertTrue(swept["success"], swept)
        self.assertEqual(swept["results"]["retried_jobs"], 1, swept)
        deliveries = [
            (row, SignedPackage.loads(row.payload))
            for row in OrmQ.objects.order_by("pk")
            if (decoded := SignedPackage.loads(row.payload))["func"] == RETRY
            and str(decoded["args"][0]) == str(self.job.pk)
        ]
        self.assertEqual(len(deliveries), 1)
        row, delivery = deliveries[0]
        self.assertEqual(OrmQ.objects.filter(pk=row.pk).delete()[0], 1)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "pending")
        self.assertEqual(delivery["args"][1], self.job.claimed_at.isoformat())
        outcome = import_string(delivery["func"])(*delivery["args"], **delivery.get("kwargs", {}))
        return outcome, delivery

    def assert_stale_no_io(self, delivery: dict[str, Any]) -> None:
        before = len(self.gateway.get_calls())
        stale = import_string(delivery["func"])(*delivery["args"], **delivery.get("kwargs", {}))
        self.assertEqual(stale["action"], "stale_claim_discarded")
        self.assertEqual(len(self.gateway.get_calls()), before)

    def assert_no_new_mutation(self, before: int) -> None:
        calls = self.gateway.get_calls()[before:]
        self.assertTrue(any(call.program == "list-domains" for call in calls), "Original ownership was not observed")
        self.assertFalse(
            any(
                call.program in {"create-domain", "enable-domain", "disable-domain", "delete-domain", "modify-domain"}
                for call in calls
            ),
            [(call.program, call.result_success) for call in calls],
        )
        self.account.refresh_from_db()
        self.assertEqual(bytes(self.account.encrypted_password), self.password)
        self.assertEqual(self.account.get_password(), self.plain_password)

    def assert_original_create_remains_unresolved(self, before: int, outcome: dict[str, Any]) -> None:
        self.assertFalse(outcome["success"], outcome)
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(self.account.status, "error")
        self.assertIn(self.job.status, {"failed", "attention"})
        self.assertIsNone(self.job.next_retry_at)
        self.assertEqual(self.server.current_domains, 0)
        self.assertEqual(self.job.parameters["domain"], self.account.domain)
        self.assertEqual(self.job.parameters["username"], self.account.virtualmin_username)
        self.assertEqual(bytes(self.account.encrypted_password), self.password)
        self.assertEqual(self.account.get_password(), self.plain_password)
        calls = self.gateway.get_calls()[before:]
        self.assertFalse(
            any(
                call.program in {"create-domain", "enable-domain", "disable-domain", "delete-domain", "modify-domain"}
                for call in calls
            ),
            [(call.program, call.result_success) for call in calls],
        )

    def test_changed_original_endpoint_never_adopts_same_named_native_owner(self) -> None:
        self.produce_failed_create(accepted_unknown=True)
        original_identity = connection_identity(self.server)
        self.withdraw_admission()
        self.server.hostname = "different-node.example.com"
        self.server.save(update_fields=["hostname", "updated_at"])
        self.assertNotEqual(connection_identity(self.server), original_identity)
        before = len(self.gateway.get_calls())
        outcome, _delivery = self.staff_retry()
        self.assert_original_create_remains_unresolved(before, outcome)
        self.assertEqual(self.server.hostname, "different-node.example.com")

    def test_rotated_original_node_credential_never_adopts_previous_create(self) -> None:
        self.produce_failed_create(accepted_unknown=True)
        original_identity = connection_identity(self.server)
        self.withdraw_admission()
        self.server.set_api_password("DifferentRecoveryServerPassword456!")
        self.server.save(update_fields=["encrypted_api_password", "updated_at"])
        changed_credential = bytes(self.server.encrypted_api_password)
        self.assertNotEqual(connection_identity(self.server), original_identity)
        before = len(self.gateway.get_calls())
        outcome, _delivery = self.staff_retry()
        self.assert_original_create_remains_unresolved(before, outcome)
        self.assertEqual(bytes(self.server.encrypted_api_password), changed_credential)

    def test_node_identity_changed_during_actual_owner_read_never_adopts(self) -> None:
        self.produce_failed_create(accepted_unknown=True)
        original_identity = connection_identity(self.server)
        self.withdraw_admission()
        observed: list[bool] = []

        def rotate_after_read() -> None:
            # An independent persisted writer must invalidate a cached account.server too.
            current = VirtualminServer.objects.get(pk=self.server.pk)
            current.set_api_password("ChangedDuringOwnershipRead789!")
            current.save(update_fields=["encrypted_api_password", "updated_at"])
            observed.append(True)

        self.gateway.after_owner_read = rotate_after_read
        before = len(self.gateway.get_calls())
        outcome, _delivery = self.staff_retry()
        self.assertEqual(observed, [True], "Original node observation never reached its external read boundary")
        self.assert_original_create_remains_unresolved(before, outcome)
        self.assertNotEqual(connection_identity(self.server), original_identity)

    def test_unknown_owned_create_is_observed_and_adopted_after_admission_withdrawal(self) -> None:
        self.produce_failed_create(accepted_unknown=True)
        self.withdraw_admission()
        before = len(self.gateway.get_calls())
        outcome, delivery = self.staff_retry()
        self.assertTrue(outcome["success"], outcome)
        self.assert_no_new_mutation(before)
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(
            (self.account.status, self.job.status, self.server.current_domains), ("active", "completed", 1)
        )
        self.assertEqual(VirtualminAccount.objects.filter(service=self.service).count(), 1)
        self.assertEqual(
            VirtualminProvisioningJob.objects.filter(account=self.account, operation="create_domain").count(), 1
        )
        self.assert_stale_no_io(delivery)
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 1)

    def test_unknown_original_now_absent_is_observed_but_never_created_on_unverified_node(self) -> None:
        self.produce_failed_create(accepted_unknown=True)
        deleted = self.gateway.call("delete-domain", {"domain": self.account.domain})
        self.assertTrue(deleted.is_ok() and deleted.unwrap().success)
        self.withdraw_admission()
        before = len(self.gateway.get_calls())
        outcome, _delivery = self.staff_retry()
        self.assertFalse(outcome["success"], outcome)
        self.assert_no_new_mutation(before)
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 0)

    def test_known_unaccepted_create_never_recreates_after_admission_withdrawal(self) -> None:
        self.produce_failed_create(accepted_unknown=False)
        self.withdraw_admission()
        before = len(self.gateway.get_calls())
        outcome, _delivery = self.staff_retry()
        self.assertFalse(outcome["success"], outcome)
        self.assert_no_new_mutation(before)
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))

    def test_admitted_legacy_create_retry_remains_functional_and_stale_delivery_is_inert(self) -> None:
        self.produce_failed_create(accepted_unknown=False)
        outcome, delivery = self.staff_retry()
        self.assertTrue(outcome["success"], outcome)
        self.job.refresh_from_db()
        self.account.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(
            (self.job.status, self.account.status, self.server.current_domains), ("completed", "active", 1)
        )
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 2)
        self.assertEqual(bytes(self.account.encrypted_password), self.password)
        self.assert_stale_no_io(delivery)

    def test_admitted_absent_retry_does_not_create_after_node_identity_changes_during_probe(self) -> None:
        self.produce_failed_create(accepted_unknown=False)
        self.assertIsNone(destination_refusal(self.server))
        observed: list[bool] = []

        def rotate_after_absence() -> None:
            self.assertIsNone(self.gateway.domain_state_of(self.account.domain))
            current = VirtualminServer.objects.get(pk=self.server.pk)
            current.set_api_password("ChangedAfterAbsenceRead321!")
            current.save(update_fields=["encrypted_api_password", "updated_at"])
            observed.append(True)

        self.gateway.after_owner_read = rotate_after_absence
        before = len(self.gateway.get_calls())
        outcome, _delivery = self.staff_retry()
        self.assertEqual(observed, [True])
        self.assertEqual(
            len(self.gateway.get_calls("create-domain")),
            1,
            "A retry issued a fresh native CREATE after its recorded node identity changed",
        )
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))
        self.assert_original_create_remains_unresolved(before, outcome)

    def test_unreadable_original_trust_input_parks_unknown_create_without_native_io(self) -> None:
        with TemporaryDirectory(prefix="praho-recovery-trust-", dir="/private/tmp") as directory:
            trust = Path(directory) / "imported-identity"
            trust.write_text("Owned test-only transport fingerprint input\n")
            trust.chmod(0o600)
            with self.settings(VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH=str(trust)):
                self.produce_failed_create(accepted_unknown=True)
                trust.unlink()
                before = len(self.gateway.get_calls())
                outcome, _delivery = self.staff_retry()
                self.assert_original_create_remains_unresolved(before, outcome)
                self.assertEqual(self.job.status, "attention")
                self.assertEqual(self.job.result["retriability"], "unknown")
                self.assertIn("creation_node_review", self.job.result)
                self.assertEqual(len(self.gateway.get_calls()), before)
