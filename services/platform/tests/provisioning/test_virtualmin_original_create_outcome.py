"""Accepted original creates remain observable after public hosting revocation."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.urls import reverse
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.common.types import Retriability
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.provisioning.virtualmin_tasks import process_failed_virtualmin_jobs, provision_virtualmin_account
from tests.provisioning import test_virtualmin_create_retry_policy as fixtures

SWEEP = "apps.provisioning.virtualmin_tasks.process_failed_virtualmin_jobs"


class _OriginalWorkerCrash(BaseException):
    """The native command was accepted, but its original worker never settled it."""


class OriginalCreateOutcomeTests(fixtures.CreateRetryFixture):
    def _explicit_off_with_origin(self, origin: object, *, held: bool, expect_off: bool) -> None:
        self._accepted_unknown_original()
        parameters = dict(self.job.parameters)
        if origin is None:
            # A pre-deployment job legitimately has no pipeline-intent metadata.
            parameters.pop("creation_intent")
        else:
            parameters["creation_intent"] = origin
        self.job.parameters = parameters
        self.job.save(update_fields=["parameters", "updated_at"])
        if held:
            self.client.force_login(self.operator)
            response = self.client.post(reverse("customers:status_change", args=[self.customer.pk, "suspend"]))
            self.assertEqual(response.status_code, 302)
            self._deliver_revocation_callbacks()
        else:
            self._cancel_and_run_normal_reconcile()
        self._staff_retry_delivery()
        off_jobs = list(
            VirtualminProvisioningJob.objects.filter(
                account=self.account, operation="suspend_domain", parameters__revoked_create_job_id=str(self.job.pk)
            )
        )
        # Deliver any actually published exact-owned job: absence of a mutation
        # is a real consumer assertion, not just an enqueue-call assertion.
        for off in off_jobs:
            self.assertEqual(len(self._deliver_owned(fixtures.RETRY, str(off.pk))), 1)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "attention")
        self.assertEqual(self.gateway.domain_state_of(self.account.domain).enabled, not expect_off)
        self.assertEqual(len(off_jobs), int(expect_off))
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), int(expect_off))
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_current_customer_hold_can_disable_proved_owned_legacy_original_without_pipeline_origin(self) -> None:
        self._explicit_off_with_origin(None, held=True, expect_off=True)

    def test_current_service_off_can_disable_proved_owned_legacy_original_without_pipeline_origin(self) -> None:
        self._explicit_off_with_origin(None, held=False, expect_off=True)

    def test_current_hold_does_not_depend_on_same_service_pipeline_origin_format(self) -> None:
        self._explicit_off_with_origin(
            {"version": True, "service_id": self.service.pk, "service_status": "active", "purpose": "create"},
            held=True,
            expect_off=True,
        )

    def _foreign_origin(self) -> dict[str, Any]:
        other = type(self.service).objects.create(
            customer=self.customer,
            currency=self.currency,
            service_plan=self.plan,
            service_name="Unrelated Service",
            domain="unrelated-origin.example.com",
            username="otherorigin",
            billing_cycle="monthly",
            price=self.service.price,
            status="active",
        )
        return {"version": 1, "service_id": other.pk, "service_status": "active", "purpose": "create"}

    def test_current_customer_hold_does_not_adopt_an_explicitly_foreign_creation_identity(self) -> None:
        self._explicit_off_with_origin(self._foreign_origin(), held=True, expect_off=False)

    def test_current_service_off_does_not_adopt_an_explicitly_foreign_creation_identity(self) -> None:
        self._explicit_off_with_origin(self._foreign_origin(), held=False, expect_off=False)

    def _original_create(self) -> dict[str, Any]:
        return provision_virtualmin_account(
            {
                "service_id": str(self.service.pk),
                "domain": self.service.domain,
                "username": self.service.username,
                "password": None,
                "template": "Default Settings",
                "server_id": str(self.server.pk),
            }
        )

    def _load_original_rows(self) -> None:
        self.account = VirtualminAccount.objects.get(service=self.service)
        self.job = VirtualminProvisioningJob.objects.get(account=self.account, operation="create_domain")
        self.original_password = self.account.encrypted_password
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)

    def _accepted_unknown_original(self) -> None:
        self.gateway.first_create_accepted = True
        self.gateway.first_create_retriability = Retriability.UNKNOWN
        outcome = self._original_create()
        self.assertFalse(outcome["success"], outcome)
        self.assertEqual(outcome["retriability"], Retriability.UNKNOWN.value)
        self._load_original_rows()
        self.assertEqual(self.account.status, "error")
        self.assertEqual(self.job.status, "failed")
        self.assertIsNone(self.job.next_retry_at, "A lost original answer is not automatic replay authority")
        self.assertEqual(self.job.retry_count, 0)
        swept = process_failed_virtualmin_jobs()
        self.assertTrue(swept["success"], swept)
        self.assertEqual(swept["results"]["retried_jobs"], 0)
        self.assertEqual(self._deliver_owned(fixtures.RETRY, str(self.job.pk)), [])

    def _staff_retry_delivery(self) -> dict[str, Any]:
        self.client.force_login(self.operator)
        before = set(OrmQ.objects.values_list("pk", flat=True))
        response = self.client.post(reverse("provisioning:virtualmin_job_retry", args=[self.job.pk]))
        self.assertEqual(response.status_code, 302)
        # Run only the exact new sweep publication from this public POST. An
        # unrelated onboarding/reconciliation row is never consumed here.
        for row in list(OrmQ.objects.exclude(pk__in=before).order_by("pk")):
            task = SignedPackage.loads(row.payload)
            if task["func"] == SWEEP and not task.get("args"):
                row.delete()
                swept = import_string(SWEEP)(*task.get("args", ()), **task.get("kwargs", {}))
                self.assertTrue(swept["success"], swept)
        deliveries = self._deliver_owned(fixtures.RETRY, str(self.job.pk))
        self.assertEqual(len(deliveries), 1, "Explicit staff retry did not publish the owned probe-capable claim")
        return deliveries[0]

    def _assert_owned_original_disabled_once(self) -> None:
        off = self._deliver_receipt_off()
        self.assertTrue(off["success"], off)
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(self.account.encrypted_password, self.original_password)
        self.assertEqual(self.job.status, "attention")
        self.assertEqual(self.job.result["revoked_creation"]["native_outcome"], "adopted")
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        self.assertFalse(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
        self.assertEqual(VirtualminAccount.objects.filter(service=self.service).count(), 1)
        self.assertEqual(self.server.current_domains, 1)

    def test_staff_retry_observes_accepted_unknown_original_after_order_cancellation(self) -> None:
        self._accepted_unknown_original()
        self._cancel_and_run_normal_reconcile()
        self._staff_retry_delivery()
        self._assert_owned_original_disabled_once()

    def test_staff_retry_can_observe_accepted_unknown_original_while_customer_is_held(self) -> None:
        self._accepted_unknown_original()
        self.client.force_login(self.operator)
        response = self.client.post(reverse("customers:status_change", args=[self.customer.pk, "suspend"]))
        self.assertEqual(response.status_code, 302)
        self._deliver_revocation_callbacks()
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.status, "suspended")
        paused = process_failed_virtualmin_jobs()
        self.assertEqual(paused["results"]["retried_jobs"], 0)
        self.assertEqual(self._deliver_owned(fixtures.RETRY, str(self.job.pk)), [])
        self._staff_retry_delivery()
        self._assert_owned_original_disabled_once()
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.status, "suspended", "Observation must not restore the customer")

    def test_expired_original_worker_observes_its_accepted_create_after_cancellation(self) -> None:
        self.gateway.fail_first_create = False

        def crash_after_native_acceptance() -> None:
            raise _OriginalWorkerCrash

        self.gateway.after_accepted_create = crash_after_native_acceptance
        with self.assertRaises(_OriginalWorkerCrash):
            self._original_create()
        self._load_original_rows()
        self.assertEqual(self.account.status, "provisioning")
        self.assertEqual(self.job.status, "running")
        self._cancel_and_run_normal_reconcile()
        with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(hours=2)):
            recovered = process_failed_virtualmin_jobs()
        self.assertTrue(recovered["success"], recovered)
        self.assertEqual(recovered["results"]["recovered_claims"], 1)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "failed")
        self.assertIsNotNone(self.job.next_retry_at)
        self._retry_through_public_sweep()
        self._assert_owned_original_disabled_once()

    def test_failed_reprovision_retries_the_actual_target_without_moving_its_account_early(self) -> None:
        # The retained local account survives loss of its native node. Only the
        # public reprovision producer may mint the target-bound replacement job.
        self.account = VirtualminAccount(
            service=self.service,
            server=self.server,
            domain=self.service.domain,
            virtualmin_username=self.service.username,
            template_name="Default Settings",
            status="active",
        )
        self.account.set_password("original-node-lost-password")
        self.account.save()
        account_id = self.account.pk
        target = VirtualminServer.objects.create(
            name="Replacement retry node",
            hostname="replacement-retry-node.example.com",
            api_username="api",
            status="active",
            max_domains=100,
            current_domains=0,
            last_health_check=timezone.now(),
        )
        target.set_api_password("replacement-node-fixture-password")
        target.save()
        source_gateway = self.gateway
        source_gateway.fail_first_create = False
        target_gateway = type(self.gateway)()
        gateways = {self.server.pk: source_gateway, target.pk: target_gateway}
        observed_servers = []

        def external_gateway(config: Any) -> Any:
            observed_servers.append(config.server.pk)
            return gateways[config.server.pk]

        with patch("apps.provisioning.virtualmin_service.VirtualminGateway", side_effect=external_gateway):
            failed = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(self.account, target)
            self.assertTrue(failed.is_err(), failed)
            self.account.refresh_from_db()
            self.job = VirtualminProvisioningJob.objects.get(account=self.account, operation="create_domain")
            self.assertEqual(self.account.pk, account_id)
            self.assertEqual(self.account.server_id, self.server.pk, "Failed staged recovery moved the account")
            self.assertEqual(self.job.server_id, target.pk)
            self.assertEqual(self.job.status, "failed")
            self.assertIsNotNone(self.job.next_retry_at)
            self.assertEqual(self.job.parameters["creation_intent"]["purpose"], "reprovision")
            self.assertEqual(len(target_gateway.get_calls("create-domain")), 1)
            self.assertIsNone(target_gateway.domain_state_of(self.account.domain))
            staged_password = self.account.encrypted_password
            original_constructors = len(observed_servers)
            retried = self._retry_through_public_sweep()
            self.assertTrue(retried["success"], retried)
            self.account.refresh_from_db()
            self.job.refresh_from_db()
            retry_servers = observed_servers[original_constructors:]
            self.assertTrue(retry_servers, "Retry never reached the external target boundary")
            self.assertEqual(set(retry_servers), {target.pk}, "Retry ignored the producer's staged target")
            self.assertEqual(self.account.pk, account_id)
            self.assertEqual(self.account.server_id, target.pk)
            self.assertEqual(self.account.encrypted_password, staged_password)
            self.assertEqual(self.account.status, "active")
            self.assertEqual(self.job.status, "completed")
            self.assertEqual(len(target_gateway.get_calls("create-domain")), 2)
            self.assertTrue(target_gateway.domain_state_of(self.account.domain).enabled)
            self.assertIsNone(source_gateway.domain_state_of(self.account.domain))
            self.assertEqual(len(source_gateway.get_calls("create-domain")), 0)
            self.assertEqual(len(source_gateway.get_calls("delete-domain")), 0)
            self.assertEqual(len(target_gateway.get_calls("delete-domain")), 0)

    def _assert_unsafe_probe_cannot_mutate(self, outcome: str) -> None:
        self._accepted_unknown_original()
        self._cancel_and_run_normal_reconcile()
        native = self.gateway.domain_state_of(self.account.domain)
        if outcome == "foreign":
            native.username = "foreign-owner"
        elif outcome == "indeterminate":
            native.username = ""
        else:
            self.gateway.fail_operations["list-domains"] = "External ownership observation unavailable"
        probes = len(self.gateway.get_calls("list-domains"))
        self._staff_retry_delivery()
        self.assertGreater(len(self.gateway.get_calls("list-domains")), probes, "Existing outcome was never observed")
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.assertNotEqual(self.account.status, "active")
        self.assertNotEqual(self.job.status, "running")
        self.assertEqual(self.account.encrypted_password, self.original_password)
        self.assertTrue(native.enabled)
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
        self.assertFalse(
            VirtualminProvisioningJob.objects.filter(
                account=self.account, parameters__revoked_create_job_id=str(self.job.pk)
            ).exists()
        )

    def test_foreign_original_resource_is_not_adopted_or_disabled(self) -> None:
        self._assert_unsafe_probe_cannot_mutate("foreign")

    def test_indeterminate_original_owner_is_not_adopted_or_disabled(self) -> None:
        self._assert_unsafe_probe_cannot_mutate("indeterminate")

    def test_unavailable_original_owner_is_not_absence_or_disable_authority(self) -> None:
        self._assert_unsafe_probe_cannot_mutate("unavailable")

    def _lost_account_and_replacement(self) -> tuple[VirtualminServer, Any]:
        self.account = VirtualminAccount(
            service=self.service,
            server=self.server,
            domain=self.service.domain,
            virtualmin_username=self.service.username,
            template_name="Default Settings",
            status="active",
            provisioned_at=timezone.now() - timedelta(days=1),
        )
        self.account.set_password("lost-node-fixture-password")
        self.account.save()
        target = self._replacement_node("replacement-original-node.example.com")
        self.gateway.fail_first_create = False
        return target, type(self.gateway)()

    def _replacement_node(self, hostname: str) -> VirtualminServer:
        target = VirtualminServer.objects.create(
            name=hostname,
            hostname=hostname,
            api_username="api",
            status="active",
            max_domains=100,
            current_domains=0,
            last_health_check=timezone.now(),
        )
        target.set_api_password("replacement-fixture-password")
        target.save()
        return target

    def test_accepted_unknown_reprovision_is_adopted_on_target_once_despite_duplicate_delivery(self) -> None:
        target, native_target = self._lost_account_and_replacement()
        native_target.first_create_accepted = True
        native_target.first_create_retriability = Retriability.UNKNOWN
        gateways = {self.server.pk: self.gateway, target.pk: native_target}
        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            side_effect=lambda config: gateways[config.server.pk],
        ):
            result = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(self.account, target)
            self.assertTrue(result.is_err(), result)
            self.account.refresh_from_db()
            self.job = VirtualminProvisioningJob.objects.get(account=self.account, operation="create_domain")
            self.assertEqual(self.account.server_id, self.server.pk)
            self.assertEqual(self.job.server_id, target.pk)
            self.assertEqual(self.job.result["retriability"], Retriability.UNKNOWN.value)
            self.assertIsNone(self.job.next_retry_at)
            self.assertTrue(native_target.domain_state_of(self.account.domain).enabled)
            staged_password, account_id = self.account.encrypted_password, self.account.pk
            self.client.force_login(self.operator)
            before = set(OrmQ.objects.values_list("pk", flat=True))
            posted = self.client.post(reverse("provisioning:virtualmin_job_retry", args=[self.job.pk]))
            self.assertEqual(posted.status_code, 302)
            for row in list(OrmQ.objects.exclude(pk__in=before).order_by("pk")):
                task = SignedPackage.loads(row.payload)
                if task["func"] == SWEEP and not task.get("args"):
                    row.delete()
                    self.assertTrue(import_string(SWEEP)(**task.get("kwargs", {}))["success"])
            copies = [
                task
                for row in OrmQ.objects.all()
                if (task := SignedPackage.loads(row.payload))["func"] == fixtures.RETRY
                and str(task["args"][0]) == str(self.job.pk)
            ]
            self.assertEqual(len(copies), 1, "Staff retry did not publish its real nonce-bound delivery")
            deliveries = self._deliver_owned(fixtures.RETRY, str(self.job.pk))
            self.assertEqual(len(deliveries), 1)
            self.assertTrue(deliveries[0]["success"], deliveries)
            # Duplicate the genuine published delivery, retaining its original
            # nonce. Do not manufacture a second claimed attempt.
            copied = copies[0]
            replayed = import_string(fixtures.RETRY)(*copied["args"], **copied.get("kwargs", {}))
            self.assertFalse(replayed["success"], replayed)
            self.assertEqual(replayed["action"], "stale_claim_discarded")
            self.account.refresh_from_db()
            self.job.refresh_from_db()
            target.refresh_from_db()
            self.assertEqual(self.account.pk, account_id)
            self.assertEqual(self.account.server_id, target.pk)
            self.assertEqual(self.account.encrypted_password, staged_password)
            self.assertEqual(self.account.status, "active")
            self.assertEqual(self.job.status, "completed")
            self.assertEqual(self.job.retry_count, 1)
            self.assertEqual(target.current_domains, 1)
            self.assertEqual(len(native_target.get_calls("create-domain")), 1)
            self.assertEqual(len(native_target.get_calls("delete-domain")), 0)
            self.assertEqual(len(self.gateway.get_calls("create-domain")), 0)

    def test_target_probe_cannot_clobber_a_newer_public_reprovision_to_another_node(self) -> None:
        target, native_target = self._lost_account_and_replacement()
        newer = self._replacement_node("newer-replacement-node.example.com")
        native_newer = type(self.gateway)()
        native_newer.fail_first_create = False
        gateways = {self.server.pk: self.gateway, target.pk: native_target, newer.pk: native_newer}
        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            side_effect=lambda config: gateways[config.server.pk],
        ):
            failed = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(self.account, target)
            self.assertTrue(failed.is_err(), failed)
            self.account.refresh_from_db()
            self.job = VirtualminProvisioningJob.objects.get(account=self.account, operation="create_domain")
            self.assertEqual(self.account.server_id, self.server.pk)
            self.assertEqual(self.job.server_id, target.pk)
            actual_probe = native_target.get_domain_owner
            newer_passwords = []

            def move_during_probe(domain: str) -> Any:
                observed = actual_probe(domain)
                moved = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(self.account, newer)
                self.assertTrue(moved.is_ok(), moved)
                self.account.refresh_from_db()
                self.assertEqual(self.account.server_id, newer.pk)
                newer_passwords.append(self.account.encrypted_password)
                return observed

            with patch.object(native_target, "get_domain_owner", side_effect=move_during_probe):
                retried = self._retry_through_public_sweep()
            self.assertFalse(retried["success"], retried)
            self.account.refresh_from_db()
            self.job.refresh_from_db()
            target.refresh_from_db()
            newer.refresh_from_db()
            self.assertEqual(len(newer_passwords), 1, "The actual target observation did not cross the public writer")
            self.assertEqual(self.account.server_id, newer.pk)
            self.assertEqual(self.account.encrypted_password, newer_passwords[0])
            self.assertEqual(self.account.status, "active")
            self.assertEqual(self.job.status, "attention", "A changed target binding left its old claim running")
            self.assertEqual(target.current_domains, 0)
            self.assertEqual(newer.current_domains, 1)
            self.assertIsNone(native_target.domain_state_of(self.account.domain))
            self.assertTrue(native_newer.domain_state_of(self.account.domain).enabled)
            self.assertEqual(len(native_target.get_calls("create-domain")), 1)
            self.assertEqual(len(native_newer.get_calls("create-domain")), 1)
            self.assertEqual(len(native_target.get_calls("delete-domain")), 0)
            self.assertEqual(len(native_newer.get_calls("delete-domain")), 0)

    def test_absent_later_observation_does_not_resolve_an_unknown_accepted_original(self) -> None:
        self._accepted_unknown_original()
        self._cancel_and_run_normal_reconcile()
        # External state can disappear after the lost response. A later absent
        # read is not evidence that the original command stopped or never ran.
        self.gateway._domains.pop(self.account.domain)
        probes = len(self.gateway.get_calls("list-domains"))
        result = self._staff_retry_delivery()
        self.assertFalse(result["success"], result)
        self.assertGreater(len(self.gateway.get_calls("list-domains")), probes)
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(self.account.status, "error")
        self.assertEqual(self.account.encrypted_password, self.original_password)
        self.assertEqual(self.job.status, "attention", "Absence silently settled an uncertain original command")
        self.assertIsNone(self.job.next_retry_at)
        self.assertIsNone(self.gateway.domain_state_of(self.account.domain))
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
        self.assertFalse(
            VirtualminProvisioningJob.objects.filter(
                account=self.account, parameters__revoked_create_job_id=str(self.job.pk)
            ).exists()
        )

    def _failed_public_recovery_to(
        self, newer: VirtualminServer, native_newer: Any, original_password: bytes
    ) -> tuple[Any, bytes]:
        failed = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(self.account, newer)
        self.assertTrue(failed.is_err(), failed)
        self.account.refresh_from_db()
        self.assertEqual(self.account.server_id, self.server.pk)
        self.assertNotEqual(self.account.encrypted_password, original_password)
        replacement = VirtualminProvisioningJob.objects.get(
            account=self.account, server=newer, operation="create_domain"
        )
        self.assertEqual(replacement.status, "failed")
        self.assertIsNotNone(replacement.next_retry_at)
        self.assertIsNone(native_newer.domain_state_of(self.account.domain))
        return replacement.pk, self.account.encrypted_password

    def _assert_newer_failed_reprovision_keeps_its_credential_authority(self, *, during_probe: bool) -> None:
        target, native_target = self._lost_account_and_replacement()
        native_target.first_create_accepted = True
        native_target.first_create_retriability = Retriability.UNKNOWN
        newer = self._replacement_node("newer-failed-replacement.example.com")
        native_newer = type(self.gateway)()
        gateways = {self.server.pk: self.gateway, target.pk: native_target, newer.pk: native_newer}
        with patch(
            "apps.provisioning.virtualmin_service.VirtualminGateway",
            side_effect=lambda config: gateways[config.server.pk],
        ):
            original = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(self.account, target)
            self.assertTrue(original.is_err(), original)
            self.account.refresh_from_db()
            self.job = VirtualminProvisioningJob.objects.get(
                account=self.account, server=target, operation="create_domain"
            )
            self.assertEqual(self.job.result["retriability"], Retriability.UNKNOWN.value)
            self.assertIsNone(self.job.next_retry_at)
            self.assertEqual(self.account.server_id, self.server.pk)
            self.assertTrue(native_target.domain_state_of(self.account.domain).enabled)
            original_password = self.account.encrypted_password
            newer_attempts = []

            def fail_newer_public_attempt() -> None:
                newer_attempts.append(self._failed_public_recovery_to(newer, native_newer, original_password))

            if during_probe:
                real_probe = native_target.get_domain_owner

                def newer_attempt_during_probe(domain: str) -> Any:
                    observed = real_probe(domain)
                    fail_newer_public_attempt()
                    return observed

                with patch.object(native_target, "get_domain_owner", side_effect=newer_attempt_during_probe):
                    retried = self._staff_retry_delivery()
            else:
                fail_newer_public_attempt()
                retried = self._staff_retry_delivery()
            self.assertFalse(retried["success"], "Old target adopted a resource using a newer failed attempt's secret")
            self.assertEqual(len(newer_attempts), 1)
            for instance in (self.account, self.job, target, newer):
                instance.refresh_from_db()
            newer_job = VirtualminProvisioningJob.objects.get(pk=newer_attempts[0][0])
            self.assertEqual(self.account.server_id, self.server.pk)
            self.assertEqual(self.account.encrypted_password, newer_attempts[0][1])
            self.assertEqual(self.account.status, "error")
            self.assertEqual(self.job.status, "attention")
            self.assertEqual(newer_job.status, "failed")
            self.assertIsNotNone(newer_job.next_retry_at)
            self.assertEqual(newer_job.retry_count, 0)
            self.assertEqual(target.current_domains, 0)
            self.assertEqual(newer.current_domains, 0)
            self.assertTrue(native_target.domain_state_of(self.account.domain).enabled)
            self.assertEqual(len(native_target.get_calls("create-domain")), 1)
            self.assertEqual(len(native_newer.get_calls("create-domain")), 1)
            self.assertEqual(len(self.gateway.get_calls("create-domain")), 0)
            self.assertEqual(len(native_target.get_calls("disable-domain")), 0)
            self.assertEqual(len(native_target.get_calls("delete-domain")), 0)
            self.assertFalse(
                VirtualminProvisioningJob.objects.filter(
                    account=self.account, parameters__revoked_create_job_id=str(self.job.pk)
                ).exists()
            )

    def test_old_target_cannot_adopt_after_newer_public_reprovision_fails_before_delivery(self) -> None:
        self._assert_newer_failed_reprovision_keeps_its_credential_authority(during_probe=False)

    def test_old_target_cannot_adopt_after_newer_public_reprovision_fails_during_probe(self) -> None:
        self._assert_newer_failed_reprovision_keeps_its_credential_authority(during_probe=True)
