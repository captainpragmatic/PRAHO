"""Real receipt OFF ownership, interrupted execution and staff resolution boundaries."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import Any, Literal
from unittest.mock import patch

from django.conf import settings
from django.contrib.messages import get_messages
from django.db import DatabaseError, connection
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from apps.common.types import Retriability
from apps.provisioning import virtualmin_views
from apps.provisioning.virtualmin_backup_service import RestoreConfig
from apps.provisioning.virtualmin_domain_state import domain_state_params
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_revoked_create import queue_revoked_create_off
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.provisioning.virtualmin_tasks import process_failed_virtualmin_jobs
from tests.provisioning import test_virtualmin_create_retry_policy as fixtures


class _WorkerCrash(BaseException):
    """A process death is not an ordinary caught provisioning exception."""


class ReceiptAuthorityTests(fixtures.CreateRetryFixture):
    def _refuse_unknown_origin(self, intent: object) -> None:
        self._failed_direct_create("failed")
        self.assertTrue(self._retry_through_public_sweep()["success"])
        self.job.refresh_from_db()
        parameters = dict(self.job.parameters)
        if intent is None:
            parameters.pop("creation_intent")
        else:
            if isinstance(intent, dict) and intent.get("service_id") != -1:
                intent = {**intent, "service_id": self.service.pk}
            parameters["creation_intent"] = intent
        self.job.parameters = parameters
        self.job.save(update_fields=["parameters", "updated_at"])
        published = queue_revoked_create_off(self.account.pk, self.job.pk, native_outcome="created")
        self.assertTrue(published.is_err(), "Unknown origin was promoted to automatic native OFF authority")
        self.assertFalse(
            VirtualminProvisioningJob.objects.filter(
                operation="suspend_domain",
                account=self.account,
            ).exists()
        )
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 0)

    def test_missing_legacy_origin_is_review_not_automatic_off_authority(self) -> None:
        self._refuse_unknown_origin(None)

    def test_malformed_origin_is_review_not_automatic_off_authority(self) -> None:
        self._refuse_unknown_origin(
            {"version": True, "service_id": self.service.pk, "service_status": "failed", "purpose": "create"}
        )

    def test_foreign_origin_is_review_not_automatic_off_authority(self) -> None:
        self._refuse_unknown_origin({"version": 1, "service_id": -1, "service_status": "failed", "purpose": "create"})


class ReceiptOffFixture(fixtures.CreateRetryFixture):
    def _queue_off(self) -> VirtualminProvisioningJob:
        self._failed_direct_create("provisioning", attach_order=True)
        self.gateway.after_accepted_create = self._cancel_and_run_normal_reconcile
        self._retry_through_public_sweep()
        return VirtualminProvisioningJob.objects.get(
            operation="suspend_domain",
            account=self.account,
            parameters__revoked_create_job_id=str(self.job.pk),
        )

    def _unknown_off(self) -> VirtualminProvisioningJob:
        off = self._queue_off()
        self.gateway.lose_disable_response = True
        result = self._deliver_receipt_off()
        self.assertFalse(result["success"], result)
        off.refresh_from_db()
        self.assertEqual(off.status, "attention")
        self.assertIsNone(off.next_retry_at)
        self.assertFalse(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(
            self.gateway.get_domain_state(self.account.domain).unwrap(),
            {
                "exists": True,
                "enabled": False,
                "owner": self.account.virtualmin_username,
            },
        )
        return off

    def _operator_client(self, off: VirtualminProvisioningJob) -> tuple[Client, str, object]:
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)
        page = client.get(reverse("provisioning:virtualmin_job_status", args=[off.pk]))
        self.assertEqual(page.status_code, 200)
        token = client.cookies[settings.CSRF_COOKIE_NAME].value
        return client, token, page


class ReceiptOffResolutionTests(ReceiptOffFixture):
    def _stale_staff_eligibility(self, mode: Literal["consumer", "queue_failure", "reaper"]) -> None:
        off = self._queue_off()
        self.gateway.disable_failure = Retriability.RETRIABLE
        self.assertFalse(self._deliver_receipt_off()["success"])
        first, first_token, _ = self._operator_client(off)
        reviewer, reviewer_token, _ = self._operator_client(off)
        actual_eligibility = virtualmin_views._job_can_be_retried
        crossed = False

        def observe_real_eligibility(candidate: VirtualminProvisioningJob) -> bool:
            nonlocal crossed
            allowed = actual_eligibility(candidate)
            if allowed and candidate.pk == off.pk and not crossed:
                crossed = True
                response = reviewer.post(
                    reverse("provisioning:virtualmin_job_retry", args=[off.pk]), HTTP_X_CSRFTOKEN=reviewer_token
                )
                self.assertEqual(response.status_code, 302)
                self.assertEqual(process_failed_virtualmin_jobs()["results"]["retried_jobs"], 1)
                self.gateway.disable_failure = None
                self.gateway.lose_disable_response = True
                self.assertFalse(self._deliver_receipt_off()["success"])
                current = reviewer.get(reverse("provisioning:virtualmin_job_status", args=[off.pk]))
                verified = reviewer.post(
                    reverse("provisioning:virtualmin_job_resolve", args=[off.pk]),
                    {
                        "note": "Exact OFF verified and all node commands stopped",
                        "commands_stopped": "on",
                        "resource_confirmed": "on",
                        "off_review_fingerprint": current.context["off_review_fingerprint"],
                    },
                    HTTP_X_CSRFTOKEN=reviewer_token,
                )
                self.assertEqual(verified.status_code, 302)
                closed = reviewer.post(
                    reverse("provisioning:virtualmin_job_resolve", args=[self.job.pk]),
                    {"note": "Verified creation recovery acknowledged"},
                    HTTP_X_CSRFTOKEN=reviewer_token,
                )
                self.assertEqual(closed.status_code, 302)
                self.job.refresh_from_db()
                self.assertEqual(self.job.status, "failed")
            # This observer returns the actual eligibility decision made before
            # the other genuine public requests; it invents no permission/claim.
            return allowed

        with patch("apps.provisioning.virtualmin_views._job_can_be_retried", side_effect=observe_real_eligibility):
            stale = first.post(
                reverse("provisioning:virtualmin_job_retry", args=[off.pk]), HTTP_X_CSRFTOKEN=first_token
            )
        self.assertEqual(stale.status_code, 302)
        self.assertTrue(crossed, "The real eligibility/public-resolution interval was never crossed")
        if mode == "queue_failure":
            with patch("apps.provisioning.virtualmin_tasks.async_task", side_effect=RuntimeError("Queue unavailable")):
                process_failed_virtualmin_jobs()
        else:
            process_failed_virtualmin_jobs()
            if mode == "reaper":
                with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(hours=2)):
                    process_failed_virtualmin_jobs()
            self._deliver_owned(fixtures.RETRY, str(off.pk))
        off.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(off.status, "failed", "Stale eligibility reopened a closed receipt's account hold")
        self.assertIsNone(off.next_retry_at)
        self.assertFalse(account_has_active_operation(self.account))
        self.assertEqual(self.job.status, "failed")
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 2)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_stale_staff_eligibility_cannot_reclaim_an_off_closed_by_public_review(self) -> None:
        self._stale_staff_eligibility("consumer")

    def test_stale_closed_off_with_failed_publication_is_retired_without_new_attempts(self) -> None:
        self._stale_staff_eligibility("queue_failure")

    def test_stale_closed_off_lost_delivery_is_retired_by_reaper_without_new_hold(self) -> None:
        self._stale_staff_eligibility("reaper")

    def test_permanent_off_failure_keeps_its_classification_and_uses_verified_review(self) -> None:
        off = self._queue_off()
        self.gateway.disable_failure = Retriability.NOT_RETRIABLE
        outcome = self._deliver_receipt_off()
        self.assertFalse(outcome["success"], outcome)
        off.refresh_from_db()
        self.assertEqual(off.status, "attention")
        self.assertEqual(off.retry_count, 0)
        self.assertIsNone(off.next_retry_at)
        self.assertEqual(off.result["native_failure_retriability"], Retriability.NOT_RETRIABLE.value)
        self.assertEqual(off.result["native_failure_reason"], off.status_message)
        self.assertTrue(account_has_active_operation(self.account))
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)
        self.gateway.disable_failure = None
        corrected = self.gateway.call("disable-domain", domain_state_params(self.account.domain))
        self.assertTrue(corrected.is_ok() and corrected.unwrap().success, corrected)
        client, token, page = self._operator_client(off)
        response = client.post(
            reverse("provisioning:virtualmin_job_resolve", args=[off.pk]),
            {
                "note": "Permanent failure corrected manually; native commands stopped",
                "commands_stopped": "on",
                "resource_confirmed": "on",
                "off_review_fingerprint": page.context["off_review_fingerprint"],
            },
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(response.status_code, 302)
        off.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(off.status, "failed")
        self.assertEqual(off.retry_count, 0)
        self.assertIsNone(off.next_retry_at)
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        rendered = client.get(reverse("provisioning:virtualmin_job_status", args=[off.pk]))
        self.assertFalse(rendered.context["can_retry"], "Verified review advertised replay of the closed OFF")
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_final_queue_failure_keeps_receipt_off_owned_for_attested_review(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_revoked_create.async_task", side_effect=RuntimeError("Queue unavailable")
        ):
            off = self._queue_off()
        with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(hours=2)):
            recovered = process_failed_virtualmin_jobs()
        self.assertEqual(recovered["results"]["recovered_claims"], 1)
        for _ in range(off.max_retries):
            off.refresh_from_db()
            with (
                patch("django.utils.timezone.now", return_value=off.next_retry_at + timedelta(seconds=1)),
                patch("apps.provisioning.virtualmin_tasks.async_task", side_effect=RuntimeError("Queue unavailable")),
            ):
                failed = process_failed_virtualmin_jobs()
            self.assertEqual(failed["results"]["skipped_jobs"], 1)
        off.refresh_from_db()
        self.assertEqual(off.retry_count, off.max_retries)
        self.assertEqual(off.status, "attention", "Exhausted unissued OFF lost its operator recovery path")
        self.assertIsNone(off.next_retry_at)
        self.assertTrue(account_has_active_operation(self.account))
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(self._deliver_owned(fixtures.RETRY, str(off.pk)), [])
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 0)

    def test_last_undelivered_off_claim_recovers_to_attention_without_native_replay(self) -> None:
        off = self._queue_off()
        self.gateway.disable_failure = Retriability.RETRIABLE
        self.assertFalse(self._deliver_receipt_off()["success"])
        for _ in range(off.max_retries - 1):
            off.refresh_from_db()
            with patch("django.utils.timezone.now", return_value=off.next_retry_at + timedelta(seconds=1)):
                self.assertEqual(process_failed_virtualmin_jobs()["results"]["retried_jobs"], 1)
            self.assertFalse(self._deliver_receipt_off()["success"])
        off.refresh_from_db()
        with patch("django.utils.timezone.now", return_value=off.next_retry_at + timedelta(seconds=1)):
            self.assertEqual(process_failed_virtualmin_jobs()["results"]["retried_jobs"], 1)
        off.refresh_from_db()
        self.assertEqual(off.status, "pending")
        self.assertEqual(off.retry_count, off.max_retries)
        attempted = len(self.gateway.get_calls("disable-domain"))
        with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(hours=2)):
            self.assertEqual(process_failed_virtualmin_jobs()["results"]["recovered_claims"], 1)
        off.refresh_from_db()
        self.assertEqual(off.status, "attention", "A lost final delivery dropped the receipt ownership")
        self.assertIsNone(off.next_retry_at)
        self.assertTrue(account_has_active_operation(self.account))
        stale = self._deliver_owned(fixtures.RETRY, str(off.pk))
        self.assertEqual([result.get("action") for result in stale], ["stale_claim_discarded"])
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), attempted)
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)

    def test_exhausted_known_off_failures_can_be_verified_without_refunding_or_replaying(self) -> None:
        off = self._queue_off()
        self.gateway.disable_failure = Retriability.RETRIABLE
        self.assertFalse(self._deliver_receipt_off()["success"])
        for _ in range(off.max_retries):
            off.refresh_from_db()
            self.assertIsNotNone(off.next_retry_at)
            with patch("django.utils.timezone.now", return_value=off.next_retry_at + timedelta(seconds=1)):
                swept = process_failed_virtualmin_jobs()
            self.assertEqual(swept["results"]["retried_jobs"], 1)
            self.assertFalse(self._deliver_receipt_off()["success"])
        off.refresh_from_db()
        self.assertEqual(off.retry_count, off.max_retries)
        self.assertIsNone(off.next_retry_at)
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)
        self.gateway.disable_failure = None
        corrected = self.gateway.call("disable-domain", domain_state_params(self.account.domain))
        self.assertTrue(corrected.is_ok() and corrected.unwrap().success, corrected)
        client, token, page = self._operator_client(off)
        writes = len(self.gateway.get_calls("disable-domain"))
        observed = len(self.gateway.get_calls("list-domains"))
        response = client.post(
            reverse("provisioning:virtualmin_job_resolve", args=[off.pk]),
            {
                "note": "Manually corrected the exact resource; all outstanding commands stopped",
                "commands_stopped": "on",
                "resource_confirmed": "on",
                "off_review_fingerprint": page.context["off_review_fingerprint"] or "",
            },
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(response.status_code, 302)
        self.assertGreater(
            len(self.gateway.get_calls("list-domains")),
            observed,
            "Terminal OFF cannot reach the real native verification boundary",
        )
        self.job.refresh_from_db()
        off.refresh_from_db()
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        self.assertEqual(off.retry_count, off.max_retries)
        self.assertIsNone(off.next_retry_at)
        self.assertEqual(off.status, "failed")
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), writes)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
        acknowledged = client.post(
            reverse("provisioning:virtualmin_job_resolve", args=[self.job.pk]),
            {"note": "Verified terminal OFF history; do not replay creation"},
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(acknowledged.status_code, 302)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "failed")
        self.assertIsNone(self.job.next_retry_at)

    def _close_verified_recovery(self) -> tuple[VirtualminProvisioningJob, Client, str]:
        off = self._unknown_off()
        client, token, page = self._operator_client(off)
        resolved = client.post(
            reverse("provisioning:virtualmin_job_resolve", args=[off.pk]),
            {
                "note": "Exact native OFF and stopped commands verified",
                "commands_stopped": "on",
                "resource_confirmed": "on",
                "off_review_fingerprint": page.context["off_review_fingerprint"],
            },
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resolved.status_code, 302)
        acknowledged = client.post(
            reverse("provisioning:virtualmin_job_resolve", args=[self.job.pk]),
            {"note": "Creation review closed after verified OFF"},
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(acknowledged.status_code, 302)
        return off, client, token

    def test_verified_creation_recovery_cannot_be_rearmed_through_staff_retry(self) -> None:
        _, client, token = self._close_verified_recovery()
        retried = client.post(reverse("provisioning:virtualmin_job_retry", args=[self.job.pk]), HTTP_X_CSRFTOKEN=token)
        self.assertEqual(retried.status_code, 302)
        process_failed_virtualmin_jobs()
        self._deliver_owned(fixtures.RETRY, str(self.job.pk))
        self.job.refresh_from_db()
        self.assertEqual(
            VirtualminProvisioningJob.objects.filter(
                account=self.account, parameters__revoked_create_job_id=str(self.job.pk)
            ).count(),
            1,
            "Acknowledged creation reissued a second receipt-bound OFF",
        )
        self.assertEqual(self.job.status, "failed")
        self.assertIsNone(self.job.next_retry_at)
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        self.assertEqual(len(self.gateway.get_calls("create-domain")), 2)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_verified_off_child_cannot_reopen_a_hold_after_parent_acknowledgement(self) -> None:
        off, client, token = self._close_verified_recovery()
        writes = len(self.gateway.get_calls("disable-domain"))
        response = client.post(reverse("provisioning:virtualmin_job_retry", args=[off.pk]), HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 302)
        process_failed_virtualmin_jobs()
        self._deliver_owned(fixtures.RETRY, str(off.pk))
        off.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(off.status, "failed", "A closed OFF was reclaimed against its acknowledged source")
        self.assertIsNone(off.next_retry_at)
        self.assertFalse(account_has_active_operation(self.account))
        self.assertEqual(self.job.status, "failed")
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), writes)

    def test_manual_pipeline_restored_during_issued_off_keeps_truthful_disabled_review(self) -> None:
        self._failed_direct_create("provisioning")
        self.client.force_login(self.operator)
        self.gateway.after_accepted_create = lambda: self.client.post(
            reverse("customers:status_change", args=[self.customer.pk, "suspend"])
        )
        self._retry_through_public_sweep()
        off = VirtualminProvisioningJob.objects.get(operation="suspend_domain", account=self.account)

        def restore_customer() -> None:
            response = self.client.post(reverse("customers:status_change", args=[self.customer.pk, "unsuspend"]))
            self.assertEqual(response.status_code, 302)

        self.gateway.after_accepted_disable = restore_customer
        outcome = self._deliver_receipt_off()
        self.assertTrue(outcome["success"], outcome)
        reconciled = self._deliver_owned(fixtures.RECONCILE, str(self.service.pk))
        self.assertTrue(reconciled, "The actual current-policy reconciliation was never delivered")
        self.assertTrue(all(result.get("action") == "noop" for result in reconciled), reconciled)
        for row in (self.customer, self.service, self.account, self.job, off):
            row.refresh_from_db()
        self.assertEqual(self.customer.status, "active")
        self.assertEqual(self.service.status, "provisioning")
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(off.status, "completed")
        self.assertEqual(self.job.status, "attention")
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        self.assertFalse(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_failed_off_publication_preserves_a_recoverable_unissued_claim(self) -> None:
        with patch(
            "apps.provisioning.virtualmin_revoked_create.async_task", side_effect=RuntimeError("Queue unavailable")
        ):
            off = self._queue_off()
        self.assertEqual(off.status, "pending")
        self.assertTrue(account_has_active_operation(self.account))
        self.assertEqual(self._deliver_owned(fixtures.RETRY, str(off.pk)), [])
        with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(hours=2)):
            recovered = process_failed_virtualmin_jobs()
        self.assertEqual(recovered["results"]["recovered_claims"], 1)
        off.refresh_from_db()
        self.assertEqual(off.status, "failed")
        self.assertIsNotNone(off.next_retry_at)
        with patch("django.utils.timezone.now", return_value=off.next_retry_at + timedelta(seconds=1)):
            resumed = process_failed_virtualmin_jobs()
        self.assertEqual(resumed["results"]["retried_jobs"], 1)
        outcome = self._deliver_receipt_off()
        self.assertTrue(outcome["success"], outcome)
        self.assertFalse(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_post_disable_database_failure_never_enables_or_deletes_and_keeps_review_hold(self) -> None:
        off = self._queue_off()
        interrupted = False

        def settlement_failure(
            execute: Callable[..., Any], sql: str, params: Any, many: bool, context: dict[str, Any]
        ) -> Any:
            nonlocal interrupted
            if (
                not interrupted
                and sql.startswith(f'UPDATE "{VirtualminAccount._meta.db_table}"')
                and self.gateway.get_calls("disable-domain")
            ):
                interrupted = True
                raise DatabaseError("Injected one-shot post-disable settlement failure")
            return execute(sql, params, many, context)

        with connection.execute_wrapper(settlement_failure):
            outcome = self._deliver_receipt_off()
        self.assertTrue(interrupted, "Did not reach the actual post-native database settlement boundary")
        self.assertFalse(outcome["success"], outcome)
        off.refresh_from_db()
        self.assertEqual(off.status, "attention")
        self.assertIsNone(off.next_retry_at)
        self.assertTrue(account_has_active_operation(self.account))
        self.assertFalse(self.gateway.domain_state_of(self.account.domain).enabled)
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)

    def test_unknown_off_requires_csrf_and_verified_operator_release(self) -> None:
        off = self._unknown_off()
        self.assertTrue(account_has_active_operation(self.account))
        refused = VirtualminBackupManagementService(self.server).create_restore_job(
            self.account,
            RestoreConfig(backup_id="operator-retained-backup"),
            initiated_by=self.operator.email,
        )
        self.assertTrue(refused.is_err(), refused)
        client, token, _ = self._operator_client(off)
        url = reverse("provisioning:virtualmin_job_resolve", args=[off.pk])
        csrf_refused = client.post(url, {"note": "No CSRF authority"})
        self.assertEqual(csrf_refused.status_code, 403)
        off.refresh_from_db()
        self.assertEqual(off.status, "attention")
        note_only = client.post(url, {"note": "A note is not proof commands stopped"}, HTTP_X_CSRFTOKEN=token)
        self.assertEqual(note_only.status_code, 302)
        off.refresh_from_db()
        self.assertEqual(off.status, "attention", "Generic note released unknown receipt-bound OFF")
        page = client.get(reverse("provisioning:virtualmin_job_status", args=[off.pk]))
        fingerprint = page.context["off_review_fingerprint"]
        native_writes = len(self.gateway.get_calls("disable-domain"))
        resolved = client.post(
            url,
            {
                "note": "Verified recorded owner and disabled domain; all node commands stopped",
                "commands_stopped": "on",
                "resource_confirmed": "on",
                "off_review_fingerprint": fingerprint,
            },
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(resolved.status_code, 302)
        off.refresh_from_db()
        self.account.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(off.status, "failed", [str(message) for message in get_messages(resolved.wsgi_request)])
        self.assertIsNone(off.next_retry_at)
        self.assertEqual(self.account.status, "suspended")
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        self.assertFalse(account_has_active_operation(self.account))
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), native_writes)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)
        self.assertEqual(len(self.gateway.get_calls("delete-domain")), 0)
        acknowledged = client.post(
            reverse("provisioning:virtualmin_job_resolve", args=[self.job.pk]),
            {"note": "Reviewed the now-verified disabled resource; cancelled Service remains off"},
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(acknowledged.status_code, 302)
        self.job.refresh_from_db()
        self.service.refresh_from_db()
        self.assertEqual(self.job.status, "failed")
        self.assertEqual(self.service.status, "failed")

    def test_original_create_cannot_be_resolved_while_linked_off_is_outstanding(self) -> None:
        off = self._queue_off()
        client, token, _ = self._operator_client(off)
        response = client.post(
            reverse("provisioning:virtualmin_job_resolve", args=[self.job.pk]),
            {"note": "Parent note cannot release outstanding child authority"},
            HTTP_X_CSRFTOKEN=token,
        )
        self.assertEqual(response.status_code, 302)
        self.job.refresh_from_db()
        self.assertEqual(self.job.status, "attention")
        self.assertTrue(account_has_active_operation(self.account))

    def test_real_off_worker_crash_recovers_to_review_without_replay(self) -> None:
        off = self._queue_off()

        def crash_after_acceptance() -> None:
            raise _WorkerCrash

        self.gateway.after_accepted_disable = crash_after_acceptance
        with self.assertRaises(_WorkerCrash):
            self._deliver_receipt_off()
        off.refresh_from_db()
        self.assertEqual(off.status, "running")
        self.assertFalse(self.gateway.domain_state_of(self.account.domain).enabled)
        with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(hours=2)):
            recovered = process_failed_virtualmin_jobs()
        self.assertTrue(recovered["success"], recovered)
        off.refresh_from_db()
        self.assertEqual(off.status, "attention", "Interrupted receipt OFF was rearmed despite unknown native outcome")
        self.assertIsNone(off.next_retry_at)
        self.assertTrue(account_has_active_operation(self.account))
        self.assertEqual(self._deliver_owned(fixtures.RETRY, str(off.pk)), [])
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)

    def _reap_while_delivery_is_waiting(self, off: VirtualminProvisioningJob) -> None:
        with patch("django.utils.timezone.now", return_value=timezone.now() + timedelta(hours=2)):
            recovered = process_failed_virtualmin_jobs()
        self.assertTrue(recovered["success"], recovered)
        off.refresh_from_db()
        self.assertEqual(off.status, "attention")

    def test_reaped_ownership_reader_cannot_issue_off_or_reclaim_running(self) -> None:
        off = self._queue_off()
        self.gateway.after_state_read = lambda: self._reap_while_delivery_is_waiting(off)
        result = self._deliver_receipt_off()
        off.refresh_from_db()
        self.assertFalse(result["success"], result)
        self.assertEqual(off.status, "attention")
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 0)
        self.assertTrue(self.gateway.domain_state_of(self.account.domain).enabled)

    def test_reaped_issued_off_cannot_overwrite_review_with_late_success(self) -> None:
        off = self._queue_off()
        self.gateway.after_accepted_disable = lambda: self._reap_while_delivery_is_waiting(off)
        result = self._deliver_receipt_off()
        off.refresh_from_db()
        self.job.refresh_from_db()
        self.assertFalse(result["success"], result)
        self.assertEqual(off.status, "attention")
        self.assertNotEqual(self.job.result["revoked_creation"]["phase"], "disabled")
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 1)
        self.assertEqual(len(self.gateway.get_calls("enable-domain")), 0)

    def test_policy_restored_during_read_supersedes_unissued_off(self) -> None:
        self._failed_direct_create("provisioning")
        self.client.force_login(self.operator)
        self.gateway.after_accepted_create = lambda: self.client.post(
            reverse("customers:status_change", args=[self.customer.pk, "suspend"])
        )
        self._retry_through_public_sweep()
        off = VirtualminProvisioningJob.objects.get(operation="suspend_domain", account=self.account)

        def restore_customer() -> None:
            response = self.client.post(reverse("customers:status_change", args=[self.customer.pk, "unsuspend"]))
            self.assertEqual(response.status_code, 302)
            self.customer.refresh_from_db()
            self.service.refresh_from_db()
            self.assertEqual(self.customer.status, "active")
            self.assertEqual(self.service.status, "provisioning")

        self.gateway.after_state_read = restore_customer
        self._deliver_receipt_off()
        off.refresh_from_db()
        self.job.refresh_from_db()
        self.assertEqual(off.status, "failed")
        self.assertIsNone(off.next_retry_at)
        self.assertEqual(self.job.result["revoked_creation"]["phase"], "restored")
        self.assertEqual(len(self.gateway.get_calls("disable-domain")), 0)
        self.assertFalse(account_has_active_operation(self.account))
