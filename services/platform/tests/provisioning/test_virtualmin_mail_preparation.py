"""The 24-hour preparation limit releases only proven untouched owner intent."""

import json
from datetime import timedelta
from uuid import uuid4

from django.test import TestCase, override_settings
from freezegun import freeze_time

from apps.audit.models import AuditEvent
from apps.provisioning import virtualmin_mail_execution as execution
from apps.provisioning.virtualmin_mail_enrollment import prepare_mail_enrollment, request_mail_enrollment
from apps.provisioning.virtualmin_mail_models import VirtualminMailOperation
from apps.provisioning.virtualmin_mail_status import cached_mail_status
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminServer
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.test_virtualmin_mail_execution import MailExecutionFixture


@override_settings(DISABLE_AUDIT_SIGNALS=True, AUDIT_CHAIN_ENABLED=False)
class MailPreparationTests(MailExecutionFixture, TestCase):
    def defer(self, *, generation=None, reason="mail_node_certificate_unproven"):
        return execution.defer_mail_preparation(
            self.operation.pk,
            generation=self.operation.target_generation if generation is None else generation,
            reason=reason,
        )

    def assert_no_effects(self):
        self.operation.configuration.refresh_from_db()
        self.assertEqual(self.operation.configuration.mode, "external")
        self.assertEqual(self.operation.configuration.readiness, {})
        for boundary in self.boundaries:
            boundary.assert_not_called()

    def test_prerequisite_wait_is_bounded_without_claiming_execution_or_inventing_progress(self):
        now = self.operation.created_at + timedelta(hours=1)
        with freeze_time(now):
            result = self.defer()
            self.assertTrue(result.is_ok(), result)
            self.assertEqual(result.unwrap(), "queued")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.resume_after, now + timedelta(minutes=15))
        self.assertEqual(
            (self.operation.status, self.operation.checkpoint, self.operation.error_code), ("queued", "", "")
        )
        self.assertEqual(self.operation.result, {})
        self.assertIsNone(self.operation.lease_token)
        self.assertIsNone(self.operation.lease_expires_at)
        self.assertTrue(account_has_active_operation(self.account))
        self.assert_no_effects()

    def test_cancellation_boundary_is_24_hours_including_the_exact_instant(self):
        deadline = self.operation.created_at + timedelta(hours=24)
        for delta, expected in ((-1, "queued"), (0, "cancelled"), (1, "cancelled")):
            with self.subTest(microseconds=delta):
                VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
                    status="queued", error_code="", resume_after=None
                )
                with freeze_time(deadline + timedelta(microseconds=delta)):
                    result = self.defer()
                    self.assertTrue(result.is_ok(), result)
                    self.assertEqual(result.unwrap(), expected)
                self.operation.refresh_from_db()
                self.assertEqual(self.operation.status, expected)
                self.assertEqual(account_has_active_operation(self.account), expected == "queued")
                if expected == "queued":
                    self.assertEqual(self.operation.resume_after, deadline)
                else:
                    self.assertIsNone(self.operation.resume_after)
                    self.assertEqual(self.operation.error_code, "mail_prerequisites_expired")
        self.assert_no_effects()

    def test_backoff_replay_never_slides_or_extends_the_original_deadline(self):
        now = self.operation.created_at + timedelta(hours=23, minutes=50)
        with freeze_time(now):
            self.assertTrue(self.defer(reason="mail_dns_source_unavailable").is_ok())
        self.operation.refresh_from_db()
        due = self.operation.resume_after
        self.assertEqual(due, self.operation.created_at + timedelta(hours=24))
        with freeze_time(now + timedelta(minutes=1)):
            self.assertEqual(self.defer().unwrap(), "queued")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.resume_after, due)
        with freeze_time(due):
            self.assertEqual(self.defer().unwrap(), "cancelled")
        self.assert_no_effects()

    def test_a_future_resume_time_cannot_hide_expiry_and_completed_cancellation_is_idempotent(self):
        VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
            resume_after=self.operation.created_at + timedelta(days=7)
        )
        now = self.operation.created_at + timedelta(days=1)
        with freeze_time(now):
            self.assertEqual(self.defer().unwrap(), "cancelled")
        self.operation.refresh_from_db()
        updated = self.operation.updated_at
        count = AuditEvent.objects.filter(object_id=str(self.operation.pk)).count()
        with freeze_time(now + timedelta(minutes=1)):
            self.assertEqual(self.defer().unwrap(), "cancelled")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.updated_at, updated)
        self.assertEqual(AuditEvent.objects.filter(object_id=str(self.operation.pk)).count(), count)
        self.assert_no_effects()

    def test_expiry_is_audited_without_changing_consent_or_releasing_submission_identity(self):
        original = (self.operation.submission_id, self.operation.consent_digest, self.operation.confirmed_plan)
        with freeze_time(self.operation.created_at + timedelta(days=1)):
            self.assertEqual(self.defer().unwrap(), "cancelled")
            self.operation.refresh_from_db()
            self.assertEqual(
                (self.operation.submission_id, self.operation.consent_digest, self.operation.confirmed_plan), original
            )
            event = AuditEvent.objects.filter(object_id=str(self.operation.pk)).latest("timestamp")
            self.assertEqual(event.old_values["status"], "queued")
            self.assertEqual(event.new_values["status"], "cancelled")
            self.assertEqual(event.new_values["error_code"], "mail_prerequisites_expired")
            self.assertNotIn("records", json.dumps(event.new_values))
            proposal = prepare_mail_enrollment(
                self.account, actor=self.owner, intent="enable", plan={"version": 1, "records": []}
            ).unwrap()
            retry = request_mail_enrollment(
                self.account,
                actor=self.owner,
                intent="enable",
                proposal_id=proposal["proposal_id"],
                consent_digest=proposal["consent_digest"],
                submission_id=uuid4(),
            ).unwrap()
            self.assertNotEqual(retry.pk, self.operation.pk)
            self.assertEqual(retry.status, "queued")
            replay = request_mail_enrollment(
                self.account,
                actor=self.owner,
                intent="enable",
                proposal_id=original[2]["proposal_id"],
                consent_digest=original[1],
                submission_id=original[0],
            ).unwrap()
            self.assertEqual(replay.pk, self.operation.pk)
            self.assertEqual(replay.status, "cancelled")
        self.assert_no_effects()

    def test_queued_evidence_including_falsy_json_is_uncertain_and_never_pristine(self):
        for fields in (
            {"checkpoint": "native_inflight"},
            {"result": {"native_started": True}},
            {"result": []},
            {"result": False},
            {"result": 0},
            {"result": ""},
            {"error_code": "mail_native_outcome_unknown"},
            {"lease_token": uuid4()},
            {"lease_expires_at": self.operation.created_at + timedelta(hours=1)},
        ):
            with self.subTest(fields=fields):
                VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
                    **{
                        "status": "queued",
                        "checkpoint": "",
                        "result": {},
                        "error_code": "",
                        "lease_token": None,
                        "lease_expires_at": None,
                        "resume_after": None,
                        **fields,
                    }
                )
                with freeze_time(self.operation.created_at + timedelta(days=1)):
                    self.assertEqual(self.defer().unwrap_err(), "mail_execution_requires_review")
                self.operation.refresh_from_db()
                self.assertEqual(self.operation.status, "needs_review")
                self.assertEqual(self.operation.error_code, "mail_execution_state_uncertain")
                self.assertTrue(account_has_active_operation(self.account))
        self.assert_no_effects()

    def test_execution_claim_also_refuses_malformed_falsy_json_instead_of_discarding_it(self):
        for value in ([], False, 0, ""):
            with self.subTest(value=value):
                VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
                    status="queued", checkpoint="", result=value, error_code="", lease_token=None, lease_expires_at=None
                )
                self.assertEqual(
                    execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_execution_requires_review"
                )
                self.operation.refresh_from_db()
                self.assertEqual(self.operation.status, "needs_review")
        self.assert_no_effects()

    def test_live_or_expired_running_work_never_becomes_pristine_cancellation(self):
        now = self.operation.created_at + timedelta(days=1)
        for hours, expected in ((1, "running"), (-1, "needs_review")):
            with self.subTest(hours=hours):
                token = uuid4()
                VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
                    status="running",
                    checkpoint="claimed",
                    lease_token=token,
                    lease_expires_at=now + timedelta(hours=hours),
                )
                with freeze_time(now):
                    self.assertTrue(self.defer().is_err())
                self.operation.refresh_from_db()
                self.assertEqual(self.operation.status, expected)
                self.assertTrue(account_has_active_operation(self.account))
                if expected == "running":
                    self.assertEqual(self.operation.lease_token, token)
        self.assert_no_effects()

    def test_dns_wait_review_and_other_terminal_states_are_preserved(self):
        for status in ("awaiting_dns", "needs_review", "completed", "failed", "cancelled"):
            with self.subTest(status=status):
                VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(status=status)
                with freeze_time(self.operation.created_at + timedelta(days=1)):
                    self.assertTrue(self.defer().is_err())
                self.operation.refresh_from_db()
                self.assertEqual(self.operation.status, status)
        self.assert_no_effects()

    def test_changed_generation_or_revoked_owner_cannot_extend_the_waiting_intent(self):
        self.assertEqual(self.defer(generation="f" * 64).unwrap_err(), "mail_generation_changed")
        VirtualminServer.objects.filter(pk=self.server.pk).update(ipv4_address="203.0.113.21")
        self.assertEqual(self.defer().unwrap_err(), "mail_generation_changed")
        VirtualminServer.objects.filter(pk=self.server.pk).update(ipv4_address=self.server.ipv4_address)
        User.objects.filter(pk=self.owner.pk).update(is_active=False)
        self.assertEqual(self.defer().unwrap_err(), "mail_execution_forbidden")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "queued")
        self.assertIsNone(self.operation.resume_after)
        self.assert_no_effects()

    def test_a_revoked_owner_cannot_leave_pristine_expired_intent_reserving_the_account(self):
        User.objects.filter(pk=self.owner.pk).update(is_active=False)
        with freeze_time(self.operation.created_at + timedelta(days=1)):
            self.assertEqual(self.defer().unwrap(), "cancelled")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "cancelled")
        self.assertFalse(account_has_active_operation(self.account))
        self.assert_no_effects()

    def test_a_changed_target_cannot_leave_pristine_expired_intent_reserving_the_account(self):
        VirtualminServer.objects.filter(pk=self.server.pk).update(ipv4_address="203.0.113.21")
        with freeze_time(self.operation.created_at + timedelta(days=1)):
            self.assertEqual(self.defer().unwrap(), "cancelled")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "cancelled")
        self.assertFalse(account_has_active_operation(self.account))
        self.assert_no_effects()

    def test_arbitrary_or_uncertain_prerequisite_reasons_do_not_mutate_the_operation(self):
        for reason in ("password=private-value", "mail_native_outcome_unknown", "mail_setup_review_required"):
            with self.subTest(reason=reason):
                self.assertEqual(self.defer(reason=reason).unwrap_err(), "mail_invalid_error_code")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "queued")
        self.assertIsNone(self.operation.resume_after)
        self.assert_no_effects()

    def test_age_alone_does_not_cancel_a_pristine_attempt_that_can_now_be_claimed(self):
        with freeze_time(self.operation.created_at + timedelta(days=1)):
            lease = execution.claim_mail_operation(self.operation.pk).unwrap()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "running")
        self.assertEqual(self.operation.lease_token, lease.token)
        self.assert_no_effects()

    def test_hosted_mail_retirement_is_not_an_opt_in_preparation_timeout(self):
        configuration = self.operation.configuration
        configuration.delete()
        configuration = self.prepared()
        configuration.enable_hosted()
        configuration.save()
        proposal = prepare_mail_enrollment(
            self.account, actor=self.owner, intent="disable", plan={"version": 1, "records": []}
        ).unwrap()
        self.operation = request_mail_enrollment(
            self.account,
            actor=self.owner,
            intent="disable",
            proposal_id=proposal["proposal_id"],
            consent_digest=proposal["consent_digest"],
            submission_id=uuid4(),
        ).unwrap()
        with freeze_time(self.operation.created_at + timedelta(days=1)):
            self.assertEqual(self.defer().unwrap_err(), "mail_preparation_not_enable")
        self.operation.refresh_from_db()
        configuration.refresh_from_db()
        self.assertEqual(self.operation.status, "queued")
        self.assertEqual(configuration.mode, "hosted")
        for boundary in self.boundaries:
            boundary.assert_not_called()

    def test_expiry_is_a_known_fixed_public_receipt_without_native_or_dns_reads(self):
        force_status(self.customer, "active")
        VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
            status="cancelled", error_code="mail_prerequisites_expired"
        )
        result = cached_mail_status(self.account.service_id, customer_id=self.customer.pk, actor=self.owner).unwrap()
        self.assertEqual(result["operation"]["status"], "cancelled")
        self.assertEqual(result["operation"]["error_code"], "mail_prerequisites_expired")
        self.assertFalse(result["enrolled"])
        self.assert_no_effects()
