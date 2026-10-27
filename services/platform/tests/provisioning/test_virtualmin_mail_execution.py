"""A mail worker owns only its current, authorized, generation-bound attempt."""

import json
from dataclasses import replace
from datetime import timedelta
from unittest.mock import patch
from uuid import UUID, uuid4

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from django_fsm import TransitionNotAllowed
from freezegun import freeze_time

from apps.provisioning import virtualmin_mail_execution as execution
from apps.provisioning.virtualmin_mail_enrollment import prepare_mail_enrollment, request_mail_enrollment
from apps.provisioning.virtualmin_mail_models import VirtualminMailConfiguration, VirtualminMailOperation
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.users.models import CustomerMembership, User
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.test_account_hostname_models import _make_server
from tests.provisioning.test_virtualmin_mail_models import MailModelFixture


class MailExecutionFixture(MailModelFixture):
    def setUp(self):
        self.enterContext(patch("apps.provisioning.virtualmin_tasks.reconcile_virtualmin_service_state_async"))
        super().setUp()
        self.owner = User.objects.create_user(email="execution-owner@example.test", password="Owner-test123!")
        self.customer = self.account.service.customer
        self.membership = CustomerMembership.objects.create(user=self.owner, customer=self.customer, role="owner")
        proposal = prepare_mail_enrollment(
            self.account,
            actor=self.owner,
            intent="enable",
            plan={"version": 1, "records": [{"name": self.account.domain, "type": "MX", "value": self.name.fqdn}]},
        ).unwrap()
        self.operation = request_mail_enrollment(
            self.account,
            actor=self.owner,
            intent="enable",
            proposal_id=proposal["proposal_id"],
            consent_digest=proposal["consent_digest"],
            submission_id=uuid4(),
        ).unwrap()
        self.boundaries = []
        for boundary in (
            "apps.provisioning.virtualmin_gateway.VirtualminGateway.call",
            "apps.infrastructure.ansible_service.AnsibleService.run_playbook",
            "apps.infrastructure.dns_zone_gateway.get_zone_gateway",
            "django_q.tasks.async_task",
        ):
            self.boundaries.append(
                self.enterContext(patch(boundary, side_effect=AssertionError("No execution backend")))
            )


@override_settings(DISABLE_AUDIT_SIGNALS=True, AUDIT_CHAIN_ENABLED=False)
class MailExecutionTests(MailExecutionFixture, TestCase):
    def claim(self):
        result = execution.claim_mail_operation(self.operation.pk)
        self.assertTrue(result.is_ok(), result)
        return result.unwrap()

    def test_claim_grants_a_fresh_token_without_native_or_business_mode_changes(self):
        lease = self.claim()
        self.operation.refresh_from_db()
        self.assertIsInstance(lease.token, UUID)
        self.assertEqual(lease.operation_id, self.operation.pk)
        self.assertEqual(lease.generation, self.operation.target_generation)
        self.assertEqual(self.operation.lease_token, lease.token)
        self.assertEqual(self.operation.status, "running")
        self.assertEqual(lease.checkpoint, "claimed")
        self.assertGreater(lease.expires_at, timezone.now())
        self.assertLessEqual(lease.expires_at, timezone.now() + execution.MAIL_EXECUTION_LEASE)
        self.assertEqual(VirtualminMailConfiguration.objects.get(pk=self.operation.configuration_id).mode, "external")
        self.assertEqual(self.operation.configuration.readiness, {})
        for boundary in self.boundaries:
            boundary.assert_not_called()

    def test_a_second_claim_cannot_replace_a_live_worker(self):
        first = self.claim()
        self.assertEqual(execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_execution_busy")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.lease_token, first.token)
        self.assertEqual(self.operation.status, "running")

    def test_due_time_is_respected_and_confirmed_consent_does_not_expire_in_the_queue(self):
        when = timezone.now() + timedelta(hours=1)
        VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(resume_after=when)
        self.assertEqual(execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_execution_not_due")
        with freeze_time(when + timedelta(seconds=1)):
            self.assertTrue(execution.claim_mail_operation(self.operation.pk).is_ok())

    def test_live_renewal_and_checkpoints_compare_current_token_generation_and_phase(self):
        lease = self.claim()
        with freeze_time(timezone.now() + timedelta(minutes=1)):
            renewed = execution.renew_mail_operation(lease).unwrap()
        self.assertGreater(renewed.expires_at, lease.expires_at)
        prepared = execution.checkpoint_mail_operation(
            renewed,
            checkpoint="preflight",
            evidence={"domain_id": "123456", "inventory_sha256": "a" * 64, "mailbox_count": 2},
        ).unwrap()
        self.assertEqual(prepared.checkpoint, "preflight")
        self.assertTrue(execution.checkpoint_mail_operation(lease, checkpoint="preflight", evidence={}).is_err())
        pending = execution.checkpoint_mail_operation(prepared, checkpoint="native_inflight", evidence={}).unwrap()
        self.assertEqual(pending.checkpoint, "native_inflight")
        self.assertTrue(execution.checkpoint_mail_operation(pending, checkpoint="preflight", evidence={}).is_err())
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "running")
        self.assertEqual(self.operation.checkpoint, "native_inflight")
        self.assertEqual(self.operation.configuration.mode, "external")
        self.assertEqual(self.operation.configuration.readiness, {})
        with self.assertRaises(TransitionNotAllowed):
            self.operation.configuration.enable_hosted()

    def test_later_checkpoints_retain_prior_identity_and_refuse_conflicting_evidence(self):
        lease = self.claim()
        evidence = {"domain_id": "123456", "inventory_sha256": "a" * 64}
        prepared = execution.checkpoint_mail_operation(lease, checkpoint="preflight", evidence=evidence).unwrap()
        self.assertEqual(
            execution.checkpoint_mail_operation(
                prepared, checkpoint="native_inflight", evidence={"domain_id": "987"}
            ).unwrap_err(),
            "mail_invalid_checkpoint",
        )
        execution.checkpoint_mail_operation(prepared, checkpoint="native_inflight", evidence={}).unwrap()
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.result["evidence"], evidence)

    def test_progress_is_audited_but_lease_heartbeats_are_not(self):
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        lease = self.claim()
        events = AuditEvent.objects.filter(action="configuration_changed", object_id=str(self.operation.pk))
        before = events.count()
        self.assertGreater(before, 0)
        renewed = execution.renew_mail_operation(lease).unwrap()
        self.assertEqual(events.count(), before)
        execution.checkpoint_mail_operation(renewed, checkpoint="preflight", evidence={"domain_id": "123456"}).unwrap()
        self.assertEqual(events.count(), before + 1)
        self.assertNotIn("result", events.latest("timestamp").new_values)

    def test_exact_domain_hold_applies_after_claim_but_an_addon_does_not(self):
        from apps.domains.models import TLD, Domain, Registrar  # noqa: PLC0415
        from apps.provisioning.relationship_models import ServiceDomain  # noqa: PLC0415

        registrar = Registrar.objects.create(name="execution", display_name="Execution", status="active")
        tld = TLD.objects.create(
            extension="test", registration_price_cents=100, renewal_price_cents=100, transfer_price_cents=100
        )
        addon = Domain.objects.create(
            name="addon-execution.example.test", customer=self.customer, registrar=registrar, tld=tld, status="expired"
        )
        ServiceDomain.objects.create(service=self.account.service, domain=addon)
        lease = self.claim()
        exact = Domain.objects.create(
            name=self.account.domain, customer=self.customer, registrar=registrar, tld=tld, status="expired"
        )
        ServiceDomain.objects.create(service=self.account.service, domain=exact)
        self.assertEqual(execution.renew_mail_operation(lease).unwrap_err(), "mail_execution_requires_review")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.error_code, "mail_hosting_held")

    def test_even_an_owned_current_generation_row_needs_exact_confirmed_consent(self):
        # fsm-bypass: close the fixture intent before creating malformed operational input.
        VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(status="cancelled")
        bad = VirtualminMailOperation.objects.create(
            configuration=self.operation.configuration,
            requested_customer=self.customer,
            requested_by=self.owner,
            submission_id=uuid4(),
            intent="enable",
            target_generation=self.operation.target_generation,
            consent_digest=self.operation.consent_digest,
            confirmed_plan={"version": 1, "plan": {}},
        )
        self.assertEqual(execution.claim_mail_operation(bad.pk).unwrap_err(), "mail_execution_invalid_consent")
        bad.refresh_from_db()
        self.assertEqual(bad.status, "queued")

    def test_a_current_owner_can_claim_retirement_while_billing_holds_hosted_mail(self):
        # fsm-bypass: replace the queued fixture intent with an established hosted configuration.
        VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(status="cancelled")
        configuration = self.operation.configuration
        configuration.consent_digest = "a" * 64
        configuration.verified_at = timezone.now()
        configuration.readiness = {
            "version": 1,
            "consent_digest": configuration.consent_digest,
            "generation": self.operation.target_generation,
            "native_ready": True,
            "dns_ready": True,
            "domain_id": "123456",
            "owner": self.account.virtualmin_username,
            "client_hostname": self.name.fqdn,
        }
        configuration.enable_hosted()
        configuration.save()
        force_status(self.account.service, "suspended")
        proposal = prepare_mail_enrollment(
            self.account, actor=self.owner, intent="disable", plan={"version": 1}
        ).unwrap()
        retirement = request_mail_enrollment(
            self.account,
            actor=self.owner,
            intent="disable",
            proposal_id=proposal["proposal_id"],
            consent_digest=proposal["consent_digest"],
            submission_id=uuid4(),
        ).unwrap()
        self.assertTrue(execution.claim_mail_operation(retirement.pk).is_ok())
        configuration.refresh_from_db()
        self.assertEqual(
            configuration.mode, "hosted", "execution ownership never performs the retirement FSM transition"
        )

    def test_service_customer_transfer_does_not_adopt_the_previous_customers_intent(self):
        from apps.customers.models import Customer  # noqa: PLC0415

        other = Customer.objects.create(name="New mail owner", primary_email="new-mail-owner@example.test")
        self.account.service.customer = other
        self.account.service.save(update_fields=["customer"])
        self.assertEqual(execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_execution_forbidden")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "queued")

    def test_stale_tokens_and_forged_generations_cannot_renew_checkpoint_or_park(self):
        lease = self.claim()
        for stale in (replace(lease, token=uuid4()), replace(lease, generation="f" * 64)):
            with self.subTest(stale=stale.token):
                self.assertTrue(execution.renew_mail_operation(stale).is_err())
                self.assertTrue(
                    execution.checkpoint_mail_operation(stale, checkpoint="preflight", evidence={}).is_err()
                )
                self.assertTrue(execution.park_mail_operation(stale, code="mail_native_outcome_unknown").is_err())
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.lease_token, lease.token)
        self.assertEqual((self.operation.status, self.operation.checkpoint), ("running", "claimed"))

    def test_expired_running_work_parks_without_a_new_token_or_native_replay(self):
        lease = self.claim()
        lease = execution.checkpoint_mail_operation(
            lease, checkpoint="preflight", evidence={"domain_id": "123456"}
        ).unwrap()
        lease = execution.checkpoint_mail_operation(
            lease, checkpoint="native_inflight", evidence={"domain_id": "123456"}
        ).unwrap()
        VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
            lease_expires_at=timezone.now() - timedelta(seconds=1)
        )
        self.assertEqual(
            execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_execution_requires_review"
        )
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "needs_review")
        self.assertEqual(self.operation.checkpoint, "native_inflight")
        self.assertEqual(self.operation.result["evidence"], {"domain_id": "123456"})
        self.assertIsNone(self.operation.lease_token)
        self.assertIsNone(self.operation.lease_expires_at)
        self.assertTrue(execution.checkpoint_mail_operation(lease, checkpoint="preflight", evidence={}).is_err())
        self.assertTrue(execution.claim_mail_operation(self.operation.pk).is_err())

    def test_missing_running_ownership_and_unknown_queued_progress_are_parked(self):
        for fields in ({"status": "running"}, {"status": "queued", "checkpoint": "native_inflight"}):
            with self.subTest(fields=fields):
                # fsm-bypass: operational status is a CharField; establish interrupted attempt evidence.
                VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
                    **{"status": "queued", "checkpoint": "", "lease_token": None, "lease_expires_at": None, **fields}
                )
                self.assertEqual(
                    execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_execution_requires_review"
                )
                self.operation.refresh_from_db()
                self.assertEqual(self.operation.status, "needs_review")

    def test_unknown_running_progress_is_parked_without_copying_raw_error_or_credentials_into_audit(self):
        from apps.audit.models import AuditEvent  # noqa: PLC0415

        lease = self.claim()
        VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
            checkpoint="unknown_native_phase", result={"password": "private-value"}, error_code="private-value"
        )
        self.assertEqual(execution.renew_mail_operation(lease).unwrap_err(), "mail_execution_requires_review")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "needs_review")
        event = AuditEvent.objects.filter(object_id=str(self.operation.pk)).latest("timestamp")
        self.assertNotIn("private-value", json.dumps({"old": event.old_values, "new": event.new_values}))

    def test_a_new_claim_parks_a_live_token_with_an_unknown_journal_instead_of_reporting_busy(self):
        self.claim()
        VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(
            checkpoint="unknown_native_phase", result={"password": "private-value"}
        )
        self.assertEqual(
            execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_execution_requires_review"
        )
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "needs_review")
        self.assertEqual(self.operation.error_code, "mail_execution_state_uncertain")
        self.assertIsNone(self.operation.lease_token)

    def test_revoked_current_owner_cannot_claim_an_unchanged_pristine_intent(self):
        User.objects.filter(pk=self.owner.pk).update(is_active=False)
        self.assertTrue(self.owner.is_active)
        self.assertEqual(execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_execution_forbidden")
        self.operation.refresh_from_db()
        self.assertEqual(self.operation.status, "queued")
        self.assertIsNone(self.operation.lease_token)
        User.objects.filter(pk=self.owner.pk).update(is_active=True)
        CustomerMembership.objects.filter(pk=self.membership.pk).update(role="tech")
        self.assertEqual(execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_execution_forbidden")

    def test_current_generation_and_hold_changes_are_checked_before_claim_and_every_checkpoint(self):
        self.server.ipv4_address = "203.0.113.99"
        self.server.save(update_fields=["ipv4_address"])
        self.assertEqual(execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_generation_changed")
        self.server.ipv4_address = "203.0.113.20"
        self.server.save(update_fields=["ipv4_address"])
        force_status(self.account.service, "suspended")
        self.assertEqual(execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_hosting_held")
        force_status(self.account.service, "active")
        lease = self.claim()
        self.server.ipv4_address = "203.0.113.99"
        self.server.save(update_fields=["ipv4_address"])
        self.assertEqual(execution.renew_mail_operation(lease).unwrap_err(), "mail_execution_requires_review")
        self.operation.refresh_from_db()
        self.assertEqual(
            (self.operation.status, self.operation.error_code), ("needs_review", "mail_generation_changed")
        )

    def test_later_owner_revocation_parks_only_the_current_workers_attempt(self):
        lease = self.claim()
        CustomerMembership.objects.filter(pk=self.membership.pk).update(is_active=False)
        self.assertEqual(
            execution.checkpoint_mail_operation(lease, checkpoint="preflight", evidence={}).unwrap_err(),
            "mail_execution_requires_review",
        )
        self.operation.refresh_from_db()
        self.assertEqual(
            (self.operation.status, self.operation.error_code), ("needs_review", "mail_execution_forbidden")
        )

    def test_restore_migration_and_running_lifecycle_jobs_exclude_execution_but_own_intent_does_not(self):
        self.account.restore_hold = "restore_pending"
        self.account.save(update_fields=["restore_hold"])
        self.assertEqual(execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_operation_active")
        self.account.restore_hold = ""
        self.account.save(update_fields=["restore_hold"])
        migration = VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=_make_server()
        )
        self.assertEqual(execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_operation_active")
        migration.delete()
        job = VirtualminProvisioningJob.objects.create(
            server=self.server,
            account=self.account,
            operation="delete_domain",
            correlation_id="mail-execution-test",
            status="running",
        )
        self.assertEqual(execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_operation_active")
        job.delete()
        self.assertIsNotNone(self.claim().token)

    def test_arbitrary_phase_completion_and_sensitive_or_oversized_evidence_are_refused(self):
        lease = self.claim()
        for checkpoint, evidence in (
            ("completed", {}),
            ("enable_hosted", {}),
            ("preflight", {"password": "private-value"}),
            ("preflight", {"domain_id": "private-value"}),
            ("preflight", {"inventory_sha256": "x" * 10000}),
            ("preflight", {"mailbox_count": True}),
            ("preflight", {"mailbox_count": 1001}),
        ):
            with self.subTest(checkpoint=checkpoint):
                self.assertEqual(
                    execution.checkpoint_mail_operation(lease, checkpoint=checkpoint, evidence=evidence).unwrap_err(),
                    "mail_invalid_checkpoint",
                )
        self.assertEqual(
            execution.park_mail_operation(lease, code="password=private-value").unwrap_err(), "mail_invalid_error_code"
        )
        self.operation.refresh_from_db()
        self.assertNotIn("private-value", json.dumps(self.operation.result))
        self.assertEqual((self.operation.status, self.operation.checkpoint), ("running", "claimed"))
        self.assertEqual(self.operation.configuration.mode, "external")

    def test_a_live_worker_can_park_a_bounded_unknown_outcome_without_changing_mail_mode(self):
        lease = self.claim()
        self.assertTrue(execution.park_mail_operation(lease, code="mail_native_outcome_unknown").is_ok())
        self.operation.refresh_from_db()
        self.assertEqual(
            (self.operation.status, self.operation.error_code), ("needs_review", "mail_native_outcome_unknown")
        )
        self.assertIsNone(self.operation.lease_token)
        self.assertEqual(self.operation.configuration.mode, "external")

    def test_awaiting_dns_and_terminal_receipts_are_not_new_executable_intents(self):
        for status in ("awaiting_dns", "completed", "failed", "cancelled"):
            with self.subTest(status=status):
                # fsm-bypass: operational status fixture, never a business mode transition.
                VirtualminMailOperation.objects.filter(pk=self.operation.pk).update(status=status)
                self.assertEqual(
                    execution.claim_mail_operation(self.operation.pk).unwrap_err(), "mail_execution_not_queued"
                )


class MailExecutionBoundsTests(SimpleTestCase):
    def test_one_setup_step_and_supported_ssh_recovery_fit_the_execution_lease(self):
        import inspect  # noqa: PLC0415

        from apps.infrastructure.ansible_service import AnsibleService  # noqa: PLC0415
        from apps.provisioning.virtualmin_mail_service import MAIL_SETUP_TIMEOUT_SECONDS  # noqa: PLC0415

        ssh_wait = inspect.signature(AnsibleService._wait_for_ssh).parameters["timeout"].default + 8
        ssh_repair = inspect.signature(AnsibleService).parameters["timeout"].default + ssh_wait + 66
        self.assertGreater(
            execution.MAIL_EXECUTION_LEASE.total_seconds(), MAIL_SETUP_TIMEOUT_SECONDS + ssh_wait + 30 + ssh_repair
        )
