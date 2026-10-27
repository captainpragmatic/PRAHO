"""Owner consent is exact, current and durable before any mail backend is invoked."""

from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

from django.test import TestCase
from django.utils import timezone

from apps.domains.models import TLD, Domain, Registrar
from apps.provisioning.relationship_models import ServiceDomain
from apps.provisioning.virtualmin_mail_enrollment import prepare_mail_enrollment, request_mail_enrollment
from apps.provisioning.virtualmin_mail_models import VirtualminMailConfiguration, VirtualminMailOperation
from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.users.models import CustomerMembership, User
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.test_account_hostname_models import _account, _make_server
from tests.provisioning.test_virtualmin_mail_models import MailModelFixture


class MailEnrollmentTests(MailModelFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.owner = User.objects.create_user(email="mail-owner@example.test", password="Owner-test123!")
        self.customer = self.account.service.customer
        self.membership = CustomerMembership.objects.create(user=self.owner, customer=self.customer, role="owner")
        self.service = self.account.service
        self.plan = {
            "version": 1,
            "records": [{"name": self.account.domain, "type": "MX", "value": f"10 {self.name.fqdn}.", "ttl": 300}],
            "spf": {
                "before": "v=spf1 include:external.example -all",
                "after": "v=spf1 include:external.example include:spf.praho.test -all",
            },
        }
        # Requests only record consent. Transport/queue boundaries must stay unused.
        for boundary in (
            "apps.provisioning.virtualmin_gateway.VirtualminGateway.call",
            "apps.infrastructure.ansible_service.AnsibleService.run_playbook",
            "apps.infrastructure.dns_zone_gateway.get_zone_gateway",
            "django_q.tasks.async_task",
        ):
            self.enterContext(patch(boundary, side_effect=AssertionError("Enrollment must perform no backend I/O")))

    def prepare(self, *, actor=None, intent="enable", plan=None):
        with self.captureOnCommitCallbacks(execute=True):
            return prepare_mail_enrollment(
                self.account,
                actor=self.owner if actor is None else actor,
                intent=intent,
                plan=self.plan if plan is None else plan,
            )

    def request(self, proposal, *, actor=None, intent="enable", submission=None, digest=None):
        with self.captureOnCommitCallbacks(execute=True):
            return request_mail_enrollment(
                self.account,
                actor=self.owner if actor is None else actor,
                intent=intent,
                proposal_id=proposal["proposal_id"],
                consent_digest=digest or proposal["consent_digest"],
                submission_id=submission or uuid4(),
            )

    def prepared(self):
        result = self.prepare()
        self.assertTrue(result.is_ok(), result)
        return result.unwrap()

    def test_current_owner_can_confirm_exact_durable_work_without_enabling_mail(self):
        proposal = self.prepared()
        self.plan["records"][0]["value"] = "10 tampered.example."
        result = self.request(proposal)
        self.assertTrue(result.is_ok(), result)
        operation = result.unwrap()
        self.assertEqual(operation.status, "queued")
        self.assertEqual(operation.requested_customer_id, self.customer.pk)
        self.assertEqual(operation.requested_by_id, self.owner.pk)
        self.assertEqual(operation.confirmed_plan["plan"]["records"][0]["value"], f"10 {self.name.fqdn}.")
        self.assertEqual(operation.consent_digest, proposal["consent_digest"])
        config = VirtualminMailConfiguration.objects.get(account=self.account)
        self.assertEqual(config.mode, "external")
        self.assertEqual(config.readiness, {})
        self.assertIsNone(config.verified_at)

    def test_tech_billing_viewer_and_missing_actor_cannot_stage_or_confirm_owner_consent(self):
        proposal = self.prepared()
        for role in ("tech", "billing", "viewer"):
            with self.subTest(role=role):
                member = User.objects.create_user(email=f"{role}@mail.example.test", password="Member-test123!")
                CustomerMembership.objects.create(user=member, customer=self.customer, role=role)
                self.assertTrue(self.prepare(actor=member).is_err())
                self.assertTrue(self.request(proposal, actor=member).is_err())
        self.assertTrue(prepare_mail_enrollment(self.account, actor=None, intent="enable", plan=self.plan).is_err())
        self.assertTrue(
            request_mail_enrollment(
                self.account,
                actor=None,
                intent="enable",
                proposal_id=proposal["proposal_id"],
                consent_digest=proposal["consent_digest"],
                submission_id=uuid4(),
            ).is_err()
        )
        self.assertFalse(VirtualminMailOperation.objects.exists())

    def test_cached_user_and_membership_cannot_outlive_revocation(self):
        proposal = self.prepared()
        User.objects.filter(pk=self.owner.pk).update(is_active=False)
        self.assertTrue(self.owner.is_active)
        self.assertTrue(self.request(proposal).is_err())
        self.assertTrue(self.prepare().is_err())
        User.objects.filter(pk=self.owner.pk).update(is_active=True)
        CustomerMembership.objects.filter(pk=self.membership.pk).update(is_active=False)
        self.assertTrue(self.membership.is_active)
        self.assertTrue(self.request(proposal).is_err())
        self.assertFalse(VirtualminMailOperation.objects.exists())

    def test_foreign_account_and_another_owner_cannot_reuse_a_proposal(self):
        proposal = self.prepared()
        foreign = _account(self.server, "foreign-consent.example.test")
        result = request_mail_enrollment(
            foreign,
            actor=self.owner,
            intent="enable",
            proposal_id=proposal["proposal_id"],
            consent_digest=proposal["consent_digest"],
            submission_id=uuid4(),
        )
        self.assertTrue(result.is_err())
        other = User.objects.create_user(email="second-owner@mail.example.test", password="Owner-test123!")
        CustomerMembership.objects.create(user=other, customer=self.customer, role="owner")
        self.assertTrue(self.request(proposal, actor=other).is_err())
        self.assertFalse(VirtualminMailOperation.objects.exists())

    def test_service_hold_after_prepare_is_seen_from_the_current_database_row(self):
        proposal = self.prepared()
        force_status(self.service, "suspended")
        self.assertTrue(self.request(proposal).is_err())
        self.assertTrue(self.prepare().is_err())
        self.assertFalse(VirtualminMailOperation.objects.exists())

    def test_exact_bound_domain_hold_refuses_enable_but_an_addon_does_not(self):
        proposal = self.prepared()
        registrar = Registrar.objects.create(name="mail-review", display_name="Mail review", status="active")
        tld = TLD.objects.create(
            extension="test", registration_price_cents=100, renewal_price_cents=100, transfer_price_cents=100
        )
        addon = Domain.objects.create(
            name="addon.example.test", customer=self.customer, registrar=registrar, tld=tld, status="expired"
        )
        ServiceDomain.objects.create(service=self.service, domain=addon)
        proposal = self.prepared()
        domain = Domain.objects.create(
            name=self.account.domain, customer=self.customer, registrar=registrar, tld=tld, status="expired"
        )
        ServiceDomain.objects.create(service=self.service, domain=domain)
        self.assertTrue(self.request(proposal).is_err())
        self.assertTrue(self.prepare().is_err())

    def test_migration_restore_delete_and_restore_hold_exclude_new_mail_work(self):
        proposal = self.prepared()
        for operation in ("restore_domain", "delete_domain", "backup_domain"):
            with self.subTest(operation=operation):
                job = VirtualminProvisioningJob.objects.create(
                    account=self.account, server=self.server, operation=operation, status="attention"
                )
                self.assertTrue(self.request(proposal).is_err())
                self.assertTrue(self.prepare().is_err())
                job.delete()
        migration = VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=_make_server(), status="needs_review"
        )
        self.assertTrue(self.request(proposal).is_err())
        self.assertTrue(self.prepare().is_err())
        migration.delete()
        self.account.restore_hold = "review required"
        self.account.save(update_fields=["restore_hold"])
        self.assertTrue(self.request(proposal).is_err())

    def test_node_address_change_invalidates_old_consent(self):
        proposal = self.prepared()
        self.server.ipv4_address = "203.0.113.21"
        self.server.save(update_fields=["ipv4_address"])
        self.assertTrue(self.request(proposal).is_err())
        self.assertFalse(VirtualminMailOperation.objects.exists())

    def test_name_retirement_invalidates_old_consent(self):
        proposal = self.prepared()
        self.name.retired_at = timezone.now()
        self.name.save(update_fields=["retired_at"])
        self.assertTrue(self.request(proposal).is_err())
        self.assertFalse(VirtualminMailOperation.objects.exists())

    def test_customer_transfer_invalidates_old_consent(self):
        proposal = self.prepared()
        foreign = _account(self.server, "new-owner.example.test")
        CustomerMembership.objects.create(user=self.owner, customer=foreign.service.customer, role="owner")
        self.service.customer = foreign.service.customer
        self.service.save(update_fields=["customer"])
        self.assertEqual(self.request(proposal).unwrap_err(), "mail_stale_proposal")
        self.assertFalse(VirtualminMailOperation.objects.exists())

    def test_committed_target_move_invalidates_an_old_review_for_the_same_owner(self):
        proposal = self.prepared()
        target = _make_server()
        self.account.server = target
        self.account.save(update_fields=["server"])
        self.name.target_server = target
        self.name.save(update_fields=["target_server"])
        self.assertEqual(self.request(proposal).unwrap_err(), "mail_stale_proposal")
        self.assertFalse(VirtualminMailOperation.objects.exists())

    def test_changed_digest_expired_or_replaced_proposal_cannot_confirm(self):
        proposal = self.prepared()
        self.assertTrue(self.request(proposal, digest="f" * 64).is_err())
        with patch(
            "apps.provisioning.virtualmin_mail_enrollment.timezone.now",
            return_value=timezone.now() + timedelta(hours=1),
        ):
            self.assertTrue(self.request(proposal).is_err())
        replacement = self.prepared()
        self.assertNotEqual(proposal["proposal_id"], replacement["proposal_id"])
        self.assertTrue(self.request(proposal).is_err())
        self.assertFalse(VirtualminMailOperation.objects.exists())

    def test_duplicate_submission_is_idempotent_but_changed_intent_or_proposal_conflicts(self):
        proposal = self.prepared()
        submission = uuid4()
        first = self.request(proposal, submission=submission).unwrap()
        second = self.request(proposal, submission=submission).unwrap()
        self.assertEqual(first.pk, second.pk)
        self.assertEqual(VirtualminMailOperation.objects.count(), 1)
        self.assertTrue(self.request(proposal, intent="disable", submission=submission).is_err())
        self.assertTrue(self.request({**proposal, "proposal_id": str(uuid4())}, submission=submission).is_err())
        self.assertEqual(VirtualminMailOperation.objects.count(), 1)

    def test_uncertain_previous_attempt_is_not_replaced_or_queued_again(self):
        proposal = self.prepared()
        submission = uuid4()
        first = self.request(proposal, submission=submission).unwrap()
        VirtualminMailOperation.objects.filter(pk=first.pk).update(status="needs_review", error_code="native_unknown")
        self.assertTrue(self.prepare().is_err())
        self.assertTrue(self.request(proposal).is_err())
        duplicate = self.request(proposal, submission=submission).unwrap()
        self.assertEqual((duplicate.pk, duplicate.status), (first.pk, "needs_review"))
        self.assertEqual(VirtualminMailOperation.objects.count(), 1)
        first.refresh_from_db()
        self.assertEqual(first.status, "needs_review")

    def test_every_open_mail_attempt_prevents_replacing_the_review_or_creating_another_request(self):
        proposal = self.prepared()
        operation = self.request(proposal).unwrap()
        for status in ("queued", "running", "awaiting_dns", "needs_review"):
            with self.subTest(status=status):
                operation.status = status
                operation.save(update_fields=["status"])
                self.assertEqual(self.prepare().unwrap_err(), "mail_operation_active")
                self.assertEqual(self.request(proposal).unwrap_err(), "mail_operation_active")
                self.assertEqual(VirtualminMailOperation.objects.count(), 1)
                config = VirtualminMailConfiguration.objects.get(account=self.account)
                self.assertEqual(config.proposal["proposal_id"], proposal["proposal_id"])

    def test_terminal_submission_remains_idempotent_and_cannot_adopt_another_reviewed_plan(self):
        proposal = self.prepared()
        submission = uuid4()
        first = self.request(proposal, submission=submission).unwrap()
        # Fixture a terminal attempt; there are no native/backend invocations in this service.
        first.status = "failed"
        first.save(update_fields=["status"])
        duplicate = self.request(proposal, submission=submission).unwrap()
        self.assertEqual(duplicate.pk, first.pk)
        self.plan["records"][0]["value"] = "10 other-reviewed.example."
        replacement = self.prepared()
        self.assertTrue(self.request(replacement, submission=submission).is_err())
        self.assertEqual(VirtualminMailOperation.objects.count(), 1)

    def test_return_to_external_mail_can_be_requested_under_a_hold_without_lifting_it(self):
        config = MailModelFixture.prepared(self)
        config.enable_hosted()
        config.save()
        force_status(self.service, "suspended")
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        proposal = self.prepare(intent="disable").unwrap()
        operation = self.request(proposal, intent="disable").unwrap()
        self.assertEqual((operation.status, operation.intent), ("queued", "disable"))
        config.refresh_from_db()
        self.service.refresh_from_db()
        self.account.refresh_from_db()
        self.assertEqual((config.mode, self.service.status, self.account.status), ("hosted", "suspended", "suspended"))

    def test_supported_depth_and_large_json_plans_can_confirm_their_own_envelope(self):
        nested = "bounded"
        for _ in range(9):
            nested = [nested]
        for plan in ({"nested": nested}, {"records": ["x" * 7000 for _ in range(9)]}):
            with self.subTest(shape=next(iter(plan))):
                proposal = self.prepare(plan=plan).unwrap()
                operation = self.request(proposal).unwrap()
                self.assertEqual(operation.confirmed_plan["plan"], plan)
                operation.status = "failed"
                operation.save(update_fields=["status"])

    def test_non_json_nonfinite_and_oversized_consent_plans_are_rejected(self):
        for plan in (
            {"bad": object()},
            {"bad": float("nan")},
            {"bad": "x" * 100000},
            {"bad": [[[[[[[[[[[[[["too deep"]]]]]]]]]]]]]]},
        ):
            with self.subTest(plan_type=next(iter(plan))):
                self.assertTrue(self.prepare(plan=plan).is_err())
        self.assertFalse(VirtualminMailConfiguration.objects.filter(account=self.account).exists())

    def test_tampering_with_staged_plan_without_matching_digest_is_rejected(self):
        proposal = self.prepared()
        config = VirtualminMailConfiguration.objects.get(account=self.account)
        config.proposal["plan"]["records"][0]["value"] = "10 foreign.example."
        config.save(update_fields=["proposal"])
        self.assertTrue(self.request(proposal).is_err())
        self.assertFalse(VirtualminMailOperation.objects.exists())
